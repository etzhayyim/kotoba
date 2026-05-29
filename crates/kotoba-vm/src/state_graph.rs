//! LangGraph-compatible `StateGraph` API backed by KOTOBA Datoms.
//!
//! ## Terminology mapping
//!
//! | LangGraph          | kotoba implementation                          |
//! |--------------------|------------------------------------------------|
//! | `StateGraph`       | `StateGraph` builder → `CompiledGraph`         |
//! | `Channel[T]`       | `ChannelSchema` + `State` channels map         |
//! | `Reducer`          | `Reducer::{Override,Append}`                   |
//! | `Node`             | `NodeKind::{Fn,ToolNode}`                      |
//! | `add_edge`         | `StateGraph::add_edge`                         |
//! | `add_conditional_edges` | `StateGraph::add_conditional_edges`       |
//! | `Thread`           | `Thread { thread_id: KotobaCid, state, steps }`|
//! | `Checkpointer`     | `PregelGraph::checkpoint_chained()`            |
//! | `graph_def_cid`    | CID over shape (channels+nodes+edges), NOT fns |
//!
//! ## Execution model
//!
//! A single Pregel vertex per `Thread` runs all nodes sequentially within one
//! superstep.  This matches LangGraph's default execution (BSP barrier is used
//! for cross-thread parallelism in a future phase, not intra-graph sequencing).

use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::agent::{Tool, ToolRegistry};
use crate::pregel::{ComputeFn, ComputeOutput, Message, PregelGraph, SuperstepResult, VertexId};

// ────────────────────────────────────────────────────────────────────────────
// Part 1 — Reducer, ChannelSchema, StateSchema, State
// ────────────────────────────────────────────────────────────────────────────

/// How a channel value is merged when `State::update` is called.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Reducer {
    /// Last write wins.  Equivalent to `Annotated[T, lambda a, b: b]`.
    Override,
    /// Values accumulate into a JSON array.  Equivalent to `Annotated[List, operator.add]`.
    Append,
}

/// Declaration of one named channel: its name and reducer.
#[derive(Debug, Clone)]
pub struct ChannelSchema {
    pub name: String,
    pub reducer: Reducer,
}

/// Schema for all channels in a `StateGraph`.
///
/// Build with the builder API:
/// ```ignore
/// let schema = StateSchema::new()
///     .channel("messages", Reducer::Append)
///     .channel("score",    Reducer::Override);
/// ```
#[derive(Debug, Clone, Default)]
pub struct StateSchema {
    channels: HashMap<String, Reducer>,
}

impl StateSchema {
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a channel.  Later calls with the same name replace the reducer.
    pub fn channel(mut self, name: impl Into<String>, reducer: Reducer) -> Self {
        self.channels.insert(name.into(), reducer);
        self
    }

    /// Reducer for the named channel; `Reducer::Override` if undeclared.
    pub fn reducer_for(&self, key: &str) -> &Reducer {
        self.channels.get(key).unwrap_or(&Reducer::Override)
    }

    /// Sorted channel names (used for deterministic `graph_def_cid` derivation).
    pub fn channel_names_sorted(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.channels.keys().map(|s| s.as_str()).collect();
        v.sort_unstable();
        v
    }
}

// ────────────────────────────────────────────────────────────────────────────
// State — runtime channel values with schema-driven reducers
// ────────────────────────────────────────────────────────────────────────────

/// Runtime state: the current value of all channels for one `Thread`.
///
/// `State` is intentionally NOT `Serialize` because it holds `Arc<StateSchema>`.
/// For Pregel vertex storage, only `State::channels()` is serialised; the
/// schema is re-injected from the compiled graph closure.
#[derive(Clone)]
pub struct State {
    schema: Arc<StateSchema>,
    channels: HashMap<String, Value>,
}

impl State {
    pub fn new(schema: Arc<StateSchema>) -> Self {
        Self {
            schema,
            channels: HashMap::new(),
        }
    }

    /// Convenience: create State with an initial `messages` array.
    ///
    /// `messages` will use whatever reducer the schema declares for that key
    /// (defaults to `Override` if not declared).
    pub fn from_messages(messages: Vec<Value>, schema: Arc<StateSchema>) -> Self {
        let mut s = Self::new(schema);
        s.channels
            .insert("messages".to_string(), Value::Array(messages));
        s
    }

    /// Reconstruct from a raw channels map (e.g. after Pregel vertex state
    /// deserialisation).
    pub(crate) fn from_channels(
        channels: HashMap<String, Value>,
        schema: Arc<StateSchema>,
    ) -> Self {
        Self { schema, channels }
    }

    /// Read a channel value.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.channels.get(key)
    }

    /// Apply a channel update using the schema's reducer.
    ///
    /// - `Reducer::Override` → replace (last-write-wins)
    /// - `Reducer::Append`   → push into JSON array
    ///   - channel absent  → initialise to `[value]`
    ///   - channel is array → push
    ///   - channel is scalar → overwrite with `[value]`
    pub fn update(&mut self, key: &str, value: Value) {
        match self.schema.reducer_for(key) {
            Reducer::Override => {
                self.channels.insert(key.to_string(), value);
            }
            Reducer::Append => {
                let existing = self
                    .channels
                    .entry(key.to_string())
                    .or_insert_with(|| Value::Array(vec![]));
                match existing {
                    Value::Array(arr) => match value {
                        // extend semantics: appending a list merges it (matches LangGraph add_messages)
                        Value::Array(new_items) => arr.extend(new_items),
                        single => arr.push(single),
                    },
                    other => match value {
                        Value::Array(new_items) => *other = Value::Array(new_items),
                        single => *other = Value::Array(vec![single]),
                    },
                }
            }
        }
    }

    /// Unconditional set — bypasses the reducer (used for initialisation).
    pub fn set_raw(&mut self, key: &str, value: Value) {
        self.channels.insert(key.to_string(), value);
    }

    /// All channel values.
    pub fn channels(&self) -> &HashMap<String, Value> {
        &self.channels
    }

    /// Convenience: return `channels["messages"]` as a `Vec<Value>`.
    /// Returns an empty vec if the channel is absent or not an array.
    pub fn messages(&self) -> Vec<Value> {
        match self.channels.get("messages") {
            Some(Value::Array(arr)) => arr.clone(),
            _ => vec![],
        }
    }

    pub fn schema(&self) -> &Arc<StateSchema> {
        &self.schema
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Part 2 — NodeOutput, EdgeTarget, RouterFn, NodeKind, StateGraph builder
// ────────────────────────────────────────────────────────────────────────────

/// What a node returns: a set of channel updates (no routing — that lives on
/// edges, exactly like LangGraph).
#[derive(Debug, Default, Clone)]
pub struct NodeOutput {
    pub updates: HashMap<String, Value>,
}

impl NodeOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(mut self, key: impl Into<String>, value: Value) -> Self {
        self.updates.insert(key.into(), value);
        self
    }

    pub fn extend(mut self, updates: HashMap<String, Value>) -> Self {
        self.updates.extend(updates);
        self
    }
}

/// Where a graph edge leads.
#[derive(Debug, Clone)]
pub enum EdgeTarget {
    /// Continue to the named node.
    Node(String),
    /// Terminate the graph.
    End,
}

/// Routing function for conditional edges.
///
/// Receives the *current* `State` and returns the next `EdgeTarget`.
pub type RouterFn = Arc<dyn Fn(&State) -> EdgeTarget + Send + Sync>;

/// Synchronous node function: reads `State`, returns channel updates.
///
/// Routing is NOT part of `NodeOutput` — use `add_conditional_edges` instead.
pub type NodeFn = Arc<dyn Fn(&State) -> NodeOutput + Send + Sync>;

#[derive(Clone)]
enum EdgeEntry {
    Always { from: String, target: EdgeTarget },
    Conditional { from: String, router: RouterFn },
}

/// Node variant: a Rust closure or the built-in `ToolNode`.
///
/// `ToolNode` reads `State.get("tool_calls")` (an array of
/// `{"tool": name, "input": str}` objects), dispatches each through the
/// `ToolRegistry`, and appends the results to `State["messages"]`.
pub enum NodeKind {
    /// Rust closure node.
    Fn(NodeFn),
    /// Built-in tool-dispatch node.  Tools are supplied via
    /// `CompiledGraph::with_tools()` or `StateGraph::compile_with_tools()`.
    ToolNode,
}

/// Builder for a `StateGraph`.
///
/// ```ignore
/// let compiled = StateGraph::new(
///         StateSchema::new()
///             .channel("messages", Reducer::Append)
///     )
///     .add_node("agent", NodeKind::Fn(agent_fn))
///     .add_node("tools", NodeKind::ToolNode)
///     .add_conditional_edges("agent", Arc::new(|s| route_from_messages(s)))
///     .add_edge("tools", "agent")
///     .set_entry_point("agent")
///     .compile();
/// ```
pub struct StateGraph {
    schema: StateSchema,
    nodes: Vec<(String, NodeKind)>,
    edges: Vec<EdgeEntry>,
    entry: Option<String>,
}

impl StateGraph {
    pub fn new(schema: StateSchema) -> Self {
        Self {
            schema,
            nodes: Vec::new(),
            edges: Vec::new(),
            entry: None,
        }
    }

    /// Register a node.  The order of registration matters only for
    /// `graph_def_cid` (sorted by name before hashing).
    pub fn add_node(mut self, name: impl Into<String>, kind: NodeKind) -> Self {
        self.nodes.push((name.into(), kind));
        self
    }

    /// Add an unconditional edge `from → to`.
    pub fn add_edge(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.edges.push(EdgeEntry::Always {
            from: from.into(),
            target: EdgeTarget::Node(to.into()),
        });
        self
    }

    /// Add a terminal unconditional edge `from → END`.
    pub fn add_end_edge(mut self, from: impl Into<String>) -> Self {
        self.edges.push(EdgeEntry::Always {
            from: from.into(),
            target: EdgeTarget::End,
        });
        self
    }

    /// Add a conditional edge.  `router` receives the current `State` and
    /// returns the next `EdgeTarget`.
    pub fn add_conditional_edges(mut self, from: impl Into<String>, router: RouterFn) -> Self {
        self.edges.push(EdgeEntry::Conditional {
            from: from.into(),
            router,
        });
        self
    }

    /// Set the entry-point node (required before `compile()`).
    pub fn set_entry_point(mut self, node: impl Into<String>) -> Self {
        self.entry = Some(node.into());
        self
    }

    /// Compile to a `CompiledGraph`.
    ///
    /// ## `graph_def_cid` derivation
    ///
    /// Only the **shape** is hashed — not the Rust closures (which are not
    /// content-addressable).  Shape = sorted channel declarations + sorted node
    /// names + sorted edge declarations + entry point.
    pub fn compile(self) -> CompiledGraph {
        self.compile_with_tools(ToolRegistry::default())
    }

    pub fn compile_with_tools(self, registry: ToolRegistry) -> CompiledGraph {
        let graph_def_cid = derive_graph_def_cid(&self);

        let schema = Arc::new(self.schema);
        let nodes: HashMap<String, NodeKind> = self.nodes.into_iter().collect();
        let edges: HashMap<String, EdgeEntry> = self
            .edges
            .into_iter()
            .map(|e| {
                let from = match &e {
                    EdgeEntry::Always { from, .. } | EdgeEntry::Conditional { from, .. } => {
                        from.clone()
                    }
                };
                (from, e)
            })
            .collect();
        let entry = self
            .entry
            .expect("StateGraph::compile(): set_entry_point() not called");

        CompiledGraph {
            graph_def_cid,
            schema,
            nodes,
            edges,
            entry,
            registry: Arc::new(registry),
        }
    }
}

/// Derive a content-addressed CID from the graph shape (not closures).
fn derive_graph_def_cid(g: &StateGraph) -> KotobaCid {
    // Canonical representation: sorted JSON
    let mut channels: Vec<(&str, &str)> = g
        .schema
        .channels
        .iter()
        .map(|(k, r)| {
            (
                k.as_str(),
                match r {
                    Reducer::Override => "override",
                    Reducer::Append => "append",
                },
            )
        })
        .collect();
    channels.sort_unstable();

    let mut node_names: Vec<&str> = g.nodes.iter().map(|(n, _)| n.as_str()).collect();
    node_names.sort_unstable();

    let mut edge_strs: Vec<String> = g
        .edges
        .iter()
        .map(|e| match e {
            EdgeEntry::Always {
                from,
                target: EdgeTarget::Node(to),
            } => format!("{from}->{to}"),
            EdgeEntry::Always {
                from,
                target: EdgeTarget::End,
            } => format!("{from}->END"),
            EdgeEntry::Conditional { from, .. } => format!("{from}->?"),
        })
        .collect();
    edge_strs.sort_unstable();

    let repr = serde_json::json!({
        "channels": channels,
        "nodes":    node_names,
        "edges":    edge_strs,
        "entry":    g.entry.as_deref().unwrap_or(""),
    });
    KotobaCid::from_bytes(repr.to_string().as_bytes())
}

// ────────────────────────────────────────────────────────────────────────────
// Part 3 — CompiledGraph, Thread, invoke()
// ────────────────────────────────────────────────────────────────────────────

/// A compiled, runnable graph.
pub struct CompiledGraph {
    /// Content-addressed identifier for the graph **shape** (not closures).
    pub graph_def_cid: KotobaCid,
    schema: Arc<StateSchema>,
    nodes: HashMap<String, NodeKind>,
    edges: HashMap<String, EdgeEntry>,
    entry: String,
    registry: Arc<ToolRegistry>,
}

impl CompiledGraph {
    /// Replace the default `ToolRegistry` (used by `NodeKind::ToolNode`).
    pub fn with_tools(mut self, registry: ToolRegistry) -> Self {
        self.registry = Arc::new(registry);
        self
    }

    /// Add a single tool on top of the current registry.
    pub fn with_tool(mut self, tool: Tool) -> Self {
        let reg = Arc::try_unwrap(self.registry).unwrap_or_else(|arc| (*arc).clone());
        self.registry = Arc::new(reg.register(tool));
        self
    }

    /// Emit the graph shape as Datoms for persistence in KQE.
    ///
    /// These quads can be stored in any `Arrangement` keyed by `graph_def_cid`.
    pub fn definition_datoms(&self) -> Vec<Quad> {
        let g = &self.graph_def_cid;
        let mut quads = vec![
            Quad {
                graph: g.clone(),
                subject: g.clone(),
                predicate: "lgraph/type".to_string(),
                object: QuadObject::Text("state_graph".to_string()),
            },
            Quad {
                graph: g.clone(),
                subject: g.clone(),
                predicate: "lgraph/entry".to_string(),
                object: QuadObject::Text(self.entry.clone()),
            },
        ];
        for name in self.schema.channel_names_sorted() {
            let reducer = match self.schema.reducer_for(name) {
                Reducer::Override => "override",
                Reducer::Append => "append",
            };
            quads.push(Quad {
                graph: g.clone(),
                subject: KotobaCid::from_bytes(format!("channel/{name}").as_bytes()),
                predicate: "lgraph/channel/reducer".to_string(),
                object: QuadObject::Text(reducer.to_string()),
            });
        }
        for node_name in self.nodes.keys() {
            quads.push(Quad {
                graph: g.clone(),
                subject: KotobaCid::from_bytes(format!("node/{node_name}").as_bytes()),
                predicate: "lgraph/node/name".to_string(),
                object: QuadObject::Text(node_name.clone()),
            });
        }
        quads
    }

    /// Run the graph from `input` and return the final `Thread`.
    ///
    /// Execution model: a single Pregel vertex runs all nodes sequentially
    /// within one superstep.  The BSP barrier is used for cross-thread
    /// parallelism in future phases.
    pub fn invoke(&self, input: State, thread_id: Option<KotobaCid>) -> Thread {
        let thread_id = thread_id.unwrap_or_else(|| {
            KotobaCid::from_bytes(
                format!("thread/{}", self.graph_def_cid.to_multibase()).as_bytes(),
            )
        });

        let schema = Arc::clone(&self.schema);
        let nodes = Arc::new(
            self.nodes
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        match v {
                            NodeKind::Fn(f) => InternalNode::Fn(Arc::clone(f)),
                            NodeKind::ToolNode => InternalNode::ToolNode,
                        },
                    )
                })
                .collect::<HashMap<String, InternalNode>>(),
        );
        let edges = Arc::new(self.edges.clone());
        let entry = self.entry.clone();
        let registry = Arc::clone(&self.registry);
        let schema2 = Arc::clone(&schema);

        // Vertex state is just the channels HashMap serialised as JSON.
        let initial_channels = input.channels().clone();
        let initial_state = serde_json::to_vec(&initial_channels).unwrap_or_default();

        let compute: ComputeFn = Box::new(move |vertex, inbox| {
            if inbox.is_empty() {
                return ComputeOutput {
                    new_state: vertex.state.clone(),
                    messages: vec![],
                    vote_halt: true,
                };
            }

            // Deserialise channels from vertex state
            let channels: HashMap<String, Value> =
                serde_json::from_slice(&vertex.state).unwrap_or_default();
            let mut state = State::from_channels(channels, Arc::clone(&schema2));

            // Sequential node traversal (LangGraph default execution model)
            let mut current = entry.clone();
            let mut visited = 0u32;
            let limit = 256u32;

            while visited < limit {
                visited += 1;

                // Run the node
                let updates = match nodes.get(&current) {
                    Some(InternalNode::Fn(f)) => f(&state).updates,
                    Some(InternalNode::ToolNode) => run_tool_node(&state, &registry),
                    None => {
                        // Unknown node — stop
                        break;
                    }
                };

                // Apply updates via schema reducers
                for (k, v) in updates {
                    state.update(&k, v);
                }

                // Resolve edge
                let next = match edges.get(&current) {
                    Some(EdgeEntry::Always {
                        target: EdgeTarget::End,
                        ..
                    }) => break,
                    Some(EdgeEntry::Always {
                        target: EdgeTarget::Node(n),
                        ..
                    }) => n.clone(),
                    Some(EdgeEntry::Conditional { router, .. }) => match router(&state) {
                        EdgeTarget::End => break,
                        EdgeTarget::Node(n) => n,
                    },
                    None => break, // no edge declared = END
                };
                current = next;
            }

            let new_state = serde_json::to_vec(state.channels()).unwrap_or_default();
            ComputeOutput {
                new_state,
                messages: vec![],
                vote_halt: true,
            }
        });

        let vid = VertexId(thread_id.clone());
        let mut graph = PregelGraph::new();
        graph.add_vertex(vid.clone(), initial_state);
        graph.inject_message(Message {
            src: vid.clone(),
            dst: vid.clone(),
            payload: b"start".to_vec(),
        });

        let superstep_results = graph.run(&compute, 2);

        let final_channels: HashMap<String, Value> = graph
            .vertex(&vid)
            .and_then(|v| if v.state.is_empty() { None } else { Some(v) })
            .and_then(|v| serde_json::from_slice(&v.state).ok())
            .unwrap_or_default();
        let final_state = State::from_channels(final_channels, schema);

        Thread {
            thread_id,
            state: final_state,
            superstep_results,
        }
    }
}

// ── Internal dispatch helper ──────────────────────────────────────────────

#[derive(Clone)]
enum InternalNode {
    Fn(NodeFn),
    ToolNode,
}

/// Execute `NodeKind::ToolNode`: read `tool_calls` from state, dispatch via
/// `ToolRegistry`, append tool results to `messages`.
fn run_tool_node(state: &State, registry: &ToolRegistry) -> HashMap<String, Value> {
    use crate::agent::AgentSnapshot;

    let calls = match state.get("tool_calls") {
        Some(Value::Array(arr)) => arr.clone(),
        _ => return HashMap::new(),
    };

    let mut snap = AgentSnapshot::default();
    let mut tool_messages: Vec<Value> = Vec::new();

    for call in calls {
        let tool_name = call
            .get("tool")
            .and_then(|v| v.as_str())
            .unwrap_or("finish");
        let input = call.get("input").and_then(|v| v.as_str()).unwrap_or("");
        let out = registry.call(tool_name, input, &mut snap);
        tool_messages.push(serde_json::json!({
            "role":    "tool",
            "content": out.observation,
            "tool":    tool_name,
        }));
    }

    let mut updates = HashMap::new();
    updates.insert("messages".to_string(), Value::Array(tool_messages));
    updates
}

// ── Thread ────────────────────────────────────────────────────────────────

/// Result of `CompiledGraph::invoke()` — equivalent to a LangGraph thread.
pub struct Thread {
    /// Content-addressed thread identifier (≅ LangGraph `thread_id`).
    pub thread_id: KotobaCid,
    /// Final state after the graph terminated.
    pub state: State,
    /// Pregel superstep results (for introspection / checkpointing).
    pub superstep_results: Vec<SuperstepResult>,
}

impl Thread {
    /// Convenience: return the final `messages` channel value.
    pub fn messages(&self) -> Vec<Value> {
        self.state.messages()
    }

    /// Convenience: return any channel value by name.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.state.get(key)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema() -> StateSchema {
        StateSchema::new()
            .channel("messages", Reducer::Append)
            .channel("score", Reducer::Override)
    }

    // ── Reducer / State ───────────────────────────────────────────────────

    #[test]
    fn override_reducer_replaces() {
        let mut s = State::new(Arc::new(schema()));
        s.update("score", json!(1));
        s.update("score", json!(2));
        assert_eq!(s.get("score"), Some(&json!(2)));
    }

    #[test]
    fn append_reducer_builds_array() {
        let mut s = State::new(Arc::new(schema()));
        s.update("messages", json!("hello"));
        s.update("messages", json!("world"));
        assert_eq!(s.messages(), vec![json!("hello"), json!("world")]);
    }

    #[test]
    fn append_on_absent_initialises_array() {
        let mut s = State::new(Arc::new(schema()));
        s.update("messages", json!("first"));
        assert_eq!(s.messages(), vec![json!("first")]);
    }

    #[test]
    fn append_on_scalar_overwrites_with_array() {
        let mut s = State::new(Arc::new(schema()));
        s.set_raw("messages", json!("not-an-array"));
        s.update("messages", json!("new"));
        assert_eq!(s.messages(), vec![json!("new")]);
    }

    #[test]
    fn undeclared_channel_defaults_to_override() {
        let mut s = State::new(Arc::new(schema()));
        s.update("extra", json!(1));
        s.update("extra", json!(2));
        assert_eq!(s.get("extra"), Some(&json!(2)));
    }

    #[test]
    fn state_messages_returns_empty_when_absent() {
        let s = State::new(Arc::new(schema()));
        assert!(s.messages().is_empty());
    }

    // ── graph_def_cid determinism ─────────────────────────────────────────

    #[test]
    fn same_shape_produces_same_cid() {
        fn build() -> StateGraph {
            StateGraph::new(schema())
                .add_node("agent", NodeKind::Fn(Arc::new(|_| NodeOutput::new())))
                .add_node("tools", NodeKind::ToolNode)
                .add_edge("tools", "agent")
                .add_conditional_edges("agent", Arc::new(|_| EdgeTarget::End))
                .set_entry_point("agent")
        }
        let cid_a = build().compile().graph_def_cid;
        let cid_b = build().compile().graph_def_cid;
        assert_eq!(cid_a, cid_b, "same shape → same CID");
    }

    #[test]
    fn different_shape_produces_different_cid() {
        let cid_a = StateGraph::new(schema())
            .add_node("agent", NodeKind::Fn(Arc::new(|_| NodeOutput::new())))
            .add_edge("agent", "agent")
            .set_entry_point("agent")
            .compile()
            .graph_def_cid;

        let cid_b = StateGraph::new(schema())
            .add_node("agent", NodeKind::Fn(Arc::new(|_| NodeOutput::new())))
            .add_node("tools", NodeKind::ToolNode)
            .add_edge("tools", "agent")
            .set_entry_point("agent")
            .compile()
            .graph_def_cid;

        assert_ne!(cid_a, cid_b);
    }

    // ── invoke / Thread ───────────────────────────────────────────────────

    #[test]
    fn single_node_graph_runs_and_terminates() {
        let compiled = StateGraph::new(schema())
            .add_node(
                "agent",
                NodeKind::Fn(Arc::new(|_s| NodeOutput::new().set("score", json!(42)))),
            )
            .add_end_edge("agent")
            .set_entry_point("agent")
            .compile();

        let input = State::new(Arc::new(schema()));
        let thread = compiled.invoke(input, None);
        assert_eq!(thread.get("score"), Some(&json!(42)));
    }

    #[test]
    fn two_node_sequential_graph() {
        // agent → tools → END
        let compiled = StateGraph::new(schema())
            .add_node(
                "agent",
                NodeKind::Fn(Arc::new(|_| {
                    NodeOutput::new().set(
                        "tool_calls",
                        json!([{"tool": "kqe.assert", "input": "fact"}]),
                    )
                })),
            )
            .add_node("tools", NodeKind::ToolNode)
            .add_edge("agent", "tools")
            .add_end_edge("tools")
            .set_entry_point("agent")
            .compile();

        let input = State::new(Arc::new(schema()));
        let thread = compiled.invoke(input, None);
        // ToolNode appended a tool result message
        let msgs = thread.messages();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["role"], "tool");
    }

    #[test]
    fn conditional_edge_routes_to_end() {
        let compiled = StateGraph::new(schema())
            .add_node(
                "agent",
                NodeKind::Fn(Arc::new(|_| NodeOutput::new().set("score", json!(99)))),
            )
            .add_conditional_edges(
                "agent",
                Arc::new(|state| {
                    if state.get("score").and_then(|v| v.as_i64()) == Some(99) {
                        EdgeTarget::End
                    } else {
                        EdgeTarget::Node("agent".to_string())
                    }
                }),
            )
            .set_entry_point("agent")
            .compile();

        let input = State::new(Arc::new(schema()));
        let thread = compiled.invoke(input, None);
        assert_eq!(thread.get("score"), Some(&json!(99)));
    }

    #[test]
    fn cycle_limit_prevents_infinite_loop() {
        // agent always routes to itself — should terminate via cycle limit
        let compiled = StateGraph::new(schema())
            .add_node("agent", NodeKind::Fn(Arc::new(|_| NodeOutput::new())))
            .add_edge("agent", "agent")
            .set_entry_point("agent")
            .compile();

        // This should return (not hang) because of the 256-step limit
        let thread = compiled.invoke(State::new(Arc::new(schema())), None);
        let _ = thread; // just checking it terminates
    }

    #[test]
    fn definition_datoms_include_channel_and_node_quads() {
        let compiled = StateGraph::new(schema())
            .add_node("agent", NodeKind::Fn(Arc::new(|_| NodeOutput::new())))
            .set_entry_point("agent")
            .compile();

        let datoms = compiled.definition_datoms();
        let has_type = datoms.iter().any(|q| q.predicate == "lgraph/type");
        let has_entry = datoms.iter().any(|q| q.predicate == "lgraph/entry");
        let has_chan = datoms
            .iter()
            .any(|q| q.predicate == "lgraph/channel/reducer");
        let has_node = datoms.iter().any(|q| q.predicate == "lgraph/node/name");
        assert!(has_type && has_entry && has_chan && has_node);
    }

    #[test]
    fn thread_id_is_deterministic_for_same_graph() {
        let compiled = StateGraph::new(schema())
            .add_node("a", NodeKind::Fn(Arc::new(|_| NodeOutput::new())))
            .add_end_edge("a")
            .set_entry_point("a")
            .compile();

        let fixed_tid = KotobaCid::from_bytes(b"fixed-thread-1");
        let t1 = compiled.invoke(State::new(Arc::new(schema())), Some(fixed_tid.clone()));
        let t2 = compiled.invoke(State::new(Arc::new(schema())), Some(fixed_tid.clone()));
        assert_eq!(t1.thread_id, t2.thread_id);
    }

    // ── additional gap tests ──────────────────────────────────────────────────

    #[test]
    fn state_from_messages_stores_messages_channel() {
        let schema = Arc::new(schema());
        let msgs = vec![json!({"role":"user","content":"hi"})];
        let s = State::from_messages(msgs.clone(), schema);
        assert_eq!(s.messages(), msgs);
    }

    #[test]
    fn state_schema_channel_names_sorted() {
        let schema = StateSchema::new()
            .channel("zebra", Reducer::Override)
            .channel("alpha", Reducer::Append)
            .channel("messages", Reducer::Append);
        let names = schema.channel_names_sorted();
        assert_eq!(names, vec!["alpha", "messages", "zebra"]);
    }

    #[test]
    fn node_output_set_and_extend() {
        let mut extra = HashMap::new();
        extra.insert("count".to_string(), json!(3));
        extra.insert("ready".to_string(), json!(true));

        let out = NodeOutput::new().set("score", json!(10)).extend(extra);

        assert_eq!(out.updates.get("score"), Some(&json!(10)));
        assert_eq!(out.updates.get("count"), Some(&json!(3)));
        assert_eq!(out.updates.get("ready"), Some(&json!(true)));
        assert_eq!(out.updates.len(), 3);
    }

    #[test]
    fn append_array_extends_existing_array() {
        let mut s = State::new(Arc::new(schema()));
        s.update("messages", json!("first"));
        s.update("messages", json!(["second", "third"])); // array extends
        let msgs = s.messages();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0], json!("first"));
        assert_eq!(msgs[1], json!("second"));
        assert_eq!(msgs[2], json!("third"));
    }

    #[test]
    fn definition_datoms_count_increases_with_channels_and_nodes() {
        let compiled_1 = StateGraph::new(StateSchema::new().channel("x", Reducer::Override))
            .add_node("n1", NodeKind::Fn(Arc::new(|_| NodeOutput::new())))
            .set_entry_point("n1")
            .compile();

        let compiled_2 = StateGraph::new(
            StateSchema::new()
                .channel("x", Reducer::Override)
                .channel("y", Reducer::Append),
        )
        .add_node("n1", NodeKind::Fn(Arc::new(|_| NodeOutput::new())))
        .add_node("n2", NodeKind::Fn(Arc::new(|_| NodeOutput::new())))
        .set_entry_point("n1")
        .compile();

        let d1 = compiled_1.definition_datoms().len();
        let d2 = compiled_2.definition_datoms().len();
        assert!(d2 > d1, "more channels + nodes → more datoms");
    }

    #[test]
    fn thread_get_returns_channel_value() {
        let compiled = StateGraph::new(schema())
            .add_node(
                "a",
                NodeKind::Fn(Arc::new(|_| {
                    NodeOutput::new()
                        .set("score", json!(77))
                        .set("messages", json!("hello"))
                })),
            )
            .add_end_edge("a")
            .set_entry_point("a")
            .compile();

        let thread = compiled.invoke(State::new(Arc::new(schema())), None);
        assert_eq!(thread.get("score"), Some(&json!(77)));
        // messages was Append so it should be an array
        assert!(thread.get("messages").is_some());
    }
}
