//! ReAct (Reason + Act) agent loop for KOTOBA.
//!
//! Two execution backends:
//!
//! 1. `ReActRunner`       — simple sync loop (test / embedded use).
//! 2. `PregelReActRunner` — BSP superstep engine via `PregelGraph`.
//!
//! ## Tool registry
//!
//! `ToolRegistry::default()` ships four built-in tools:
//!   - `kqe.assert(<quad>)`            — append a fact to the session quad log
//!   - `kqe.query(<q>)`                — list facts from the session quad log
//!   - `kse.publish(<topic>,<msg>)`    — emit a KSE publish event
//!   - `finish(<answer>)`              — terminal; halts the vertex
//!
//! Register custom tools via `AgentSession::with_tool()`:
//! ```ignore
//! let session = AgentSession::new("task", graph_cid, 10)
//!     .with_tool(Tool::from_fn("http.get", "Fetch a URL", Arc::new(|url, _snap| {
//!         ToolOutput { observation: format!("body of {url}"), done: false, route: None }
//!     })));
//! ```
//!
//! ## Named channels
//!
//! Typed, persistent state alongside the quad log:
//! ```ignore
//! snap.channel_set("score", serde_json::json!(42), ChannelMode::Override);
//! let v = snap.channel_get("score"); // Some(Value::Number(42))
//! snap.channel_set("log", serde_json::json!("step1"), ChannelMode::Append);
//! snap.channel_set("log", serde_json::json!("step2"), ChannelMode::Append);
//! // channels["log"] == ["step1", "step2"]
//! ```
//!
//! ## Conditional routing (Pregel backend)
//!
//! A tool may return `route: Some("vertex_key")` to redirect the continuation
//! message to a different `PregelGraph` vertex.  The target is auto-created with
//! empty state if it does not exist yet.
//!
//! **Warning:** auto-created vertices start with an empty `AgentSnapshot` (empty
//! task string).  Pre-seed the destination vertex with a meaningful task before
//! calling `run()`, or ensure the destination's first compute step does not
//! depend on an initialised task prompt.

use kotoba_core::cid::KotobaCid;
use kotoba_kqe::{
    arrangement::Arrangement,
    datom::{Datom, Value as DatomValue},
    delta::Delta,
    quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject},
};
use kotoba_runtime::host::InferenceFn;
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// ToolOutput
// ---------------------------------------------------------------------------

/// Value returned by every tool invocation.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    /// Text presented to the agent as the observation for this action.
    pub observation: String,
    /// `true` → push `ReActStep::Finish` and vote halt.
    pub done: bool,
    /// Vertex key for the next message in `PregelReActRunner`.
    /// `None` = self-loop (continue on the same vertex).
    /// `Some(key)` = route to a different vertex (conditional routing).
    pub route: Option<String>,
}

// ---------------------------------------------------------------------------
// Tool
// ---------------------------------------------------------------------------

/// Synchronous callable registered in `ToolRegistry`.
///
/// The function receives the raw action input string and a mutable reference
/// to the current `AgentSnapshot` so it can read/write the quad log and
/// named channels.
pub type ToolFn = Arc<dyn Fn(&str, &mut AgentSnapshot) -> ToolOutput + Send + Sync>;

pub struct Tool {
    pub name: String,
    pub description: String,
    func: ToolFn,
}

impl Clone for Tool {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            description: self.description.clone(),
            func: Arc::clone(&self.func),
        }
    }
}

impl Tool {
    pub fn new(name: impl Into<String>, description: impl Into<String>, func: ToolFn) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            func,
        }
    }

    /// Convenience constructor — wraps the closure in `Arc` for you.
    ///
    /// ```ignore
    /// Tool::from_fn("echo", "Echo input back", |input, _snap| ToolOutput {
    ///     observation: input.to_string(),
    ///     done: false,
    ///     route: None,
    /// })
    /// ```
    pub fn from_fn<F>(name: impl Into<String>, description: impl Into<String>, f: F) -> Self
    where
        F: Fn(&str, &mut AgentSnapshot) -> ToolOutput + Send + Sync + 'static,
    {
        Self::new(name, description, Arc::new(f))
    }

    pub fn call(&self, input: &str, snap: &mut AgentSnapshot) -> ToolOutput {
        (self.func)(input, snap)
    }
}

// ---------------------------------------------------------------------------
// ToolRegistry
// ---------------------------------------------------------------------------

pub struct ToolRegistry {
    tools: HashMap<String, Tool>,
}

impl Clone for ToolRegistry {
    fn clone(&self) -> Self {
        Self {
            tools: self
                .tools
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Add or replace a tool.  Builder-style — returns `Self` for chaining.
    pub fn register(mut self, tool: Tool) -> Self {
        self.tools.insert(tool.name.clone(), tool);
        self
    }

    /// Invoke a named tool.  Returns an "unknown tool" observation if the name
    /// is not registered — matches the fall-through behaviour of the original
    /// hard-coded match.
    pub fn call(&self, name: &str, input: &str, snap: &mut AgentSnapshot) -> ToolOutput {
        match self.tools.get(name) {
            Some(t) => t.call(input, snap),
            None => ToolOutput {
                observation: format!("unknown tool: {name}"),
                done: false,
                route: None,
            },
        }
    }

    /// Single-line listing of all tools injected into the agent prompt.
    pub fn tool_descriptions(&self) -> String {
        let mut names: Vec<&str> = self.tools.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names
            .iter()
            .map(|n| format!("{n}: {}", self.tools[*n].description))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn names(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.tools.keys().map(|s| s.as_str()).collect();
        v.sort_unstable();
        v
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
            .register(Tool::from_fn(
                "finish",
                "Return the final answer and halt",
                |input, _snap| ToolOutput {
                    observation: input.to_string(),
                    done: true,
                    route: None,
                },
            ))
            .register(Tool::from_fn(
                "kqe.assert",
                "Assert a fact (JSON Quad or plain text) into the session quad log",
                |input, snap| {
                    let obs = snap.assert_quad(input);
                    ToolOutput {
                        observation: obs,
                        done: false,
                        route: None,
                    }
                },
            ))
            .register(Tool::from_fn(
                "kqe.query",
                "List facts from the session quad log",
                |_input, snap| {
                    let obs = snap.query_quads();
                    ToolOutput {
                        observation: obs,
                        done: false,
                        route: None,
                    }
                },
            ))
            .register(Tool::from_fn(
                "kse.publish",
                "Publish a KSE event: kse.publish(<topic>,<message>)",
                |input, _snap| ToolOutput {
                    observation: format!("published: {}", &input[..input.len().min(64)]),
                    done: false,
                    route: None,
                },
            ))
    }
}

// ---------------------------------------------------------------------------
// ReAct step types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReActStep {
    Thought { text: String },
    Action { tool: String, input: String },
    Observation { output: String },
    Finish { answer: String },
}

// ---------------------------------------------------------------------------
// Named channel mode
// ---------------------------------------------------------------------------

/// Controls how `AgentSnapshot::channel_set` merges with an existing value.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ChannelMode {
    /// Replace the existing value (last-write-wins).
    Override,
    /// Merge into a JSON array.
    /// - Channel absent → initialises to `[value]`.
    /// - Channel holds an array → appends `value`.
    /// - Channel holds a non-array scalar → overwrites with `[value]`.
    Append,
}

// ---------------------------------------------------------------------------
// AgentSession
// ---------------------------------------------------------------------------

/// Carries all live (non-serializable) state for one agent run.
pub struct AgentSession {
    pub session_cid: KotobaCid,
    pub graph_cid: KotobaCid,
    pub task: String,
    pub steps: Vec<ReActStep>,
    pub arrangement: Arrangement,
    pub max_steps: u32,
    /// Tool registry.  Defaults to `ToolRegistry::default()` (four built-in tools).
    pub registry: Arc<ToolRegistry>,
    /// Named channels populated by tools during the run.
    pub channels: HashMap<String, serde_json::Value>,
}

impl AgentSession {
    /// Create a session with the default tool registry.
    ///
    /// Signature is unchanged from the original — existing call sites compile
    /// without modification.
    pub fn new(task: impl Into<String>, graph_cid: KotobaCid, max_steps: u32) -> Self {
        let task = task.into();
        let session_cid = KotobaCid::from_bytes(
            format!(
                "agent/{}/{}",
                graph_cid.to_multibase(),
                &task[..task.len().min(64)]
            )
            .as_bytes(),
        );
        Self {
            session_cid,
            graph_cid,
            task,
            steps: Vec::new(),
            arrangement: Arrangement::new(),
            max_steps,
            registry: Arc::new(ToolRegistry::default()),
            channels: HashMap::new(),
        }
    }

    /// Replace the entire tool registry (builder-style).
    pub fn with_registry(mut self, registry: ToolRegistry) -> Self {
        self.registry = Arc::new(registry);
        self
    }

    /// Add a single tool on top of the current registry (builder-style).
    ///
    /// If the registry `Arc` is uniquely owned it is unwrapped in place;
    /// otherwise the registry is cloned before inserting the tool.
    pub fn with_tool(mut self, tool: Tool) -> Self {
        let reg = Arc::try_unwrap(self.registry).unwrap_or_else(|arc| (*arc).clone());
        self.registry = Arc::new(reg.register(tool));
        self
    }
}

// ---------------------------------------------------------------------------
// AgentSnapshot — serializable vertex state for Pregel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AgentSnapshot {
    pub task: String,
    pub steps: Vec<ReActStep>,
    /// Quad log: `(subject_multibase, predicate, object_json)` triples.
    pub quads: Vec<(String, String, String)>,
    pub max_steps: u32,
    /// Named channels written by tools via `channel_set`.
    /// The `#[serde(default)]` attribute ensures older snapshots (without this
    /// field) deserialise without error.
    #[serde(default)]
    pub channels: HashMap<String, serde_json::Value>,
}

impl AgentSnapshot {
    fn from_session(s: &AgentSession) -> Self {
        Self {
            task: s.task.clone(),
            steps: s.steps.clone(),
            quads: Vec::new(),
            max_steps: s.max_steps,
            channels: s.channels.clone(),
        }
    }

    // -- quad log helpers ---------------------------------------------------

    /// Assert a fact.  Accepts a JSON-encoded `Quad` or falls back to plain text.
    fn assert_quad(&mut self, input: &str) -> String {
        let (subj, pred, obj) = if let Ok(q) = serde_json::from_str::<Quad>(input) {
            (
                q.subject.to_multibase(),
                q.predicate.clone(),
                serde_json::to_string(&q.object).unwrap_or_else(|_| input.to_string()),
            )
        } else {
            let obj_val = QuadObject::Text(input.to_string());
            (
                KotobaCid::from_bytes(input.as_bytes()).to_multibase(),
                "agent/fact".to_string(),
                serde_json::to_string(&obj_val).unwrap_or_default(),
            )
        };
        self.quads.push((subj, pred, obj));
        format!("asserted; quad log now has {} entries", self.quads.len())
    }

    fn query_quads(&self) -> String {
        if self.quads.is_empty() {
            return "quad log is empty".to_string();
        }
        let preview: Vec<String> = self
            .quads
            .iter()
            .take(5)
            .map(|(s, p, o)| format!("({s} {p} {o})"))
            .collect();
        format!(
            "{} quads: [{}{}]",
            self.quads.len(),
            preview.join(", "),
            if self.quads.len() > 5 { ", ..." } else { "" },
        )
    }

    // -- named channel helpers ----------------------------------------------

    /// Write a value to a named channel.
    ///
    /// - `ChannelMode::Override` — replaces any existing value.
    /// - `ChannelMode::Append`   — merges into a JSON array.
    ///   If the channel holds a non-array scalar it is **overwritten** with
    ///   `[value]` (no implicit wrapping of the old scalar into the array).
    pub fn channel_set(&mut self, key: &str, value: serde_json::Value, mode: ChannelMode) {
        match mode {
            ChannelMode::Override => {
                self.channels.insert(key.to_string(), value);
            }
            ChannelMode::Append => {
                let entry = self
                    .channels
                    .entry(key.to_string())
                    .or_insert_with(|| serde_json::Value::Array(vec![]));
                match entry {
                    serde_json::Value::Array(arr) => arr.push(value),
                    other => *other = serde_json::Value::Array(vec![value]),
                }
            }
        }
    }

    /// Read a named channel value.  Returns `None` if the channel is absent.
    pub fn channel_get(&self, key: &str) -> Option<&serde_json::Value> {
        self.channels.get(key)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn build_prompt(task: &str, steps: &[ReActStep], registry: &ToolRegistry) -> String {
    let mut p = String::new();
    let _ = writeln!(
        p,
        "You are a KOTOBA reasoning agent. Solve tasks step-by-step using ReAct."
    );
    let _ = writeln!(p);
    let _ = writeln!(p, "TOOLS:");
    let mut names: Vec<&str> = registry.tools.keys().map(|s| s.as_str()).collect();
    names.sort_unstable();
    for name in &names {
        let _ = writeln!(p, "  {name} — {}", registry.tools[*name].description);
    }
    let _ = writeln!(p);
    let _ = writeln!(p, "RULES:");
    let _ = writeln!(
        p,
        "  - Each response MUST contain exactly these two lines (nothing else):"
    );
    let _ = writeln!(p, "      Thought: <your reasoning>");
    let _ = writeln!(p, "      Action: <tool_name>(<input>)");
    let _ = writeln!(
        p,
        "  - Call finish when you have the answer: Action: finish(<answer>)"
    );
    let _ = writeln!(p);
    let _ = writeln!(p, "EXAMPLE:");
    let _ = writeln!(p, "Thought: I should check what facts I have.");
    let _ = writeln!(p, "Action: kqe.query(*)");
    let _ = writeln!(p, "Observation: quad log is empty");
    let _ = writeln!(
        p,
        "Thought: No prior facts. I will answer from my knowledge."
    );
    let _ = writeln!(p, "Action: finish(The capital of France is Paris.)");
    let _ = writeln!(p);
    let _ = writeln!(p, "--- TASK ---");
    let _ = writeln!(p, "Task: {task}");
    let _ = writeln!(p);
    for step in steps {
        match step {
            ReActStep::Thought { text } => {
                let _ = writeln!(p, "Thought: {text}");
            }
            ReActStep::Action { tool, input } => {
                let _ = writeln!(p, "Action: {tool}({input})");
            }
            ReActStep::Observation { output } => {
                let _ = writeln!(p, "Observation: {output}");
            }
            ReActStep::Finish { answer } => {
                let _ = writeln!(p, "Answer: {answer}");
            }
        }
    }
    let _ = write!(p, "Thought:");
    p
}

/// Try to parse `tool(input)` from a single trimmed string.
/// Returns `None` if the string does not match the pattern or has an invalid tool name.
fn try_parse_tool_call(s: &str) -> Option<(String, String)> {
    let paren = s.find('(')?;
    let tool = s[..paren].trim();
    // Tool names are alphanumeric + dots + underscores only.
    if tool.is_empty()
        || !tool
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '_')
    {
        return None;
    }
    let rest = &s[paren + 1..];
    let input = rest.strip_suffix(')').unwrap_or(rest).trim().to_string();
    Some((tool.to_string(), input))
}

/// Extract the `(tool, input)` pair from LLM output.
///
/// Scan strategy (in order):
///  1. Any line that starts with "Action:" — parse `tool(input)` from it.
///  2. Fallback: parse the first line directly as `tool(input)` (bare format).
///  3. No parseable action: treat the entire text as a `finish` answer.
fn parse_action(text: &str) -> (String, String) {
    // Pass 1: look for an explicit "Action: tool(input)" line.
    for line in text.lines() {
        let line = line.trim();
        if let Some(candidate) = line.strip_prefix("Action:") {
            if let Some(pair) = try_parse_tool_call(candidate.trim()) {
                return pair;
            }
        }
    }
    // Pass 2: bare `tool(input)` on the first line (test engines / simple models).
    let first = text.lines().next().unwrap_or(text).trim();
    if let Some(pair) = try_parse_tool_call(first) {
        return pair;
    }
    // Pass 3: no structured action — surface the full text as a finish answer.
    ("finish".to_string(), text.trim().to_string())
}

// Reconstruct an `Arrangement` from the flat quad tuples stored in a snapshot.
fn arrangement_from_snap(snap: &AgentSnapshot, graph_cid: &KotobaCid) -> Arrangement {
    let mut arr = Arrangement::new();
    for (subj_mb, pred, obj_json) in &snap.quads {
        if let (Some(subject), Ok(obj)) = (
            KotobaCid::from_multibase(subj_mb),
            serde_json::from_str::<QuadObject>(obj_json),
        ) {
            arr.insert(&Quad {
                graph: graph_cid.clone(),
                subject,
                predicate: pred.clone(),
                object: obj,
            });
        }
    }
    arr
}

// ---------------------------------------------------------------------------
// Backend 1: simple sync ReActRunner
// ---------------------------------------------------------------------------

pub struct ReActRunner {
    inference_engine: InferenceFn,
    max_tokens: usize,
}

impl ReActRunner {
    pub fn new(inference_engine: InferenceFn, max_tokens: usize) -> Self {
        Self {
            inference_engine,
            max_tokens,
        }
    }

    pub fn run(&self, mut session: AgentSession) -> AgentSession {
        // Use a persistent snapshot as the single source of truth for this run.
        // Tools mutate `snap.quads` and `snap.channels`; at the end both are
        // synced back into `session.arrangement` and `session.channels`.
        let mut snap = AgentSnapshot::from_session(&session);

        for _ in 0..session.max_steps {
            let prompt = build_prompt(&snap.task, &snap.steps, &session.registry);
            let thought_text = match (self.inference_engine)(&prompt, self.max_tokens) {
                Ok(t) => t.trim().to_string(),
                Err(e) => {
                    snap.steps.push(ReActStep::Observation {
                        output: format!("inference error: {e}"),
                    });
                    continue;
                }
            };
            snap.steps.push(ReActStep::Thought {
                text: thought_text.clone(),
            });

            let (tool, input) = parse_action(&thought_text);
            snap.steps.push(ReActStep::Action {
                tool: tool.clone(),
                input: input.clone(),
            });

            let out = session.registry.call(&tool, &input, &mut snap);

            if out.done {
                snap.steps.push(ReActStep::Finish {
                    answer: out.observation,
                });
                break;
            }
            snap.steps.push(ReActStep::Observation {
                output: out.observation,
            });
        }

        if !snap
            .steps
            .iter()
            .any(|s| matches!(s, ReActStep::Finish { .. }))
        {
            snap.steps.push(ReActStep::Finish {
                answer: format!("max_steps={} reached", session.max_steps),
            });
        }

        session.arrangement = arrangement_from_snap(&snap, &session.graph_cid);
        session.channels = snap.channels;
        session.steps = snap.steps;
        session
    }
}

// ---------------------------------------------------------------------------
// Backend 2: PregelReActRunner — one superstep = one ReAct cycle
// ---------------------------------------------------------------------------

/// Runs the ReAct loop inside a `PregelGraph`.
///
/// Mapping:
///   vertex_id    = session CID (or a custom key when routing)
///   vertex.state = JSON-serialised `AgentSnapshot`
///   superstep    = one cycle: Thought + Action + Observation
///   self-message = continue on the same vertex
///   routed msg   = continue on a different vertex (conditional routing)
///   vote_halt    = `finish` tool fired OR step limit reached
pub struct PregelReActRunner {
    inference_engine: InferenceFn,
    max_tokens: usize,
}

impl PregelReActRunner {
    pub fn new(inference_engine: InferenceFn, max_tokens: usize) -> Self {
        Self {
            inference_engine,
            max_tokens,
        }
    }

    pub fn run(
        &self,
        session: AgentSession,
    ) -> (AgentSession, Vec<crate::pregel::SuperstepResult>) {
        use crate::pregel::{ComputeFn, ComputeOutput, Message, PregelGraph, VertexId};

        let vid = VertexId(session.session_cid.clone());
        let _graph_cid = session.graph_cid.clone();
        let max_steps = session.max_steps;
        let registry = Arc::clone(&session.registry);

        let initial_snap = AgentSnapshot::from_session(&session);
        let initial_state = serde_json::to_vec(&initial_snap).unwrap_or_default();

        let mut graph = PregelGraph::new();
        graph.add_vertex(vid.clone(), initial_state);
        graph.inject_message(Message {
            src: vid.clone(),
            dst: vid.clone(),
            payload: b"start".to_vec(),
        });

        let engine = self.inference_engine.clone();
        let max_tokens = self.max_tokens;

        let compute: ComputeFn = Box::new(move |vertex, inbox| {
            // Empty inbox: already halted (or freshly routed with no message yet)
            if inbox.is_empty() {
                return ComputeOutput {
                    new_state: vertex.state.clone(),
                    messages: vec![],
                    vote_halt: true,
                };
            }

            let mut snap: AgentSnapshot = serde_json::from_slice(&vertex.state).unwrap_or_default();

            // Step limit guard
            let cycles_done = snap
                .steps
                .iter()
                .filter(|s| matches!(s, ReActStep::Thought { .. }))
                .count() as u32;
            if cycles_done >= max_steps {
                snap.steps.push(ReActStep::Finish {
                    answer: format!("pregel max_steps={max_steps} reached"),
                });
                return ComputeOutput {
                    new_state: serde_json::to_vec(&snap).unwrap_or_default(),
                    messages: vec![],
                    vote_halt: true,
                };
            }

            // ── Thought ────────────────────────────────────────────────────
            let prompt = build_prompt(&snap.task, &snap.steps, &registry);
            let thought_text = match engine(&prompt, max_tokens) {
                Ok(t) => t.trim().to_string(),
                Err(e) => {
                    snap.steps.push(ReActStep::Observation {
                        output: format!("inference error: {e}"),
                    });
                    let msg = Message {
                        src: vertex.id.clone(),
                        dst: vertex.id.clone(),
                        payload: b"cont".to_vec(),
                    };
                    return ComputeOutput {
                        new_state: serde_json::to_vec(&snap).unwrap_or_default(),
                        messages: vec![msg],
                        vote_halt: false,
                    };
                }
            };
            snap.steps.push(ReActStep::Thought {
                text: thought_text.clone(),
            });

            // ── Action ─────────────────────────────────────────────────────
            let (tool, input) = parse_action(&thought_text);
            snap.steps.push(ReActStep::Action {
                tool: tool.clone(),
                input: input.clone(),
            });

            // ── Tool call ──────────────────────────────────────────────────
            let out = registry.call(&tool, &input, &mut snap);

            let vote_halt = out.done;

            if out.done {
                snap.steps.push(ReActStep::Finish {
                    answer: out.observation.clone(),
                });
            } else {
                snap.steps.push(ReActStep::Observation {
                    output: out.observation.clone(),
                });
            }

            let new_state = serde_json::to_vec(&snap).unwrap_or_default();

            // Build continuation message — routed or self
            let messages = if vote_halt {
                vec![]
            } else {
                let dst = match out.route.as_deref() {
                    Some(key) => VertexId::from(key),
                    None => vertex.id.clone(),
                };
                vec![Message {
                    src: vertex.id.clone(),
                    dst,
                    payload: b"cont".to_vec(),
                }]
            };

            ComputeOutput {
                new_state,
                messages,
                vote_halt,
            }
        });

        let superstep_results = graph.run(&compute, max_steps + 1);

        // Reconstruct AgentSession from the initial vertex's final state
        let final_state = graph
            .vertex(&vid)
            .map(|v| v.state.clone())
            .unwrap_or_default();
        let final_snap: AgentSnapshot = serde_json::from_slice(&final_state).unwrap_or_default();

        let out_session = AgentSession {
            session_cid: session.session_cid,
            graph_cid: session.graph_cid.clone(),
            task: session.task,
            steps: final_snap.steps.clone(),
            arrangement: arrangement_from_snap(&final_snap, &session.graph_cid),
            max_steps: session.max_steps,
            registry: session.registry,
            channels: final_snap.channels,
        };
        (out_session, superstep_results)
    }
}

// ---------------------------------------------------------------------------
// session_to_quads
// ---------------------------------------------------------------------------

pub fn session_to_quads(session: &AgentSession) -> Vec<Delta> {
    session
        .steps
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let text = match step {
                ReActStep::Thought { text } => format!("thought:{text}"),
                ReActStep::Action { tool, input } => format!("action:{tool}({input})"),
                ReActStep::Observation { output } => format!("observation:{output}"),
                ReActStep::Finish { answer } => format!("finish:{answer}"),
            };
            Delta::assert_datom(Datom::assert(
                session.session_cid.clone(),
                format!("agent/step/{i}"),
                DatomValue::Text(text),
                session.graph_cid.clone(),
            ))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_engine(response: &'static str) -> InferenceFn {
        Arc::new(move |_: &str, _: usize| Ok(response.to_string()))
    }

    fn counter_engine(responses: Vec<&'static str>) -> InferenceFn {
        let responses = Arc::new(responses);
        let i = Arc::new(std::sync::Mutex::new(0usize));
        Arc::new(move |_: &str, _: usize| {
            let mut idx = i.lock().unwrap();
            let r = responses.get(*idx).copied().unwrap_or("finish(done)");
            *idx += 1;
            Ok(r.to_string())
        })
    }

    fn graph() -> KotobaCid {
        KotobaCid::from_bytes(b"test-graph")
    }

    // ── ReActRunner (simple backend) ──────────────────────────────────────

    #[test]
    fn simple_finish_on_first_step() {
        let runner = ReActRunner::new(make_engine("finish(the answer is 42)"), 128);
        let session = AgentSession::new("test task", graph(), 10);
        let result = runner.run(session);
        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
    }

    #[test]
    fn simple_assert_then_finish() {
        let engine = counter_engine(vec!["kqe.assert(some fact)", "finish(done)"]);
        let runner = ReActRunner::new(engine, 128);
        let session = AgentSession::new("test", graph(), 10);
        let result = runner.run(session);
        let n_obs = result
            .steps
            .iter()
            .filter(|s| matches!(s, ReActStep::Observation { .. }))
            .count();
        assert_eq!(n_obs, 1);
        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
    }

    #[test]
    fn simple_max_steps_terminates() {
        let runner = ReActRunner::new(make_engine("kqe.query(*)"), 64);
        let session = AgentSession::new("loop", graph(), 3);
        let result = runner.run(session);
        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
    }

    // ── PregelReActRunner (Pregel backend) ────────────────────────────────

    #[test]
    fn pregel_finish_on_first_superstep() {
        let runner = PregelReActRunner::new(make_engine("finish(pregel answer)"), 128);
        let session = AgentSession::new("pregel test", graph(), 5);
        let (result, supersteps) = runner.run(session);

        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
        if let Some(ReActStep::Finish { answer }) = result.steps.last() {
            assert!(answer.contains("pregel answer"), "got: {answer}");
        }
        assert_eq!(
            supersteps.len(),
            1,
            "expected 1 superstep, got {}",
            supersteps.len()
        );
        assert!(supersteps[0].all_halted);
    }

    #[test]
    fn pregel_assert_then_finish() {
        let engine = counter_engine(vec!["kqe.assert(alice knows bob)", "finish(stored)"]);
        let runner = PregelReActRunner::new(engine, 128);
        let session = AgentSession::new("store a fact", graph(), 5);
        let (result, supersteps) = runner.run(session);

        let n_obs = result
            .steps
            .iter()
            .filter(|s| matches!(s, ReActStep::Observation { .. }))
            .count();
        assert_eq!(n_obs, 1);
        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
        assert_eq!(
            supersteps.len(),
            2,
            "superstep 1=assert, superstep 2=finish"
        );

        assert_eq!(result.arrangement.len(), 1);
    }

    #[test]
    fn pregel_query_after_assert() {
        let engine = counter_engine(vec![
            "kqe.assert(alice knows bob)",
            "kqe.query(*)",
            "finish(queried)",
        ]);
        let runner = PregelReActRunner::new(engine, 128);
        let session = AgentSession::new("assert then query", graph(), 5);
        let (result, supersteps) = runner.run(session);

        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
        assert_eq!(supersteps.len(), 3);
    }

    #[test]
    fn pregel_max_steps_terminates() {
        let runner = PregelReActRunner::new(make_engine("kqe.query(*)"), 64);
        let session = AgentSession::new("infinite loop", graph(), 3);
        let (result, _) = runner.run(session);
        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
    }

    #[test]
    fn pregel_superstep_count_matches_cycles() {
        let engine = counter_engine(vec![
            "kqe.assert(fact-a)",
            "kqe.assert(fact-b)",
            "finish(both stored)",
        ]);
        let runner = PregelReActRunner::new(engine, 64);
        let session = AgentSession::new("two asserts", graph(), 5);
        let (result, supersteps) = runner.run(session);

        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
        assert_eq!(supersteps.len(), 3);
        assert_eq!(
            result.arrangement.len(),
            2,
            "both quads should be in arrangement"
        );
    }

    #[test]
    fn pregel_checkpoint_persists_state() {
        use kotoba_core::store::BlockStore as _;
        use kotoba_store::MemoryBlockStore;

        let engine = counter_engine(vec!["kqe.assert(data)", "finish(done)"]);
        let runner = PregelReActRunner::new(engine, 64);
        let session = AgentSession::new("checkpoint test", graph(), 5);
        let (_, _) = runner.run(session);

        use crate::pregel::{PregelGraph, VertexId};
        let mut g = PregelGraph::new();
        g.add_vertex(VertexId::from("agent"), b"state".to_vec());
        let store = MemoryBlockStore::new();
        let cid = g.checkpoint(&store).unwrap();
        assert!(store.has(&cid));
    }

    // ── parse_action ──────────────────────────────────────────────────────

    #[test]
    fn parse_with_action_prefix() {
        let (tool, input) = parse_action("Action: finish(hello world)");
        assert_eq!(tool, "finish");
        assert_eq!(input, "hello world");
    }

    #[test]
    fn parse_direct() {
        let (tool, input) = parse_action("kqe.query(some datalog)");
        assert_eq!(tool, "kqe.query");
        assert_eq!(input, "some datalog");
    }

    // ── session_to_quads ──────────────────────────────────────────────────

    #[test]
    fn session_quads_count_matches_steps() {
        let engine = make_engine("finish(ok)");
        let runner = PregelReActRunner::new(engine, 64);
        let session = AgentSession::new("t", graph(), 5);
        let (result, _) = runner.run(session);
        let deltas = session_to_quads(&result);
        assert_eq!(deltas.len(), result.steps.len());
        assert!(deltas.iter().all(|d| d.is_assert()));
    }

    // ── New: tool registry ────────────────────────────────────────────────

    #[test]
    fn custom_echo_tool_simple_runner() {
        let engine = counter_engine(vec!["echo(hello world)", "finish(done)"]);
        let session = AgentSession::new("echo test", graph(), 5).with_tool(Tool::from_fn(
            "echo",
            "Echo input back as observation",
            |input, _snap| ToolOutput {
                observation: input.to_string(),
                done: false,
                route: None,
            },
        ));
        let runner = ReActRunner::new(engine, 128);
        let result = runner.run(session);

        let has_echo = result
            .steps
            .iter()
            .any(|s| matches!(s, ReActStep::Observation { output } if output == "hello world"));
        assert!(has_echo, "echo tool should return input as observation");
        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
    }

    #[test]
    fn custom_echo_tool_pregel_runner() {
        let engine = counter_engine(vec!["echo(hello pregel)", "finish(done)"]);
        let session = AgentSession::new("echo pregel", graph(), 5).with_tool(Tool::from_fn(
            "echo",
            "Echo input back",
            |input, _snap| ToolOutput {
                observation: input.to_string(),
                done: false,
                route: None,
            },
        ));
        let runner = PregelReActRunner::new(engine, 128);
        let (result, supersteps) = runner.run(session);

        let has_echo = result
            .steps
            .iter()
            .any(|s| matches!(s, ReActStep::Observation { output } if output == "hello pregel"));
        assert!(has_echo, "echo tool should return input as observation");
        assert_eq!(supersteps.len(), 2);
        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
    }

    #[test]
    fn unknown_tool_produces_observation_and_continues() {
        let engine = counter_engine(vec!["frobnicate(x)", "finish(ok)"]);
        let runner = PregelReActRunner::new(engine, 128);
        let session = AgentSession::new("unknown tool test", graph(), 5);
        let (result, supersteps) = runner.run(session);

        let has_unknown = result.steps.iter().any(|s| {
            matches!(s, ReActStep::Observation { output } if output.contains("unknown tool: frobnicate"))
        });
        assert!(
            has_unknown,
            "unknown tool should produce an observation, got: {:?}",
            result.steps
        );
        assert_eq!(
            supersteps.len(),
            2,
            "loop should continue after unknown tool"
        );
        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
    }

    // ── New: named channels ───────────────────────────────────────────────

    #[test]
    fn channel_override_survives_superstep_boundary() {
        // Tool "store_result" writes to a channel; we verify it survives
        // serde round-trip across the superstep boundary.
        let engine = counter_engine(vec!["store_result(42)", "finish(stored)"]);
        let session = AgentSession::new("channel test", graph(), 5).with_tool(Tool::from_fn(
            "store_result",
            "Store a value in the result channel",
            |input, snap| {
                snap.channel_set(
                    "result",
                    serde_json::Value::String(input.to_string()),
                    ChannelMode::Override,
                );
                ToolOutput {
                    observation: format!("stored: {input}"),
                    done: false,
                    route: None,
                }
            },
        ));
        let runner = PregelReActRunner::new(engine, 128);
        let (result, supersteps) = runner.run(session);

        assert_eq!(supersteps.len(), 2);
        assert!(matches!(
            result.steps.last(),
            Some(ReActStep::Finish { .. })
        ));
        assert_eq!(
            result.channels.get("result"),
            Some(&serde_json::Value::String("42".to_string())),
            "channel value must survive superstep serialisation"
        );
    }

    #[test]
    fn channel_append_accumulates_across_steps() {
        let engine = counter_engine(vec!["log_step(alpha)", "log_step(beta)", "finish(done)"]);
        let session = AgentSession::new("append test", graph(), 5).with_tool(Tool::from_fn(
            "log_step",
            "Append a string to the log channel",
            |input, snap| {
                snap.channel_set(
                    "log",
                    serde_json::Value::String(input.to_string()),
                    ChannelMode::Append,
                );
                ToolOutput {
                    observation: format!("logged: {input}"),
                    done: false,
                    route: None,
                }
            },
        ));
        let runner = PregelReActRunner::new(engine, 128);
        let (result, _) = runner.run(session);

        let log = result
            .channels
            .get("log")
            .expect("log channel should exist");
        let arr = log.as_array().expect("log channel should be an array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], serde_json::Value::String("alpha".to_string()));
        assert_eq!(arr[1], serde_json::Value::String("beta".to_string()));
    }

    // ── New: conditional routing ──────────────────────────────────────────

    #[test]
    fn pregel_routing_sends_message_to_different_vertex() {
        // Agent A calls "delegate" which routes to vertex "agent_b".
        // Agent B is auto-created with empty state; the mock engine returns
        // "finish(B done)" which halts B.
        //
        // Superstep 1: A activates (seed), calls delegate → sends to agent_b.
        //              A vote_halt=false → A stays active.
        // Superstep 2: B activates (gets "cont"), A still active (empty inbox → halt).
        //              Both run → active_count = 2.
        //              B finishes, A halts (empty inbox guard).
        // all_halted → run stops after superstep 2.
        let engine = counter_engine(vec![
            "delegate(go)",   // A: calls delegate
            "finish(B done)", // B: finishes
        ]);
        let session = AgentSession::new("delegate to B", graph(), 5).with_tool(Tool::from_fn(
            "delegate",
            "Delegate continuation to agent_b",
            |_input, _snap| ToolOutput {
                observation: "delegated to agent_b".to_string(),
                done: false,
                route: Some("agent_b".to_string()),
            },
        ));
        let runner = PregelReActRunner::new(engine, 128);
        let (result_a, supersteps) = runner.run(session);

        // Two supersteps: step 1 = A routes, step 2 = A halts + B finishes
        assert_eq!(supersteps.len(), 2, "expected 2 supersteps");
        // Both A and B are active in superstep 2
        assert_eq!(
            supersteps[1].active_count, 2,
            "A (empty inbox) and B both run in step 2"
        );

        // A's steps include the delegation observation
        let has_delegation = result_a.steps.iter().any(|s| {
            matches!(s, ReActStep::Observation { output } if output.contains("delegated to agent_b"))
        });
        assert!(
            has_delegation,
            "A should observe the delegation: {:?}",
            result_a.steps
        );
    }
}
