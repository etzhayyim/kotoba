//! Pregel BSP (Bulk Synchronous Parallel) engine for KOTOBA.
//!
//! KOTOBA definition: KOTOBA ≝ ... × Pregel[BSP] × Datalog[Δ] × ...
//!
//! Each superstep:
//!   1. All active vertices execute `compute(vertex, inbox)` — produces outgoing messages
//!      and a `vote_halt` flag.
//!   2. BSP barrier: all computes complete before any messages are delivered.
//!   3. Messages are delivered to recipient vertices for the next superstep.
//!   4. A vertex that voted to halt becomes inactive unless it receives a message.
//!
//! In-process implementation (single node). Distributed supersteps across libp2p
//! nodes are wired in Phase 7 (kotoba-net integration).
//!
//! Mapping to Datalog:
//!   - Vertex ID = subject KotobaCid in the Quad store
//!   - Vertex state = serialized facts about that subject
//!   - Message payload = serialized Delta (assert/retract)
//!   - compute() = program.evaluate_delta(incoming_deltas) for that vertex's rules

use std::collections::HashMap;
use kotoba_core::cid::KotobaCid;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VertexId(pub KotobaCid);

impl VertexId {
    pub fn from_str(s: &str) -> Self {
        Self(KotobaCid::from_bytes(s.as_bytes()))
    }
    pub fn cid(&self) -> &KotobaCid { &self.0 }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub src:     VertexId,
    pub dst:     VertexId,
    pub payload: Vec<u8>,  // CBOR-encoded Delta or arbitrary bytes
}

#[derive(Debug, Clone)]
pub struct Vertex {
    pub id:     VertexId,
    pub state:  Vec<u8>,   // CBOR-encoded vertex state (opaque to Pregel engine)
    pub active: bool,
}

/// Output from one vertex's compute() invocation.
pub struct ComputeOutput {
    pub new_state:  Vec<u8>,         // updated vertex state
    pub messages:   Vec<Message>,    // outgoing messages to other vertices
    pub vote_halt:  bool,            // true → become inactive if no future messages
}

/// Result of one BSP superstep.
#[derive(Debug, Clone)]
pub struct SuperstepResult {
    pub superstep:     u32,
    pub active_count:  usize,    // vertices that ran compute() this step
    pub msg_sent:      usize,    // total messages sent this step
    pub msg_delivered: usize,    // messages delivered to vertices
    pub all_halted:    bool,     // true → no active vertices + no pending messages
}

/// Compute function type: (vertex, inbox) → ComputeOutput.
/// Must be Send + Sync for potential future parallel execution.
pub type ComputeFn = Box<dyn Fn(&Vertex, &[Message]) -> ComputeOutput + Send + Sync>;

// ---------------------------------------------------------------------------
// PregelGraph
// ---------------------------------------------------------------------------

/// In-process Pregel graph.
pub struct PregelGraph {
    vertices:    HashMap<VertexId, Vertex>,
    /// Messages queued for delivery at the start of the next superstep
    pending:     Vec<Message>,
    /// Current superstep counter
    superstep:   u32,
}

impl PregelGraph {
    pub fn new() -> Self {
        Self {
            vertices:  HashMap::new(),
            pending:   Vec::new(),
            superstep: 0,
        }
    }

    /// Add (or replace) a vertex.
    ///
    /// Vertices start **inactive** — they become active only when they receive
    /// a message. This matches Pregel semantics: all vertices begin halted; the
    /// first message (injected via `inject_message`) activates them.
    pub fn add_vertex(&mut self, id: VertexId, state: Vec<u8>) {
        self.vertices.insert(id.clone(), Vertex { id, state, active: false });
    }

    /// Inject a message into the pending queue (bypassing a superstep).
    /// Used to seed the graph with initial messages.
    pub fn inject_message(&mut self, msg: Message) {
        self.pending.push(msg);
    }

    /// Run one BSP superstep.
    ///
    /// 1. Deliver `pending` messages to recipient vertices (activate them).
    /// 2. For each active vertex: run `compute(vertex, inbox)`.
    /// 3. Collect all outgoing messages into `pending` for the next step.
    /// 4. Update vertex states and active flags.
    pub fn superstep(&mut self, compute: &ComputeFn) -> SuperstepResult {
        let step = self.superstep;
        self.superstep += 1;

        // --- Phase 1: Deliver pending messages ---
        // Group by destination
        let mut inboxes: HashMap<VertexId, Vec<Message>> = HashMap::new();
        let msg_delivered = self.pending.len();
        for msg in self.pending.drain(..) {
            // Auto-create vertex if it doesn't exist (vertex-on-demand)
            self.vertices.entry(msg.dst.clone()).or_insert_with(|| Vertex {
                id:     msg.dst.clone(),
                state:  Vec::new(),
                active: false,
            });
            inboxes.entry(msg.dst.clone()).or_default().push(msg);
        }
        // Activate vertices that received messages
        for vid in inboxes.keys() {
            if let Some(v) = self.vertices.get_mut(vid) {
                v.active = true;
            }
        }

        // --- Phase 2: Compute ---
        let active_ids: Vec<VertexId> = self.vertices.values()
            .filter(|v| v.active)
            .map(|v| v.id.clone())
            .collect();
        let active_count = active_ids.len();
        let mut all_out_messages: Vec<Message> = Vec::new();

        for vid in &active_ids {
            let inbox = inboxes.get(vid).map(|v| v.as_slice()).unwrap_or(&[]);
            let vertex = match self.vertices.get(vid) {
                Some(v) => v.clone(),
                None    => continue,
            };

            let output = compute(&vertex, inbox);

            // Update state
            if let Some(v) = self.vertices.get_mut(vid) {
                v.state  = output.new_state;
                v.active = !output.vote_halt;
            }

            all_out_messages.extend(output.messages);
        }

        let msg_sent = all_out_messages.len();

        // --- Phase 3: Queue outgoing messages ---
        self.pending.extend(all_out_messages);

        let all_halted = self.vertices.values().all(|v| !v.active) && self.pending.is_empty();

        SuperstepResult { superstep: step, active_count, msg_sent, msg_delivered, all_halted }
    }

    /// Run until all vertices halted and no pending messages, or `max_supersteps` reached.
    /// Returns the result of each superstep.
    pub fn run(&mut self, compute: &ComputeFn, max_supersteps: u32) -> Vec<SuperstepResult> {
        let mut results = Vec::new();
        for _ in 0..max_supersteps {
            let r = self.superstep(compute);
            let halted = r.all_halted;
            results.push(r);
            if halted { break; }
        }
        results
    }

    pub fn vertices(&self) -> impl Iterator<Item = &Vertex> {
        self.vertices.values()
    }

    pub fn vertex(&self, id: &VertexId) -> Option<&Vertex> {
        self.vertices.get(id)
    }

    pub fn vertex_count(&self) -> usize { self.vertices.len() }
    pub fn current_superstep(&self) -> u32 { self.superstep }
}

impl Default for PregelGraph { fn default() -> Self { Self::new() } }

// ---------------------------------------------------------------------------
// Datalog-on-Pregel bridge
// ---------------------------------------------------------------------------

use kotoba_kqe::{
    datalog::DatalogProgram,
    delta::Delta,
    quad::QuadObject,
};

/// Build a PregelGraph from a set of input Deltas.
///
/// Each unique subject CID in the deltas becomes a vertex.
/// The vertex state is initially empty; the vertices are seeded with one
/// message per Delta addressed to the subject vertex.
pub fn graph_from_deltas(deltas: &[Delta]) -> PregelGraph {
    let mut graph = PregelGraph::new();

    // Collect unique subjects
    let mut seen_subjects = std::collections::HashSet::new();
    for d in deltas {
        let key = d.quad.subject.to_multibase();
        if seen_subjects.insert(key.clone()) {
            let vid = VertexId::from_str(&key);
            graph.add_vertex(vid, Vec::new());
        }
    }

    // Seed with one message per delta (to the subject vertex)
    let seed_id = VertexId::from_str("__seed__");
    for d in deltas {
        // Serialize delta minimally as predicate bytes
        let payload = d.quad.predicate.as_bytes().to_vec();
        graph.inject_message(Message {
            src:     seed_id.clone(),
            dst:     VertexId::from_str(&d.quad.subject.to_multibase()),
            payload,
        });
    }

    graph
}

/// Compute function for Datalog-on-Pregel.
///
/// Each vertex runs the DatalogProgram over the deltas it received as messages.
/// Derived facts are sent as messages to their object-vertex.
pub fn datalog_compute_fn(
    program: std::sync::Arc<DatalogProgram>,
    all_deltas: std::sync::Arc<Vec<Delta>>,
) -> ComputeFn {
    Box::new(move |vertex: &Vertex, _inbox: &[Message]| {
        // Find deltas where subject == this vertex
        let vertex_cid_str = vertex.id.cid().to_multibase();
        let local_deltas: Vec<Delta> = all_deltas.iter()
            .filter(|d| d.quad.subject.to_multibase() == vertex_cid_str)
            .cloned()
            .collect();

        let derived = if local_deltas.is_empty() {
            vec![]
        } else {
            program.evaluate_delta(&local_deltas)
        };

        // Convert derived deltas to messages targeted at their object vertices
        let messages: Vec<Message> = derived.iter().map(|d| {
            let dst_key = if let QuadObject::Cid(c) = &d.quad.object {
                c.to_multibase()
            } else {
                d.quad.predicate.clone()
            };
            Message {
                src:     vertex.id.clone(),
                dst:     VertexId::from_str(&dst_key),
                payload: d.quad.predicate.as_bytes().to_vec(),
            }
        }).collect();

        // State = number of derived facts (as 8-byte LE)
        let new_state = (derived.len() as u64).to_le_bytes().to_vec();

        ComputeOutput {
            new_state,
            messages,
            vote_halt: true, // single-shot: each vertex computes once then halts
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg(src: &str, dst: &str, payload: &[u8]) -> Message {
        Message {
            src: VertexId::from_str(src),
            dst: VertexId::from_str(dst),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn test_single_vertex_compute() {
        let mut graph = PregelGraph::new();
        let vid = VertexId::from_str("v1");
        graph.add_vertex(vid.clone(), Vec::new());
        graph.inject_message(make_msg("seed", "v1", b"ping"));

        let compute: ComputeFn = Box::new(|_v, inbox| {
            let new_state = format!("received:{}", inbox.len()).into_bytes();
            ComputeOutput { new_state, messages: vec![], vote_halt: true }
        });

        let result = graph.superstep(&compute);
        assert_eq!(result.active_count, 1);
        assert_eq!(result.msg_delivered, 1);
        assert!(result.all_halted);

        let v = graph.vertex(&vid).unwrap();
        assert_eq!(v.state, b"received:1");
    }

    #[test]
    fn test_message_passing_between_vertices() {
        let mut graph = PregelGraph::new();
        // Vertices start inactive; they activate when they receive messages.
        graph.add_vertex(VertexId::from_str("a"), Vec::new());
        graph.add_vertex(VertexId::from_str("b"), Vec::new());
        graph.inject_message(make_msg("seed", "a", b"start"));

        // a receives "start", sends "hello" to b
        let compute: ComputeFn = Box::new(|v, inbox| {
            if v.id == VertexId::from_str("a") && !inbox.is_empty() {
                ComputeOutput {
                    new_state:  b"sent".to_vec(),
                    messages:   vec![Message {
                        src:     v.id.clone(),
                        dst:     VertexId::from_str("b"),
                        payload: b"hello".to_vec(),
                    }],
                    vote_halt: true,
                }
            } else if v.id == VertexId::from_str("b") && !inbox.is_empty() {
                let got = inbox[0].payload.clone();
                ComputeOutput { new_state: got, messages: vec![], vote_halt: true }
            } else {
                ComputeOutput { new_state: v.state.clone(), messages: vec![], vote_halt: true }
            }
        });

        // Step 1: a receives "start" (only a is activated), sends "hello" to b
        let r1 = graph.superstep(&compute);
        assert_eq!(r1.active_count, 1); // only a activated by the pending message
        assert_eq!(r1.msg_sent, 1);     // a → b

        // Step 2: b receives "hello"
        let r2 = graph.superstep(&compute);
        assert_eq!(r2.msg_delivered, 1);
        assert!(r2.all_halted);

        let b = graph.vertex(&VertexId::from_str("b")).unwrap();
        assert_eq!(b.state, b"hello");
    }

    #[test]
    fn test_run_reaches_fixpoint() {
        let mut graph = PregelGraph::new();
        graph.add_vertex(VertexId::from_str("x"), Vec::new());
        graph.inject_message(make_msg("s", "x", b"go"));

        let compute: ComputeFn = Box::new(|_, _inbox| ComputeOutput {
            new_state: vec![],
            messages:  vec![],
            vote_halt: true,
        });

        let results = graph.run(&compute, 100);
        // x gets activated by the seed message, votes halt, no outgoing messages.
        // The engine reports all_halted=true at the end of superstep 0, so run()
        // breaks after a single iteration.
        assert_eq!(results.len(), 1);
        assert!(results.last().unwrap().all_halted);
    }

    #[test]
    fn test_vertex_on_demand() {
        // A message sent to a non-existent vertex should auto-create it
        let mut graph = PregelGraph::new();
        graph.inject_message(make_msg("src", "new-vertex", b"data"));

        let compute: ComputeFn = Box::new(|_v, _inbox| ComputeOutput {
            new_state: b"created".to_vec(),
            messages: vec![],
            vote_halt: true,
        });

        let r = graph.superstep(&compute);
        assert_eq!(r.active_count, 1);
        let v = graph.vertex(&VertexId::from_str("new-vertex")).unwrap();
        assert_eq!(v.state, b"created");
    }

    #[test]
    fn test_superstep_counter() {
        let mut graph = PregelGraph::new();
        graph.add_vertex(VertexId::from_str("a"), Vec::new());
        graph.inject_message(make_msg("s", "a", b"x"));

        let compute: ComputeFn = Box::new(|_, _| ComputeOutput {
            new_state: vec![], messages: vec![], vote_halt: true,
        });

        assert_eq!(graph.current_superstep(), 0);
        graph.superstep(&compute);
        assert_eq!(graph.current_superstep(), 1);
        graph.superstep(&compute); // no active vertices, all halted
        assert_eq!(graph.current_superstep(), 2);
    }
}
