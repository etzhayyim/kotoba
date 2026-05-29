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

use kotoba_core::cid::KotobaCid;
use kotoba_core::prolly::{ProllyNode, ProllyTree};
use kotoba_core::store::BlockStore;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VertexId(pub KotobaCid);

impl VertexId {
    pub fn cid(&self) -> &KotobaCid {
        &self.0
    }
}

impl std::str::FromStr for VertexId {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(KotobaCid::from_bytes(s.as_bytes())))
    }
}

impl From<&str> for VertexId {
    fn from(s: &str) -> Self {
        Self(KotobaCid::from_bytes(s.as_bytes()))
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub src: VertexId,
    pub dst: VertexId,
    pub payload: Vec<u8>, // CBOR-encoded Delta or arbitrary bytes
}

#[derive(Debug, Clone)]
pub struct Vertex {
    pub id: VertexId,
    pub state: Vec<u8>, // CBOR-encoded vertex state (opaque to Pregel engine)
    pub active: bool,
}

/// Output from one vertex's compute() invocation.
pub struct ComputeOutput {
    pub new_state: Vec<u8>,     // updated vertex state
    pub messages: Vec<Message>, // outgoing messages to other vertices
    pub vote_halt: bool,        // true → become inactive if no future messages
}

/// Result of one BSP superstep.
#[derive(Debug, Clone)]
pub struct SuperstepResult {
    pub superstep: u32,
    pub active_count: usize,  // vertices that ran compute() this step
    pub msg_sent: usize,      // total messages sent this step
    pub msg_delivered: usize, // messages delivered to vertices
    pub all_halted: bool,     // true → no active vertices + no pending messages
}

/// Compute function type: (vertex, inbox) → ComputeOutput.
/// Must be Send + Sync for potential future parallel execution.
pub type ComputeFn = Box<dyn Fn(&Vertex, &[Message]) -> ComputeOutput + Send + Sync>;

// ---------------------------------------------------------------------------
// PregelGraph
// ---------------------------------------------------------------------------

/// In-process Pregel graph.
pub struct PregelGraph {
    vertices: HashMap<VertexId, Vertex>,
    /// Messages queued for delivery at the start of the next superstep
    pending: Vec<Message>,
    /// Current superstep counter
    superstep: u32,
}

impl PregelGraph {
    pub fn new() -> Self {
        Self {
            vertices: HashMap::new(),
            pending: Vec::new(),
            superstep: 0,
        }
    }

    /// Add (or replace) a vertex.
    ///
    /// Vertices start **inactive** — they become active only when they receive
    /// a message. This matches Pregel semantics: all vertices begin halted; the
    /// first message (injected via `inject_message`) activates them.
    pub fn add_vertex(&mut self, id: VertexId, state: Vec<u8>) {
        self.vertices.insert(
            id.clone(),
            Vertex {
                id,
                state,
                active: false,
            },
        );
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
            self.vertices
                .entry(msg.dst.clone())
                .or_insert_with(|| Vertex {
                    id: msg.dst.clone(),
                    state: Vec::new(),
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

        // Sort each inbox deterministically: (src_cid_multibase, payload).
        // Gossip delivery order varies across nodes; sorting here ensures that
        // every node with the same message set produces identical compute inputs.
        // The next superstep re-sorts its own inboxes, so pending queue order
        // after Phase 3 does not affect determinism.
        for inbox in inboxes.values_mut() {
            inbox.sort_by(|a, b| {
                a.src
                    .cid()
                    .to_multibase()
                    .cmp(&b.src.cid().to_multibase())
                    .then_with(|| a.payload.cmp(&b.payload))
            });
        }

        // --- Phase 2: Compute ---
        // Sort active vertex IDs so all nodes iterate in the same order.
        let mut active_ids: Vec<VertexId> = self
            .vertices
            .values()
            .filter(|v| v.active)
            .map(|v| v.id.clone())
            .collect();
        active_ids.sort_by_key(|id| id.cid().to_multibase());
        let active_count = active_ids.len();
        let mut all_out_messages: Vec<Message> = Vec::new();

        for vid in &active_ids {
            let inbox = inboxes.get(vid).map(|v| v.as_slice()).unwrap_or(&[]);
            let vertex = match self.vertices.get(vid) {
                Some(v) => v.clone(),
                None => continue,
            };

            let output = compute(&vertex, inbox);

            // Update state
            if let Some(v) = self.vertices.get_mut(vid) {
                v.state = output.new_state;
                v.active = !output.vote_halt;
            }

            all_out_messages.extend(output.messages);
        }

        let msg_sent = all_out_messages.len();

        // --- Phase 3: Queue outgoing messages ---
        self.pending.extend(all_out_messages);

        let all_halted = self.vertices.values().all(|v| !v.active) && self.pending.is_empty();

        SuperstepResult {
            superstep: step,
            active_count,
            msg_sent,
            msg_delivered,
            all_halted,
        }
    }

    /// Run until all vertices halted and no pending messages, or `max_supersteps` reached.
    /// Returns the result of each superstep.
    pub fn run(&mut self, compute: &ComputeFn, max_supersteps: u32) -> Vec<SuperstepResult> {
        let mut results = Vec::new();
        for _ in 0..max_supersteps {
            let r = self.superstep(compute);
            let halted = r.all_halted;
            results.push(r);
            if halted {
                break;
            }
        }
        results
    }

    pub fn vertices(&self) -> impl Iterator<Item = &Vertex> {
        self.vertices.values()
    }

    pub fn vertex(&self, id: &VertexId) -> Option<&Vertex> {
        self.vertices.get(id)
    }

    pub fn vertex_count(&self) -> usize {
        self.vertices.len()
    }
    pub fn current_superstep(&self) -> u32 {
        self.superstep
    }

    /// Snapshot all vertex states into a content-addressed ProllyTree leaf node
    /// and return the root CID.
    ///
    /// Entries are sorted by vertex CID for deterministic output.
    pub fn checkpoint(&self, store: &dyn BlockStore) -> anyhow::Result<KotobaCid> {
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .vertices
            .values()
            .map(|v| (v.id.cid().0.to_vec(), v.state.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let placeholder = KotobaCid::from_bytes(b"superstep-checkpoint");
        let leaf = ProllyNode::Leaf {
            entries,
            cid: placeholder,
        };
        ProllyTree::put_node(&leaf, store)
    }

    /// Hash-chain checkpoint: `CID = sha2-256(root_bytes || prev_bytes)`.
    ///
    /// Links the current superstep state to the previous one so every step
    /// cryptographically commits to the full execution history — tampering
    /// with any intermediate step changes all subsequent chain-link CIDs.
    ///
    /// The link block (root_bytes || prev_bytes) is persisted so it can be
    /// re-verified independently.  Pass `prev = None` for superstep 0.
    pub fn checkpoint_chained(
        &self,
        store: &dyn BlockStore,
        prev: Option<&KotobaCid>,
    ) -> anyhow::Result<KotobaCid> {
        let root_cid = self.checkpoint(store)?;

        // link_bytes = root_cid_bytes ++ prev_cid_bytes (empty for step 0)
        let mut link_bytes = root_cid.0.to_vec();
        if let Some(p) = prev {
            link_bytes.extend_from_slice(&p.0);
        }

        let link_cid = KotobaCid::from_bytes(&link_bytes);
        store.put(&link_cid, &link_bytes)?;
        Ok(link_cid)
    }
}

impl Default for PregelGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Datalog-on-Pregel bridge
// ---------------------------------------------------------------------------

use kotoba_kqe::{datalog::DatalogProgram, datom::Value, delta::Delta};

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
        let key = d.entity().to_multibase();
        if seen_subjects.insert(key.clone()) {
            let vid = VertexId::from(key.as_str());
            graph.add_vertex(vid, Vec::new());
        }
    }

    // Seed with one message per delta (to the subject vertex)
    let seed_id = VertexId::from("__seed__");
    for d in deltas {
        // Serialize delta minimally as predicate bytes
        let payload = d.attribute().as_bytes().to_vec();
        let dst_mb = d.entity().to_multibase();
        graph.inject_message(Message {
            src: seed_id.clone(),
            dst: VertexId::from(dst_mb.as_str()),
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
        let local_deltas: Vec<Delta> = all_deltas
            .iter()
            .filter(|d| d.entity().to_multibase() == vertex_cid_str)
            .cloned()
            .collect();

        let derived = if local_deltas.is_empty() {
            vec![]
        } else {
            program.evaluate_delta(&local_deltas)
        };

        // Convert derived deltas to messages targeted at their object vertices
        let messages: Vec<Message> = derived
            .iter()
            .map(|d| {
                let dst_key = if let Value::Cid(c) = d.value() {
                    c.to_multibase()
                } else {
                    d.attribute().to_string()
                };
                Message {
                    src: vertex.id.clone(),
                    dst: VertexId::from(dst_key.as_str()),
                    payload: d.attribute().as_bytes().to_vec(),
                }
            })
            .collect();

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
            src: VertexId::from(src),
            dst: VertexId::from(dst),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn test_single_vertex_compute() {
        let mut graph = PregelGraph::new();
        let vid = VertexId::from("v1");
        graph.add_vertex(vid.clone(), Vec::new());
        graph.inject_message(make_msg("seed", "v1", b"ping"));

        let compute: ComputeFn = Box::new(|_v, inbox| {
            let new_state = format!("received:{}", inbox.len()).into_bytes();
            ComputeOutput {
                new_state,
                messages: vec![],
                vote_halt: true,
            }
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
        graph.add_vertex(VertexId::from("a"), Vec::new());
        graph.add_vertex(VertexId::from("b"), Vec::new());
        graph.inject_message(make_msg("seed", "a", b"start"));

        // a receives "start", sends "hello" to b
        let compute: ComputeFn = Box::new(|v, inbox| {
            if v.id == VertexId::from("a") && !inbox.is_empty() {
                ComputeOutput {
                    new_state: b"sent".to_vec(),
                    messages: vec![Message {
                        src: v.id.clone(),
                        dst: VertexId::from("b"),
                        payload: b"hello".to_vec(),
                    }],
                    vote_halt: true,
                }
            } else if v.id == VertexId::from("b") && !inbox.is_empty() {
                let got = inbox[0].payload.clone();
                ComputeOutput {
                    new_state: got,
                    messages: vec![],
                    vote_halt: true,
                }
            } else {
                ComputeOutput {
                    new_state: v.state.clone(),
                    messages: vec![],
                    vote_halt: true,
                }
            }
        });

        // Step 1: a receives "start" (only a is activated), sends "hello" to b
        let r1 = graph.superstep(&compute);
        assert_eq!(r1.active_count, 1); // only a activated by the pending message
        assert_eq!(r1.msg_sent, 1); // a → b

        // Step 2: b receives "hello"
        let r2 = graph.superstep(&compute);
        assert_eq!(r2.msg_delivered, 1);
        assert!(r2.all_halted);

        let b = graph.vertex(&VertexId::from("b")).unwrap();
        assert_eq!(b.state, b"hello");
    }

    #[test]
    fn test_run_reaches_fixpoint() {
        let mut graph = PregelGraph::new();
        graph.add_vertex(VertexId::from("x"), Vec::new());
        graph.inject_message(make_msg("s", "x", b"go"));

        let compute: ComputeFn = Box::new(|_, _inbox| ComputeOutput {
            new_state: vec![],
            messages: vec![],
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
        let v = graph.vertex(&VertexId::from("new-vertex")).unwrap();
        assert_eq!(v.state, b"created");
    }

    #[test]
    fn test_inbox_sort_is_deterministic() {
        // Two graphs receive the same three messages in different injection orders.
        // A compute function that concatenates payload bytes into vertex state
        // will produce identical output only if inboxes are sorted before compute.
        let compute: ComputeFn = Box::new(|_v, inbox| {
            // Concatenate payloads in inbox order — sensitive to ordering
            let new_state: Vec<u8> = inbox
                .iter()
                .flat_map(|m| m.payload.iter().copied())
                .collect();
            ComputeOutput {
                new_state,
                messages: vec![],
                vote_halt: true,
            }
        });

        let dst = VertexId::from("target");

        // Graph A: inject in order alpha, beta, gamma
        let mut graph_a = PregelGraph::new();
        graph_a.add_vertex(dst.clone(), Vec::new());
        graph_a.inject_message(make_msg("src-alpha", "target", b"A"));
        graph_a.inject_message(make_msg("src-beta", "target", b"B"));
        graph_a.inject_message(make_msg("src-gamma", "target", b"C"));

        // Graph B: inject in reverse order
        let mut graph_b = PregelGraph::new();
        graph_b.add_vertex(dst.clone(), Vec::new());
        graph_b.inject_message(make_msg("src-gamma", "target", b"C"));
        graph_b.inject_message(make_msg("src-beta", "target", b"B"));
        graph_b.inject_message(make_msg("src-alpha", "target", b"A"));

        graph_a.superstep(&compute);
        graph_b.superstep(&compute);

        let state_a = graph_a.vertex(&dst).unwrap().state.clone();
        let state_b = graph_b.vertex(&dst).unwrap().state.clone();
        assert_eq!(
            state_a, state_b,
            "inbox sort must produce identical state regardless of injection order"
        );
    }

    #[test]
    fn test_active_vertex_iteration_is_deterministic() {
        // Three vertices all receive a message; compute records the vertex CID
        // into a shared vec. After sorting active_ids, the execution order is
        // lexicographic by CID multibase — independent of HashMap iteration order.
        use std::sync::{Arc, Mutex};

        let order: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let order_clone = Arc::clone(&order);

        let compute: ComputeFn = Box::new(move |v, _inbox| {
            order_clone.lock().unwrap().push(v.id.cid().to_multibase());
            ComputeOutput {
                new_state: vec![],
                messages: vec![],
                vote_halt: true,
            }
        });

        let mut graph = PregelGraph::new();
        for name in &["vc", "va", "vb"] {
            let vid = VertexId::from(*name);
            graph.add_vertex(vid.clone(), Vec::new());
            graph.inject_message(make_msg("seed", name, b"go"));
        }
        graph.superstep(&compute);

        let recorded = order.lock().unwrap().clone();
        let mut sorted = recorded.clone();
        sorted.sort();
        assert_eq!(
            recorded, sorted,
            "vertices must be computed in sorted CID order"
        );
    }

    #[test]
    fn test_superstep_counter() {
        let mut graph = PregelGraph::new();
        graph.add_vertex(VertexId::from("a"), Vec::new());
        graph.inject_message(make_msg("s", "a", b"x"));

        let compute: ComputeFn = Box::new(|_, _| ComputeOutput {
            new_state: vec![],
            messages: vec![],
            vote_halt: true,
        });

        assert_eq!(graph.current_superstep(), 0);
        graph.superstep(&compute);
        assert_eq!(graph.current_superstep(), 1);
        graph.superstep(&compute); // no active vertices, all halted
        assert_eq!(graph.current_superstep(), 2);
    }

    #[test]
    fn test_checkpoint_produces_block() {
        use kotoba_store::MemoryBlockStore;

        let mut graph = PregelGraph::new();
        let va = VertexId::from("a");
        let vb = VertexId::from("b");
        graph.add_vertex(va.clone(), b"state-a".to_vec());
        graph.add_vertex(vb.clone(), b"state-b".to_vec());

        let store = MemoryBlockStore::new();
        let cid = graph.checkpoint(&store).unwrap();

        // The returned CID must exist as a block in the store.
        assert!(store.has(&cid), "checkpoint block must be persisted");
    }

    #[test]
    fn test_checkpoint_deterministic_across_vertex_order() {
        use kotoba_store::MemoryBlockStore;

        // Two graphs with the same vertex states but inserted in different order
        // must produce the same checkpoint CID.
        let mut g1 = PregelGraph::new();
        g1.add_vertex(VertexId::from("alpha"), b"state-1".to_vec());
        g1.add_vertex(VertexId::from("beta"), b"state-2".to_vec());

        let mut g2 = PregelGraph::new();
        g2.add_vertex(VertexId::from("beta"), b"state-2".to_vec());
        g2.add_vertex(VertexId::from("alpha"), b"state-1".to_vec());

        let s1 = MemoryBlockStore::new();
        let s2 = MemoryBlockStore::new();

        let cid1 = g1.checkpoint(&s1).unwrap();
        let cid2 = g2.checkpoint(&s2).unwrap();

        assert_eq!(
            cid1, cid2,
            "checkpoint CID must be deterministic regardless of insertion order"
        );
    }

    #[test]
    fn test_default_equals_new() {
        let g1 = PregelGraph::new();
        let g2 = PregelGraph::default();
        assert_eq!(g1.vertex_count(), g2.vertex_count());
        assert_eq!(g1.current_superstep(), g2.current_superstep());
    }

    #[test]
    fn test_empty_graph_superstep_all_halted() {
        let mut graph = PregelGraph::new();
        let compute: ComputeFn = Box::new(|_, _| ComputeOutput {
            new_state: vec![],
            messages: vec![],
            vote_halt: true,
        });
        let r = graph.superstep(&compute);
        assert!(
            r.all_halted,
            "empty graph with no pending messages should be all_halted"
        );
        assert_eq!(r.active_count, 0);
        assert_eq!(r.msg_delivered, 0);
    }

    #[test]
    fn test_vertex_count_after_add_and_auto_create() {
        let mut graph = PregelGraph::new();
        graph.add_vertex(VertexId::from("a"), Vec::new());
        graph.add_vertex(VertexId::from("b"), Vec::new());
        assert_eq!(graph.vertex_count(), 2);

        // inject a message to a non-existent vertex; it should be auto-created in superstep
        graph.inject_message(make_msg("src", "c", b"hi"));
        let compute: ComputeFn = Box::new(|_, _| ComputeOutput {
            new_state: b"ok".to_vec(),
            messages: vec![],
            vote_halt: true,
        });
        graph.superstep(&compute);
        assert_eq!(
            graph.vertex_count(),
            3,
            "auto-created vertex c should be counted"
        );
    }

    #[test]
    fn test_run_max_zero_returns_empty() {
        let mut graph = PregelGraph::new();
        graph.add_vertex(VertexId::from("v"), Vec::new());
        graph.inject_message(make_msg("s", "v", b"go"));
        let compute: ComputeFn = Box::new(|_, _| ComputeOutput {
            new_state: vec![],
            messages: vec![],
            vote_halt: true,
        });
        let results = graph.run(&compute, 0);
        assert!(results.is_empty(), "run(max=0) should return no results");
    }

    #[test]
    fn test_checkpoint_chained_prev_none_differs_from_some() {
        use kotoba_store::MemoryBlockStore;

        let mut graph = PregelGraph::new();
        graph.add_vertex(VertexId::from("x"), b"state".to_vec());

        let s1 = MemoryBlockStore::new();
        let s2 = MemoryBlockStore::new();

        let cid_no_prev = graph.checkpoint_chained(&s1, None).unwrap();

        // Chain with a fake prev CID
        let prev = kotoba_core::cid::KotobaCid::from_bytes(b"prev-checkpoint");
        let cid_with_prev = graph.checkpoint_chained(&s2, Some(&prev)).unwrap();

        assert_ne!(
            cid_no_prev, cid_with_prev,
            "chained CID with prev must differ from no-prev"
        );
    }

    #[test]
    fn test_graph_from_deltas_creates_vertices_and_messages() {
        use kotoba_core::cid::KotobaCid;
        use kotoba_kqe::datom::{Datom, Value};
        use kotoba_kqe::delta::Delta;

        let subj_a = KotobaCid::from_bytes(b"subject-a");
        let subj_b = KotobaCid::from_bytes(b"subject-b");
        let graph_cid = KotobaCid::from_bytes(b"graph");

        let deltas = vec![
            Delta::assert_datom(Datom::assert(
                subj_a.clone(),
                "pred/one".to_string(),
                Value::Text("val1".to_string()),
                graph_cid.clone(),
            )),
            Delta::assert_datom(Datom::assert(
                subj_b.clone(),
                "pred/two".to_string(),
                Value::Text("val2".to_string()),
                graph_cid.clone(),
            )),
            // Second delta for subj_a — should NOT add a second vertex
            Delta::assert_datom(Datom::assert(
                subj_a.clone(),
                "pred/three".to_string(),
                Value::Text("val3".to_string()),
                graph_cid.clone(),
            )),
        ];

        let g = graph_from_deltas(&deltas);
        // Unique subjects: subj_a and subj_b → 2 vertices
        assert_eq!(
            g.vertex_count(),
            2,
            "should create one vertex per unique subject"
        );
    }

    #[test]
    fn test_vertex_id_from_str_parses() {
        let vid: VertexId = "hello".into();
        let vid2 = VertexId::from("hello");
        assert_eq!(vid, vid2);
    }

    #[test]
    fn test_superstep_result_fields_populated() {
        let mut graph = PregelGraph::new();
        graph.add_vertex(VertexId::from("v"), Vec::new());
        graph.inject_message(make_msg("s", "v", b"x"));

        let compute: ComputeFn = Box::new(|v, _inbox| {
            let out_msg = Message {
                src: v.id.clone(),
                dst: VertexId::from("w"),
                payload: b"reply".to_vec(),
            };
            ComputeOutput {
                new_state: b"done".to_vec(),
                messages: vec![out_msg],
                vote_halt: true,
            }
        });

        let r = graph.superstep(&compute);
        assert_eq!(r.superstep, 0);
        assert_eq!(r.active_count, 1);
        assert_eq!(r.msg_sent, 1);
        assert_eq!(r.msg_delivered, 1);
    }
}
