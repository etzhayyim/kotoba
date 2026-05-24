//! Distributed Pregel runner — routes cross-node messages via async channels.
//!
//! Architecture:
//!   - Local vertex compute runs in-process (`PregelGraph::superstep`)
//!   - Messages whose `dst` is NOT in the local vertex set are sent via `outbound_tx`
//!   - The server layer connects `outbound_tx` / `inbound_rx` to `KotobaSwarm` gossip
//!   - Messages arriving from peers come in via `inbound_rx`
//!
//! Vertex ownership model (Phase 6 — full mesh):
//!   Every node holds a FULL copy of the graph (replicated state).
//!   Messages are gossiped to all peers, giving eventual consistency.
//!   Sharded ownership (each node holds 1/K vertices) is Phase 8.
//!
//! Usage (wiring to KotobaSwarm is done by the server layer):
//! ```ignore
//! let (inbound_tx, outbound_rx, mut runner) =
//!     DistributedPregelRunner::channel_pair(256);
//!
//! // server: forward swarm GossipMessages → inbound_tx
//! // server: forward outbound_rx → swarm.send_pregel_message()
//!
//! let vid = VertexId::from_str("vertex-a");
//! runner.add_local_vertex(vid.clone(), Vec::new());
//! runner.graph.inject_message(Message { src: VertexId::from_str("seed"), dst: vid, payload: b"go".to_vec() });
//!
//! let compute: SharedComputeFn = Arc::new(|v, inbox| ComputeOutput {
//!     new_state:  format!("step:{}", inbox.len()).into_bytes(),
//!     messages:   vec![],
//!     vote_halt:  true,
//! });
//! let results = runner.run(compute, 10).await;
//! ```

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::pregel::{ComputeOutput, Message, PregelGraph, SuperstepResult, Vertex, VertexId};

// ---------------------------------------------------------------------------
// Shared compute function type
// ---------------------------------------------------------------------------

/// Arc-wrapped compute function for use with `DistributedPregelRunner`.
///
/// Using `Arc` instead of `&ComputeFn` lets the closure be cloned into the
/// wrapping interceptor closure without lifetime issues.
pub type SharedComputeFn =
    Arc<dyn Fn(&Vertex, &[Message]) -> ComputeOutput + Send + Sync>;

// ---------------------------------------------------------------------------
// DistributedMessage
// ---------------------------------------------------------------------------

/// A Pregel message routed between KOTOBA nodes.
#[derive(Debug, Clone)]
pub struct DistributedMessage {
    /// Source vertex ID (multibase-encoded CID string)
    pub src:     String,
    /// Destination vertex ID (multibase-encoded CID string)
    pub dst:     String,
    /// Opaque payload bytes
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// DistributedPregelRunner
// ---------------------------------------------------------------------------

/// Runs Pregel BSP supersteps with cross-node message routing.
///
/// Inbound messages from peers are received on `inbound_rx` and injected into
/// the local graph before each superstep.  Outgoing messages whose destination
/// vertex is not locally owned are pushed onto `outbound_tx` so the server
/// layer can gossip them via `KotobaSwarm::send_pregel_message`.
pub struct DistributedPregelRunner {
    /// The in-process Pregel graph.  Caller may add vertices and seed messages
    /// directly on this field before calling `run`.
    pub graph:           PregelGraph,
    inbound_rx:          mpsc::Receiver<DistributedMessage>,
    outbound_tx:         mpsc::Sender<DistributedMessage>,
    /// Multibase-encoded vertex IDs that are owned by this node.
    local_vertex_ids:    HashSet<String>,
}

impl DistributedPregelRunner {
    /// Create a runner from pre-built channel halves.
    ///
    /// Prefer `channel_pair` which constructs all three objects at once.
    pub fn new(
        inbound_rx:  mpsc::Receiver<DistributedMessage>,
        outbound_tx: mpsc::Sender<DistributedMessage>,
    ) -> Self {
        Self {
            graph:            PregelGraph::new(),
            inbound_rx,
            outbound_tx,
            local_vertex_ids: HashSet::new(),
        }
    }

    /// Register a vertex as locally owned and add it to the graph.
    ///
    /// Only locally-owned vertices' messages are computed here; messages for
    /// any other `dst` are forwarded via `outbound_tx`.
    pub fn add_local_vertex(&mut self, id: VertexId, state: Vec<u8>) {
        let key = id.cid().to_multibase();
        self.local_vertex_ids.insert(key);
        self.graph.add_vertex(id, state);
    }

    /// Drain the inbound channel and inject all buffered peer messages into the
    /// local graph.  Non-blocking — returns immediately after consuming whatever
    /// is currently available.
    pub fn drain_inbound(&mut self) {
        while let Ok(dmsg) = self.inbound_rx.try_recv() {
            let dst = VertexId::from_str(&dmsg.dst);
            let src = VertexId::from_str(&dmsg.src);
            self.graph.inject_message(Message {
                src,
                dst,
                payload: dmsg.payload,
            });
        }
    }

    /// Run one distributed BSP superstep:
    ///
    /// 1. Drain inbound peer messages into the local graph.
    /// 2. Run a single local `superstep`, wrapping the user's compute function
    ///    to intercept messages destined for non-local vertices.
    /// 3. Push intercepted remote messages onto `outbound_tx` for the server
    ///    layer to gossip.
    ///
    /// The method is `async` for API consistency with `run`, even though the
    /// current implementation does not `.await` anything after the sync
    /// `superstep` call.
    pub async fn distributed_superstep(
        &mut self,
        user_compute: SharedComputeFn,
    ) -> SuperstepResult {
        // 1. Receive messages from peers
        self.drain_inbound();

        // 2. Build a wrapping compute function that intercepts remote messages.
        //    Messages for locally-owned vertices stay in `output.messages` so
        //    PregelGraph queues them for the next step.  Messages for unknown
        //    vertices are captured in `outbound_buffer` and sent after the
        //    superstep.
        let local_ids       = self.local_vertex_ids.clone();
        let outbound_buffer: Arc<Mutex<Vec<DistributedMessage>>> =
            Arc::new(Mutex::new(Vec::new()));
        let buf_clone = Arc::clone(&outbound_buffer);

        let wrapped: crate::pregel::ComputeFn = Box::new(move |vertex: &Vertex, inbox: &[Message]| {
            let output = user_compute(vertex, inbox);

            let mut local_messages  = Vec::new();
            let mut guard           = buf_clone.lock().expect("outbound_buffer poisoned");

            for msg in output.messages {
                let dst_key = msg.dst.cid().to_multibase();
                if local_ids.contains(&dst_key) {
                    local_messages.push(msg);
                } else {
                    guard.push(DistributedMessage {
                        src:     msg.src.cid().to_multibase(),
                        dst:     dst_key,
                        payload: msg.payload,
                    });
                }
            }

            ComputeOutput {
                new_state:  output.new_state,
                messages:   local_messages,
                vote_halt:  output.vote_halt,
            }
        });

        // 3. Execute the local superstep
        let result = self.graph.superstep(&wrapped);

        // 4. Forward captured remote messages to peers (non-blocking; drop if full)
        let to_send = std::mem::take(
            &mut *outbound_buffer.lock().expect("outbound_buffer poisoned"),
        );
        for dmsg in to_send {
            // `try_send` to avoid blocking inside an async context.
            // If the channel is full the message is dropped — the caller can
            // increase the buffer size via `channel_pair(buffer)`.
            let _ = self.outbound_tx.try_send(dmsg);
        }

        result
    }

    /// Run until all vertices have halted and the pending queue is empty, or
    /// until `max_supersteps` have been executed.
    ///
    /// Returns the `SuperstepResult` for each superstep that ran.
    pub async fn run(
        &mut self,
        compute:       SharedComputeFn,
        max_supersteps: u32,
    ) -> Vec<SuperstepResult> {
        let mut results = Vec::new();
        for _ in 0..max_supersteps {
            let r = self.distributed_superstep(Arc::clone(&compute)).await;
            let halted = r.all_halted;
            results.push(r);
            if halted { break; }
        }
        results
    }

    /// Create a `(inbound_tx, outbound_rx, runner)` triple ready for wiring to
    /// the server layer.
    ///
    /// ```text
    /// KotobaSwarm GossipMessage
    ///   → decode PregelNetMessage
    ///   → inbound_tx.send(DistributedMessage)    ← server writes here
    ///
    /// outbound_rx.recv()                          ← server reads here
    ///   → swarm.send_pregel_message(src, dst, payload)
    /// ```
    pub fn channel_pair(
        buffer: usize,
    ) -> (
        mpsc::Sender<DistributedMessage>,   // inbound_tx  (server: swarm → runner)
        mpsc::Receiver<DistributedMessage>, // outbound_rx (server: runner → swarm)
        DistributedPregelRunner,
    ) {
        let (inbound_tx,  inbound_rx)  = mpsc::channel(buffer);
        let (outbound_tx, outbound_rx) = mpsc::channel(buffer);
        let runner = Self::new(inbound_rx, outbound_tx);
        (inbound_tx, outbound_rx, runner)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pregel::{ComputeOutput, Vertex};

    fn halt_compute() -> SharedComputeFn {
        Arc::new(|_v: &Vertex, inbox: &[Message]| ComputeOutput {
            new_state:  format!("step:{}", inbox.len()).into_bytes(),
            messages:   vec![],
            vote_halt:  true,
        })
    }

    #[tokio::test]
    async fn test_distributed_runner_local_compute() {
        let (_, _, mut runner) = DistributedPregelRunner::channel_pair(64);

        let vid = VertexId::from_str("vertex-a");
        runner.add_local_vertex(vid.clone(), Vec::new());
        runner.graph.inject_message(Message {
            src:     VertexId::from_str("seed"),
            dst:     vid.clone(),
            payload: b"hello".to_vec(),
        });

        let results = runner.run(halt_compute(), 10).await;
        assert!(!results.is_empty(), "at least one superstep should run");
        assert!(
            results.last().unwrap().all_halted,
            "graph should reach fixpoint"
        );
    }

    #[tokio::test]
    async fn test_channel_pair_returns_correct_types() {
        let (inbound_tx, _outbound_rx, runner) = DistributedPregelRunner::channel_pair(16);
        assert_eq!(runner.graph.vertex_count(), 0);

        // inbound_tx must accept DistributedMessage without blocking
        inbound_tx
            .try_send(DistributedMessage {
                src:     "a".to_string(),
                dst:     "b".to_string(),
                payload: b"test".to_vec(),
            })
            .expect("channel should not be full");
    }

    #[tokio::test]
    async fn test_inbound_messages_injected_before_superstep() {
        let (inbound_tx, _, mut runner) = DistributedPregelRunner::channel_pair(16);

        let vid = VertexId::from_str("vertex-b");
        runner.add_local_vertex(vid.clone(), Vec::new());

        // Send a message via the inbound channel (simulates a peer gossip message)
        inbound_tx
            .send(DistributedMessage {
                src:     "remote-peer".to_string(),
                dst:     vid.cid().to_multibase(),
                payload: b"from-peer".to_vec(),
            })
            .await
            .unwrap();

        // Run one superstep; the inbound message should activate vertex-b
        let result = runner
            .distributed_superstep(halt_compute())
            .await;

        assert_eq!(result.active_count, 1, "vertex-b should be activated by inbound message");
        assert_eq!(result.msg_delivered, 1);
    }

    #[tokio::test]
    async fn test_remote_messages_sent_via_outbound_channel() {
        let (_, mut outbound_rx, mut runner) = DistributedPregelRunner::channel_pair(16);

        // Add vertex-local; it will send a message to "remote-vertex" (not local)
        let local_vid = VertexId::from_str("local-vertex");
        runner.add_local_vertex(local_vid.clone(), Vec::new());
        runner.graph.inject_message(Message {
            src:     VertexId::from_str("seed"),
            dst:     local_vid.clone(),
            payload: b"go".to_vec(),
        });

        // Compute: send one message to a non-local vertex
        let remote_key = VertexId::from_str("remote-vertex").cid().to_multibase();
        let remote_key_clone = remote_key.clone();
        let compute: SharedComputeFn = Arc::new(move |v: &Vertex, _inbox: &[Message]| {
            ComputeOutput {
                new_state: v.state.clone(),
                messages:  vec![Message {
                    src:     v.id.clone(),
                    dst:     VertexId::from_str("remote-vertex"),
                    payload: b"hello-remote".to_vec(),
                }],
                vote_halt: true,
            }
        });

        runner.distributed_superstep(compute).await;

        // The message for "remote-vertex" should appear on outbound_rx
        let dmsg = outbound_rx
            .try_recv()
            .expect("outbound message should be queued");
        assert_eq!(dmsg.dst, remote_key_clone);
        assert_eq!(dmsg.payload, b"hello-remote");
    }

    #[tokio::test]
    async fn test_local_messages_stay_in_graph() {
        let (_, mut outbound_rx, mut runner) = DistributedPregelRunner::channel_pair(16);

        let va = VertexId::from_str("va");
        let vb = VertexId::from_str("vb");
        runner.add_local_vertex(va.clone(), Vec::new());
        runner.add_local_vertex(vb.clone(), Vec::new());
        runner.graph.inject_message(Message {
            src:     VertexId::from_str("seed"),
            dst:     va.clone(),
            payload: b"start".to_vec(),
        });

        // va sends to vb (both local) — should NOT appear on outbound_rx
        let vb_clone = vb.clone();
        let compute: SharedComputeFn = Arc::new(move |v: &Vertex, _inbox: &[Message]| {
            if v.id == VertexId::from_str("va") {
                ComputeOutput {
                    new_state: b"done".to_vec(),
                    messages:  vec![Message {
                        src:     v.id.clone(),
                        dst:     vb_clone.clone(),
                        payload: b"local-msg".to_vec(),
                    }],
                    vote_halt: true,
                }
            } else {
                ComputeOutput { new_state: v.state.clone(), messages: vec![], vote_halt: true }
            }
        });

        runner.distributed_superstep(compute).await;

        // Nothing on outbound — the message is destined for a local vertex
        assert!(
            outbound_rx.try_recv().is_err(),
            "no outbound messages expected for local destinations"
        );
    }
}
