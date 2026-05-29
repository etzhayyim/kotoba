//! Integration tests: QuadStore gossip propagation correctness.
//!
//! These tests use direct channel simulation — no real libp2p swarms.
//! The gossip_tx channel from KotobaState is wired directly to a second
//! KotobaState's QuadStore so we can verify that asserted quads propagate
//! correctly without the 10-second GossipSub heartbeat overhead.

use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject};
use kotoba_server::server::KotobaState;
use std::sync::Arc;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_quad(graph: &str, subject: &str, predicate: &str, object: &str) -> Quad {
    Quad {
        graph: KotobaCid::from_bytes(graph.as_bytes()),
        subject: KotobaCid::from_bytes(subject.as_bytes()),
        predicate: predicate.to_string(),
        object: QuadObject::Text(object.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Test 1: quad propagates via gossip_tx → quad_store on receiving node
// ---------------------------------------------------------------------------

/// Simulates two KOTOBA nodes communicating through an in-memory gossip channel.
///
/// Architecture under test:
///   state1.journal_assert(quad)
///     → gossip_tx.send(("quad/assert", payload))
///     → relay task
///     → state2.quad_store.assert(quad)  (simulating the swarm consumer)
///
/// Verifies that a quad written on node1 is readable from node2's QuadStore.
#[tokio::test]
async fn quad_propagation_via_gossip_tx() {
    // ── Node 1: attach a gossip_tx so journal_assert forwards to the channel ──
    let (gossip_tx, mut gossip_rx) = mpsc::channel::<(String, Vec<u8>)>(64);

    let state1 = KotobaState::new(None)
        .expect("KotobaState::new should succeed")
        .attach_gossip(gossip_tx);
    let state1 = Arc::new(state1);

    // ── Node 2: plain state (no gossip sender — it only receives) ────────────
    let state2 = Arc::new(KotobaState::new(None).expect("KotobaState::new should succeed"));

    // ── Relay task: forward gossip messages to state2's QuadStore ────────────
    let state2_for_relay = Arc::clone(&state2);
    let relay = tokio::spawn(async move {
        let mut received = 0usize;
        while let Some((topic, payload)) = gossip_rx.recv().await {
            if topic == "quad/assert" {
                if let Ok(quad) = serde_json::from_slice::<Quad>(&payload) {
                    state2_for_relay.quad_store.assert(quad).await;
                    received += 1;
                }
            }
        }
        received
    });

    // ── Assert two quads on node1 ────────────────────────────────────────────
    let graph_cid = KotobaCid::from_bytes(b"test-graph-distributed");
    let subject_cid = KotobaCid::from_bytes(b"alice");

    let quad1 = make_quad("test-graph-distributed", "alice", "knows", "bob");
    let quad2 = make_quad("test-graph-distributed", "alice", "location", "Tokyo");

    state1.journal_assert(&quad1).await;
    state1.journal_assert(&quad2).await;

    // Drop gossip_tx (held by state1) to terminate the relay
    drop(state1);

    let relayed_count = relay.await.expect("relay task should complete cleanly");
    assert_eq!(
        relayed_count, 2,
        "relay should have forwarded 2 quad/assert messages"
    );

    // ── Verify node2's QuadStore contains the propagated quads ───────────────
    let quads = state2
        .quad_store
        .get_entity_quads(Some(&graph_cid), &subject_cid)
        .await;

    assert_eq!(
        quads.len(),
        2,
        "node2 should have received both quads for subject 'alice'"
    );

    let predicates: Vec<&str> = quads.iter().map(|q| q.predicate.as_str()).collect();
    assert!(
        predicates.contains(&"knows"),
        "quad1 (knows) must be in node2's store"
    );
    assert!(
        predicates.contains(&"location"),
        "quad2 (location) must be in node2's store"
    );
}

// ---------------------------------------------------------------------------
// Test 2: retract is also propagated via gossip channel
// ---------------------------------------------------------------------------

/// Verifies that journal_retract also fires the gossip_tx so a peer can apply
/// retract operations.  The relay simulates a peer that first asserts then
/// retracts the quad, and we confirm the QuadStore ends up empty.
#[tokio::test]
async fn quad_retract_propagates_via_gossip_tx() {
    let (gossip_tx, mut gossip_rx) = mpsc::channel::<(String, Vec<u8>)>(64);

    let state1 = Arc::new(
        KotobaState::new(None)
            .expect("state1 init")
            .attach_gossip(gossip_tx),
    );

    let state2 = Arc::new(KotobaState::new(None).expect("state2 init"));

    let state2_relay = Arc::clone(&state2);
    let relay = tokio::spawn(async move {
        let mut ops: Vec<(String, Quad)> = Vec::new();
        while let Some((topic, payload)) = gossip_rx.recv().await {
            if let Ok(quad) = serde_json::from_slice::<Quad>(&payload) {
                match topic.as_str() {
                    "quad/assert" => {
                        state2_relay.quad_store.assert(quad.clone()).await;
                    }
                    "quad/retract" => {
                        state2_relay.quad_store.retract(quad.clone()).await;
                    }
                    _ => {}
                }
                ops.push((topic, quad));
            }
        }
        ops
    });

    let graph_cid = KotobaCid::from_bytes(b"retract-graph");
    let subject_cid = KotobaCid::from_bytes(b"charlie");

    let quad = make_quad("retract-graph", "charlie", "status", "online");

    // Assert then retract
    state1.journal_assert(&quad).await;
    state1.journal_retract(&quad).await;

    drop(state1); // terminate relay

    let ops = relay.await.expect("relay task must complete");
    assert_eq!(ops.len(), 2, "relay should see one assert + one retract");
    assert_eq!(ops[0].0, "quad/assert", "first op is assert");
    assert_eq!(ops[1].0, "quad/retract", "second op is retract");

    // After assert + retract, the quad should not be in node2's QuadStore
    let quads = state2
        .quad_store
        .get_entity_quads(Some(&graph_cid), &subject_cid)
        .await;

    assert!(
        quads.is_empty(),
        "after retract, node2 QuadStore must contain no quads for subject 'charlie'"
    );
}

// ---------------------------------------------------------------------------
// Test 3: gossip_tx is None → journal_assert still works (no panic)
// ---------------------------------------------------------------------------

/// Verifies that KotobaState without a gossip channel functions correctly —
/// journal_assert must not panic when gossip_tx is None.
#[tokio::test]
async fn journal_assert_works_without_gossip_tx() {
    let state = Arc::new(KotobaState::new(None).expect("state init"));
    assert!(
        state.gossip_tx.is_none(),
        "gossip_tx should be None without attach_gossip"
    );

    let quad = make_quad("solo-graph", "alice", "likes", "coffee");

    // Must not panic
    let cid_str = state.journal_assert(&quad).await;
    assert!(
        !cid_str.is_empty(),
        "journal_assert must return a non-empty CID string"
    );

    // Also available locally in the state's own quad_store via direct assert
    state.quad_store.assert(quad.clone()).await;

    let graph_cid = KotobaCid::from_bytes(b"solo-graph");
    let subject_cid = KotobaCid::from_bytes(b"alice");

    let quads = state
        .quad_store
        .get_entity_quads(Some(&graph_cid), &subject_cid)
        .await;

    assert_eq!(quads.len(), 1);
    assert_eq!(quads[0].predicate, "likes");
}
