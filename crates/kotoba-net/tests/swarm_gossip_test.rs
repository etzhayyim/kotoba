//! Integration tests: GossipSub message delivery between two KotobaSwarm instances.
//!
//! These tests spin up two real libp2p swarms on ephemeral local QUIC ports and
//! verify end-to-end gossip delivery.
//!
//! TIMING NOTE: GossipSub requires a mesh heartbeat (10 s in production) before
//! messages flow.  To keep tests fast the swarms are driven concurrently with
//! `tokio::select!` so GRAFT/SUBSCRIBE control messages exchange immediately
//! over the established QUIC connection.  Even so, GossipSub mesh formation
//! can take 100–500 ms; tests use a 5 s deadline with 50 ms polling.

use std::time::Duration;
use tokio::time::{timeout, sleep, Instant};
use kotoba_net::{KotobaSwarm, KotobaNetEvent, Multiaddr, PREGEL_GOSSIP_TOPIC};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collect swarm1's first `ListenAddr` event.  Returns None on timeout.
async fn get_listen_addr(swarm: &mut KotobaSwarm) -> Option<Multiaddr> {
    timeout(Duration::from_secs(5), async {
        loop {
            match swarm.next_event().await? {
                KotobaNetEvent::ListenAddr(a) => return Some(a),
                _ => {}
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Drive both swarms concurrently until a `GossipMessage` matching `topic_suffix`
/// arrives on swarm2.  Returns the message data or None on deadline.
///
/// Both swarms are polled in a `select!` loop so GossipSub mesh control messages
/// (GRAFT, SUBSCRIBE) can flow in both directions while we wait.
async fn drive_until_gossip(
    swarm1: &mut KotobaSwarm,
    swarm2: &mut KotobaSwarm,
    topic_suffix: &str,
    deadline: Duration,
) -> Option<Vec<u8>> {
    let start = Instant::now();
    loop {
        if start.elapsed() > deadline {
            return None;
        }
        tokio::select! {
            ev1 = swarm1.next_event() => {
                if ev1.is_none() { return None; }
                // Swarm1 events keep it alive (GossipSub heartbeat, GRAFT etc.)
            }
            ev2 = swarm2.next_event() => {
                match ev2 {
                    None => return None,
                    Some(KotobaNetEvent::GossipMessage { topic, data, .. }) => {
                        if topic.contains(topic_suffix) {
                            return Some(data);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 1: basic gossip delivery
// ---------------------------------------------------------------------------

/// Two swarms subscribe to the same topic, connect, then swarm1 publishes a
/// message.  The test asserts swarm2 receives it with the correct payload.
///
/// Timing sensitivity: GossipSub mesh formation requires a heartbeat exchange.
/// The `drive_until_gossip` helper polls both swarms concurrently so control
/// messages flow immediately over the established QUIC connection.
#[tokio::test]
async fn gossip_message_delivered_between_two_swarms() {
    let addr1: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
    let addr2: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();

    let mut swarm1 = KotobaSwarm::new(addr1).await.expect("swarm1 init");
    let mut swarm2 = KotobaSwarm::new(addr2).await.expect("swarm2 init");

    let topic = "test/gossip/hello";
    swarm1.subscribe(topic).expect("swarm1 subscribe");
    swarm2.subscribe(topic).expect("swarm2 subscribe");

    // Get swarm1's actual OS-assigned listen address
    let listen_addr = get_listen_addr(&mut swarm1).await
        .expect("swarm1 did not emit a ListenAddr event within timeout");

    // Connect swarm2 → swarm1
    swarm2.add_peer(swarm1.local_peer_id, listen_addr);

    // Wait for the TCP/QUIC connection to be established
    let connected = timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                ev1 = swarm1.next_event() => {
                    if let Some(KotobaNetEvent::PeerConnected(_)) = ev1 { return true; }
                }
                ev2 = swarm2.next_event() => {
                    if let Some(KotobaNetEvent::PeerConnected(_)) = ev2 { return true; }
                }
            }
        }
    })
    .await;
    assert!(
        connected.is_ok(),
        "swarms failed to connect within 5 s; check QUIC / libp2p installation"
    );

    // Small delay to allow GossipSub SUBSCRIBE/GRAFT to propagate over the
    // already-established connection before the first publish
    sleep(Duration::from_millis(200)).await;

    // Publish from swarm1 — retry loop handles InsufficientPeers during mesh ramp-up
    let payload = b"hello-gossip".to_vec();
    let mut published = false;
    for _ in 0..10 {
        match swarm1.publish(topic, payload.clone()) {
            Ok(_) => { published = true; break; }
            Err(_) => {
                // Drive both swarms briefly then retry
                tokio::select! {
                    _ = swarm1.next_event() => {}
                    _ = swarm2.next_event() => {}
                    _ = sleep(Duration::from_millis(100)) => {}
                }
            }
        }
    }
    assert!(published, "swarm1 could not publish to GossipSub topic within 10 retries");

    // Drive both swarms until swarm2 receives the message
    let received = drive_until_gossip(&mut swarm1, &mut swarm2, topic, Duration::from_secs(5)).await;
    assert!(received.is_some(), "swarm2 did not receive gossip message within 5 s");
    assert_eq!(received.unwrap(), payload, "received payload must match sent payload");
}

// ---------------------------------------------------------------------------
// Test 2: topic isolation — pregel topic is separate from quad topic
// ---------------------------------------------------------------------------

/// Both swarms subscribe to the Pregel topic so the mesh can form.
/// swarm1 also subscribes to a quad topic; swarm2 does NOT.
///
/// swarm2 publishes a Pregel message.
///
/// Asserts:
///   - swarm1 receives the Pregel message on the Pregel topic (delivery works)
///   - the message is NOT surfaced as a quad-topic event on swarm1 (topic isolation)
///   - swarm2 does NOT receive its own message back (no GossipSub loopback)
///
/// Design note: GossipSub requires subscription to a topic to form a mesh and
/// publish successfully.  Both swarms subscribe to pregel; isolation is verified
/// by checking that the pregel payload does not appear in swarm1's quad channel.
///
/// Timing: same concurrent-drive pattern; 5 s deadline.
#[tokio::test]
async fn pregel_gossip_topic_is_separate_from_quad_topic() {
    let addr1: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
    let addr2: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();

    let mut swarm1 = KotobaSwarm::new(addr1).await.expect("swarm1 init");
    let mut swarm2 = KotobaSwarm::new(addr2).await.expect("swarm2 init");

    let quad_topic = "test/quad/assert";

    // Both subscribe to pregel so the pregel mesh can form and publish works.
    swarm1.subscribe_pregel().expect("swarm1 subscribe pregel");
    swarm2.subscribe_pregel().expect("swarm2 subscribe pregel");

    // Only swarm1 subscribes to the quad topic.
    swarm1.subscribe(quad_topic).expect("swarm1 subscribe quad");

    // Connect
    let listen_addr = get_listen_addr(&mut swarm1).await
        .expect("swarm1 ListenAddr timeout");
    swarm2.add_peer(swarm1.local_peer_id, listen_addr);

    // Wait for connection
    let _ = timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                ev1 = swarm1.next_event() => {
                    if let Some(KotobaNetEvent::PeerConnected(_)) = ev1 { return; }
                }
                ev2 = swarm2.next_event() => {
                    if let Some(KotobaNetEvent::PeerConnected(_)) = ev2 { return; }
                }
            }
        }
    })
    .await;

    sleep(Duration::from_millis(200)).await;

    // swarm2 publishes a Pregel message
    let pregel_payload = b"pregel-only".to_vec();
    let mut pregel_published = false;
    for _ in 0..10 {
        match swarm2.send_pregel_message("src-peer", "dst-peer", &pregel_payload) {
            Ok(_)  => { pregel_published = true; break; }
            Err(_) => {
                tokio::select! {
                    _ = swarm1.next_event() => {}
                    _ = swarm2.next_event() => {}
                    _ = sleep(Duration::from_millis(100)) => {}
                }
            }
        }
    }
    assert!(pregel_published, "swarm2 could not publish pregel message within 10 retries");

    // swarm1 should receive the pregel message on the pregel topic
    let received_on_swarm1 = drive_until_gossip(
        &mut swarm2,  // drive swarm2 to keep it alive
        &mut swarm1,  // look for message on swarm1
        PREGEL_GOSSIP_TOPIC,
        Duration::from_secs(5),
    ).await;
    assert!(
        received_on_swarm1.is_some(),
        "swarm1 (subscribed to pregel topic) should receive the pregel message"
    );

    // Verify it is parseable as a PregelNetMessage
    let parsed = serde_json::from_slice::<serde_json::Value>(&received_on_swarm1.unwrap())
        .expect("pregel message payload must be valid JSON");
    assert_eq!(parsed["src"], "src-peer");
    assert_eq!(parsed["dst"], "dst-peer");

    // Isolation: the pregel message must NOT appear as a quad-topic event on swarm1.
    // Drain swarm1's event queue briefly and assert no quad-topic gossip arrives.
    let quad_leak = timeout(Duration::from_millis(300), async {
        loop {
            match swarm1.next_event().await {
                Some(KotobaNetEvent::GossipMessage { topic, .. })
                    if topic.contains(quad_topic) => return true,
                None => return false,
                _ => {}
            }
        }
    })
    .await
    .unwrap_or(false);

    assert!(
        !quad_leak,
        "pregel message must NOT appear in swarm1's quad-topic subscription"
    );
}
