use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use kotoba_graph::QuadStore;
use kotoba_kqe::{quad::LegacyQuad as Quad, Datom};
use kotoba_kse::JournalEntry;
use kotoba_net::{KotobaNetEvent, KotobaSwarm, PREGEL_GOSSIP_TOPIC};
use kotoba_vm::distributed::DistributedMessage;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

/// Maximum number of CID existence checks in a single Bitswap want_have list.
const MAX_WANT_HAVE: usize = 1_000;
/// Maximum number of full block fetches in a single Bitswap want_block list.
const MAX_WANT_BLOCK: usize = 100;
/// Maximum number of WantSince delta-sync entries in a single request.
const MAX_WANT_SINCE: usize = 16;
/// Maximum commits returned per WantSince entry.
const MAX_DELTA_COMMITS_PER_GRAPH: usize = 1_000;
/// Total serialised byte cap across all delta_commits in one response (8 MiB).
const MAX_DELTA_COMMITS_TOTAL_BYTES: usize = 8 * 1024 * 1024;

/// GossipSub topic carrying the full KSE Journal firehose (E: relay role).
const FIREHOSE_TOPIC: &str = "firehose";
/// Bound on the echo-guard set that stops a relay re-gossiping what it received.
const FIREHOSE_SEEN_CAP: usize = 8192;

/// Bounded content-CID de-dup guard. A relay receives a firehose entry, re-logs
/// it to its own Journal (re-sequenced), and that local Journal entry would
/// otherwise be picked up by the relay's own firehose cursor and gossiped back —
/// looping forever and inflating seq. Recording the entry's content CID (stable
/// blake3 of the payload, identical across nodes) lets the cursor skip the echo.
struct FirehoseSeen {
    ring: VecDeque<KotobaCid>,
    set: HashSet<KotobaCid>,
    cap: usize,
}

impl FirehoseSeen {
    fn new(cap: usize) -> Self {
        Self {
            ring: VecDeque::with_capacity(cap.min(1024)),
            set: HashSet::new(),
            cap,
        }
    }

    fn contains(&self, cid: &KotobaCid) -> bool {
        self.set.contains(cid)
    }

    fn insert(&mut self, cid: KotobaCid) {
        if self.set.insert(cid.clone()) {
            self.ring.push_back(cid);
            if self.ring.len() > self.cap {
                if let Some(old) = self.ring.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }
}

/// Swarm actor task.
///
/// Four-way fan-out via `tokio::select!`:
///   1. `publish_rx`         — KSE outbound → `swarm.publish`
///   2. `pregel_outbound_rx` — Pregel runner outbound → `swarm.send_pregel_message`
///   3. `swarm.next_event`   — inbound events → Bitswap serving, KSE Journal, or Pregel channel
///
/// GossipSub topics managed here:
///   "kotoba/quad/assert"  / "kotoba/quad/retract" — KSE quad propagation
///   "kotoba/pregel/messages"                       — Distributed Pregel BSP messages
///   "kotoba/firehose"                              — full Journal relay (relay role)
///
/// Bug fix: after `journal.publish()` for "quad/assert" or "quad/retract" topics,
/// also deserialize the data as the legacy Quad wire projection and apply it to
/// the local graph store as a Datom whose transaction is the Journal entry CID.
///
/// When `relay` is true (NodeRole::Relay), the node additionally bridges its
/// full KSE Journal onto the `firehose` gossip topic and re-logs peers' firehose
/// entries — the mesh half of the D+E federation surface (2026-05-30).
pub async fn run(
    mut swarm: KotobaSwarm,
    mut publish_rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    journal: Arc<kotoba_kse::Journal>,
    pregel_inbound_tx: tokio::sync::mpsc::Sender<DistributedMessage>,
    mut pregel_out_rx: tokio::sync::mpsc::Receiver<DistributedMessage>,
    block_store: Arc<dyn BlockStore + Send + Sync>,
    quad_store: Arc<QuadStore>,
    relay: bool,
) {
    swarm.subscribe("quad/assert").ok();
    swarm.subscribe("quad/retract").ok();
    swarm.subscribe_pregel().ok();

    // Full gossip topic string as published by KotobaSwarm (has "kotoba/" prefix)
    let pregel_full_topic = format!("kotoba/{PREGEL_GOSSIP_TOPIC}");

    // ── Relay role (E): bridge the local Journal onto the gossip firehose ──
    let mut firehose_cursor = journal.subscribe();
    let mut firehose_seen = FirehoseSeen::new(FIREHOSE_SEEN_CAP);
    if relay {
        swarm.subscribe(FIREHOSE_TOPIC).ok();
        tracing::info!("net_actor: relay role active — bridging KSE Journal ↔ gossip firehose");
    }

    loop {
        tokio::select! {
            // ── KSE outbound: forward journal publish requests ───────────
            msg = publish_rx.recv() => {
                let Some((kse_topic, data)) = msg else { break };
                swarm.publish(&kse_topic, data).ok();
            }

            // ── Pregel outbound: forward runner messages to gossip ───────
            dmsg = pregel_out_rx.recv() => {
                let Some(dmsg) = dmsg else { break };
                swarm
                    .send_pregel_message(&dmsg.src, &dmsg.dst, &dmsg.payload)
                    .ok();
            }

            // ── Relay: bridge local Journal entries onto the gossip firehose ──
            jentry = firehose_cursor.next(), if relay => {
                if let Some(entry) = jentry {
                    // Quad mutations + Pregel control already have dedicated
                    // gossip paths — skip them to avoid double propagation.
                    // Skip entries we received via firehose (echo guard).
                    let own_path = entry.topic == "quad/assert"
                        || entry.topic == "quad/retract"
                        || entry.topic == PREGEL_GOSSIP_TOPIC;
                    if !own_path && !firehose_seen.contains(&entry.cid) {
                        let mut cbor = Vec::new();
                        if ciborium::into_writer(&entry, &mut cbor).is_ok() {
                            swarm.publish(FIREHOSE_TOPIC, cbor).ok();
                        }
                    }
                }
            }

            // ── Inbound: peer events → Bitswap / KSE Journal / Pregel ───
            event = swarm.next_event() => {
                let Some(event) = event else { break };
                match event {
                    KotobaNetEvent::BitswapRequest { peer, request, channel } => {
                        let n_have  = request.want_have.len();
                        let n_block = request.want_block.len();
                        let n_since = request.want_since.len();
                        if n_have > MAX_WANT_HAVE || n_block > MAX_WANT_BLOCK || n_since > MAX_WANT_SINCE {
                            tracing::warn!(
                                peer = %peer,
                                n_have, n_block, n_since,
                                "Bitswap request exceeds per-request caps — ignored"
                            );
                            // Do not respond; the peer will time out on its end.
                            continue;
                        }

                        let mut have          = Vec::new();
                        let mut dont_have     = Vec::new();
                        let mut blocks        = Vec::new();
                        let mut delta_commits = Vec::new();
                        let mut delta_bytes   = 0usize;

                        for raw in &request.want_have {
                            let cid = kotoba_core::cid::KotobaCid(*raw);
                            if block_store.has(&cid) {
                                have.push(*raw);
                            } else {
                                dont_have.push(*raw);
                            }
                        }
                        for raw in &request.want_block {
                            let cid = kotoba_core::cid::KotobaCid(*raw);
                            match block_store.get(&cid) {
                                Ok(Some(bytes)) => blocks.push((*raw, bytes.to_vec())),
                                _               => dont_have.push(*raw),
                            }
                        }
                        // Selective-sync delta: CBOR-serialise Commit chain oldest-first.
                        // Hard cap: MAX_DELTA_COMMITS_PER_GRAPH commits per graph,
                        // MAX_DELTA_COMMITS_TOTAL_BYTES bytes total.
                        'ws_loop: for ws in &request.want_since {
                            let graph_cid = kotoba_core::cid::KotobaCid(ws.graph_cid);
                            let head      = ws.head_cid.map(kotoba_core::cid::KotobaCid);
                            let commits   = quad_store.commits_since(&graph_cid, head.as_ref()).await;
                            for commit in commits.into_iter().take(MAX_DELTA_COMMITS_PER_GRAPH) {
                                if delta_bytes >= MAX_DELTA_COMMITS_TOTAL_BYTES {
                                    tracing::warn!(
                                        peer = %peer,
                                        "Bitswap delta_commits byte cap reached — truncating response"
                                    );
                                    break 'ws_loop;
                                }
                                let cid_raw = commit.cid.0;
                                let mut buf = Vec::new();
                                if ciborium::into_writer(&commit, &mut buf).is_ok() {
                                    delta_bytes += buf.len();
                                    delta_commits.push((cid_raw, buf));
                                }
                            }
                        }

                        swarm.swarm.behaviour_mut().bitswap
                            .send_response(channel, kotoba_net::BitswapResponse {
                                have, dont_have, blocks, delta_commits,
                            })
                            .ok();
                    }
                    KotobaNetEvent::GossipMessage { topic, data, .. } => {
                        if topic == pregel_full_topic
                            || topic.ends_with(PREGEL_GOSSIP_TOPIC)
                        {
                            // Decode Pregel gossip message and forward to runner
                            if let Ok(pnet) =
                                serde_json::from_slice::<kotoba_net::PregelNetMessage>(&data)
                            {
                                use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
                                match B64.decode(&pnet.payload_b64) {
                                    Ok(payload) => {
                                        pregel_inbound_tx
                                            .try_send(DistributedMessage {
                                                src: pnet.src,
                                                dst: pnet.dst,
                                                payload,
                                            })
                                            .ok();
                                    }
                                    Err(e) => {
                                        tracing::warn!(src = %pnet.src, err = %e, "pregel gossip: bad base64 payload — skipped");
                                    }
                                }
                            }
                        } else {
                            let kse_name = topic
                                .strip_prefix("kotoba/")
                                .unwrap_or(&topic)
                                .to_string();

                            if kse_name == FIREHOSE_TOPIC {
                                // Relay inbound: decode the JournalEntry envelope
                                // and re-log it locally (re-sequenced) for
                                // durability + HTTP-tap (D) visibility + onward
                                // gossip forwarding. Record its content CID so
                                // our own firehose cursor doesn't echo it back.
                                match ciborium::from_reader::<JournalEntry, _>(&data[..]) {
                                    Ok(fe) => {
                                        firehose_seen.insert(fe.cid.clone());
                                        journal
                                            .publish(
                                                kotoba_kse::Topic(fe.topic),
                                                bytes::Bytes::from(fe.payload),
                                            )
                                            .await;
                                    }
                                    Err(e) => tracing::warn!(err = %e, "firehose: bad JournalEntry envelope — skipped"),
                                }
                            } else {
                                let maybe_quad_op = if kse_name == "quad/assert" {
                                    serde_json::from_slice::<Quad>(&data).ok().map(|quad| (quad, true))
                                } else if kse_name == "quad/retract" {
                                    serde_json::from_slice::<Quad>(&data).ok().map(|quad| (quad, false))
                                } else {
                                    None
                                };
                                let kse_topic = kotoba_kse::Topic(kse_name);
                                let entry = journal.publish(kse_topic, bytes::Bytes::from(data)).await;
                                if let Some((quad, op)) = maybe_quad_op {
                                    let graph_cid = quad.graph.clone();
                                    let mut datom = Datom::from_legacy_quad(quad, op);
                                    datom.tx = entry.cid.clone();
                                    quad_store.apply_journaled_datom(graph_cid, datom).await;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(byte: u8) -> KotobaCid {
        KotobaCid([byte; 36])
    }

    #[test]
    fn firehose_seen_dedups_and_evicts_fifo() {
        let mut seen = FirehoseSeen::new(2);
        seen.insert(cid(1));
        seen.insert(cid(2));
        assert!(seen.contains(&cid(1)));
        assert!(seen.contains(&cid(2)));

        // Over capacity → oldest (cid 1) evicted.
        seen.insert(cid(3));
        assert!(!seen.contains(&cid(1)));
        assert!(seen.contains(&cid(2)));
        assert!(seen.contains(&cid(3)));
    }

    #[test]
    fn firehose_seen_insert_is_idempotent() {
        let mut seen = FirehoseSeen::new(4);
        seen.insert(cid(9));
        seen.insert(cid(9));
        // A duplicate insert must not consume a second ring slot.
        seen.insert(cid(10));
        seen.insert(cid(11));
        seen.insert(cid(12));
        assert!(seen.contains(&cid(9)));
        assert!(seen.contains(&cid(12)));
    }

    #[test]
    fn max_want_have_is_1000() {
        assert_eq!(MAX_WANT_HAVE, 1_000);
    }

    #[test]
    fn max_want_block_is_100() {
        assert_eq!(MAX_WANT_BLOCK, 100);
    }

    #[test]
    fn max_want_since_is_16() {
        assert_eq!(MAX_WANT_SINCE, 16);
    }

    #[test]
    fn max_delta_commits_per_graph_is_1000() {
        assert_eq!(MAX_DELTA_COMMITS_PER_GRAPH, 1_000);
    }

    #[test]
    fn max_delta_commits_total_bytes_is_8mib() {
        assert_eq!(MAX_DELTA_COMMITS_TOTAL_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn want_block_is_fraction_of_want_have() {
        assert!(
            MAX_WANT_BLOCK < MAX_WANT_HAVE,
            "want_block limit should be smaller than want_have"
        );
    }
}
