use std::sync::Arc;
use kotoba_net::{KotobaNetEvent, KotobaSwarm, PREGEL_GOSSIP_TOPIC};
use kotoba_vm::distributed::DistributedMessage;
use kotoba_core::store::BlockStore;
use kotoba_graph::QuadStore;

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
///
/// Bug fix: after `journal.publish()` for "quad/assert" or "quad/retract" topics,
/// also deserialize the data as `kotoba_kqe::quad::Quad` and call
/// `quad_store.assert(quad).await` / `quad_store.retract(quad).await`
/// so that the receiving node's in-memory Arrangement is updated.
pub async fn run(
    mut swarm:           KotobaSwarm,
    mut publish_rx:      tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    journal:             Arc<kotoba_kse::Journal>,
    pregel_inbound_tx:   tokio::sync::mpsc::Sender<DistributedMessage>,
    mut pregel_out_rx:   tokio::sync::mpsc::Receiver<DistributedMessage>,
    block_store:         Arc<dyn BlockStore + Send + Sync>,
    quad_store:          Arc<QuadStore>,
) {
    swarm.subscribe("quad/assert").ok();
    swarm.subscribe("quad/retract").ok();
    swarm.subscribe_pregel().ok();

    // Full gossip topic string as published by KotobaSwarm (has "kotoba/" prefix)
    let pregel_full_topic = format!("kotoba/{PREGEL_GOSSIP_TOPIC}");

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
                            // Propagate quad assert/retract to local QuadStore Arrangement
                            if kse_name == "quad/assert" {
                                if let Ok(quad) = serde_json::from_slice::<kotoba_kqe::quad::Quad>(&data) {
                                    quad_store.assert(quad).await;
                                }
                            } else if kse_name == "quad/retract" {
                                if let Ok(quad) = serde_json::from_slice::<kotoba_kqe::quad::Quad>(&data) {
                                    quad_store.retract(quad).await;
                                }
                            }
                            let kse_topic = kotoba_kse::Topic(kse_name);
                            journal.publish(kse_topic, bytes::Bytes::from(data)).await;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
