use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use kotoba_server::{build_router, server::KotobaState};
use kotoba_net::{KotobaNetEvent, KotobaSwarm, PREGEL_GOSSIP_TOPIC};
use kotoba_vm::distributed::{DistributedMessage, DistributedPregelRunner};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!(
        definition = "Datom[CID/T] × EAVT × Pregel[BSP] × Datalog[Δ] × LLM × WASM/WIT",
        "kotoba starting"
    );

    // ── 1. Inference engine (optional) ────────────────────────────────────────
    let inference_engine: Option<kotoba_runtime::host::InferenceFn> =
        if std::env::var("KOTOBA_LOAD_GEMMA").is_ok() {
            #[cfg(feature = "local-inference")]
            {
                use kotoba_llm::GemmaRunner;
                tracing::info!("loading Gemma 4 E2B from HuggingFace Hub (first run downloads ~4 GB)...");
                let runner = Arc::new(std::sync::Mutex::new(
                    GemmaRunner::load()
                        .await
                        .map_err(|e| anyhow::anyhow!("Gemma load failed: {e}"))?,
                ));
                tracing::info!("Gemma 4 E2B loaded");
                let engine: kotoba_runtime::host::InferenceFn =
                    Arc::new(move |prompt: &str, max_tokens: usize| {
                        runner.lock().unwrap().generate(prompt, max_tokens)
                    });
                Some(engine)
            }
            #[cfg(not(feature = "local-inference"))]
            {
                tracing::warn!(
                    "KOTOBA_LOAD_GEMMA is set but the `local-inference` feature is not enabled.\n\
                     Rebuild with: cargo build -p kotoba-server --features local-inference"
                );
                None
            }
        } else {
            None
        };

    // ── 2. KotobaState ────────────────────────────────────────────────────────
    let state = KotobaState::new(inference_engine)?;

    tracing::info!(
        version  = state.version,
        node_id  = %hex::encode(state.local_node_id.0),
        "KSE Journal + Shelf + KDHT Neighborhood ready"
    );

    // ── 3. Distributed Pregel channel pair ────────────────────────────────────
    // Created unconditionally so the runner is always available in KotobaState.
    // The swarm actor bridges the channels to GossipSub when the swarm is running.
    let (pregel_inbound_tx, pregel_outbound_rx, pregel_runner) =
        DistributedPregelRunner::channel_pair(1024);

    let state = state.attach_pregel(pregel_runner);

    // ── 4. Swarm actor (optional — set KOTOBA_NO_SWARM to disable) ────────────
    let state = if std::env::var("KOTOBA_NO_SWARM").is_err() {
        let listen_port: u16 = std::env::var("KOTOBA_P2P_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);

        let listen_addr = kotoba_net::quic_addr(listen_port);

        match KotobaSwarm::new(listen_addr).await {
            Ok(mut swarm) => {
                // ── C. Bootstrap peers from env ──────────────────────────────
                // Format: KOTOBA_BOOTSTRAP_PEERS=<peer_id>@<multiaddr>[,...]
                // Example: 12D3KooW...@/ip4/1.2.3.4/udp/4001/quic-v1
                if let Ok(peers_str) = std::env::var("KOTOBA_BOOTSTRAP_PEERS") {
                    let mut bootstrapped = false;
                    for entry in peers_str.split(',') {
                        let entry = entry.trim();
                        if entry.is_empty() { continue; }
                        if let Some((pid_str, addr_str)) = entry.split_once('@') {
                            match (
                                pid_str.trim().parse::<kotoba_net::PeerId>(),
                                addr_str.trim().parse::<kotoba_net::Multiaddr>(),
                            ) {
                                (Ok(peer_id), Ok(addr)) => {
                                    swarm.add_peer(peer_id, addr.clone());
                                    tracing::info!(%peer_id, %addr, "added bootstrap peer");
                                    bootstrapped = true;
                                }
                                (Err(e), _) => tracing::warn!("invalid peer_id in KOTOBA_BOOTSTRAP_PEERS: {e}"),
                                (_, Err(e)) => tracing::warn!("invalid multiaddr in KOTOBA_BOOTSTRAP_PEERS: {e}"),
                            }
                        } else {
                            tracing::warn!(entry, "KOTOBA_BOOTSTRAP_PEERS entry missing '@' separator; expected <peer_id>@<multiaddr>");
                        }
                    }
                    if bootstrapped {
                        swarm.bootstrap().ok();
                        tracing::info!("Kademlia bootstrap triggered");
                    }
                }

                let (publish_tx, publish_rx) =
                    tokio::sync::mpsc::channel::<(String, Vec<u8>)>(1024);

                let journal_arc = Arc::clone(&state.journal);

                tokio::spawn(swarm_actor(
                    swarm,
                    publish_rx,
                    journal_arc,
                    pregel_inbound_tx,
                    pregel_outbound_rx,
                ));

                tracing::info!("kotoba-net swarm started (QUIC + GossipSub + Kademlia)");
                state.attach_gossip(publish_tx)
            }
            Err(e) => {
                tracing::warn!(err = %e, "swarm init failed — running without p2p");
                state
            }
        }
    } else {
        tracing::info!("KOTOBA_NO_SWARM set — skipping p2p swarm");
        state
    };

    let state = Arc::new(state);

    let app = build_router(Arc::clone(&state));

    let port = std::env::var("KOTOBA_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!(%addr, "kotoba listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Swarm actor task.
///
/// Three-way fan-out via `tokio::select!`:
///   1. `publish_rx`       — KSE outbound → `swarm.publish`
///   2. `pregel_outbound_rx` — Pregel runner outbound → `swarm.send_pregel_message`
///   3. `swarm.next_event` — inbound gossip → route to KSE Journal or Pregel inbound channel
///
/// GossipSub topics managed here:
///   "kotoba/quad/assert"  / "kotoba/quad/retract" — KSE quad propagation
///   "kotoba/pregel/messages"                       — Distributed Pregel BSP messages
async fn swarm_actor(
    mut swarm:           KotobaSwarm,
    mut publish_rx:      tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    journal:             Arc<kotoba_kse::Journal>,
    pregel_inbound_tx:   tokio::sync::mpsc::Sender<DistributedMessage>,
    mut pregel_out_rx:   tokio::sync::mpsc::Receiver<DistributedMessage>,
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

            // ── Inbound: peer gossip → KSE Journal or Pregel channel ────
            event = swarm.next_event() => {
                let Some(event) = event else { break };
                if let KotobaNetEvent::GossipMessage { topic, data, .. } = event {
                    if topic == pregel_full_topic
                        || topic.ends_with(PREGEL_GOSSIP_TOPIC)
                    {
                        // Decode Pregel gossip message and forward to runner
                        if let Ok(pnet) =
                            serde_json::from_slice::<kotoba_net::PregelNetMessage>(&data)
                        {
                            use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
                            let payload = B64.decode(&pnet.payload_b64).unwrap_or_default();
                            pregel_inbound_tx
                                .try_send(DistributedMessage {
                                    src: pnet.src,
                                    dst: pnet.dst,
                                    payload,
                                })
                                .ok();
                        }
                    } else {
                        // KSE journal ingest — strip "kotoba/" prefix
                        let kse_name = topic
                            .strip_prefix("kotoba/")
                            .unwrap_or(&topic)
                            .to_string();
                        let kse_topic = kotoba_kse::Topic(kse_name);
                        journal.publish(kse_topic, bytes::Bytes::from(data)).await;
                    }
                }
            }
        }
    }
}
