use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use kotoba_server::{build_router, server::KotobaState};
use kotoba_net::KotobaSwarm;
use kotoba_vm::distributed::DistributedPregelRunner;

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
    //
    // Priority:
    //   1. KOTOBA_INFERENCE_URL  — HTTP (OpenAI-compat: Ollama, vLLM, Vultr A16)
    //   2. KOTOBA_LOAD_GEMMA     — local candle inference (requires --features local-inference)
    let inference_engine: Option<kotoba_runtime::host::InferenceFn> =
        if let Ok(_url) = std::env::var("KOTOBA_INFERENCE_URL") {
            let model = std::env::var("KOTOBA_INFERENCE_MODEL")
                .unwrap_or_else(|_| "gemma4:e4b".to_string());
            tracing::info!(_url, model, "HTTP inference engine active");
            let engine = kotoba_llm::HttpInferEngine::from_env()
                .map_err(|e| anyhow::anyhow!("HttpInferEngine init failed: {e}"))?;
            let engine = Arc::new(engine);
            let fn_: kotoba_runtime::host::InferenceFn =
                Arc::new(move |prompt: &str, max_tokens: usize| {
                    engine.generate(prompt, max_tokens)
                });
            Some(fn_)
        } else if std::env::var("KOTOBA_LOAD_GEMMA").is_ok() {
            #[cfg(feature = "local-inference")]
            {
                use kotoba_llm::GemmaRunner;
                tracing::info!("loading Gemma 2 2B IT from HuggingFace Hub (first run downloads ~5 GB)...");
                let runner = Arc::new(std::sync::Mutex::new(
                    GemmaRunner::load()
                        .await
                        .map_err(|e| anyhow::anyhow!("Gemma load failed: {e}"))?,
                ));
                tracing::info!("Gemma 2 2B IT loaded");
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

    // ── 2b. WAL replay — restore QuadStore Arrangement from Journal ────────────
    state.replay_wal().await;

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

                let journal_arc     = Arc::clone(&state.journal);
                let block_store_arc = Arc::clone(&state.block_store);
                let quad_store_arc  = Arc::clone(&state.quad_store);

                tokio::spawn(kotoba_server::net_actor::run(
                    swarm,
                    publish_rx,
                    journal_arc,
                    pregel_inbound_tx,
                    pregel_outbound_rx,
                    block_store_arc,
                    quad_store_arc,
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

    // ── 5. Jetstream AT Protocol firehose (optional) ──────────────────────────
    if std::env::var("KOTOBA_JETSTREAM").is_ok() {
        let journal_arc     = Arc::clone(&state.journal);
        let quad_store_arc  = Arc::clone(&state.quad_store);
        tokio::spawn(kotoba_graph::run_jetstream_client(journal_arc, quad_store_arc));
        tracing::info!("Jetstream client started (Journal + QuadStore)");
    }

    // ── 6. subscribeRepos binary firehose (optional) ──────────────────────────
    if std::env::var("KOTOBA_SUBSCRIBE_REPOS").is_ok() {
        let journal_arc     = Arc::clone(&state.journal);
        let quad_store_arc  = Arc::clone(&state.quad_store);
        let block_store_arc = Arc::clone(&state.block_store);
        let gossip_tx       = state.gossip_tx.clone();
        tokio::spawn(kotoba_graph::run_subscribe_repos(
            journal_arc, quad_store_arc, block_store_arc, gossip_tx,
        ));
        tracing::info!("subscribeRepos firehose client started (CAR blocks + Quads + GossipSub)");
    }

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

