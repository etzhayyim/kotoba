use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use kotoba_server::{build_router, server::KotobaState};
use kotoba_net::{KotobaNetEvent, KotobaSwarm};

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

    // ── 3. Swarm actor (optional — set KOTOBA_NO_SWARM to disable) ────────────
    let state = if std::env::var("KOTOBA_NO_SWARM").is_err() {
        let listen_port: u16 = std::env::var("KOTOBA_P2P_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(0); // 0 = OS-assigned

        let listen_addr = kotoba_net::quic_addr(listen_port);

        match KotobaSwarm::new(listen_addr).await {
            Ok(swarm) => {
                let (publish_tx, publish_rx) =
                    tokio::sync::mpsc::channel::<(String, Vec<u8>)>(1024);

                let journal_arc = Arc::clone(&state.journal);

                // Swarm actor: owns the swarm, handles outbound publish + inbound ingest.
                // Subscribes to two coarse KSE topics so peer asserts and retracts are
                // ingested into the local Journal.
                tokio::spawn(swarm_actor(swarm, publish_rx, journal_arc));

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
/// Owns the `KotobaSwarm` exclusively, fan-out:
///   - Receive `(kse_topic, payload)` from `publish_rx` → `swarm.publish`
///   - Receive peer `GossipMessage` → ingest into local `Journal`
///
/// Subscribed to two coarse gossip topics:
///   - `"quad/assert"`  ← peer quad asserts
///   - `"quad/retract"` ← peer quad retracts
///
/// `KotobaSwarm::publish` internally prepends `"kotoba/"` so the raw KSE topic names
/// passed through the channel must NOT include that prefix.
async fn swarm_actor(
    mut swarm:      KotobaSwarm,
    mut publish_rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    journal:        Arc<kotoba_kse::Journal>,
) {
    // Subscribe to coarse assertion and retraction topics.
    swarm.subscribe("quad/assert").ok();
    swarm.subscribe("quad/retract").ok();

    loop {
        tokio::select! {
            // ── Outbound: forward publish requests from KotobaState ─────────
            msg = publish_rx.recv() => {
                let Some((kse_topic, data)) = msg else { break };
                swarm.publish(&kse_topic, data).ok();
            }

            // ── Inbound: peer gossip → local Journal ingest ─────────────────
            event = swarm.next_event() => {
                let Some(event) = event else { break };
                if let KotobaNetEvent::GossipMessage { topic, data, .. } = event {
                    // GossipSub topic is "kotoba/<kse_topic>"; strip the prefix
                    // to recover the raw KSE topic name for Journal storage.
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
