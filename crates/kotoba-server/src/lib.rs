pub mod attestation;
pub mod cc_xrpc;
pub mod email_xrpc;
pub mod fingerprint;
pub mod graph_auth;
pub mod kg;
pub mod kotobase_xrpc;
pub mod mcp;
pub mod net_actor;
pub mod nonce_store;
pub mod pre_proxy;
pub mod server;
pub mod signal_xrpc;
pub mod xrpc;

use std::sync::Arc;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};

use tower_http::trace::TraceLayer;
use crate::server::KotobaState;

#[cfg(test)]
mod tests {
    use super::xrpc::*;

    // ── NSID format invariants ─────────────────────────────────────────────

    const ALL_NSIDS: &[&str] = &[
        NSID_QUAD_CREATE,
        NSID_QUAD_RETRACT,
        NSID_GRAPH_QUERY,
        NSID_COMMIT_GET,
        NSID_COMMIT_STORE,
        NSID_INVOKE_RUN,
        NSID_INFER_RUN,
        NSID_WEIGHT_PUT,
        NSID_WEIGHT_GET,
        NSID_LORA_APPLY,
        NSID_EMBED_CREATE,
        NSID_NODE_STATUS,
        NSID_BLOCK_PUT,
        NSID_BLOCK_GET,
        NSID_AGENT_RUN,
        NSID_AGENT_SYNC_OPEN,
        NSID_AGENT_SYNC_ADV,
        NSID_AGENT_SYNC_CLOSE,
        NSID_VAULT_PUT,
        NSID_VAULT_GET,
        // email
        super::email_xrpc::NSID_EMAIL_LIST,
        super::email_xrpc::NSID_EMAIL_READ,
        super::email_xrpc::NSID_EMAIL_INGEST,
        // attestation
        super::attestation::NSID_ATTEST_CLAIM,
        super::attestation::NSID_ATTEST_CHALLENGE,
        super::attestation::NSID_ATTEST_QUERY,
        super::attestation::NSID_REQUEST_LOG,
        // cc vector search
        super::cc_xrpc::NSID_CC_SEARCH,
        super::cc_xrpc::NSID_CC_RAG,
        super::cc_xrpc::NSID_CC_INGEST,
        super::cc_xrpc::NSID_CC_STATUS,
    ];

    #[test]
    fn all_nsids_have_kotoba_prefix() {
        for nsid in ALL_NSIDS {
            assert!(
                nsid.starts_with("ai.gftd.apps.kotoba."),
                "NSID does not start with ai.gftd.apps.kotoba.: {nsid}"
            );
        }
    }

    #[test]
    fn all_nsids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for nsid in ALL_NSIDS {
            assert!(seen.insert(*nsid), "duplicate NSID: {nsid}");
        }
    }

    #[test]
    fn all_nsids_lowercase_dotted() {
        for nsid in ALL_NSIDS {
            assert!(
                nsid.chars().all(|c| c.is_ascii_lowercase() || c == '.'),
                "NSID must be lowercase+dots: {nsid}"
            );
        }
    }

    // ── kotobase NSID invariants ───────────────────────────────────────────

    #[test]
    fn kotobase_nsids_have_kotobase_prefix() {
        for nsid in super::kotobase_xrpc::ALL_NSIDS {
            assert!(
                nsid.starts_with("ai.gftd.apps.kotobase."),
                "kotobase NSID does not start with ai.gftd.apps.kotobase.: {nsid}"
            );
        }
    }

    #[test]
    fn kotobase_nsids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for nsid in super::kotobase_xrpc::ALL_NSIDS {
            assert!(seen.insert(*nsid), "duplicate kotobase NSID: {nsid}");
        }
    }

    // ── Router construction ────────────────────────────────────────────────

    #[test]
    fn build_router_does_not_panic() {
        let state = super::server::KotobaState::new(None)
            .expect("KotobaState::new should succeed in test env");
        let _router = super::build_router(std::sync::Arc::new(state));
    }

    // ── NSID detailed format checks ───────────────────────────────────────

    #[test]
    fn all_nsids_no_trailing_dot() {
        for nsid in ALL_NSIDS {
            assert!(!nsid.ends_with('.'), "NSID must not end with dot: {nsid}");
        }
    }

    #[test]
    fn all_nsids_have_at_least_four_segments() {
        for nsid in ALL_NSIDS {
            let segments: Vec<&str> = nsid.split('.').collect();
            assert!(
                segments.len() >= 4,
                "NSID should have at least 4 dot-separated segments: {nsid}"
            );
        }
    }

    #[test]
    fn all_nsids_start_with_ai_gftd_apps() {
        for nsid in ALL_NSIDS {
            assert!(
                nsid.starts_with("ai.gftd.apps."),
                "NSID does not start with ai.gftd.apps.: {nsid}"
            );
        }
    }

    #[test]
    fn all_nsids_no_consecutive_dots() {
        for nsid in ALL_NSIDS {
            assert!(
                !nsid.contains(".."),
                "NSID must not contain consecutive dots: {nsid}"
            );
        }
    }

    #[test]
    fn all_nsids_no_uppercase() {
        for nsid in ALL_NSIDS {
            assert!(
                !nsid.chars().any(|c| c.is_uppercase()),
                "NSID must not contain uppercase: {nsid}"
            );
        }
    }

    #[test]
    fn kotobase_nsids_have_at_least_four_segments() {
        for nsid in super::kotobase_xrpc::ALL_NSIDS {
            let segments: Vec<&str> = nsid.split('.').collect();
            assert!(
                segments.len() >= 4,
                "kotobase NSID should have >= 4 segments: {nsid}"
            );
        }
    }

    #[test]
    fn kotobase_nsids_no_consecutive_dots() {
        for nsid in super::kotobase_xrpc::ALL_NSIDS {
            assert!(
                !nsid.contains(".."),
                "kotobase NSID must not contain consecutive dots: {nsid}"
            );
        }
    }
}

pub fn build_router(state: Arc<KotobaState>) -> Router {
    Router::new()
        .route("/_app/meta",  get(xrpc::health))
        .route("/health",     get(xrpc::health))
        .route(
            &format!("/xrpc/{}", xrpc::NSID_QUAD_CREATE),
            post(xrpc::quad_create),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_INVOKE_RUN),
            post(xrpc::invoke_run),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_NODE_STATUS),
            get(xrpc::node_status),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_BLOCK_PUT),
            // 32 MiB base64 + JSON framing overhead
            post(xrpc::block_put).layer(DefaultBodyLimit::max(34 * 1024 * 1024)),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_BLOCK_GET),
            get(xrpc::block_get),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_COMMIT_GET),
            get(xrpc::commit_get),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_COMMIT_STORE),
            post(xrpc::commit_store),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_GRAPH_QUERY),
            get(xrpc::graph_query),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_WEIGHT_PUT),
            // 512 MiB base64 tensor + JSON framing overhead
            post(xrpc::weight_put).layer(DefaultBodyLimit::max(530 * 1024 * 1024)),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_QUAD_RETRACT),
            post(xrpc::quad_retract),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_WEIGHT_GET),
            get(xrpc::weight_get),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_LORA_APPLY),
            // 128 MiB LoRA adapter base64 + JSON framing overhead
            post(xrpc::lora_apply).layer(DefaultBodyLimit::max(136 * 1024 * 1024)),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_EMBED_CREATE),
            post(xrpc::embed_create),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_INFER_RUN),
            post(xrpc::infer_run),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_AGENT_RUN),
            post(xrpc::agent_run),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_AGENT_SYNC_OPEN),
            post(xrpc::agent_sync_open),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_AGENT_SYNC_ADV),
            post(xrpc::agent_sync_advance),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_AGENT_SYNC_CLOSE),
            post(xrpc::agent_sync_close),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_VAULT_PUT),
            post(xrpc::vault_put),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_VAULT_GET),
            get(xrpc::vault_get),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_ENTITY),
            get(kg::kg_entity),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_CATALOG),
            get(kg::kg_catalog),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_EMBED),
            post(kg::kg_embed),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_SEARCH),
            get(kg::kg_search),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_QUERY),
            post(kg::kg_query),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_SPARQL),
            post(kg::kg_sparql),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_INGEST),
            post(kg::kg_ingest),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_INGEST_BATCH),
            post(kg::kg_ingest_batch),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_DELETE),
            post(kg::kg_delete),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_COMMIT),
            post(kg::kg_commit),
        )
        // MCP body limit: 50 MB to allow kotoba_wasm_run with large WASM payloads
        .route("/mcp", post(mcp::mcp_handler).layer(DefaultBodyLimit::max(50 * 1024 * 1024)))
        // ── kotobase multi-tenant pinning service (ADR-2605260001) ──────────
        .route(
            &format!("/xrpc/{}", kotobase_xrpc::NSID_ACCOUNT_CREATE),
            post(kotobase_xrpc::handle_account_create),
        )
        .route(
            &format!("/xrpc/{}", kotobase_xrpc::NSID_ACCOUNT_STATUS),
            post(kotobase_xrpc::handle_account_status),
        )
        .route(
            &format!("/xrpc/{}", kotobase_xrpc::NSID_PIN_CREATE),
            post(kotobase_xrpc::handle_pin_create),
        )
        .route(
            &format!("/xrpc/{}", kotobase_xrpc::NSID_PIN_LIST),
            post(kotobase_xrpc::handle_pin_list),
        )
        .route(
            &format!("/xrpc/{}", kotobase_xrpc::NSID_PIN_DELETE),
            post(kotobase_xrpc::handle_pin_delete),
        )
        .route(
            &format!("/xrpc/{}", kotobase_xrpc::NSID_USAGE_GET),
            post(kotobase_xrpc::handle_usage_get),
        )
        // ── Common Crawl vector search / RAG ───────────────────────────────
        .route(
            &format!("/xrpc/{}", cc_xrpc::NSID_CC_SEARCH),
            get(cc_xrpc::cc_search),
        )
        .route(
            &format!("/xrpc/{}", cc_xrpc::NSID_CC_RAG),
            post(cc_xrpc::cc_rag),
        )
        .route(
            &format!("/xrpc/{}", cc_xrpc::NSID_CC_INGEST),
            post(cc_xrpc::cc_ingest),
        )
        .route(
            &format!("/xrpc/{}", cc_xrpc::NSID_CC_STATUS),
            get(cc_xrpc::cc_status),
        )
        // ── Email E2E XRPC ──────────────────────────────────────────────────
        .route(
            &format!("/xrpc/{}", email_xrpc::NSID_EMAIL_LIST),
            get(email_xrpc::email_list),
        )
        .route(
            &format!("/xrpc/{}", email_xrpc::NSID_EMAIL_READ),
            get(email_xrpc::email_read),
        )
        .route(
            &format!("/xrpc/{}", email_xrpc::NSID_EMAIL_INGEST),
            // 33 MiB raw email base64 + JSON framing overhead
            post(email_xrpc::email_ingest).layer(DefaultBodyLimit::max(36 * 1024 * 1024)),
        )
        // ── Signal Protocol E2E (ai.gftd.signal.*) ─────────────────────────
        .route(
            &format!("/xrpc/{}", signal_xrpc::NSID_SIGNAL_REGISTER_PREKEYS),
            // 256 KiB: two 64 KiB bundles + DID/device_id fields + JSON framing
            post(signal_xrpc::register_prekeys).layer(DefaultBodyLimit::max(256 * 1024)),
        )
        .route(
            &format!("/xrpc/{}", signal_xrpc::NSID_SIGNAL_GET_PREKEY_BUNDLE),
            get(signal_xrpc::get_prekey_bundle),
        )
        .route(
            &format!("/xrpc/{}", signal_xrpc::NSID_SIGNAL_SEND_MESSAGE),
            post(signal_xrpc::send_message),
        )
        .route(
            &format!("/xrpc/{}", signal_xrpc::NSID_SIGNAL_SEND_GROUP_MESSAGE),
            post(signal_xrpc::send_group_message),
        )
        .route(
            &format!("/xrpc/{}", signal_xrpc::NSID_SIGNAL_DISTRIBUTE_SENDER_KEY),
            post(signal_xrpc::distribute_sender_key),
        )
        // ── Attestation ────────────────────────────────────────────────────
        .route(
            &format!("/xrpc/{}", attestation::NSID_ATTEST_CLAIM),
            post(attestation::attest_claim),
        )
        .route(
            &format!("/xrpc/{}", attestation::NSID_ATTEST_CHALLENGE),
            post(attestation::attest_challenge),
        )
        .route(
            &format!("/xrpc/{}", attestation::NSID_ATTEST_QUERY),
            get(attestation::attest_query),
        )
        .route(
            &format!("/xrpc/{}", attestation::NSID_REQUEST_LOG),
            get(attestation::request_log_query),
        )
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            fingerprint::fingerprint_middleware,
        ))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// Start the kotoba server, blocking until shutdown.
/// All configuration is read from environment variables (same as the binary).
pub async fn run() -> anyhow::Result<()> {
    use std::sync::Arc;
    use kotoba_net::KotobaSwarm;
    use kotoba_vm::distributed::DistributedPregelRunner;

    tracing::info!(
        definition = "Datom[CID/T] × EAVT × Pregel[BSP] × Datalog[Δ] × LLM × WASM/WIT",
        "kotoba starting"
    );

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
                        runner.lock().unwrap_or_else(|e| e.into_inner()).generate(prompt, max_tokens)
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

    let state = server::KotobaState::new(inference_engine)?;
    let state = state.init_crypto().await?;

    // IPFS daemon liveness probe — non-fatal but logs a clear warning so the
    // operator notices when Kubo isn't reachable.  Skipped when KOTOBA_IPFS=off.
    let ipfs_off = std::env::var("KOTOBA_IPFS")
        .map(|v| v.eq_ignore_ascii_case("off") || v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false);
    if !ipfs_off {
        let probe = kotoba_store::KuboBlockStore::from_env();
        match probe.probe_version().await {
            Ok((ver, commit)) => tracing::info!(
                kubo_version = %ver,
                kubo_commit  = %commit,
                "IPFS daemon reachable"
            ),
            Err(e) => tracing::warn!(
                error  = %e,
                hint   = "set KOTOBA_IPFS=off to silence, or start `ipfs daemon`",
                "IPFS daemon NOT reachable — block writes/reads will fall back to hot cache only"
            ),
        }
    }

    tracing::info!(
        version  = state.version,
        node_id  = %hex::encode(state.local_node_id.0),
        did      = %state.operator_did,
        "KSE Journal + Shelf + KDHT Neighborhood ready"
    );

    state.register_node().await;

    {
        let quad_store = Arc::clone(&state.quad_store);
        tokio::spawn(async move {
            quad_store.replay_from_journal().await;
        });
    }

    let (pregel_inbound_tx, pregel_outbound_rx, pregel_runner) =
        DistributedPregelRunner::channel_pair(1024);
    let state = state.attach_pregel(pregel_runner);

    let state = if std::env::var("KOTOBA_NO_SWARM").is_err() {
        let listen_port: u16 = std::env::var("KOTOBA_P2P_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        let listen_addr = kotoba_net::quic_addr(listen_port);

        match KotobaSwarm::new(listen_addr).await {
            Ok(mut swarm) => {
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
                                (Err(e), _) => tracing::warn!("invalid peer_id: {e}"),
                                (_, Err(e)) => tracing::warn!("invalid multiaddr: {e}"),
                            }
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

                tokio::spawn(net_actor::run(
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

    if std::env::var("KOTOBA_GMAIL_CLIENT_ID").is_ok() {
        if let Some(ref crypto) = state.crypto {
            let cr = Arc::clone(crypto);
            let vt = Arc::clone(&state.vault);
            let qs = Arc::clone(&state.quad_store);
            tokio::spawn(kotoba_ingest::gmail_poll_loop(cr, vt, qs));
        }
    }

    if std::env::var("KOTOBA_JETSTREAM").is_ok() {
        let journal_arc    = Arc::clone(&state.journal);
        let quad_store_arc = Arc::clone(&state.quad_store);
        tokio::spawn(kotoba_graph::run_jetstream_client(journal_arc, quad_store_arc));
        tracing::info!("Jetstream client started");
    }

    if std::env::var("KOTOBA_SUBSCRIBE_REPOS").is_ok() {
        let journal_arc     = Arc::clone(&state.journal);
        let quad_store_arc  = Arc::clone(&state.quad_store);
        let block_store_arc = Arc::clone(&state.block_store);
        let gossip_tx       = state.gossip_tx.clone();
        tokio::spawn(kotoba_graph::run_subscribe_repos(
            journal_arc, quad_store_arc, block_store_arc, gossip_tx,
        ));
        tracing::info!("subscribeRepos firehose client started");
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
