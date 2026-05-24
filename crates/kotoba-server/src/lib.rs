pub mod mcp;
pub mod server;
pub mod xrpc;

use std::sync::Arc;
use axum::{
    Router,
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

    // ── Router construction ────────────────────────────────────────────────

    #[test]
    fn build_router_does_not_panic() {
        let state = super::server::KotobaState::new(None)
            .expect("KotobaState::new should succeed in test env");
        let _router = super::build_router(std::sync::Arc::new(state));
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
            post(xrpc::block_put),
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
            post(xrpc::weight_put),
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
            post(xrpc::lora_apply),
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
        .route("/mcp", post(mcp::mcp_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
