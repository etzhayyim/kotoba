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
            &format!("/xrpc/{}", kg::NSID_KG_INGEST),
            post(kg::kg_ingest),
        )
        .route(
            &format!("/xrpc/{}", kg::NSID_KG_DELETE),
            post(kg::kg_delete),
        )
        .route("/mcp", post(mcp::mcp_handler))
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
            post(email_xrpc::email_ingest),
        )
        // ── Signal Protocol E2E (ai.gftd.signal.*) ─────────────────────────
        .route(
            &format!("/xrpc/{}", signal_xrpc::NSID_SIGNAL_REGISTER_PREKEYS),
            post(signal_xrpc::register_prekeys),
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
