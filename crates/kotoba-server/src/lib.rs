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

/// Build the axum router with all XRPC + meta routes.
pub fn build_router(state: Arc<KotobaState>) -> Router {
    Router::new()
        // Health / meta
        .route("/_app/meta",   get(xrpc::health))
        .route("/health",      get(xrpc::health))
        // XRPC procedure routes
        .route(
            &format!("/xrpc/{}", xrpc::NSID_QUAD_CREATE),
            post(xrpc::quad_create),
        )
        .route(
            &format!("/xrpc/{}", xrpc::NSID_INVOKE_RUN),
            post(xrpc::invoke_run),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
