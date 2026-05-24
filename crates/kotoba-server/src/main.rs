use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use kotoba_server::{build_router, server::KotobaState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!(
        definition = "Datom[CID/T] × EAVT × Pregel[BSP] × Datalog[Δ] × LLM × WASM/WIT",
        "kotoba starting"
    );

    // Initialize shared state (WasmExecutor + UdfExecutor + InvokeRouter)
    let state = Arc::new(KotobaState::new()?);
    tracing::info!(version = state.version, "subsystems ready");

    // Build axum router
    let app = build_router(state);

    // Bind address
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
