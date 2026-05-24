use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("kotoba starting");
    tracing::info!("KOTOBA = Datom[CID/T] × EAVT[KSE Topic] × Pregel[BSP] × Datalog[Δ] × LLM/Weight");

    // Phase 8: full server init
    // - KSE Journal + Shelf + Vault
    // - KDHT + Source Chain + Neighborhood
    // - KQE Datalog + Arrangement + MV
    // - KVM executor + CALL_FOREIGN bridge
    // - kotoba-llm inference bridge
    // - XRPC + MCP endpoints

    Ok(())
}
