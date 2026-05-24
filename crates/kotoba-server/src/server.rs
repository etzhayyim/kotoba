use std::sync::Arc;

use kotoba_runtime::{UdfExecutor, WasmExecutor};
use kotoba_vm::InvokeRouter;

/// Shared server state — injected into every axum handler via State<Arc<KotobaState>>.
pub struct KotobaState {
    pub version:  &'static str,
    pub executor: Arc<WasmExecutor>,
    pub udf:      Arc<UdfExecutor>,
    pub router:   Arc<InvokeRouter>,
}

impl KotobaState {
    pub fn new() -> anyhow::Result<Self> {
        let executor = WasmExecutor::new(10_000_000)?;
        let udf      = UdfExecutor::new()?;
        let router   = InvokeRouter::new(
            10_000_000,
            std::env::var("KOTOBA_GATEWAY_URL")
                .unwrap_or_else(|_| "http://localhost:9000".into()),
        )?;
        Ok(Self {
            version: env!("CARGO_PKG_VERSION"),
            executor: Arc::new(executor),
            udf:      Arc::new(udf),
            router:   Arc::new(router),
        })
    }
}
