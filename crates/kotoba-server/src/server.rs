/// Kotoba server state (shared across handlers)
pub struct KotobaState {
    pub version: &'static str,
}

impl KotobaState {
    pub fn new() -> Self {
        Self { version: env!("CARGO_PKG_VERSION") }
    }
}
