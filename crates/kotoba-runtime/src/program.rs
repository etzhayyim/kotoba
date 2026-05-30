use anyhow::Result;
use dashmap::DashMap;
use std::sync::Arc;
use wasmtime::component::Component;

use crate::host::KotobaEngine;

/// ProgramStore caches compiled WASM Components by their program_cid.
///
/// program_cid = Kotoba CIDv1 blake3 of the raw .wasm bytes.
/// Compiled Component is reused across invocations (amortises Cranelift JIT cost).
#[derive(Clone)]
pub struct ProgramStore {
    engine: KotobaEngine,
    cache: Arc<DashMap<String, Component>>,
}

impl ProgramStore {
    pub fn new(engine: KotobaEngine) -> Self {
        Self {
            engine,
            cache: Arc::new(DashMap::new()),
        }
    }

    /// Load a compiled Component for `program_cid`.
    /// Caller is responsible for fetching `wasm_bytes` from Vault/Shelf if not cached.
    pub fn get_or_compile(&self, program_cid: &str, wasm_bytes: &[u8]) -> Result<Component> {
        if let Some(cached) = self.cache.get(program_cid) {
            return Ok(cached.clone());
        }
        let component = self.engine.compile(wasm_bytes)?;
        self.cache
            .insert(program_cid.to_string(), component.clone());
        Ok(component)
    }

    /// Evict a program (e.g., after RETRACT of a program Quad)
    pub fn evict(&self, program_cid: &str) {
        self.cache.remove(program_cid);
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}
