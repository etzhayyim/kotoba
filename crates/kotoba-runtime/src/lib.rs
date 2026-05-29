//! kotoba-runtime — WASM Component Model host for Kotoba node programs.
//!
//! Architecture:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │  KotobaRuntime (wasmtime Engine + ProgramStore)                  │
//! │                                                                  │
//! │  Invoke ChainEntry ──► WasmExecutor::execute()                  │
//! │       program_cid  ──► ProgramStore::get_or_compile()           │
//! │       ctx_cbor     ──► guest export run(ctx)                    │
//! │                                                                  │
//! │  WIT Host Interfaces (bound to every WASM Store):               │
//! │    kotoba:kais/kqe   assert/retract/query (ASSERT 0x1)          │
//! │    kotoba:kais/kse   publish/drain (SEND 0x3 / RECV 0x4)       │
//! │    kotoba:kais/auth  current-did / verify-cacao                 │
//! │    kotoba:kais/llm   infer/embed → CALL_FOREIGN(0xF) bridge     │
//! │    kotoba:kais/chain append-infer / head-cid                    │
//! │                                                                  │
//! │  WASM Guest (any language via WIT Component Model):             │
//! │    Rust  — wit-bindgen 0.28 + wasm32-wasip2                     │
//! │    Python — componentize-py 0.5                                 │
//! │    JS/TS  — jco ComponentizeJS                                   │
//! │    Go     — TinyGo + wit-bindgen-go                             │
//! │    C/C++  — clang --target=wasm32-wasi                         │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! WIT world definition: `wit/world.wit`
//! ADR: `90-docs/adr/2605240001-kotoba-cleanroom-architecture.md` §16

pub mod error;
pub mod executor;
pub mod host;
pub mod program;
pub mod sdk;
pub mod udf;

pub use error::RuntimeError;
pub use executor::{InvokeContext, InvokeResult, WasmExecutor};
pub use host::{HostState, KotobaEngine, KotobaLinker};
pub use program::ProgramStore;
pub use udf::UdfExecutor;

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use wasmtime::component::{Component, Linker};
    use wasmtime::{Config, Engine, Store};
    use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

    use crate::host::WitQuad;

    struct TestState {
        wasi_ctx: WasiCtx,
        wasi_table: ResourceTable,
    }
    impl WasiView for TestState {
        fn ctx(&mut self) -> &mut WasiCtx {
            &mut self.wasi_ctx
        }
        fn table(&mut self) -> &mut ResourceTable {
            &mut self.wasi_table
        }
    }

    #[test]
    fn test_wasm_instantiate() -> Result<()> {
        let wasm_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/kotoba-hello/target/wasm32-wasip2/release/kotoba_hello.wasm"
        );
        let wasm_bytes = std::fs::read(wasm_path)?;

        let mut config = Config::new();
        config.wasm_component_model(true);
        let engine = Engine::new(&config)?;
        let component = Component::new(&engine, &wasm_bytes)?;

        let mut linker: Linker<TestState> = Linker::new(&engine);
        wasmtime_wasi::add_to_linker_sync(&mut linker)?;

        {
            let mut inst = linker.instance("kotoba:kais/kqe@0.1.0")?;
            // assert-quad: func(q: quad) -> result<_, string>
            // WIT record requires WitQuad (ComponentType/Lift/Lower), not a plain tuple.
            inst.func_wrap(
                "assert-quad",
                |_: wasmtime::StoreContextMut<TestState>,
                 (q,): (WitQuad,)|
                 -> Result<(Result<(), String>,)> {
                    println!("assert-quad: {} {} {}", q.graph, q.subject, q.predicate);
                    Ok((Ok(()),))
                },
            )?;
            inst.func_wrap(
                "retract-quad",
                |_: wasmtime::StoreContextMut<TestState>,
                 (q,): (WitQuad,)|
                 -> Result<(Result<(), String>,)> {
                    println!("retract-quad: {} {} {}", q.graph, q.subject, q.predicate);
                    Ok((Ok(()),))
                },
            )?;
            inst.func_wrap(
                "query",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_src,): (String,)|
                 -> Result<(Result<Vec<WitQuad>, String>,)> { Ok((Ok(vec![]),)) },
            )?;
            inst.func_wrap(
                "get-objects",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_g, _s, _p): (String, String, String)|
                 -> Result<(Vec<Vec<u8>>,)> { Ok((vec![],)) },
            )?;
            inst.func_wrap(
                "get-head",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_g,): (String,)|
                 -> Result<(Option<String>,)> { Ok((None,)) },
            )?;
        }
        {
            let mut inst = linker.instance("kotoba:kais/kse@0.1.0")?;
            inst.func_wrap(
                "publish",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_t, _p): (String, Vec<u8>)|
                 -> Result<(Result<String, String>,)> {
                    Ok((Ok("cid".to_string()),))
                },
            )?;
            inst.func_wrap(
                "drain",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_pat, _max): (String, u32)|
                 -> Result<(Result<Vec<(String, Vec<u8>)>, String>,)> {
                    Ok((Ok(vec![]),))
                },
            )?;
        }
        {
            let mut inst = linker.instance("kotoba:kais/auth@0.1.0")?;
            inst.func_wrap(
                "current-did",
                |_: wasmtime::StoreContextMut<TestState>, (): ()| -> Result<(String,)> {
                    Ok(("did:plc:test".to_string(),))
                },
            )?;
            inst.func_wrap(
                "verify-cacao",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_cbor,): (Vec<u8>,)|
                 -> Result<(Result<String, String>,)> {
                    Ok((Err("not implemented".to_string()),))
                },
            )?;
            inst.func_wrap(
                "has-capability",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_uri, _ability): (String, String)|
                 -> Result<(bool,)> { Ok((false,)) },
            )?;
        }
        {
            let mut inst = linker.instance("kotoba:kais/llm@0.1.0")?;
            inst.func_wrap(
                "infer",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_m, _p): (String, Vec<u8>)|
                 -> Result<(Result<Vec<u8>, String>,)> {
                    Ok((Err("stub".to_string()),))
                },
            )?;
            inst.func_wrap(
                "embed",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_m, _t): (String, String)|
                 -> Result<(Result<Vec<u8>, String>,)> {
                    Ok((Err("stub".to_string()),))
                },
            )?;
            inst.func_wrap(
                "load-lora",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_b, _l): (String, String)|
                 -> Result<(Result<(), String>,)> {
                    Ok((Err("stub".to_string()),))
                },
            )?;
        }
        {
            let mut inst = linker.instance("kotoba:kais/chain@0.1.0")?;
            inst.func_wrap(
                "append-infer",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_m, _p, _o): (String, String, String)|
                 -> Result<(Result<String, String>,)> {
                    Ok((Err("stub".to_string()),))
                },
            )?;
            inst.func_wrap(
                "head-cid",
                |_: wasmtime::StoreContextMut<TestState>, (): ()| -> Result<(Option<String>,)> {
                    Ok((None,))
                },
            )?;
        }
        {
            let mut inst = linker.instance("kotoba:kais/evm@0.1.0")?;
            inst.func_wrap(
                "eth-call",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_url, _to, _cd, _bt): (String, String, Vec<u8>, Option<String>)|
                 -> Result<(Result<Vec<u8>, String>,)> { Ok((Ok(vec![]),)) },
            )?;
            inst.func_wrap(
                "eth-get-storage-at",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_url, _addr, _slot): (String, String, String)|
                 -> Result<(Result<Vec<u8>, String>,)> { Ok((Ok(vec![0u8; 32]),)) },
            )?;
            inst.func_wrap(
                "eth-get-balance",
                |_: wasmtime::StoreContextMut<TestState>,
                 (_url, _addr): (String, String)|
                 -> Result<(Result<String, String>,)> {
                    Ok((Ok("0x0".to_string()),))
                },
            )?;
        }

        let state = TestState {
            wasi_ctx: WasiCtxBuilder::new().inherit_stderr().build(),
            wasi_table: ResourceTable::new(),
        };
        let mut store = Store::new(&engine, state);
        let _instance = linker
            .instantiate(&mut store, &component)
            .map_err(|e| anyhow::anyhow!("instantiate failed: {e}"))?;
        println!("Instantiated OK!");
        Ok(())
    }

    /// Verify that HostState defaults to no inference engine loaded.
    #[test]
    fn test_host_state_inference_engine_default_is_none() {
        let state = crate::host::HostState::new("did:test:000", 10_000_000);
        assert!(
            state.inference_engine.is_none(),
            "HostState::new() must leave inference_engine as None"
        );
    }

    #[test]
    fn runtime_error_program_not_found_display() {
        let e = crate::error::RuntimeError::ProgramNotFound("cid-abc".to_string());
        let s = e.to_string();
        assert!(
            s.contains("cid-abc"),
            "display must include the program id: {s}"
        );
    }

    #[test]
    fn runtime_error_gas_exceeded_contains_limit() {
        let e = crate::error::RuntimeError::GasExceeded { limit: 5_000 };
        let s = e.to_string();
        assert!(
            s.contains("5000") || s.contains("5_000"),
            "must mention gas limit: {s}"
        );
    }

    #[test]
    fn runtime_error_trap_contains_message() {
        let e = crate::error::RuntimeError::Trap("stack overflow".to_string());
        assert!(e.to_string().contains("stack overflow"));
    }

    #[test]
    fn host_state_stores_agent_did() {
        let state = crate::host::HostState::new("did:plc:runtime-test", 1_000);
        assert_eq!(state.agent_did, "did:plc:runtime-test");
    }

    #[test]
    fn host_state_stores_gas_remaining() {
        let state = crate::host::HostState::new("did:plc:test", 99_999);
        assert_eq!(state.gas_remaining, 99_999);
    }

    #[test]
    fn host_state_pending_asserts_empty_on_new() {
        let state = crate::host::HostState::new("did:plc:test", 1_000);
        assert!(state.pending_asserts.is_empty());
    }

    #[test]
    fn host_state_pending_retracts_empty_on_new() {
        let state = crate::host::HostState::new("did:plc:test", 1_000);
        assert!(state.pending_retracts.is_empty());
    }

    #[test]
    fn host_state_quad_snapshot_empty_on_new() {
        let state = crate::host::HostState::new("did:plc:test", 1_000);
        assert!(state.quad_snapshot.is_empty());
    }

    #[test]
    fn host_state_pending_publishes_empty_on_new() {
        let state = crate::host::HostState::new("did:plc:test", 1_000);
        assert!(state.pending_publishes.is_empty());
    }

    #[test]
    fn host_state_pending_chain_entries_empty_on_new() {
        let state = crate::host::HostState::new("did:plc:test", 1_000);
        assert!(state.pending_chain_entries.is_empty());
    }

    #[test]
    fn host_state_pending_lora_loads_empty_on_new() {
        let state = crate::host::HostState::new("did:plc:test", 1_000);
        assert!(state.pending_lora_loads.is_empty());
    }

    #[test]
    fn host_state_head_commits_empty_on_new() {
        let state = crate::host::HostState::new("did:plc:test", 1_000);
        assert!(state.head_commits.is_empty());
    }

    #[test]
    fn host_state_kse_inbox_empty_on_new() {
        let state = crate::host::HostState::new("did:plc:test", 1_000);
        assert!(state.kse_inbox.is_empty());
    }

    #[test]
    fn host_state_source_chain_head_none_on_new() {
        let state = crate::host::HostState::new("did:plc:test", 1_000);
        assert!(state.source_chain_head.is_none());
    }

    #[test]
    fn host_state_embed_fn_none_on_new() {
        let state = crate::host::HostState::new("did:plc:test", 1_000);
        assert!(state.embed_fn.is_none());
    }
}
