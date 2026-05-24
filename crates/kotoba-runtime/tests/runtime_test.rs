/// kotoba-runtime integration tests
///
/// Phase 1: infrastructure verification (no WASM component required)
///   - Engine / Linker / Store setup
///   - All 5 WIT host interface bindings
///   - ProgramStore cache
///   - HostState gas accounting
///
/// Phase 2 (TODO): end-to-end WASM execution
///   - requires a compiled kotoba-node component (wit-bindgen + wasm32-wasip2)
///   - deferred until kotoba-runtime reaches beta

use kotoba_runtime::{
    HostState, KotobaEngine, UdfExecutor, WasmExecutor,
    host::KotobaLinker,
    program::ProgramStore,
};

// ── Engine / Linker ────────────────────────────────────────────────────────

#[test]
fn engine_new_ok() {
    let engine = KotobaEngine::new();
    assert!(engine.is_ok(), "KotobaEngine::new() failed: {:?}", engine.err());
}

#[test]
fn linker_bind_all_interfaces_ok() {
    let engine = KotobaEngine::new().expect("engine");
    let mut linker = engine.new_linker();
    let result = linker.bind_kotoba_interfaces();
    assert!(
        result.is_ok(),
        "bind_kotoba_interfaces() failed: {:?}",
        result.err()
    );
}

#[test]
fn store_gas_accounting() {
    let engine = KotobaEngine::new().expect("engine");
    let mut state = HostState::new("did:plc:test", 1000);

    assert_eq!(state.gas_remaining, 1000);

    state.charge_gas(100).expect("charge 100");
    assert_eq!(state.gas_remaining, 900);

    let err = state.charge_gas(901);
    assert!(err.is_err(), "charge beyond limit should fail");
    // gas_remaining unchanged on error
    assert_eq!(state.gas_remaining, 900);

    // Store can be created
    let _store = engine.new_store(state);
}

// ── ProgramStore ───────────────────────────────────────────────────────────

#[test]
fn program_store_cache_miss_on_invalid_wasm() {
    let engine = KotobaEngine::new().expect("engine");
    let store = ProgramStore::new(engine);

    // Invalid WASM bytes should return an error, not panic
    let result = store.get_or_compile("bfake_cid", b"not valid wasm");
    assert!(result.is_err(), "invalid WASM should error");
    // Cache should remain empty after failed compile
    assert_eq!(store.cache_size(), 0);
}

#[test]
fn program_store_evict_noop_on_unknown_cid() {
    let engine = KotobaEngine::new().expect("engine");
    let store = ProgramStore::new(engine);
    // Should not panic on evicting an unknown CID
    store.evict("bnonexistent");
    assert_eq!(store.cache_size(), 0);
}

// ── WasmExecutor / UdfExecutor ─────────────────────────────────────────────

#[test]
fn wasm_executor_new_ok() {
    let executor = WasmExecutor::new(10_000_000);
    assert!(
        executor.is_ok(),
        "WasmExecutor::new() failed: {:?}",
        executor.err()
    );
}

#[test]
fn udf_executor_new_ok() {
    let executor = UdfExecutor::new();
    assert!(
        executor.is_ok(),
        "UdfExecutor::new() failed: {:?}",
        executor.err()
    );
}

#[test]
fn wasm_executor_rejects_invalid_program() {
    let executor = WasmExecutor::new(10_000_000).expect("executor");
    let result = executor.execute(
        "bfake_program_cid",
        b"not valid wasm component",
        "did:plc:test",
        vec![],
    );
    assert!(result.is_err(), "invalid WASM should return RuntimeError");
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("CompileFailed") || err_str.contains("compile"),
        "expected CompileFailed, got: {}",
        err_str
    );
}

#[test]
fn udf_executor_rejects_invalid_program() {
    let executor = UdfExecutor::new().expect("executor");
    let result = executor.eval("bfake_udf_cid", b"not valid wasm", vec![]);
    assert!(result.is_err(), "invalid WASM should return RuntimeError");
}

// ── HostState pending quad accumulation ───────────────────────────────────

#[test]
fn host_state_pending_quads_empty_on_new() {
    let state = HostState::new("did:plc:alice", 5000);
    assert!(state.pending_asserts.is_empty());
    assert!(state.pending_retracts.is_empty());
    assert_eq!(state.agent_did, "did:plc:alice");
    assert_eq!(state.gas_remaining, 5000);
}
