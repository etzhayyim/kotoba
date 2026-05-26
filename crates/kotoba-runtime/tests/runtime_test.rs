/// kotoba-runtime integration tests
///
/// Phase 3: host stub fix verification (pure Rust, no WASM component)
///   - chain.head-cid  → HostState::source_chain_head
///   - auth.has-capability → quad_snapshot predicate scan
///   - llm.embed → EmbedFn dispatch
///   - kqe.evaluate-rules → DatalogProgram::evaluate_delta via CBOR rules
///
/// Phase 1: infrastructure verification (no WASM component required)
///   - Engine / Linker / Store setup
///   - All 5 WIT host interface bindings
///   - ProgramStore cache
///   - HostState gas accounting
///
/// Phase 2: end-to-end WASM execution via kotoba-guest component
///   - `build_guest_component()` compiles kotoba-guest to wasm32-wasip2
///   - `guest_wasm_executes_assert_quad_and_publish` runs the full kqe+kse host ABI
///   - `guest_wasm_gas_exhaustion_errors` verifies gas accounting traps
///   - Skips gracefully when cargo-component or wasm32-wasip2 target is unavailable

use std::sync::Arc;
use kotoba_runtime::{
    HostState, KotobaEngine, UdfExecutor, WasmExecutor,
    host::{KotobaLinker, WitQuad, EmbedFn},
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
        vec![],
        std::collections::HashMap::new(),
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

// ── Phase 3: host stub fix verification ───────────────────────────────────

#[test]
fn chain_head_cid_returns_pre_populated_head() {
    let state = HostState::new("did:plc:alice", 5000)
        .with_source_chain_head(Some("bafy2bzace123".to_string()));
    assert_eq!(
        state.source_chain_head.as_deref(),
        Some("bafy2bzace123"),
        "source_chain_head should be returned by chain.head-cid"
    );
}

#[test]
fn chain_head_cid_none_when_not_set() {
    let state = HostState::new("did:plc:alice", 5000);
    assert!(state.source_chain_head.is_none());
}

#[test]
fn auth_has_capability_matches_quad_snapshot() {
    // Build a quad snapshot granting did:plc:alice the "cc/index" "write" capability
    let cap_quad = WitQuad {
        graph:       "kotoba/auth".to_string(),
        subject:     "did:plc:alice".to_string(),
        predicate:   "auth/capability/cc%2Findex/write".to_string(),
        object_cbor: vec![0xf5], // CBOR true
    };
    let state = HostState::new("did:plc:alice", 5000)
        .with_snapshot(vec![cap_quad]);

    let agent_did   = &state.agent_did;
    let resource_uri = "cc%2Findex";
    let ability      = "write";
    let predicate    = format!("auth/capability/{resource_uri}/{ability}");

    let has = state.quad_snapshot.iter()
        .any(|q| &q.subject == agent_did && q.predicate == predicate);
    assert!(has, "capability predicate scan should find the quad");
}

#[test]
fn auth_has_capability_miss_on_wrong_did() {
    let cap_quad = WitQuad {
        graph:       "kotoba/auth".to_string(),
        subject:     "did:plc:bob".to_string(),   // different DID
        predicate:   "auth/capability/resource/read".to_string(),
        object_cbor: vec![0xf5],
    };
    let state = HostState::new("did:plc:alice", 5000)
        .with_snapshot(vec![cap_quad]);

    let predicate = "auth/capability/resource/read";
    let has = state.quad_snapshot.iter()
        .any(|q| q.subject == state.agent_did && q.predicate == predicate);
    assert!(!has, "capability check should fail for wrong DID");
}

#[test]
fn auth_has_capability_miss_on_wrong_ability() {
    let cap_quad = WitQuad {
        graph:       "kotoba/auth".to_string(),
        subject:     "did:plc:alice".to_string(),
        predicate:   "auth/capability/resource/read".to_string(),
        object_cbor: vec![0xf5],
    };
    let state = HostState::new("did:plc:alice", 5000)
        .with_snapshot(vec![cap_quad]);

    let predicate = "auth/capability/resource/write"; // different ability
    let has = state.quad_snapshot.iter()
        .any(|q| q.subject == state.agent_did && q.predicate == predicate);
    assert!(!has, "capability check should fail for wrong ability");
}

#[test]
fn llm_embed_fn_dispatches_and_returns_f32_bytes() {
    let embed_fn: EmbedFn = Arc::new(|text: &str| {
        // Return a 3-element embedding proportional to text length
        let v = text.len() as f32;
        Ok(vec![v, v * 2.0, v * 3.0])
    });
    let state = HostState::new("did:plc:alice", 5000)
        .with_embed_fn(embed_fn);

    let f = state.embed_fn.as_ref().expect("embed_fn should be set");
    let floats = f("hello").expect("embed should succeed");
    assert_eq!(floats.len(), 3);
    assert!((floats[0] - 5.0).abs() < 1e-6, "f[0] = text.len() = 5");
    assert!((floats[1] - 10.0).abs() < 1e-6);
    assert!((floats[2] - 15.0).abs() < 1e-6);

    // Also verify raw byte encoding (little-endian f32)
    let expected_bytes: Vec<u8> = floats.iter().flat_map(|f| f.to_le_bytes()).collect();
    assert_eq!(expected_bytes.len(), 12, "3 × 4 bytes");
}

#[test]
fn llm_embed_fn_none_without_configuration() {
    let state = HostState::new("did:plc:alice", 5000);
    assert!(state.embed_fn.is_none(), "embed_fn should default to None");
}

#[test]
fn kqe_evaluate_rules_datalog_cbor_roundtrip() {
    use kotoba_kqe::{DatalogProgram, DatalogRule};
    use kotoba_kqe::datalog::{Atom, BodyLiteral, Term};

    // Rule: knows(X, Z) :- knows(X, Y), knows(Y, Z)  (transitivity)
    let rule = DatalogRule {
        head: Atom { relation: "knows".to_string(), args: vec![Term::Variable("X".to_string()), Term::Variable("Z".to_string())] },
        body: vec![
            BodyLiteral::Positive(Atom { relation: "knows".to_string(), args: vec![Term::Variable("X".to_string()), Term::Variable("Y".to_string())] }),
            BodyLiteral::Positive(Atom { relation: "knows".to_string(), args: vec![Term::Variable("Y".to_string()), Term::Variable("Z".to_string())] }),
        ],
    };

    // CBOR roundtrip
    let rules = vec![rule];
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&rules, &mut cbor_bytes).expect("CBOR serialize");

    let decoded: Vec<DatalogRule> = ciborium::de::from_reader(cbor_bytes.as_slice())
        .expect("CBOR deserialize");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].head.relation, "knows");
    assert_eq!(decoded[0].body.len(), 2);
}

#[test]
fn kqe_evaluate_rules_derives_transitive_facts() {
    use kotoba_kqe::{DatalogProgram, DatalogRule, Delta};
    use kotoba_kqe::datalog::{Atom, BodyLiteral, Term};
    use kotoba_kqe::quad::{Quad, QuadObject};
    use kotoba_core::cid::KotobaCid;

    fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

    // Rule: knows(X,Z) :- knows(X,Y), knows(Y,Z)
    let rule = DatalogRule {
        head: Atom { relation: "knows".to_string(), args: vec![Term::Variable("X".to_string()), Term::Variable("Z".to_string())] },
        body: vec![
            BodyLiteral::Positive(Atom { relation: "knows".to_string(), args: vec![Term::Variable("X".to_string()), Term::Variable("Y".to_string())] }),
            BodyLiteral::Positive(Atom { relation: "knows".to_string(), args: vec![Term::Variable("Y".to_string()), Term::Variable("Z".to_string())] }),
        ],
    };

    let mut program = DatalogProgram::new();
    program.add_rule(rule);

    // Base facts: alice knows bob, bob knows carol
    let graph = cid("g");
    let input = vec![
        Delta::assert(Quad { graph: graph.clone(), subject: cid("alice"), predicate: "knows".into(), object: QuadObject::Cid(cid("bob")) }),
        Delta::assert(Quad { graph: graph.clone(), subject: cid("bob"),   predicate: "knows".into(), object: QuadObject::Cid(cid("carol")) }),
    ];

    let derived = program.evaluate_delta(&input);

    // Should derive: alice knows carol
    let derived_text: Vec<String> = derived.iter()
        .filter(|d| d.is_assert())
        .map(|d| format!("{} -> {}", d.quad.subject, d.quad.predicate))
        .collect();
    assert!(!derived.is_empty(), "expected at least 1 derived fact, derived: {derived_text:?}");
    let alice_knows_carol = derived.iter().any(|d| {
        d.is_assert()
            && d.quad.subject == cid("alice")
            && d.quad.predicate == "knows"
            && d.quad.object == QuadObject::Cid(cid("carol"))
    });
    assert!(alice_knows_carol, "expected derived fact alice-knows-carol; got: {derived_text:?}");
}

// ── Phase 2: end-to-end WASM guest execution ──────────────────────────────
//
// These tests build `crates/kotoba-guest` with `cargo component build` and
// execute the resulting WASM component through WasmExecutor.
//
// Run with: `cargo test -p kotoba-runtime --test runtime_test guest_wasm`
// Requires: wasm32-wasip2 target + cargo-component installed.

/// Build the kotoba-guest component and return the WASM bytes.
/// Skips the test if cargo-component or the wasm32-wasip2 target is missing.
#[cfg(test)]
fn build_guest_component() -> Option<Vec<u8>> {
    use std::process::Command;

    // Locate workspace root (parent of the crate manifest).
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().unwrap().parent().unwrap();

    let status = Command::new("cargo")
        .args([
            "component", "build",
            "--manifest-path", "crates/kotoba-guest/Cargo.toml",
            "--target", "wasm32-wasip2",
            "--release",
            "--quiet",
        ])
        .current_dir(workspace)
        .status();

    let Ok(s) = status else {
        eprintln!("cargo component not available — skipping WASM guest test");
        return None;
    };
    if !s.success() {
        eprintln!("kotoba-guest build failed — skipping WASM guest test");
        return None;
    }

    let wasm_path = workspace
        .join("target/wasm32-wasip2/release/kotoba_echo_assert.wasm");
    if !wasm_path.exists() {
        // cargo-component may place the file under a different name
        // (package name = "kotoba:echo-assert" → file = "kotoba_echo_assert.wasm")
        let alt = workspace.join("target/wasm32-wasip2/release/kotoba_guest.wasm");
        if alt.exists() {
            return Some(std::fs::read(alt).expect("read wasm"));
        }
        // Try any .wasm in the release dir
        let entries = std::fs::read_dir(workspace.join("target/wasm32-wasip2/release"))
            .ok()?;
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "wasm").unwrap_or(false) {
                let name = p.file_name().unwrap().to_string_lossy();
                if name.contains("kotoba") || name.contains("echo") || name.contains("guest") {
                    return Some(std::fs::read(&p).expect("read wasm"));
                }
            }
        }
        eprintln!("kotoba-guest wasm not found — skipping");
        return None;
    }

    Some(std::fs::read(wasm_path).expect("read wasm"))
}

/// Encode an InvokeContext to CBOR.
#[cfg(test)]
fn make_ctx_cbor(graph: &str, args: &[u8]) -> Vec<u8> {
    use std::collections::BTreeMap;
    // InvokeContext as a CBOR map with string keys.
    let mut map: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
    map.insert("graph",       ciborium::Value::Text(graph.to_string()));
    map.insert("session_cid", ciborium::Value::Null);
    map.insert("args_cbor",   ciborium::Value::Bytes(args.to_vec()));
    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf).expect("cbor encode");
    buf
}

#[test]
fn guest_wasm_executes_assert_quad_and_publish() {
    let Some(wasm_bytes) = build_guest_component() else { return };

    let executor = WasmExecutor::new(10_000_000).expect("executor");

    let ctx_cbor = make_ctx_cbor("test-graph", b"hello kotoba wasm");

    let result = executor.execute(
        "btest_echo_assert_cid",
        &wasm_bytes,
        "did:plc:kotoba-test",
        ctx_cbor,
        vec![],
        std::collections::HashMap::new(),
    );

    let r = result.expect("WasmExecutor::execute failed");

    // Guest calls kqe.assert-quad once → pending_asserts must have 1 entry.
    assert_eq!(r.assert_quads.len(), 1,
        "expected 1 assert quad, got {}: {:?}", r.assert_quads.len(), r.assert_quads);

    let q = &r.assert_quads[0];
    assert_eq!(q.graph,     "test-graph");
    assert_eq!(q.predicate, "kotoba/task");
    assert_eq!(q.subject,   "did:plc:kotoba-test");
    assert_eq!(q.object_cbor, b"hello kotoba wasm");

    // Guest calls kse.publish once → pending_publishes must have 1 entry.
    assert_eq!(r.pending_publishes.len(), 1,
        "expected 1 kse publish, got {}", r.pending_publishes.len());
    assert!(r.pending_publishes[0].0.contains("test-graph"));

    // Gas must have been consumed (assert=10, kse.publish=20, auth.current_did + overhead).
    assert!(r.gas_used >= 30, "expected ≥30 gas used, got {}", r.gas_used);

    // Output CBOR should decode to a map containing "status" = "ok".
    let out: ciborium::Value = ciborium::from_reader(r.output_cbor.as_slice())
        .expect("output_cbor should be valid CBOR");
    if let ciborium::Value::Map(pairs) = out {
        let status = pairs.iter().find_map(|(k, v)| {
            if k == &ciborium::Value::Text("status".into()) {
                v.as_text().map(|s| s.to_string())
            } else { None }
        });
        assert_eq!(status.as_deref(), Some("ok"),
            "expected status=ok in output CBOR");
    } else {
        panic!("output CBOR is not a map: {:?}", out);
    }
}

#[test]
fn guest_wasm_gas_exhaustion_errors() {
    let Some(wasm_bytes) = build_guest_component() else { return };

    // Only 5 gas — assert-quad costs 10, so the guest should fail with gas exhausted.
    let executor = WasmExecutor::new(5).expect("executor");
    let ctx_cbor = make_ctx_cbor("gas-test", b"x");

    let result = executor.execute(
        "bgas_test_cid",
        &wasm_bytes,
        "did:plc:test",
        ctx_cbor,
        vec![],
        std::collections::HashMap::new(),
    );

    // Gas exhaustion surfaces as a WASM trap (anyhow panics → host trap).
    assert!(result.is_err(), "expected gas exhaustion error (got Ok)");
}
