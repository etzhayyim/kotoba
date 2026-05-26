//! WASM-driven Pregel BSP runner for KOTOBA.
//!
//! `WasmPregelRunner` wires a compiled WASM Component Model program into
//! the Pregel BSP engine: each BSP superstep invokes the guest's `run(ctx_cbor)`
//! export via `WasmExecutor`. The guest controls continuation by returning
//! output CBOR with `"status": "continue"`; any other status (e.g. `"ok"`) or
//! a missing key causes the vertex to vote_halt.
//!
//! Single-vertex self-loop model:
//!   superstep N — guest returns output_cbor
//!   if status == "continue" → output_cbor becomes ctx_cbor for superstep N+1
//!   otherwise              → vertex votes halt, run() terminates
//!
//! Accumulated quads and KSE publishes are collected across all supersteps
//! and returned in `WasmRunResult`.

use std::collections::HashMap;
use std::sync::Arc;

use kotoba_runtime::{WasmExecutor, InvokeResult, RuntimeError};
use kotoba_runtime::executor::SerializedQuad;

use crate::pregel::{
    ComputeFn, ComputeOutput, Message, PregelGraph, SuperstepResult, VertexId,
};

// ---------------------------------------------------------------------------
// Vertex state (CBOR-serialised, persisted in PregelGraph)
// ---------------------------------------------------------------------------

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct WasmVertexState {
    accumulated_quads:    Vec<SerializedQuadOwned>,
    accumulated_retracts: Vec<SerializedQuadOwned>,
    accumulated_publishes: Vec<(String, Vec<u8>)>,
    total_gas_used:       u64,
    final_output_cbor:    Vec<u8>,
}

/// Owned mirror of `SerializedQuad` with Serialize/Deserialize
/// (the runtime type re-derives them, but we need the owned form here).
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct SerializedQuadOwned {
    pub graph:       String,
    pub subject:     String,
    pub predicate:   String,
    pub object_cbor: Vec<u8>,
}

impl From<SerializedQuad> for SerializedQuadOwned {
    fn from(q: SerializedQuad) -> Self {
        Self { graph: q.graph, subject: q.subject, predicate: q.predicate, object_cbor: q.object_cbor }
    }
}

impl From<SerializedQuadOwned> for SerializedQuad {
    fn from(q: SerializedQuadOwned) -> Self {
        SerializedQuad { graph: q.graph, subject: q.subject, predicate: q.predicate, object_cbor: q.object_cbor }
    }
}

// ---------------------------------------------------------------------------
// Public result type
// ---------------------------------------------------------------------------

pub struct WasmRunResult {
    pub superstep_results: Vec<SuperstepResult>,
    pub assert_quads:       Vec<SerializedQuad>,
    pub retract_quads:      Vec<SerializedQuad>,
    pub pending_publishes:  Vec<(String, Vec<u8>)>,
    pub final_output_cbor:  Vec<u8>,
    pub total_gas_used:     u64,
    pub supersteps_run:     u32,
}

// ---------------------------------------------------------------------------
// WasmPregelRunner
// ---------------------------------------------------------------------------

pub struct WasmPregelRunner {
    executor:       Arc<WasmExecutor>,
    program_cid:    String,
    wasm_bytes:     Arc<Vec<u8>>,
    agent_did:      String,
    max_supersteps: u32,
}

impl WasmPregelRunner {
    pub fn new(
        executor:       Arc<WasmExecutor>,
        program_cid:    impl Into<String>,
        wasm_bytes:     Vec<u8>,
        agent_did:      impl Into<String>,
        max_supersteps: u32,
    ) -> Self {
        Self {
            executor,
            program_cid: program_cid.into(),
            wasm_bytes:  Arc::new(wasm_bytes),
            agent_did:   agent_did.into(),
            max_supersteps,
        }
    }

    /// Run the WASM program in the Pregel BSP loop.
    ///
    /// The single vertex is seeded with `initial_ctx_cbor` via the inject
    /// mechanism. Each superstep the vertex calls the WASM guest; if the guest
    /// signals `"status": "continue"` in its output CBOR the output becomes
    /// the ctx_cbor for the next superstep. Otherwise the vertex votes halt.
    pub fn run(&self, initial_ctx_cbor: Vec<u8>) -> Result<WasmRunResult, RuntimeError> {
        let executor     = Arc::clone(&self.executor);
        let program_cid  = Arc::new(self.program_cid.clone());
        let wasm_bytes   = Arc::clone(&self.wasm_bytes);
        let agent_did    = Arc::new(self.agent_did.clone());

        let compute: ComputeFn = Box::new(move |vertex, inbox| {
            // Extract ctx_cbor from inbox (message payload carries it)
            let ctx_cbor: Vec<u8> = inbox
                .iter()
                .find(|_| true)
                .map(|m| m.payload.clone())
                .unwrap_or_default();

            if ctx_cbor.is_empty() {
                // No message → nothing to do, halt immediately
                return ComputeOutput {
                    new_state: vertex.state.clone(),
                    messages:  vec![],
                    vote_halt: true,
                };
            }

            // Decode accumulated state from vertex
            let mut state: WasmVertexState = if vertex.state.is_empty() {
                WasmVertexState::default()
            } else {
                ciborium::from_reader(vertex.state.as_slice())
                    .unwrap_or_default()
            };

            // Invoke WASM guest
            let result = executor.execute(
                &program_cid,
                &wasm_bytes,
                &agent_did,
                ctx_cbor,
                vec![],
                HashMap::new(),
            );

            let invoke: InvokeResult = match result {
                Ok(r)  => r,
                Err(e) => {
                    // On error: encode {"err": "..."} as CBOR (matches Python handle_invoke format)
                    let err_cbor = ciborium::Value::Map(vec![(
                        ciborium::Value::Text("err".into()),
                        ciborium::Value::Text(format!("{e:?}")),
                    )]);
                    let mut err_buf = Vec::new();
                    let _ = ciborium::into_writer(&err_cbor, &mut err_buf);
                    state.final_output_cbor = err_buf;
                    let mut buf = Vec::new();
                    let _ = ciborium::into_writer(&state, &mut buf);
                    return ComputeOutput { new_state: buf, messages: vec![], vote_halt: true };
                }
            };

            // Accumulate side effects — cap asserts to avoid unbounded memory across supersteps.
            // The post-run MCP/XRPC layer enforces the hard limit; we stop accumulating
            // one over that limit so the caller can detect the overflow and reject.
            const MAX_ACCUMULATED_QUADS: usize = 10_001;
            state.total_gas_used += invoke.gas_used;
            state.accumulated_quads.extend(invoke.assert_quads.into_iter().map(Into::into));
            state.accumulated_retracts.extend(invoke.retract_quads.into_iter().map(Into::into));
            state.accumulated_publishes.extend(invoke.pending_publishes);
            // Vote halt immediately if quad budget is exceeded (no point continuing).
            if state.accumulated_quads.len() >= MAX_ACCUMULATED_QUADS {
                state.final_output_cbor = br#"{"status":"quota_exceeded"}"#.to_vec();
                let mut buf = Vec::new();
                let _ = ciborium::into_writer(&state, &mut buf);
                return ComputeOutput { new_state: buf, messages: vec![], vote_halt: true };
            }

            // Decide continuation: check for "status": "continue" in output CBOR
            let should_continue = decode_status_continue(&invoke.output_cbor);

            let (messages, vote_halt) = if should_continue {
                let next_msg = Message {
                    src:     vertex.id.clone(),
                    dst:     vertex.id.clone(),
                    payload: invoke.output_cbor.clone(),
                };
                (vec![next_msg], false)
            } else {
                state.final_output_cbor = invoke.output_cbor;
                (vec![], true)
            };

            let mut new_state_bytes = Vec::new();
            let _ = ciborium::into_writer(&state, &mut new_state_bytes);

            ComputeOutput { new_state: new_state_bytes, messages, vote_halt }
        });

        // Build graph: one vertex, seeded with initial_ctx_cbor
        let mut graph  = PregelGraph::new();
        let vertex_id  = VertexId::from("wasm::program");
        graph.add_vertex(vertex_id.clone(), Vec::new());
        graph.inject_message(Message {
            src:     VertexId::from("__init__"),
            dst:     vertex_id.clone(),
            payload: initial_ctx_cbor,
        });

        let superstep_results = graph.run(&compute, self.max_supersteps);
        let supersteps_run    = superstep_results.len() as u32;

        // Extract final accumulated state from the vertex
        let final_state: WasmVertexState = graph
            .vertex(&vertex_id)
            .and_then(|v| if v.state.is_empty() { None } else { Some(v) })
            .and_then(|v| ciborium::from_reader(v.state.as_slice()).ok())
            .unwrap_or_default();

        Ok(WasmRunResult {
            superstep_results,
            assert_quads:      final_state.accumulated_quads.into_iter().map(Into::into).collect(),
            retract_quads:     final_state.accumulated_retracts.into_iter().map(Into::into).collect(),
            pending_publishes: final_state.accumulated_publishes,
            final_output_cbor: final_state.final_output_cbor,
            total_gas_used:    final_state.total_gas_used,
            supersteps_run,
        })
    }
}

/// Return true iff `cbor` decodes to a CBOR map containing `"status": "continue"`.
fn decode_status_continue(cbor: &[u8]) -> bool {
    if cbor.is_empty() {
        return false;
    }
    let val: ciborium::Value = match ciborium::from_reader(cbor) {
        Ok(v)  => v,
        Err(_) => return false,
    };
    if let ciborium::Value::Map(pairs) = val {
        for (k, v) in &pairs {
            if k == &ciborium::Value::Text("status".into()) {
                return v.as_text().map(|s| s == "continue").unwrap_or(false);
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_status_continue_ok_is_false() {
        // Guest returning {"status":"ok"} → halt
        let mut buf = Vec::new();
        let mut map = std::collections::BTreeMap::new();
        map.insert("status", ciborium::Value::Text("ok".into()));
        ciborium::into_writer(&map, &mut buf).unwrap();
        assert!(!decode_status_continue(&buf));
    }

    #[test]
    fn decode_status_continue_continue_is_true() {
        let mut buf = Vec::new();
        let mut map = std::collections::BTreeMap::new();
        map.insert("status", ciborium::Value::Text("continue".into()));
        ciborium::into_writer(&map, &mut buf).unwrap();
        assert!(decode_status_continue(&buf));
    }

    #[test]
    fn decode_status_continue_empty_is_false() {
        assert!(!decode_status_continue(&[]));
    }

    #[test]
    fn decode_status_continue_invalid_cbor_is_false() {
        assert!(!decode_status_continue(b"not cbor"));
    }

    /// Integration test: runs the compiled kotoba-guest through WasmPregelRunner.
    /// Skips if cargo-component or wasm32-wasip2 is unavailable.
    #[test]
    fn wasm_pregel_single_superstep() {
        let Some(wasm_bytes) = build_guest_component() else { return };

        let executor = Arc::new(WasmExecutor::new(10_000_000).expect("executor"));
        let runner = WasmPregelRunner::new(
            executor,
            "btest_wasm_pregel_cid",
            wasm_bytes,
            "did:plc:kotoba-pregel-test",
            10,
        );

        let ctx_cbor = make_ctx_cbor("pregel-graph", b"hello pregel");
        let result = runner.run(ctx_cbor).expect("WasmPregelRunner::run failed");

        // The existing echo-assert guest returns {"status":"ok"} → halts after 1 superstep
        assert_eq!(result.supersteps_run, 1,
            "expected 1 superstep, got {}", result.supersteps_run);

        // Guest asserts 1 quad
        assert_eq!(result.assert_quads.len(), 1,
            "expected 1 assert quad, got {}", result.assert_quads.len());
        assert_eq!(result.assert_quads[0].predicate, "kotoba/task");
        assert_eq!(result.assert_quads[0].graph, "pregel-graph");

        // Gas consumed
        assert!(result.total_gas_used > 0, "expected gas_used > 0");

        // Output CBOR contains "status": "ok"
        let out: ciborium::Value = ciborium::from_reader(result.final_output_cbor.as_slice())
            .expect("final_output_cbor should be valid CBOR");
        if let ciborium::Value::Map(pairs) = out {
            let status = pairs.iter().find_map(|(k, v)| {
                if k == &ciborium::Value::Text("status".into()) {
                    v.as_text().map(|s| s.to_string())
                } else { None }
            });
            assert_eq!(status.as_deref(), Some("ok"));
        } else {
            panic!("final_output_cbor is not a CBOR map");
        }
    }

    #[test]
    fn wasm_pregel_gas_exhaustion() {
        let Some(wasm_bytes) = build_guest_component() else { return };

        // Only 5 gas — assert-quad costs 10, guest must fail
        let executor = Arc::new(WasmExecutor::new(5).expect("executor"));
        let runner = WasmPregelRunner::new(
            executor,
            "bgas_test_pregel_cid",
            wasm_bytes,
            "did:plc:test",
            10,
        );

        let ctx_cbor = make_ctx_cbor("gas-test", b"x");
        // Gas exhaustion surfaces as a RuntimeError trapped in the closure;
        // the runner records the error in vertex state and votes halt — so run() succeeds
        // but the output CBOR contains an error status, not "ok".
        let result = runner.run(ctx_cbor).expect("run should not propagate RuntimeError");
        assert_eq!(result.supersteps_run, 1);
        // No quads asserted (gas killed before kqe.assert-quad returned)
        // final_output_cbor is the error bytes written by the closure
        assert!(!result.final_output_cbor.is_empty());
    }

    // ── Helpers (mirrors of runtime_test.rs helpers) ───────────────────────

    fn build_guest_component() -> Option<Vec<u8>> {
        use std::process::Command;
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
            eprintln!("cargo component not available — skipping WASM pregel test");
            return None;
        };
        if !s.success() {
            eprintln!("kotoba-guest build failed — skipping WASM pregel test");
            return None;
        }

        let wasm_path = workspace.join("target/wasm32-wasip2/release/kotoba_echo_assert.wasm");
        if wasm_path.exists() {
            return Some(std::fs::read(wasm_path).expect("read wasm"));
        }
        let alt = workspace.join("target/wasm32-wasip2/release/kotoba_guest.wasm");
        if alt.exists() {
            return Some(std::fs::read(alt).expect("read wasm"));
        }
        let entries = std::fs::read_dir(workspace.join("target/wasm32-wasip2/release")).ok()?;
        for e in entries.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "wasm").unwrap_or(false) {
                let name = p.file_name().unwrap().to_string_lossy();
                if name.contains("kotoba") || name.contains("echo") || name.contains("guest") {
                    return Some(std::fs::read(&p).expect("read wasm"));
                }
            }
        }
        None
    }

    fn make_ctx_cbor(graph: &str, args: &[u8]) -> Vec<u8> {
        use std::collections::BTreeMap;
        let mut map: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        map.insert("graph",       ciborium::Value::Text(graph.to_string()));
        map.insert("session_cid", ciborium::Value::Null);
        map.insert("args_cbor",   ciborium::Value::Bytes(args.to_vec()));
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).expect("cbor encode");
        buf
    }
}
