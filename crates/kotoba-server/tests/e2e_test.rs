//! E2E integration tests for kotoba-server.
//!
//! Each test spawns the axum router on a random OS-assigned port, fires HTTP
//! requests with `reqwest`, and asserts on the JSON response.  The server is
//! dropped at the end of each test via a tokio `JoinHandle` abort.
//!
//! A deterministic stub `InferenceFn` satisfies agent.run / infer.run so these
//! tests run without a real LLM or network dependency.

use std::sync::Arc;

use kotoba_server::{build_router, server::KotobaState};
use serde_json::{json, Value};

// ── Stub inference engine ─────────────────────────────────────────────────────

fn stub_engine() -> kotoba_runtime::host::InferenceFn {
    Arc::new(|prompt: &str, _max: usize| -> anyhow::Result<String> {
        if prompt.contains("Thought") || prompt.is_empty() {
            Ok("Thought: done.\nAction: Finish[stub answer]".into())
        } else {
            Ok(format!("stub: {prompt}"))
        }
    })
}

// ── Server fixture ────────────────────────────────────────────────────────────

struct TestServer {
    base_url: String,
    handle:   tokio::task::JoinHandle<()>,
    client:   reqwest::Client,
}

impl TestServer {
    async fn start(with_inference: bool) -> Self {
        let engine = if with_inference { Some(stub_engine()) } else { None };
        let state  = KotobaState::new(engine).expect("KotobaState::new");
        let app    = build_router(Arc::new(state));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        // brief settle — axum::serve is ready immediately after spawn
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        Self {
            base_url,
            handle,
            client: reqwest::Client::new(),
        }
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        let r = self.client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .expect("GET");
        let status = r.status().as_u16();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let r = self.client
            .post(format!("{}{}", self.base_url, path))
            .json(&body)
            .send()
            .await
            .expect("POST");
        let status = r.status().as_u16();
        let resp: Value = r.json().await.unwrap_or(Value::Null);
        (status, resp)
    }

    async fn post_auth(&self, path: &str, body: Value, token: &str) -> (u16, Value) {
        let r = self.client
            .post(format!("{}{}", self.base_url, path))
            .header("Authorization", format!("Bearer {token}"))
            .json(&body)
            .send()
            .await
            .expect("POST");
        let status = r.status().as_u16();
        let resp: Value = r.json().await.unwrap_or(Value::Null);
        (status, resp)
    }

    /// GET with `Authorization: Bearer <token>` for authenticated-tier graphs.
    async fn get_authed(&self, path: &str) -> (u16, Value) {
        let r = self.client
            .get(format!("{}{}", self.base_url, path))
            .header("Authorization", "Bearer test-e2e-token")
            .send()
            .await
            .expect("GET authed");
        let status = r.status().as_u16();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    /// POST quad.create with a freshly-signed Ed25519 CACAO for the given graph.
    async fn post_quad(&self, graph: &str, subject: &str, predicate: &str, object: &str) -> (u16, Value) {
        let (_, cacao_b64) = build_ed25519_cacao(graph);
        self.post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({
                "graph":     graph,
                "subject":   subject,
                "predicate": predicate,
                "object":    object,
                "cacao_b64": cacao_b64,
            }),
        ).await
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/health").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert!(body["version"].as_str().is_some());
}

#[tokio::test]
async fn app_meta_returns_ok() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/_app/meta").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn node_status_returns_node_id() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.apps.kotoba.node.status").await;
    assert_eq!(status, 200);
    assert!(body["node_id"].as_str().is_some(), "node_id missing: {body}");
}

#[tokio::test]
async fn quad_create_returns_journal_cid() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_quad("e2e", "alice", "knows", "bob").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["journal_cid"].as_str().is_some());
}

#[tokio::test]
async fn graph_query_empty_graph_returns_zero() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let cid = KotobaCid::from_bytes(b"nonexistent-graph-xyz").to_multibase();
    // Unknown graphs default to Authenticated tier — send a Bearer token.
    let (status, body) = s.get_authed(
        &format!("/xrpc/ai.gftd.apps.kotoba.graph.query?graph={cid}")
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["count"], 0);
}

#[tokio::test]
async fn graph_query_after_create_returns_quad() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;

    s.post_quad("qtest", "x", "rel", "y").await;

    let graph_cid = KotobaCid::from_bytes(b"qtest").to_multibase();
    // Unknown graphs default to Authenticated tier — send a Bearer token.
    let (status, body) = s.get_authed(
        &format!("/xrpc/ai.gftd.apps.kotoba.graph.query?graph={graph_cid}")
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["count"].as_u64().unwrap_or(0) >= 1, "expected ≥1 quad: {body}");
}

#[tokio::test]
async fn quad_retract_returns_ok() {
    let s = TestServer::start(false).await;
    let (_, cacao_b64) = build_ed25519_cacao("e2e");
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.retract",
        json!({
            "graph":     "e2e",
            "subject":   "alice",
            "predicate": "knows",
            "object":    "bob",
            "cacao_b64": cacao_b64,
        }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn quad_retract_without_cacao_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.retract",
        json!({ "graph": "e2e", "subject": "alice", "predicate": "knows", "object": "bob" }),
    ).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn quad_retract_cacao_graph_mismatch_returns_401() {
    let s = TestServer::start(false).await;
    // CACAO signed for "other-graph" but request targets "e2e"
    let (_, cacao_b64) = build_ed25519_cacao("other-graph");
    let (status, _body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.retract",
        json!({
            "graph":     "e2e",
            "subject":   "alice",
            "predicate": "knows",
            "object":    "bob",
            "cacao_b64": cacao_b64,
        }),
    ).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn block_put_and_get_roundtrip() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;

    let payload = b"kotoba e2e block";
    let (status, put) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.block.put",
        json!({ "data_b64": B64.encode(payload) }),
    ).await;
    assert_eq!(status, 200, "{put}");
    let cid = put["cid"].as_str().expect("cid");

    let (status2, get) = s.get(
        &format!("/xrpc/ai.gftd.apps.kotoba.block.get?cid={cid}")
    ).await;
    assert_eq!(status2, 200, "{get}");
    let bytes = B64.decode(get["data_b64"].as_str().expect("data_b64")).unwrap();
    assert_eq!(bytes, payload);
}

#[tokio::test]
async fn commit_store_and_get_roundtrip() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let graph_cid = KotobaCid::from_bytes(b"commit-e2e").to_multibase();

    s.post_quad("commit-e2e", "s", "p", "o").await;

    // CACAO must be built against the same graph string sent in the request (multibase CID)
    let (_, cacao_b64) = build_ed25519_cacao(&graph_cid);
    let (status, store) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.commit.store",
        json!({ "graph": graph_cid, "author": "did:plc:e2e", "seq": 1, "cacao_b64": cacao_b64 }),
    ).await;
    assert_eq!(status, 200, "{store}");
    assert!(store["cid"].as_str().is_some());

    let (status2, get) = s.get(
        &format!("/xrpc/ai.gftd.apps.kotoba.commit.get?graph={graph_cid}")
    ).await;
    assert_eq!(status2, 200, "{get}");
    assert_eq!(get["seq"], 1);
    assert_eq!(get["author"], "did:plc:e2e");
}

#[tokio::test]
async fn commit_store_without_cacao_returns_401() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let graph_cid = KotobaCid::from_bytes(b"commit-e2e-noauth").to_multibase();

    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.commit.store",
        json!({ "graph": graph_cid, "author": "did:plc:e2e", "seq": 1 }),
    ).await;
    assert_eq!(status, 401, "missing cacao must return 401: {body}");
}

#[tokio::test]
async fn embed_create_returns_quad_cid() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let graph_cid = KotobaCid::from_bytes(b"embed-e2e").to_multibase();
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.embed.create",
        json!({
            "text": "hello kotoba",
            "doc_cid": "doc1",
            "model_cid": "model1",
            "graph": graph_cid
        }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["dims"].as_u64().unwrap_or(0) > 0);
}

#[tokio::test]
async fn infer_run_with_stub_engine() {
    let s = TestServer::start(true).await;
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.infer.run",
        json!({ "prompt": "what is kotoba?", "max_new_tokens": 32 }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["output"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
}

#[tokio::test]
async fn infer_run_without_engine_returns_503() {
    let s = TestServer::start(false).await;
    let (status, _) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.infer.run",
        json!({ "prompt": "hello" }),
    ).await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn agent_run_with_stub_engine_completes() {
    let s = TestServer::start(true).await;
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.run",
        json!({ "task": "test: 2+2?", "max_steps": 3, "max_tokens": 64 }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["session_cid"].as_str().is_some());
    assert!(body["supersteps"].as_u64().unwrap_or(0) >= 1);
}

#[tokio::test]
async fn agent_run_without_engine_returns_503() {
    let s = TestServer::start(false).await;
    let (status, _) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.run",
        json!({ "task": "x" }),
    ).await;
    assert_eq!(status, 503);
}

// ── MCP ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_initialize_returns_protocol_version() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": null }),
    ).await;
    assert_eq!(status, 200);
    assert_eq!(body["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(body["result"]["serverInfo"]["name"], "kotoba");
}

#[tokio::test]
async fn mcp_tools_list_returns_expected_count() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": null }),
    ).await;
    assert_eq!(status, 200);
    let tools = body["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 15);
}

#[tokio::test]
async fn mcp_ping_returns_empty_result() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": 5, "method": "ping" }),
    ).await;
    assert_eq!(status, 200);
    assert!(body["result"].is_object());
    assert!(body.get("error").is_none());
}

#[tokio::test]
async fn mcp_node_info_returns_did_and_roles() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": { "name": "kotoba_node_info", "arguments": {} }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert!(content["did"].as_str().unwrap_or("").starts_with("did:"),
        "expected DID, got: {}", content["did"]);
    assert!(!content["node_id_hex"].as_str().unwrap_or("").is_empty());
    assert!(content["roles"].is_array());
    assert!(content.get("ephemeral").is_some());
}

#[tokio::test]
async fn mcp_node_register_returns_ok() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": { "name": "kotoba_node_register", "arguments": {} }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["status"], "ok");
    assert!(content["operator_did"].as_str().unwrap_or("").starts_with("did:"));
}

#[tokio::test]
async fn mcp_network_peers_returns_local_node_id() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 12, "method": "tools/call",
            "params": { "name": "kotoba_network_peers", "arguments": {} }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert!(!content["local_node_id_hex"].as_str().unwrap_or("").is_empty());
    assert!(content["peers"].is_array());
    assert_eq!(content["peer_count"].as_u64().unwrap_or(99), 0,
        "fresh node has no peers");
}

#[tokio::test]
async fn mcp_tools_call_quad_create_ok() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "kotoba_quad_create",
                "arguments": { "graph": "mcp-g", "subject": "s", "predicate": "p", "object": "o" }
            }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    assert!(body["result"].is_object());
}

#[tokio::test]
async fn mcp_tools_call_without_auth_returns_error() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {
                "name": "kotoba_quad_create",
                "arguments": { "graph": "g", "subject": "s", "predicate": "p", "object": "o" }
            }
        }),
    ).await;
    assert_eq!(status, 200);
    assert!(body["error"].is_object(), "expected JSON-RPC error");
    assert_eq!(body["error"]["code"], -32001);
}

// ── MCP kotoba_wasm_run (skips if cargo-component unavailable) ───────────────

#[tokio::test]
async fn mcp_wasm_run_writes_gas_attribution() {
    let Some(wasm_bytes) = build_guest_component() else {
        eprintln!("cargo-component unavailable — skipping mcp_wasm_run_writes_gas_attribution");
        return;
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

    let mut ctx_cbor = Vec::new();
    {
        use std::collections::BTreeMap;
        let mut map: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        map.insert("graph",       ciborium::Value::Text("mcp-wasm-graph".into()));
        map.insert("session_cid", ciborium::Value::Null);
        map.insert("args_cbor",   ciborium::Value::Bytes(b"mcp_wasm_test".to_vec()));
        ciborium::into_writer(&map, &mut ctx_cbor).unwrap();
    }

    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 20, "method": "tools/call",
            "params": {
                "name": "kotoba_wasm_run",
                "arguments": {
                    "wasm_b64":     B64.encode(&wasm_bytes),
                    "agent_did":    "did:plc:e2e_mcp_wasm",
                    "ctx_cbor_b64": B64.encode(&ctx_cbor),
                }
            }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");

    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["status"], "ok", "{content}");
    assert!(content["total_gas_used"].as_u64().unwrap_or(0) > 0,
        "expected gas_used > 0, got: {content}");
    assert!(content["output_cbor_b64"].as_str().is_some(),
        "missing output_cbor_b64: {content}");
}

// ── MCP kotoba_datalog_run ────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_datalog_run_derives_and_flushes_royalty() {
    let s = TestServer::start(false).await;

    // Seed the graph with two edges: a→b and b→c
    let graph = "mcp-datalog-test-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);
    for (subj, pred, obj) in [("a", "edge", "b"), ("b", "edge", "c")] {
        let (st, _) = s.post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({
                "graph":     graph,
                "subject":   subj,
                "predicate": pred,
                "object":    obj,
                "cacao_b64": cacao_b64,
            }),
        ).await;
        assert_eq!(st, 200);
    }

    // reachable(?x, ?y) :- edge(?x, ?y)
    let rule = json!({
        "head": { "relation": "reachable", "args": [{"Variable": "x"}, {"Variable": "y"}] },
        "body": [{ "Positive": { "relation": "edge", "args": [{"Variable": "x"}, {"Variable": "y"}] } }]
    });

    let (status, body) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 21, "method": "tools/call",
            "params": {
                "name": "kotoba_datalog_run",
                "arguments": {
                    "graph": graph,
                    "rules": [rule],
                    "epoch_pool_koto": 1_000_000u64,
                }
            }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");

    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["status"], "ok", "{content}");
    assert!(content["derived"].as_u64().unwrap_or(0) >= 2,
        "expected derived >= 2, got: {content}");
    assert!(content["citations"].as_u64().unwrap_or(0) > 0,
        "expected citations > 0, got: {content}");
    assert!(content.get("epoch").is_some(), "missing epoch field: {content}");
}

// ── WASM invoke.run (skips if cargo-component unavailable) ────────────────────

#[tokio::test]
async fn invoke_run_wasm_guest_via_xrpc() {
    let Some(wasm_bytes) = build_guest_component() else {
        eprintln!("cargo-component unavailable — skipping invoke_run_wasm_guest_via_xrpc");
        return;
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

    let mut ctx = Vec::new();
    {
        use std::collections::BTreeMap;
        let mut map: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        map.insert("graph",       ciborium::Value::Text("e2e-wasm-graph".into()));
        map.insert("session_cid", ciborium::Value::Null);
        map.insert("args_cbor",   ciborium::Value::Bytes(b"e2e test".to_vec()));
        ciborium::into_writer(&map, &mut ctx).unwrap();
    }

    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.invoke.run",
        json!({
            "program_cid":  "be2e_wasm_invoke",
            "program_type": "wasm-node",
            "agent_did":    "did:plc:e2e",
            "wasm_b64":     B64.encode(&wasm_bytes),
            "ctx_b64":      B64.encode(&ctx),
        }),
    ).await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["gas_used"].as_u64().unwrap_or(0) > 0);
    assert!(body["assert_count"].as_u64().unwrap_or(0) >= 1, "{body}");

    let out_bytes = B64.decode(body["output_b64"].as_str().expect("output_b64")).unwrap();
    let out: ciborium::Value = ciborium::from_reader(out_bytes.as_slice()).unwrap();
    if let ciborium::Value::Map(pairs) = out {
        let status_val = pairs.iter().find_map(|(k, v)| {
            if k == &ciborium::Value::Text("status".into()) { v.as_text().map(|s| s.to_string()) } else { None }
        });
        assert_eq!(status_val.as_deref(), Some("ok"));
    } else {
        panic!("output CBOR not a map");
    }
}

// ── SyncWindow session lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn agent_sync_open_creates_session() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph").to_multibase();

    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({
            "session_id": "sess-1",
            "graph_cid":  graph_cid,
            "since_seq":  0,
            "head_cid":   null,
        }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["session_id"], "sess-1");
    assert_eq!(body["since_seq"], 0);
}

#[tokio::test]
async fn agent_sync_advance_updates_watermark() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph-adv").to_multibase();
    let head_cid  = KotobaCid::from_bytes(b"head-v1").to_multibase();

    s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({ "session_id": "sess-adv", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
    ).await;

    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
        json!({ "session_id": "sess-adv", "new_head_cid": head_cid, "new_seq": 42 }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["since_seq"], 42);
}

#[tokio::test]
async fn agent_sync_advance_unknown_session_returns_404() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let head_cid = KotobaCid::from_bytes(b"h").to_multibase();

    let (status, _) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
        json!({ "session_id": "no-such", "new_head_cid": head_cid, "new_seq": 1 }),
    ).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn agent_sync_close_removes_session() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph-close").to_multibase();

    s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({ "session_id": "sess-close", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
    ).await;

    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncclose",
        json!({ "session_id": "sess-close" }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["session_id"], "sess-close");

    // Second close → 404 (session removed)
    let (status2, _) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncclose",
        json!({ "session_id": "sess-close" }),
    ).await;
    assert_eq!(status2, 404);
}

#[tokio::test]
async fn agent_sync_full_lifecycle() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"lifecycle-graph").to_multibase();
    let head1     = KotobaCid::from_bytes(b"lifecycle-head-1").to_multibase();
    let head2     = KotobaCid::from_bytes(b"lifecycle-head-2").to_multibase();

    // open
    let (st, _) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({ "session_id": "lc", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
    ).await;
    assert_eq!(st, 200);

    // advance × 2
    let (st, b) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
        json!({ "session_id": "lc", "new_head_cid": head1, "new_seq": 10 }),
    ).await;
    assert_eq!(st, 200);
    assert_eq!(b["since_seq"], 10);

    let (st, b) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
        json!({ "session_id": "lc", "new_head_cid": head2, "new_seq": 20 }),
    ).await;
    assert_eq!(st, 200);
    assert_eq!(b["since_seq"], 20);

    // close
    let (st, _) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncclose",
        json!({ "session_id": "lc" }),
    ).await;
    assert_eq!(st, 200);
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn build_guest_component() -> Option<Vec<u8>> {
    use std::process::Command;
    let manifest   = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace  = manifest.parent().unwrap().parent().unwrap();
    let status = Command::new("cargo")
        .args(["component", "build",
               "--manifest-path", "crates/kotoba-guest/Cargo.toml",
               "--target", "wasm32-wasip2", "--release", "--quiet"])
        .current_dir(workspace)
        .status();
    let Ok(s) = status else { return None; };
    if !s.success() { return None; }
    let p = workspace.join("target/wasm32-wasip2/release/kotoba_echo_assert.wasm");
    if p.exists() { return std::fs::read(p).ok(); }
    let alt = workspace.join("target/wasm32-wasip2/release/kotoba_guest.wasm");
    if alt.exists() { return std::fs::read(alt).ok(); }
    let dir = std::fs::read_dir(workspace.join("target/wasm32-wasip2/release")).ok()?;
    for e in dir.flatten() {
        let p = e.path();
        if p.extension().map(|x| x == "wasm").unwrap_or(false) {
            let n = p.file_name().unwrap().to_string_lossy();
            if n.contains("kotoba") || n.contains("echo") || n.contains("guest") {
                return std::fs::read(&p).ok();
            }
        }
    }
    None
}

// ── vault.put / vault.get tests ───────────────────────────────────────────────

#[tokio::test]
async fn vault_put_returns_cid_and_size() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let data = b"hello vault";
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.vault.put",
        json!({ "data_b64": B64.encode(data) }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["cid"].as_str().is_some(), "cid missing: {body}");
    assert_eq!(body["size"], data.len() as u64, "size mismatch: {body}");
}

#[tokio::test]
async fn vault_put_then_get_roundtrip() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let data = b"roundtrip blob content";
    let data_b64 = B64.encode(data);

    let (status, put_body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.vault.put",
        json!({ "data_b64": data_b64 }),
    ).await;
    assert_eq!(status, 200, "{put_body}");
    let cid = put_body["cid"].as_str().expect("cid");

    let (status, get_body) = s.get(
        &format!("/xrpc/ai.gftd.apps.kotoba.vault.get?cid={cid}"),
    ).await;
    assert_eq!(status, 200, "{get_body}");
    assert_eq!(get_body["cid"].as_str(), Some(cid), "cid mismatch");
    assert_eq!(get_body["data_b64"].as_str(), Some(data_b64.as_str()), "data mismatch");
}

#[tokio::test]
async fn vault_get_unknown_cid_returns_404() {
    let s = TestServer::start(false).await;
    // KotobaCid multibase = 'b' + base32-nopad of 36 bytes (lowercase).
    // 36 zero-bytes → 58 'a' chars. blake3 of any real content won't produce all-zeros,
    // so this CID is valid format but never stored.
    let zero_cid = format!("b{}", "a".repeat(58));
    let (status, _body) = s.get(
        &format!("/xrpc/ai.gftd.apps.kotoba.vault.get?cid={zero_cid}"),
    ).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn vault_get_missing_cid_param_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s.get("/xrpc/ai.gftd.apps.kotoba.vault.get").await;
    assert_eq!(status, 400);
}

// ── kg.entity / kg.ingest tests ──────────────────────────────────────────────

#[tokio::test]
async fn kg_entity_lookup_by_id_after_quad_create() {
    let s = TestServer::start(false).await;

    // Seed quads directly via quad.create into yatabase-kg-v1 graph
    let g = "yatabase-kg-v1";
    let subj = "e2e-person-001";

    for (pred, obj) in &[
        ("kg/id",       subj),
        ("kg/type",     "Person"),
        ("kg/label/ja", "テスト太郎"),
        ("kg/label/en", "Test Taro"),
        ("kg/qid",      "Q99901"),
    ] {
        let (st, b) = s.post_quad(g, subj, pred, obj).await;
        assert_eq!(st, 200, "seed failed for {pred}: {b}");
    }

    // Seed one claim
    let (st, _) = s.post_quad(g, subj, "kg/claim/birthYear", "1990").await;
    assert_eq!(st, 200);

    // Query by id — kg graph defaults to Authenticated tier.
    let (status, body) = s.get_authed(
        &format!("/xrpc/ai.gftd.apps.yata.kg.entity?id={subj}")
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "ok false: {body}");

    let entity = &body["entity"];
    assert_eq!(entity["id"],      subj,       "id mismatch: {body}");
    assert_eq!(entity["type"],    "Person",   "type mismatch: {body}");
    assert_eq!(entity["labelJa"], "テスト太郎", "labelJa mismatch: {body}");
    assert_eq!(entity["labelEn"], "Test Taro","labelEn mismatch: {body}");
    assert_eq!(entity["qid"],     "Q99901",   "qid mismatch: {body}");

    let claims = entity["claims"].as_array().expect("claims array");
    assert!(
        claims.iter().any(|c| c["predicate"] == "birthYear" && c["value"] == "1990"),
        "birthYear claim missing: {body}"
    );
}

#[tokio::test]
async fn kg_entity_lookup_by_qid() {
    let s = TestServer::start(false).await;
    let g    = "yatabase-kg-v1";
    let subj = "e2e-person-qid";

    for (pred, obj) in &[
        ("kg/id",  subj),
        ("kg/qid", "Q42"),
        ("kg/type","Human"),
    ] {
        s.post_quad(g, subj, pred, obj).await;
    }

    let (status, body) = s.get_authed("/xrpc/ai.gftd.apps.yata.kg.entity?qid=Q42").await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false));
    assert_eq!(body["entity"]["qid"], "Q42");
    assert_eq!(body["entity"]["type"], "Human");
}

#[tokio::test]
async fn kg_entity_not_found_returns_ok_false() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get_authed("/xrpc/ai.gftd.apps.yata.kg.entity?id=no-such-entity").await;
    assert_eq!(status, 200, "{body}");
    assert!(!body["ok"].as_bool().unwrap_or(true), "expected ok:false: {body}");
    assert!(body["error"].as_str().is_some(), "error missing: {body}");
}

#[tokio::test]
async fn kg_entity_missing_param_returns_400() {
    let s = TestServer::start(false).await;
    // Must pass auth first (authenticated tier), then the missing-param check fires.
    let (status, _) = s.get_authed("/xrpc/ai.gftd.apps.yata.kg.entity").await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kg_ingest_and_entity_roundtrip() {
    let s = TestServer::start(false).await;

    let (status, put) = s.post(
        "/xrpc/ai.gftd.apps.yata.kg.ingest",
        json!({
            "id":        "ingest-e2e-001",
            "qid":       "Q100",
            "type":      "Organization",
            "labelJa":   "テスト会社",
            "labelEn":   "Test Corp",
            "confidence":"0.95",
            "license":   "CC0-1.0",
            "sourceId":  "src-abc",
            "claims": [
                { "pred": "founded", "value": "2020" },
                { "pred": "country", "value": "JP" }
            ],
            "relations": []
        }),
    ).await;
    assert_eq!(status, 200, "{put}");
    assert!(put["ok"].as_bool().unwrap_or(false), "ingest failed: {put}");
    assert!(put["subjectCid"].as_str().is_some(), "subjectCid missing: {put}");
    // kg/id + optional fields + 2 claims
    assert!(put["quadCount"].as_u64().unwrap_or(0) >= 3, "quadCount low: {put}");

    // Lookup via kg.entity — kg graph defaults to Authenticated tier.
    let (status, body) = s.get_authed("/xrpc/ai.gftd.apps.yata.kg.entity?id=ingest-e2e-001").await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "entity not found: {body}");

    let entity = &body["entity"];
    assert_eq!(entity["id"],       "ingest-e2e-001", "{body}");
    assert_eq!(entity["qid"],      "Q100",           "{body}");
    assert_eq!(entity["type"],     "Organization",   "{body}");
    assert_eq!(entity["labelJa"],  "テスト会社",      "{body}");
    assert_eq!(entity["labelEn"],  "Test Corp",      "{body}");
    assert_eq!(entity["confidence"],"0.95",          "{body}");
    assert_eq!(entity["license"],  "CC0-1.0",        "{body}");
    assert_eq!(entity["sourceId"], "src-abc",        "{body}");

    let claims = entity["claims"].as_array().expect("claims");
    assert!(claims.iter().any(|c| c["predicate"] == "founded" && c["value"] == "2020"), "{body}");
    assert!(claims.iter().any(|c| c["predicate"] == "country"  && c["value"] == "JP"),  "{body}");
}

#[tokio::test]
async fn kg_ingest_with_relations() {
    let s = TestServer::start(false).await;

    // Ingest target entity first (needed for relation dst)
    s.post(
        "/xrpc/ai.gftd.apps.yata.kg.ingest",
        json!({ "id": "rel-dst-001", "type": "City", "labelEn": "Tokyo" }),
    ).await;

    // Ingest source entity with relation to target
    let (status, put) = s.post(
        "/xrpc/ai.gftd.apps.yata.kg.ingest",
        json!({
            "id":      "rel-src-001",
            "type":    "Person",
            "labelEn": "Alice",
            "relations": [
                { "pred": "locatedIn", "dstId": "rel-dst-001" }
            ]
        }),
    ).await;
    assert_eq!(status, 200, "{put}");
    assert!(put["ok"].as_bool().unwrap_or(false));

    // Query source entity — kg graph defaults to Authenticated tier.
    let (st, body) = s.get_authed("/xrpc/ai.gftd.apps.yata.kg.entity?id=rel-src-001").await;
    assert_eq!(st, 200, "{body}");

    let rels = body["entity"]["relations"].as_array().expect("relations");
    assert!(!rels.is_empty(), "expected relations: {body}");
    assert_eq!(rels[0]["predicate"], "locatedIn", "{body}");
    assert!(rels[0]["dstCid"].as_str().is_some(), "dstCid missing: {body}");
}

#[tokio::test]
async fn kg_catalog_reflects_ingested_entities() {
    let s = TestServer::start(false).await;

    // Ingest two entities
    for (id, label) in &[("cat-e1", "EntityOne"), ("cat-e2", "EntityTwo")] {
        let (st, _) = s.post(
            "/xrpc/ai.gftd.apps.yata.kg.ingest",
            json!({ "id": id, "type": "Thing", "labelEn": label, "sourceId": "cat-test-src" }),
        ).await;
        assert_eq!(st, 200);
    }

    // kg graph defaults to Authenticated tier — send a Bearer token.
    let (status, body) = s.get_authed("/xrpc/ai.gftd.apps.yata.kg.catalog").await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false));
    assert!(body["stats"]["totalEntities"].as_u64().unwrap_or(0) >= 2, "{body}");
}

// ── quad.create CACAO auth tests ─────────────────────────────────────────────

/// Build a signed Ed25519 CACAO granting `quad:write` on `graph`. Returns `(issuer_did, cacao_b64)`.
fn build_ed25519_cacao(graph: &str) -> (String, String) {
    use base64::{Engine as _, engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD}};
    use ed25519_dalek::{SigningKey, Signer};
    use kotoba_auth::did_key::ed25519_pubkey_to_did_key;

    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let did = ed25519_pubkey_to_did_key(pk.as_bytes());

    let mut cacao = kotoba_auth::Cacao {
        h: kotoba_auth::CacaoHeader { t: "caip122".into() },
        p: kotoba_auth::CacaoPayload {
            iss:       did.clone(),
            aud:       "kotoba://node/test".into(),
            issued_at: "2026-05-26T00:00:00Z".into(),
            expiry:    Some("2030-01-01T00:00:00Z".into()),
            nonce:     "nonce-42".into(),
            domain:    "kotoba.test".into(),
            statement: Some("Authorize quad write".into()),
            version:   "1".into(),
            resources: vec![
                format!("kotoba://graph/{graph}"),
                "kotoba://can/quad:write".into(),
            ],
        },
        s: kotoba_auth::CacaoSig { t: "EdDSA".into(), s: String::new() },
    };

    let msg = cacao.siwe_message();
    let sig: ed25519_dalek::Signature = sk.sign(msg.as_bytes());
    cacao.s.s = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let mut cbor_buf = Vec::new();
    ciborium::into_writer(&cacao, &mut cbor_buf).expect("cbor encode");
    (did, B64.encode(&cbor_buf))
}

#[tokio::test]
async fn quad_create_without_cacao_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({ "graph": "public", "subject": "alice", "predicate": "knows", "object": "bob" }),
    ).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn quad_create_with_valid_ed25519_cacao_stores_author_did() {
    let s = TestServer::start(false).await;
    let graph = "cacao-test-graph";
    let (issuer_did, cacao_b64) = build_ed25519_cacao(graph);

    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({
            "graph":     graph,
            "subject":   "alice",
            "predicate": "knows",
            "object":    "bob",
            "cacao_b64": cacao_b64,
        }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    let journal_cid = body["journal_cid"].as_str().expect("journal_cid").to_string();

    // Verify meta/author quad was stored with the journal CID as subject
    let graph_cid = kotoba_core::cid::KotobaCid::from_bytes(graph.as_bytes()).to_multibase();
    let url = format!(
        "/xrpc/ai.gftd.apps.kotoba.graph.query?graph={graph_cid}&subject={journal_cid}&predicate=meta%2Fauthor"
    );
    let (qstatus, qbody) = s.get_authed(&url).await;
    assert_eq!(qstatus, 200, "{qbody}");

    let quads = qbody["quads"].as_array().expect("quads array");
    assert!(!quads.is_empty(), "meta/author quad must exist: {qbody}");
    let author_quad = quads.iter()
        .find(|q| q["predicate"] == "meta/author")
        .expect("meta/author quad not found");
    // QuadObject::Text serializes as {"Text": "<value>"}
    assert_eq!(author_quad["object"]["Text"], issuer_did, "author DID must match CACAO issuer");
}

#[tokio::test]
async fn quad_create_cacao_graph_mismatch_returns_401() {
    let s = TestServer::start(false).await;
    let (_, cacao_b64) = build_ed25519_cacao("other-graph");
    // CACAO covers "other-graph" but request targets "my-graph"
    let (status, _body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({
            "graph":     "my-graph",
            "subject":   "s",
            "predicate": "p",
            "object":    "o",
            "cacao_b64": cacao_b64,
        }),
    ).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn quad_create_invalid_cacao_b64_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({
            "graph": "private-graph",
            "subject": "alice",
            "predicate": "knows",
            "object": "bob",
            "cacao_b64": "not-valid-base64!!!"
        }),
    ).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn quad_create_cacao_cbor_parse_error_returns_400() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    // Valid base64 but not valid DAG-CBOR
    let (status, _body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({
            "graph": "private-graph",
            "subject": "alice",
            "predicate": "knows",
            "object": "bob",
            "cacao_b64": B64.encode(b"this is not cbor")
        }),
    ).await;
    assert_eq!(status, 400);
}

// ── quad.create / quad.retract field-length caps (security bounds) ────────────

#[tokio::test]
async fn quad_create_oversized_graph_returns_400() {
    let s = TestServer::start(false).await;
    // Build CACAO for the oversized graph so auth succeeds; size cap fires after.
    let oversized_graph = "g".repeat(513);
    let (_, cacao_b64) = build_ed25519_cacao(&oversized_graph);
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({
            "graph":     oversized_graph,
            "subject":   "s",
            "predicate": "p",
            "object":    "o",
            "cacao_b64": cacao_b64,
        }),
    ).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn quad_create_oversized_object_returns_400() {
    let s = TestServer::start(false).await;
    let (_, cacao_b64) = build_ed25519_cacao("e2e");
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({
            "graph":     "e2e",
            "subject":   "s",
            "predicate": "p",
            "object":    "x".repeat(8 * 1024 + 1), // > 8 KiB limit
            "cacao_b64": cacao_b64,
        }),
    ).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn mcp_quad_create_oversized_field_returns_error() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth("/mcp", json!({
        "jsonrpc": "2.0", "id": 20, "method": "tools/call",
        "params": {
            "name": "kotoba_quad_create",
            "arguments": {
                "graph":     "g",
                "subject":   "s",
                "predicate": "p",
                "object":    "x".repeat(4097), // > 4096 byte MCP limit
            }
        }
    }), "test-token").await;
    assert_eq!(status, 200, "{body}");
    // MCP tools return errors as JSON-RPC error objects, not HTTP 4xx
    assert!(body.get("error").is_some(), "expected error for oversized field: {body}");
}

// ── kotobase input validation tests ──────────────────────────────────────────

const KOTOBASE_ACCOUNT_CREATE:  &str = "/xrpc/ai.gftd.apps.kotobase.accountCreate";
const KOTOBASE_ACCOUNT_STATUS:  &str = "/xrpc/ai.gftd.apps.kotobase.accountStatus";
const KOTOBASE_PIN_CREATE:      &str = "/xrpc/ai.gftd.apps.kotobase.pinCreate";
const KOTOBASE_PIN_DELETE:      &str = "/xrpc/ai.gftd.apps.kotobase.pinDelete";
const KOTOBASE_PIN_LIST:        &str = "/xrpc/ai.gftd.apps.kotobase.pinList";
const KOTOBASE_USAGE_GET:       &str = "/xrpc/ai.gftd.apps.kotobase.usageGet";

/// Build a minimal JWT with `sub = did` and a far-future `exp`.
/// Signature is intentionally fake — the server does not verify JWT signatures.
fn tenant_jwt(did: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let header  = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        format!(r#"{{"sub":"{did}","exp":9999999999}}"#).as_bytes()
    );
    format!("{header}.{payload}.fakesig")
}

#[tokio::test]
async fn kotobase_account_create_roundtrip() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zAlice";
    let (status, body) = s.post_auth(KOTOBASE_ACCOUNT_CREATE, json!({
        "tenant_did": did,
        "tier": "free",
    }), &tenant_jwt(did)).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert_eq!(body["tier"], "free");
    assert_eq!(body["tenant_did"], did);
}

#[tokio::test]
async fn kotobase_account_create_invalid_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s.post(KOTOBASE_ACCOUNT_CREATE, json!({
        "tenant_did": "not-a-did",
    })).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kotobase_account_create_empty_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s.post(KOTOBASE_ACCOUNT_CREATE, json!({
        "tenant_did": "",
    })).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kotobase_account_create_unknown_tier_returns_400() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zAlice2";
    let (status, _body) = s.post_auth(KOTOBASE_ACCOUNT_CREATE, json!({
        "tenant_did": did,
        "tier": "enterprise_ultra",
    }), &tenant_jwt(did)).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kotobase_pin_create_negative_size_returns_400() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zAlice3";
    let (status, body) = s.post_auth(KOTOBASE_PIN_CREATE, json!({
        "tenant_did": did,
        "name": "my-pin",
        "cid": "bafytest",
        "size_hint_bytes": -1_i64,
    }), &tenant_jwt(did)).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kotobase_pin_create_name_too_long_returns_400() {
    let s         = TestServer::start(false).await;
    let did       = "did:key:zAlice4";
    let long_name = "x".repeat(300);
    let (status, body) = s.post_auth(KOTOBASE_PIN_CREATE, json!({
        "tenant_did": did,
        "name": long_name,
        "cid": "bafytest",
    }), &tenant_jwt(did)).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kotobase_pin_create_too_many_triples_returns_400() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zAlice5";
    // 1025 triples exceeds MAX_TRIPLES_PER_PIN = 1024
    let triples: Vec<serde_json::Value> = (0..1025u32).map(|i| json!({
        "subject":   format!("s{i}"),
        "predicate": "p",
        "object":    "o",
    })).collect();
    let (status, body) = s.post_auth(KOTOBASE_PIN_CREATE, json!({
        "tenant_did": did,
        "name": "big-triples",
        "quads": { "graph": "test-graph", "triples": triples },
    }), &tenant_jwt(did)).await;
    assert_eq!(status, 400, "{body}");
    let err = body["error"].as_str().unwrap_or("");
    assert!(err.contains("1024"), "error should mention limit: {body}");
}

#[tokio::test]
async fn kotobase_pin_list_invalid_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s.post(KOTOBASE_PIN_LIST, json!({
        "tenant_did": "invalid",
    })).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kotobase_usage_get_empty_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s.post(KOTOBASE_USAGE_GET, json!({
        "tenant_did": "",
    })).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kotobase_account_and_pin_lifecycle() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zLifecycle1";
    let tok = tenant_jwt(did);

    // Create account
    let (status, body) = s.post_auth(KOTOBASE_ACCOUNT_CREATE, json!({
        "tenant_did": did,
    }), &tok).await;
    assert_eq!(status, 200, "{body}");

    // Pin a CID
    let (status, body) = s.post_auth(KOTOBASE_PIN_CREATE, json!({
        "tenant_did": did,
        "name": "test-pin",
        "cid": "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354",
        "size_hint_bytes": 1024_i64,
    }), &tok).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert!(!body["pin_id"].as_str().unwrap_or("").is_empty(), "{body}");

    // Check usage
    let (status, body) = s.post_auth(KOTOBASE_USAGE_GET, json!({
        "tenant_did": did,
    }), &tok).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["pin_count"], 1, "{body}");
}

#[tokio::test]
async fn kotobase_account_status_returns_tier_and_quota() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zStatus1";
    let tok = tenant_jwt(did);

    // account must exist first
    let (status, _) = s.post_auth(KOTOBASE_ACCOUNT_CREATE, json!({ "tenant_did": did }), &tok).await;
    assert_eq!(status, 200);

    let (status, body) = s.post_auth(KOTOBASE_ACCOUNT_STATUS, json!({ "tenant_did": did }), &tok).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert_eq!(body["tenant_did"], did, "{body}");
    assert!(body["tier"].is_string(), "tier missing: {body}");
    assert!(body["quota_pins"].is_number(), "quota_pins missing: {body}");
    assert!(body["quota_bytes"].is_number(), "quota_bytes missing: {body}");
    assert!(body["used_pins"].is_number(), "used_pins missing: {body}");
    assert!(body["used_bytes"].is_number(), "used_bytes missing: {body}");
}

#[tokio::test]
async fn kotobase_pin_delete_removes_pin() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zDelete1";
    let tok = tenant_jwt(did);

    // create account
    let (status, _) = s.post_auth(KOTOBASE_ACCOUNT_CREATE, json!({ "tenant_did": did }), &tok).await;
    assert_eq!(status, 200);

    // pin a CID
    let (status, body) = s.post_auth(KOTOBASE_PIN_CREATE, json!({
        "tenant_did": did,
        "name": "del-test",
        "cid": "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354",
        "size_hint_bytes": 512_i64,
    }), &tok).await;
    assert_eq!(status, 200, "{body}");
    let pin_id = body["pin_id"].as_str().expect("pin_id").to_string();

    // delete the pin
    let (status, body) = s.post_auth(KOTOBASE_PIN_DELETE, json!({
        "tenant_did": did,
        "pin_id": pin_id,
    }), &tok).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");

    // list should now be empty
    let (status, body) = s.post_auth(KOTOBASE_PIN_LIST, json!({ "tenant_did": did }), &tok).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 0, "expected 0 pins after delete: {body}");
}

#[tokio::test]
async fn mcp_graph_query_empty_graph_returns_zero_count() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth("/mcp", json!({
        "jsonrpc": "2.0", "id": 10, "method": "tools/call",
        "params": {
            "name": "kotoba_graph_query",
            "arguments": { "graph": "did:example:emptygraph" }
        }
    }), "test-token").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["count"], 0, "{content}");
    assert!(content["quads"].is_array(), "quads must be array: {content}");
}

#[tokio::test]
async fn mcp_email_list_no_emails_returns_empty() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth("/mcp", json!({
        "jsonrpc": "2.0", "id": 11, "method": "tools/call",
        "params": {
            "name": "kotoba_email_list",
            "arguments": { "owner_did": "did:key:zNoEmails1" }
        }
    }), "test-token").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["total"], 0, "{content}");
    assert!(content["emails"].as_array().map(|a| a.is_empty()).unwrap_or(false), "{content}");
}

#[tokio::test]
async fn mcp_infer_run_without_engine_returns_error() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth("/mcp", json!({
        "jsonrpc": "2.0", "id": 12, "method": "tools/call",
        "params": {
            "name": "kotoba_infer_run",
            "arguments": { "prompt": "hello" }
        }
    }), "test-token").await;
    assert_eq!(status, 200, "{body}");
    // without a loaded model the tool must return a JSON-RPC error, not panic
    let err = &body["error"];
    assert!(err.is_object(), "expected error object when no engine loaded: {body}");
}

#[tokio::test]
async fn mcp_graph_gc_returns_deleted_count() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth("/mcp", json!({
        "jsonrpc": "2.0", "id": 99, "method": "tools/call",
        "params": { "name": "kotoba_graph_gc", "arguments": {} }
    }), "test-token").await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["status"], "ok", "{content}");
    assert!(content["deleted_blocks"].is_number(), "missing deleted_blocks: {content}");
}

// ── XRPC route smoke tests (KG / CC / email) ──────────────────────────────────

#[tokio::test]
async fn kg_catalog_empty_returns_zero_stats() {
    let s = TestServer::start(false).await;
    // KG graph defaults to Authenticated visibility — opaque Bearer token suffices
    let (status, body) = s
        .get_authed("/xrpc/ai.gftd.apps.yata.kg.catalog")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    let stats = &body["stats"];
    assert_eq!(stats["totalEntities"], 0, "{body}");
    assert_eq!(stats["totalClaims"], 0, "{body}");
    assert_eq!(stats["totalRelations"], 0, "{body}");
}

#[tokio::test]
async fn cc_status_returns_index_counts() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.apps.kotoba.cc.status").await;
    assert_eq!(status, 200, "{body}");
    assert!(body["chunks_indexed"].is_number(), "{body}");
    assert!(body["pages_indexed"].is_number(), "{body}");
    assert!(body["ivf_centroids"].is_number(), "{body}");
}

#[tokio::test]
async fn email_list_xrpc_unknown_owner_returns_empty() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get("/xrpc/ai.gftd.apps.kotoba.email.list?owner_did=did:key:zEmailXrpc1")
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 0, "{body}");
    assert!(
        body["emails"].as_array().map(|a| a.is_empty()).unwrap_or(false),
        "{body}"
    );
}

// ── weight.put CACAO auth tests ───────────────────────────────────────────────

#[tokio::test]
async fn weight_put_with_valid_cacao_returns_blob_cid() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let graph = "weight-test-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);

    // Minimal 1-element FP8 tensor
    let data = vec![0x3cu8];
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.weight.put",
        json!({
            "model_cid":  "bafkreiabcdef",
            "layer":      0,
            "data_b64":   B64.encode(&data),
            "shape":      [1u32],
            "dtype":      "fp8e4m3",
            "graph":      graph,
            "cacao_b64":  cacao_b64,
        }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["blob_cid"].as_str().is_some(), "blob_cid missing: {body}");
    assert!(body["quad_cid"].as_str().is_some(), "quad_cid missing: {body}");
    assert_eq!(body["layer"], 0u64, "layer mismatch: {body}");
}

#[tokio::test]
async fn weight_put_without_cacao_returns_401() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let data = vec![0x3cu8];
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.weight.put",
        json!({
            "model_cid": "bafkreiabcdef",
            "layer":     0,
            "data_b64":  B64.encode(&data),
            "shape":     [1u32],
            "dtype":     "fp8e4m3",
            "graph":     "weight-test-graph",
        }),
    ).await;
    assert_eq!(status, 401, "{body}");
}

// ── lora.apply CACAO auth tests ───────────────────────────────────────────────

#[tokio::test]
async fn lora_apply_with_valid_cacao_returns_adapter_cid() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let graph = "lora-test-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);

    let adapter = vec![0x01u8, 0x02u8, 0x03u8];
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.lora.apply",
        json!({
            "model_cid":   "bafkreiabcdef",
            "rank":        4u32,
            "graph":       graph,
            "adapter_b64": B64.encode(&adapter),
            "cacao_b64":   cacao_b64,
        }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["adapter_cid"].as_str().is_some(), "adapter_cid missing: {body}");
    assert!(body["quad_cid"].as_str().is_some(), "quad_cid missing: {body}");
}

#[tokio::test]
async fn lora_apply_without_cacao_returns_401() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let adapter = vec![0x01u8, 0x02u8, 0x03u8];
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.lora.apply",
        json!({
            "model_cid":   "bafkreiabcdef",
            "rank":        4u32,
            "graph":       "lora-test-graph",
            "adapter_b64": B64.encode(&adapter),
        }),
    ).await;
    assert_eq!(status, 401, "{body}");
}

// ── kotobase quota enforcement tests ─────────────────────────────────────────

// Free tier allows QUOTA_FREE_PINS=3 pins. The 4th pin must be rejected with QuotaExceeded.
#[tokio::test]
async fn kotobase_pin_quota_exceeded_returns_429() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zQuotaPin1";
    let tok = tenant_jwt(did);

    let (status, _) = s.post_auth(KOTOBASE_ACCOUNT_CREATE, json!({ "tenant_did": did }), &tok).await;
    assert_eq!(status, 200);

    // Pin up to the free-tier limit (3 pins)
    for i in 0..3u32 {
        let cid_str = format!("bafybeiquota{i:04}abcdefghijklmnopqrstuvwxyz12345678");
        let (status, body) = s.post_auth(KOTOBASE_PIN_CREATE, json!({
            "tenant_did": did,
            "name":       format!("quota-pin-{i}"),
            "cid":        cid_str,
            "size_hint_bytes": 100_i64,
        }), &tok).await;
        assert_eq!(status, 200, "pin {i} should succeed: {body}");
    }

    // 4th pin must be rejected
    let (status, body) = s.post_auth(KOTOBASE_PIN_CREATE, json!({
        "tenant_did": did,
        "name":       "quota-overflow",
        "cid":        "bafybeiquotaoverflow000000000000000000000000000000",
        "size_hint_bytes": 100_i64,
    }), &tok).await;
    assert_eq!(status, 429, "expected QuotaExceeded 429: {body}");
    let err = body["error"].as_str().unwrap_or("");
    assert!(err.contains("QuotaExceeded"), "error should mention QuotaExceeded: {body}");
}

// Free tier allows QUOTA_FREE_BYTES=100 MiB. A single pin that exceeds the byte quota is rejected.
#[tokio::test]
async fn kotobase_byte_quota_exceeded_returns_429() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zQuotaByte1";
    let tok = tenant_jwt(did);

    let (status, _) = s.post_auth(KOTOBASE_ACCOUNT_CREATE, json!({ "tenant_did": did }), &tok).await;
    assert_eq!(status, 200);

    // Attempt to pin something bigger than the free-tier byte quota (100 MiB = 104857600 bytes)
    let over_quota_bytes: i64 = 105_000_000; // ~100.1 MiB
    let (status, body) = s.post_auth(KOTOBASE_PIN_CREATE, json!({
        "tenant_did":      did,
        "name":            "byte-overflow",
        "cid":             "bafybeibytequotaoverflow00000000000000000000000000",
        "size_hint_bytes": over_quota_bytes,
    }), &tok).await;
    assert_eq!(status, 429, "expected QuotaExceeded 429: {body}");
    let err = body["error"].as_str().unwrap_or("");
    assert!(err.contains("QuotaExceeded"), "error should mention QuotaExceeded: {body}");
}

// ── kotobase DID ownership auth tests ────────────────────────────────────────

#[tokio::test]
async fn kotobase_account_create_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s.post(KOTOBASE_ACCOUNT_CREATE, json!({
        "tenant_did": "did:key:zNoAuth1",
    })).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_pin_create_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s.post(KOTOBASE_PIN_CREATE, json!({
        "tenant_did": "did:key:zNoAuth2",
        "name": "my-pin",
        "cid": "bafytest",
    })).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_pin_delete_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s.post(KOTOBASE_PIN_DELETE, json!({
        "tenant_did": "did:key:zNoAuth3",
        "pin_id": "some-pin-id",
    })).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_pin_create_wrong_sub_returns_401() {
    let s = TestServer::start(false).await;
    let victim_did = "did:key:zVictim1";
    let attacker_jwt = tenant_jwt("did:key:zAttacker1");
    let (status, _) = s.post_auth(KOTOBASE_PIN_CREATE, json!({
        "tenant_did": victim_did,
        "name": "stolen-pin",
        "cid": "bafytest",
    }), &attacker_jwt).await;
    assert_eq!(status, 401);
}

// ── weight.get tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn weight_get_unknown_cid_returns_404() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    // A well-formed multibase CID that does not exist in the store
    let cid = KotobaCid::from_bytes(b"nonexistent-weight-blob").to_multibase();
    let (status, _body) = s.get(
        &format!("/xrpc/ai.gftd.apps.kotoba.weight.get?cid={cid}")
    ).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn weight_put_then_get_roundtrip() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let graph = "weight-roundtrip-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);

    let data = vec![0x3cu8, 0x7fu8, 0x00u8];
    let (status, put_body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.weight.put",
        json!({
            "model_cid":  "bafkreiabcdef",
            "layer":      1u32,
            "data_b64":   B64.encode(&data),
            "shape":      [3u32],
            "dtype":      "fp8e4m3",
            "graph":      graph,
            "cacao_b64":  cacao_b64,
        }),
    ).await;
    assert_eq!(status, 200, "{put_body}");
    let blob_cid = put_body["blob_cid"].as_str().expect("blob_cid").to_string();

    // Now GET the blob back by its CID
    let (status, get_body) = s.get(
        &format!("/xrpc/ai.gftd.apps.kotoba.weight.get?cid={blob_cid}")
    ).await;
    assert_eq!(status, 200, "{get_body}");
    assert_eq!(get_body["cid"], blob_cid, "{get_body}");
    let returned = B64.decode(get_body["data_b64"].as_str().expect("data_b64"))
        .expect("valid base64");
    assert_eq!(returned, data, "roundtripped bytes must match");
}

// ── kg.search / kg.query / kg.delete smoke tests ─────────────────────────────

#[tokio::test]
async fn kg_search_empty_returns_empty_results() {
    let s = TestServer::start(false).await;
    // KG graph defaults to Authenticated — send Bearer token
    let (status, body) = s.get_authed(
        "/xrpc/ai.gftd.apps.yata.kg.search?q=nonexistent+entity"
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["results"].is_array(), "expected results array: {body}");
    let results = body["results"].as_array().unwrap();
    assert!(results.is_empty(), "expected empty results on fresh store: {body}");
}

#[tokio::test]
async fn kg_search_after_ingest_returns_entity() {
    let s = TestServer::start(false).await;

    // Ingest an entity with a label so the search index has data
    let (status, _) = s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.ingest",
        json!({
            "id":      "ent-search-1",
            "labelJa": "東京都",
            "labelEn": "Tokyo",
            "type":    "Place",
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "ingest failed");

    // Search for the entity (blake3 pseudo-vector fallback, no LLM needed)
    let (status, body) = s.get_authed(
        "/xrpc/ai.gftd.apps.yata.kg.search?q=Tokyo"
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["results"].is_array(), "{body}");
    // At minimum the field must be present; exact match depends on vector similarity
    assert!(body["elapsedMs"].is_number(), "elapsedMs missing: {body}");
}

#[tokio::test]
async fn kg_query_sparql_empty_graph_returns_empty() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.query",
        json!({
            "lang":  "sparql",
            "query": "PREFIX k: <urn:kg:> SELECT ?s ?o WHERE { ?s k:id ?o }",
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["results"].is_array(), "expected results array: {body}");
    assert_eq!(body["results"].as_array().unwrap().len(), 0, "fresh graph should have no quads: {body}");
}

#[tokio::test]
async fn kg_query_unknown_lang_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.query",
        json!({ "lang": "sql", "query": "SELECT 1" }),
        "test-token",
    ).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kg_delete_nonexistent_entity_returns_ok_zero_retracted() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.delete",
        json!({ "id": "ent-does-not-exist" }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert_eq!(body["retractedCount"], 0, "{body}");
}

#[tokio::test]
async fn kg_ingest_then_delete_removes_entity() {
    let s = TestServer::start(false).await;

    // Ingest an entity
    let (status, _) = s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.ingest",
        json!({ "id": "ent-delete-me", "type": "Thing", "labelEn": "Delete Target" }),
        "test-token",
    ).await;
    assert_eq!(status, 200);

    // Verify it's present
    let (status, body) = s.get_authed(
        "/xrpc/ai.gftd.apps.yata.kg.entity?id=ent-delete-me"
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "entity not found before delete: {body}");

    // Delete it
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.delete",
        json!({ "id": "ent-delete-me" }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert!(body["retractedCount"].as_u64().unwrap_or(0) > 0, "expected >0 retracted: {body}");

    // Entity should no longer be found
    let (status, body) = s.get_authed(
        "/xrpc/ai.gftd.apps.yata.kg.entity?id=ent-delete-me"
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(!body["ok"].as_bool().unwrap_or(true), "entity still found after delete: {body}");
}

// ── kotobase read-endpoint auth tests ────────────────────────────────────────

#[tokio::test]
async fn kotobase_account_status_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s.post(KOTOBASE_ACCOUNT_STATUS, json!({
        "tenant_did": "did:key:zStatusNoAuth1",
    })).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_pin_list_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s.post(KOTOBASE_PIN_LIST, json!({
        "tenant_did": "did:key:zPinListNoAuth1",
    })).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_usage_get_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s.post(KOTOBASE_USAGE_GET, json!({
        "tenant_did": "did:key:zUsageNoAuth1",
    })).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_pin_list_offset_pagination() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zPaginate1";
    let tok = tenant_jwt(did);

    let (status, _) = s.post_auth(KOTOBASE_ACCOUNT_CREATE, json!({
        "tenant_did": did, "tier": "starter",
    }), &tok).await;
    assert_eq!(status, 200);

    // Create 3 pins
    for name in &["pin-a", "pin-b", "pin-c"] {
        let (status, body) = s.post_auth(KOTOBASE_PIN_CREATE, json!({
            "tenant_did": did, "name": name,
            "cid": format!("bafytest{name}"),
        }), &tok).await;
        assert_eq!(status, 200, "create {name}: {body}");
    }

    // Page 1: offset=0, limit=2
    let (status, body) = s.post_auth(KOTOBASE_PIN_LIST, json!({
        "tenant_did": did, "limit": 2, "offset": 0,
    }), &tok).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 3, "total should be 3: {body}");
    assert_eq!(body["offset"], 0, "{body}");
    assert_eq!(body["limit"],  2, "{body}");
    assert_eq!(body["pins"].as_array().map(|a| a.len()).unwrap_or(0), 2, "{body}");

    // Page 2: offset=2, limit=2
    let (status, body) = s.post_auth(KOTOBASE_PIN_LIST, json!({
        "tenant_did": did, "limit": 2, "offset": 2,
    }), &tok).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 3, "total still 3: {body}");
    assert_eq!(body["offset"], 2, "{body}");
    assert_eq!(body["pins"].as_array().map(|a| a.len()).unwrap_or(0), 1, "{body}");
}

// ── cc.search / cc.rag / cc.ingest smoke tests ───────────────────────────────

#[tokio::test]
async fn cc_search_without_real_embed_endpoint_returns_error() {
    let s = TestServer::start(false).await;
    // The embed client initializes with default localhost:11434 but no server is running.
    // The request should return an error response (500 or 503) — not 200 with data.
    let (status, body) = s.get("/xrpc/ai.gftd.apps.kotoba.cc.search?q=test").await;
    assert!(status == 500 || status == 503, "expected 500 or 503, got {status}: {body}");
    assert!(body["error"].as_str().is_some(), "expected error field: {body}");
}

#[tokio::test]
async fn cc_rag_without_real_embed_endpoint_returns_error() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.cc.rag",
        json!({ "query": "what is Rust?" }),
    ).await;
    assert!(status == 500 || status == 503, "expected 500 or 503, got {status}: {body}");
    assert!(body["error"].as_str().is_some(), "expected error field: {body}");
}

#[tokio::test]
async fn cc_ingest_trigger_returns_started_job_id() {
    let s = TestServer::start(false).await;
    // Even with a non-existent parquet_dir, the ingest endpoint accepts the request
    // and spawns the job asynchronously; the response must include job_id + status=started
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.cc.ingest",
        json!({ "parquetDir": "/tmp/no-such-dir", "mode": "chunks" }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["job_id"].as_str().is_some(), "job_id missing: {body}");
    assert_eq!(body["status"], "started", "{body}");
}

#[tokio::test]
async fn cc_search_empty_query_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.apps.kotoba.cc.search?q=").await;
    assert_eq!(status, 400, "{body}");
    assert!(body["error"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn cc_ingest_invalid_mode_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.cc.ingest",
        json!({ "parquetDir": "/tmp/test", "mode": "invalid" }),
    ).await;
    assert_eq!(status, 400, "{body}");
    assert!(body["error"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn cc_rag_empty_query_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.cc.rag",
        json!({ "query": "" }),
    ).await;
    assert_eq!(status, 400, "{body}");
    assert!(body["error"].as_str().is_some(), "{body}");
}
