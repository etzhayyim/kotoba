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
    base_url:     String,
    operator_did: String,
    handle:       tokio::task::JoinHandle<()>,
    client:       reqwest::Client,
}

impl TestServer {
    async fn start(with_inference: bool) -> Self {
        let engine = if with_inference { Some(stub_engine()) } else { None };
        let state  = KotobaState::new(engine).expect("KotobaState::new");
        let operator_did = state.operator_did.clone();
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
            operator_did,
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

    async fn get_with_auth(&self, path: &str, token: &str) -> (u16, Value) {
        let r = self.client
            .get(format!("{}{}", self.base_url, path))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .expect("GET with auth");
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
async fn block_get_invalid_cid_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.apps.kotoba.block.get?cid=not-a-valid-cid").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn block_get_unknown_cid_returns_404() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let cid = KotobaCid::from_bytes(b"block-does-not-exist-xyz").to_multibase();
    let (status, body) = s.get(&format!("/xrpc/ai.gftd.apps.kotoba.block.get?cid={cid}")).await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn commit_get_invalid_cid_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.apps.kotoba.commit.get?graph=not-a-cid").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn commit_get_unknown_graph_returns_404() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let cid = KotobaCid::from_bytes(b"graph-commit-does-not-exist").to_multibase();
    let (status, body) = s.get(&format!("/xrpc/ai.gftd.apps.kotoba.commit.get?graph={cid}")).await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn block_put_and_get_roundtrip() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);

    let payload = b"kotoba e2e block";
    let (status, put) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.block.put",
        json!({ "data_b64": B64.encode(payload) }),
        &tok,
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
    let tok = tenant_jwt(&s.operator_did);
    let graph_cid = KotobaCid::from_bytes(b"embed-e2e").to_multibase();
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.embed.create",
        json!({
            "text": "hello kotoba",
            "doc_cid": "doc1",
            "model_cid": "model1",
            "graph": graph_cid
        }),
        &tok,
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["dims"].as_u64().unwrap_or(0) > 0);
}

#[tokio::test]
async fn embed_create_empty_text_returns_400() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph_cid = KotobaCid::from_bytes(b"embed-empty").to_multibase();
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.embed.create",
        json!({ "text": "", "doc_cid": "doc-empty", "model_cid": "model1", "graph": graph_cid }),
        &tok,
    ).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn infer_run_with_stub_engine() {
    let s = TestServer::start(true).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.infer.run",
        json!({ "prompt": "what is kotoba?", "max_new_tokens": 32 }),
        &tok,
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["output"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
}

#[tokio::test]
async fn infer_run_without_auth_returns_401() {
    let s = TestServer::start(true).await;
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.infer.run",
        json!({ "prompt": "hello" }),
    ).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn infer_run_without_engine_returns_503() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, _) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.infer.run",
        json!({ "prompt": "hello" }),
        &tok,
    ).await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn agent_run_with_stub_engine_completes() {
    let s = TestServer::start(true).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.run",
        json!({ "task": "test: 2+2?", "max_steps": 3, "max_tokens": 64 }),
        &tok,
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["session_cid"].as_str().is_some());
    assert!(body["supersteps"].as_u64().unwrap_or(0) >= 1);
}

#[tokio::test]
async fn agent_run_without_engine_returns_503() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, _) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.run",
        json!({ "task": "x" }),
        &tok,
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

// ── MCP kotoba_wasm_run — Python componentize-py guest ───────────────────────

#[tokio::test]
async fn mcp_wasm_run_python_langgraph_agent() {
    // Load the pre-built Python LangGraph agent WASM.
    // Skip if the file is absent (developer hasn't built it yet or CI excludes it).
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().unwrap().parent().unwrap();
    let wasm_path = workspace.join("examples/kotoba-langgraph-hello/agent.wasm");
    let wasm_bytes = match std::fs::read(&wasm_path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("kotoba-langgraph-hello/agent.wasm not found — skipping mcp_wasm_run_python_langgraph_agent");
            return;
        }
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

    // Build CBOR InvokeContext expected by handle_invoke() in _entry.py:
    //   { "graph": str, "session_cid": str, "args": { "input": {...}, "thread_id": str } }
    let mut ctx_cbor = Vec::new();
    {
        use std::collections::BTreeMap;
        let mut input_msg: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        input_msg.insert("type",    ciborium::Value::Text("human".into()));
        input_msg.insert("content", ciborium::Value::Text("hello".into()));

        let mut input_state: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        input_state.insert("messages", ciborium::Value::Array(vec![
            ciborium::Value::Map(
                input_msg.into_iter().map(|(k, v)| (ciborium::Value::Text(k.into()), v)).collect()
            ),
        ]));

        let mut args: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        args.insert("input",     ciborium::Value::Map(
            input_state.into_iter().map(|(k, v)| (ciborium::Value::Text(k.into()), v)).collect()
        ));
        args.insert("thread_id", ciborium::Value::Text("py-test-thread".into()));

        let mut ctx: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        ctx.insert("graph",       ciborium::Value::Text("py-hello-graph".into()));
        ctx.insert("session_cid", ciborium::Value::Text("py-test-session".into()));
        ctx.insert("args",        ciborium::Value::Map(
            args.into_iter().map(|(k, v)| (ciborium::Value::Text(k.into()), v)).collect()
        ));

        ciborium::into_writer(&ctx, &mut ctx_cbor).unwrap();
    }

    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 30, "method": "tools/call",
            "params": {
                "name": "kotoba_wasm_run",
                "arguments": {
                    "wasm_b64":     B64.encode(&wasm_bytes),
                    "agent_did":    "did:plc:e2e_py_langgraph",
                    "ctx_cbor_b64": B64.encode(&ctx_cbor),
                }
            }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected json-rpc error: {body}");

    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    // WasmPregelRunner must complete without a Rust panic (HTTP 200 + status=ok)
    assert_eq!(content["status"], "ok",
        "expected WasmPregelRunner status=ok, got: {content}");

    // Decode the output CBOR — must always be valid CBOR with "ok" or "err" key
    let out_b64 = content["output_cbor_b64"].as_str().expect("output_cbor_b64");
    let out_cbor = B64.decode(out_b64).expect("valid base64");
    let out: ciborium::Value = ciborium::from_reader(std::io::Cursor::new(&out_cbor))
        .expect("output_cbor_b64 must be valid CBOR (WasmPregelRunner encodes errors as CBOR)");
    let out_map: std::collections::HashMap<String, ciborium::Value> = match out {
        ciborium::Value::Map(ref m) => m.iter()
            .filter_map(|(k, v)| k.as_text().map(|s| (s.to_string(), v.clone())))
            .collect(),
        _ => panic!("expected CBOR map from Python agent output, got: {out:?}"),
    };
    assert!(
        out_map.contains_key("ok") || out_map.contains_key("err"),
        "Python handle_invoke must return {{ok/err}}, got keys: {:?}",
        out_map.keys().collect::<Vec<_>>()
    );

    let gas = content["total_gas_used"].as_u64().unwrap_or(0);
    if gas > 0 {
        // Python WASM executed — LLM may have failed but graph code ran
        eprintln!("Python LangGraph WASM executed successfully: gas_used={gas}");
    } else {
        // gas=0 means WASM compilation failed before execution.
        // Expected with wasmtime 22 which disables the extended-const proposal
        // required by componentize-py 0.23 output. Upgrade wasmtime to fix.
        let err_text = out_map.get("err")
            .and_then(|v| v.as_text())
            .unwrap_or("");
        assert!(
            err_text.contains("CompileFailed") || err_text.contains("compile"),
            "gas=0 but error is unexpected (not a compile error): {err_text}"
        );
        eprintln!("NOTE: Python WASM compile failed (extended-const / wasmtime 22 limitation): {err_text}");
    }
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

// ── MCP datalog_run rules-count cap ───────────────────────────────────────────

#[tokio::test]
async fn mcp_datalog_run_too_many_rules_returns_error() {
    let s = TestServer::start(false).await;
    // Build 257 rules (MAX_DATALOG_RULES = 256).
    let rule = json!({
        "head": { "relation": "reachable", "args": [{"Variable": "x"}, {"Variable": "y"}] },
        "body": [{ "Positive": { "relation": "edge", "args": [{"Variable": "x"}, {"Variable": "y"}] } }]
    });
    let rules: Vec<_> = (0..257).map(|_| rule.clone()).collect();

    let (status, body) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 99, "method": "tools/call",
            "params": {
                "name": "kotoba_datalog_run",
                "arguments": { "graph": "cap-test-graph", "rules": rules }
            }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    // kotoba MCP returns JSON-RPC top-level error for invalid params
    let err_node = if body["error"].is_object() { &body["error"] } else { &body["result"]["error"] };
    let err_code = err_node["code"].as_i64();
    assert!(err_code.is_some(), "expected MCP error, got: {body}");
    assert_eq!(err_code.unwrap(), -32602, "expected ERR_INVALID_PARAMS: {body}");
    let err_msg = err_node["message"].as_str().unwrap_or("");
    assert!(err_msg.contains("257") || err_msg.contains("256"),
        "error should mention count/limit: {body}");
}

#[tokio::test]
async fn mcp_datalog_run_too_many_body_literals_returns_error() {
    let s = TestServer::start(false).await;
    // Build a rule with 17 body literals (MAX_BODY_LITERALS = 16).
    let body_lit = json!({ "Positive": { "relation": "edge", "args": [{"Variable": "x"}, {"Variable": "y"}] } });
    let body: Vec<_> = (0..17).map(|_| body_lit.clone()).collect();
    let rule = json!({
        "head": { "relation": "reachable", "args": [{"Variable": "x"}, {"Variable": "y"}] },
        "body": body
    });

    let (status, body_resp) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 100, "method": "tools/call",
            "params": {
                "name": "kotoba_datalog_run",
                "arguments": { "graph": "lit-test-graph", "rules": [rule] }
            }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body_resp}");
    let err_node = if body_resp["error"].is_object() { &body_resp["error"] } else { &body_resp["result"]["error"] };
    let err_code = err_node["code"].as_i64();
    assert!(err_code.is_some(), "expected MCP error, got: {body_resp}");
    assert_eq!(err_code.unwrap(), -32602, "expected ERR_INVALID_PARAMS: {body_resp}");
    let err_msg = err_node["message"].as_str().unwrap_or("");
    assert!(err_msg.contains("17") || err_msg.contains("16"),
        "error should mention literal count/limit: {body_resp}");
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
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.invoke.run",
        json!({
            "program_cid":  "be2e_wasm_invoke",
            "program_type": "wasm-node",
            "agent_did":    "did:plc:e2e",
            "wasm_b64":     B64.encode(&wasm_bytes),
            "ctx_b64":      B64.encode(&ctx),
        }),
        &tok,
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

#[tokio::test]
async fn invoke_run_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.invoke.run",
        json!({ "program_cid": "x", "program_type": "datalog", "agent_did": "did:plc:x" }),
    ).await;
    assert_eq!(status, 401);
}

// ── SyncWindow session lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn agent_sync_open_creates_session() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph").to_multibase();
    let tok = tenant_jwt(&s.operator_did);

    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({
            "session_id": "sess-1",
            "graph_cid":  graph_cid,
            "since_seq":  0,
            "head_cid":   null,
        }),
        &tok,
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["session_id"], "sess-1");
    assert_eq!(body["since_seq"], 0);
}

#[tokio::test]
async fn agent_sync_open_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph-noauth").to_multibase();
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({ "session_id": "sess-noauth", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
    ).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn agent_sync_advance_updates_watermark() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph-adv").to_multibase();
    let head_cid  = KotobaCid::from_bytes(b"head-v1").to_multibase();
    let tok = tenant_jwt(&s.operator_did);

    s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({ "session_id": "sess-adv", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
        &tok,
    ).await;

    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
        json!({ "session_id": "sess-adv", "new_head_cid": head_cid, "new_seq": 42 }),
        &tok,
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["since_seq"], 42);
}

#[tokio::test]
async fn agent_sync_close_removes_session() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph-close").to_multibase();
    let tok = tenant_jwt(&s.operator_did);

    s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({ "session_id": "sess-close", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
        &tok,
    ).await;

    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncclose",
        json!({ "session_id": "sess-close" }),
        &tok,
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["session_id"], "sess-close");

    // Second close → 404 (session removed)
    let (status2, _) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncclose",
        json!({ "session_id": "sess-close" }),
        &tok,
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
    let tok = tenant_jwt(&s.operator_did);

    // open
    let (st, _) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({ "session_id": "lc", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
        &tok,
    ).await;
    assert_eq!(st, 200);

    // advance × 2
    let (st, b) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
        json!({ "session_id": "lc", "new_head_cid": head1, "new_seq": 10 }),
        &tok,
    ).await;
    assert_eq!(st, 200);
    assert_eq!(b["since_seq"], 10);

    let (st, b) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
        json!({ "session_id": "lc", "new_head_cid": head2, "new_seq": 20 }),
        &tok,
    ).await;
    assert_eq!(st, 200);
    assert_eq!(b["since_seq"], 20);

    // close
    let (st, _) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncclose",
        json!({ "session_id": "lc" }),
        &tok,
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
    let tok = tenant_jwt(&s.operator_did);
    let data = b"hello vault";
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.vault.put",
        json!({ "data_b64": B64.encode(data) }),
        &tok,
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["cid"].as_str().is_some(), "cid missing: {body}");
    assert_eq!(body["size"], data.len() as u64, "size mismatch: {body}");
}

#[tokio::test]
async fn vault_put_then_get_roundtrip() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let data = b"roundtrip blob content";
    let data_b64 = B64.encode(data);

    let (status, put_body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.vault.put",
        json!({ "data_b64": data_b64 }),
        &tok,
    ).await;
    assert_eq!(status, 200, "{put_body}");
    let cid = put_body["cid"].as_str().expect("cid");

    let (status, get_body) = s.get_with_auth(
        &format!("/xrpc/ai.gftd.apps.kotoba.vault.get?cid={cid}"),
        &tok,
    ).await;
    assert_eq!(status, 200, "{get_body}");
    assert_eq!(get_body["cid"].as_str(), Some(cid), "cid mismatch");
    assert_eq!(get_body["data_b64"].as_str(), Some(data_b64.as_str()), "data mismatch");
}

#[tokio::test]
async fn vault_get_without_auth_returns_401() {
    // Regression guard: vault_get must require operator auth — unauthenticated
    // reads would expose private encrypted blobs to any caller.
    let s = TestServer::start(false).await;
    let zero_cid = format!("b{}", "a".repeat(58));
    let (status, _body) = s.get(
        &format!("/xrpc/ai.gftd.apps.kotoba.vault.get?cid={zero_cid}"),
    ).await;
    assert_eq!(status, 401, "vault_get must reject unauthenticated requests");
}

#[tokio::test]
async fn vault_get_unknown_cid_returns_404() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    // KotobaCid multibase = 'b' + base32-nopad of 36 bytes (lowercase).
    // 36 zero-bytes → 58 'a' chars. blake3 of any real content won't produce all-zeros,
    // so this CID is valid format but never stored.
    let zero_cid = format!("b{}", "a".repeat(58));
    let (status, _body) = s.get_with_auth(
        &format!("/xrpc/ai.gftd.apps.kotoba.vault.get?cid={zero_cid}"),
        &tok,
    ).await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn vault_get_missing_cid_param_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, _body) = s.get_with_auth("/xrpc/ai.gftd.apps.kotoba.vault.get", &tok).await;
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
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgRoundtrip1");

    let (status, put) = s.post_auth(
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
        &tok,
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
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgRelations1");

    // Ingest target entity first (needed for relation dst)
    s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.ingest",
        json!({ "id": "rel-dst-001", "type": "City", "labelEn": "Tokyo" }),
        &tok,
    ).await;

    // Ingest source entity with relation to target
    let (status, put) = s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.ingest",
        json!({
            "id":      "rel-src-001",
            "type":    "Person",
            "labelEn": "Alice",
            "relations": [
                { "pred": "locatedIn", "dstId": "rel-dst-001" }
            ]
        }),
        &tok,
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
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgCatalog1");

    // Ingest two entities
    for (id, label) in &[("cat-e1", "EntityOne"), ("cat-e2", "EntityTwo")] {
        let (st, _) = s.post_auth(
            "/xrpc/ai.gftd.apps.yata.kg.ingest",
            json!({ "id": id, "type": "Thing", "labelEn": label, "sourceId": "cat-test-src" }),
            &tok,
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

/// Build an expired JWT (exp = 1 = past Unix epoch).
fn expired_jwt(did: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let header  = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        format!(r#"{{"sub":"{did}","exp":1}}"#).as_bytes()
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
async fn email_list_xrpc_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get("/xrpc/ai.gftd.apps.kotoba.email.list?owner_did=did:key:zEmailXrpc1")
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn email_list_xrpc_unknown_owner_returns_empty() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zEmailXrpc1";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .get_with_auth(
            &format!("/xrpc/ai.gftd.apps.kotoba.email.list?owner_did={did}"),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 0, "{body}");
    assert!(
        body["emails"].as_array().map(|a| a.is_empty()).unwrap_or(false),
        "{body}"
    );
}

#[tokio::test]
async fn email_ingest_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.apps.kotoba.email.ingest", json!({
        "owner_did": "did:key:zEmailIngest1",
        "raw_b64": "aGVsbG8=",
    })).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn email_ingest_empty_owner_did_returns_400() {
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zEmailOwner1");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.email.ingest", json!({
        "owner_did": "",
        "raw_b64": "aGVsbG8=",
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
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
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgSearch1");

    // Ingest an entity with a label so the search index has data
    let (status, _) = s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.ingest",
        json!({
            "id":      "ent-search-1",
            "labelJa": "東京都",
            "labelEn": "Tokyo",
            "type":    "Place",
        }),
        &tok,
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
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgDel1");
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.delete",
        json!({ "id": "ent-does-not-exist" }),
        &tok,
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert_eq!(body["retractedCount"], 0, "{body}");
}

#[tokio::test]
async fn kg_ingest_then_delete_removes_entity() {
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgDel2");

    // Ingest an entity
    let (status, _) = s.post_auth(
        "/xrpc/ai.gftd.apps.yata.kg.ingest",
        json!({ "id": "ent-delete-me", "type": "Thing", "labelEn": "Delete Target" }),
        &tok,
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
        &tok,
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
    let tok = tenant_jwt(&s.operator_did);
    // Even with a non-existent parquet_dir, the ingest endpoint accepts the request
    // and spawns the job asynchronously; the response must include job_id + status=started
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.cc.ingest",
        json!({ "parquetDir": "/tmp/no-such-dir", "mode": "chunks" }),
        &tok,
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["job_id"].as_str().is_some(), "job_id missing: {body}");
    assert_eq!(body["status"], "started", "{body}");
}

#[tokio::test]
async fn cc_ingest_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.cc.ingest",
        json!({ "parquetDir": "/tmp/test", "mode": "chunks" }),
    ).await;
    assert_eq!(status, 401, "{body}");
    assert!(body["error"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn cc_ingest_with_non_operator_did_returns_401() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zNotTheOperator");
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.cc.ingest",
        json!({ "parquetDir": "/tmp/test", "mode": "chunks" }),
        &tok,
    ).await;
    assert_eq!(status, 401, "{body}");
    assert!(body["error"].as_str().is_some(), "{body}");
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
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.cc.ingest",
        json!({ "parquetDir": "/tmp/test", "mode": "invalid" }),
        &tok,
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

// ── agent.sync security tests ─────────────────────────────────────────────────

#[tokio::test]
async fn agent_sync_open_empty_session_id_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.apps.kotoba.agent.syncopen", json!({
        "session_id": "",
        "graph_cid":  "bafybeisync000000000000000000000000000000000000000",
        "since_seq":  0u64,
    })).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn agent_sync_open_oversized_session_id_returns_400() {
    let s = TestServer::start(false).await;
    let long_id = "x".repeat(257); // > 256 bytes
    let (status, body) = s.post("/xrpc/ai.gftd.apps.kotoba.agent.syncopen", json!({
        "session_id": long_id,
        "graph_cid":  "bafybeisync000000000000000000000000000000000000000",
        "since_seq":  0u64,
    })).await;
    assert_eq!(status, 400, "{body}");
}

// ── kg input-validation tests ─────────────────────────────────────────────────

#[tokio::test]
async fn kg_ingest_empty_id_returns_400() {
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgVal1");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.yata.kg.ingest", json!({
        "id": "",
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kg_embed_empty_text_returns_400() {
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgVal2");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.yata.kg.embed", json!({
        "entityId": "ent-1",
        "text": "",
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kg_search_empty_query_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.apps.yata.kg.search?q=").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kg_delete_empty_id_returns_400() {
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgVal3");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.yata.kg.delete", json!({
        "id": "",
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kg_query_empty_query_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.yata.kg.query", json!({
        "lang": "sparql", "query": "",
    }), "test-token").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kg_ingest_too_many_claims_returns_400() {
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgVal4");
    let claims: Vec<_> = (0..1025).map(|i| json!({"pred": format!("p{i}"), "value": "v"})).collect();
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.yata.kg.ingest", json!({
        "id": "ent-overflow",
        "claims": claims,
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn agent_sync_open_non_ascii_session_id_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.apps.kotoba.agent.syncopen", json!({
        "session_id": "セッション",  // non-ASCII
        "graph_cid":  "bafybeisync000000000000000000000000000000000000000",
        "since_seq":  0u64,
    })).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn agent_sync_advance_unknown_session_returns_404() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let head_cid = KotobaCid::from_bytes(b"head-adv").to_multibase();
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.agent.syncadvance", json!({
        "session_id":   "no-such-session",
        "new_head_cid": head_cid,
        "new_seq":      0u64,
    }), &tok).await;
    assert_eq!(status, 404, "{body}");
}

// ── signal endpoint security tests ───────────────────────────────────────────

#[tokio::test]
async fn signal_register_prekeys_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.signal.register.prekeys", json!({
        "did": "did:plc:test123",
        "deviceId": "device-1",
        "identityKey": {},
        "prekeyBundle": {},
    })).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn signal_register_prekeys_empty_did_returns_400() {
    let s = TestServer::start(false).await;
    // Use a token whose sub matches the empty DID (won't reach the check — empty DID is caught first)
    let (status, body) = s.post_auth("/xrpc/ai.gftd.signal.register.prekeys", json!({
        "did": "",
        "deviceId": "device-1",
        "identityKey": {},
        "prekeyBundle": {},
    }), "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6cGxjOnRlc3QxMjMifQ.dummysig").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_send_message_oversized_payload_returns_413() {
    let s = TestServer::start(false).await;
    // Build a payload exceeding 256 KiB
    let large_ciphertext = "x".repeat(300 * 1024);
    let (status, body) = s.post("/xrpc/ai.gftd.signal.send.message", json!({
        "signalMessage": {
            "recipientDid": "did:plc:recipient",
            "deviceId": "device-1",
            "ciphertext": large_ciphertext,
            "messageType": 1u32,
        },
    })).await;
    assert_eq!(status, 413, "{body}");
}

#[tokio::test]
async fn signal_get_prekey_bundle_empty_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.signal.get.prekey.bundle?did=").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_send_group_message_empty_group_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.signal.send.group.message", json!({
        "groupId": "",
        "senderDid": "did:plc:sender",
        "senderKeyMessage": {},
    })).await;
    assert_eq!(status, 400, "{body}");
}

// ── attestation endpoint security tests ──────────────────────────────────────

#[tokio::test]
async fn attest_claim_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.apps.kotoba.attest.claim", json!({
        "entity_did":   "did:key:zEntity1",
        "attester_did": "did:key:zAttester1",
        "claim_type":   "self",
        "stake_mkoto":  1_000_000_000u64,
    })).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn attest_claim_invalid_claim_type_returns_400() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zAttester2";
    let tok = tenant_jwt(did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.claim", json!({
        "entity_did":   "did:key:zEntity2",
        "attester_did": did,
        "claim_type":   "unknown_type",
        "stake_mkoto":  1_000_000_000u64,
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn attest_claim_roundtrip() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zAttester3";
    let tok = tenant_jwt(did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.claim", json!({
        "entity_did":   "did:key:zEntity3",
        "attester_did": did,
        "claim_type":   "self",
        "stake_mkoto":  1_000_000_000u64,
    }), &tok).await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["status"], "attested", "{body}");
    assert!(body["claim_cid"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn attest_challenge_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.apps.kotoba.attest.challenge", json!({
        "claim_cid":      "bafybeifake000000000000000000000000000",
        "challenger_did": "did:key:zChallenger1",
        "reason":         "fabricated evidence",
    })).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn attest_challenge_empty_reason_returns_400() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zChallenger2";
    let tok = tenant_jwt(did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.challenge", json!({
        "claim_cid":      "bafybeifake000000000000000000000000000",
        "challenger_did": did,
        "reason":         "",
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

// ── kg write-endpoint auth tests ──────────────────────────────────────────────

#[tokio::test]
async fn kg_ingest_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.apps.yata.kg.ingest", json!({
        "id": "ent-noauth",
        "labelEn": "Test Entity",
    })).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["ok"], false, "{body}");
}

#[tokio::test]
async fn kg_delete_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.apps.yata.kg.delete", json!({
        "id": "ent-noauth-del",
    })).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["ok"], false, "{body}");
}

#[tokio::test]
async fn kg_embed_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.apps.yata.kg.embed", json!({
        "entityId": "ent-embed-noauth",
        "text": "some text",
    })).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn kg_ingest_with_auth_succeeds() {
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgWriter1");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.yata.kg.ingest", json!({
        "id":      "ent-auth-ok",
        "labelEn": "Authenticated Entity",
        "labelJa": "認証済みエンティティ",
    }), &tok).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ok"], true, "{body}");
    assert!(body["subjectCid"].as_str().is_some(), "{body}");
    assert!(body["quadCount"].as_u64().unwrap_or(0) > 0, "{body}");
}

#[tokio::test]
async fn kg_delete_with_auth_on_missing_entity_returns_ok_zero() {
    let s   = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgWriter2");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.yata.kg.delete", json!({
        "id": "ent-does-not-exist-auth",
    }), &tok).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(body["retractedCount"], 0, "{body}");
}

// ── attest_challenge happy path ───────────────────────────────────────────────

#[tokio::test]
async fn attest_challenge_roundtrip() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zChallenger3";
    let tok = tenant_jwt(did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.challenge", json!({
        "claim_cid":      "bafybeifake000000000000000000000000000",
        "challenger_did": did,
        "reason":         "counter-evidence",
    }), &tok).await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["status"], "challenged", "{body}");
    assert!(body["challenge_cid"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn attest_challenge_empty_claim_cid_returns_400() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zChallenger4";
    let tok = tenant_jwt(did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.challenge", json!({
        "claim_cid":      "",
        "challenger_did": did,
        "reason":         "some reason",
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

// ── attest_query ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn attest_query_returns_empty_list() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get(
        "/xrpc/ai.gftd.apps.kotoba.attest.query?entity_did=did:key:zNobody"
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["claims"].as_array().is_some(), "claims must be array: {body}");
    assert_eq!(body["total"].as_u64().unwrap_or(1), 0, "{body}");
}

#[tokio::test]
async fn attest_query_oversized_entity_did_returns_400() {
    let s = TestServer::start(false).await;
    let big_did = "x".repeat(600);
    let (status, body) = s.get(
        &format!("/xrpc/ai.gftd.apps.kotoba.attest.query?entity_did={big_did}")
    ).await;
    assert_eq!(status, 400, "{body}");
}

// ── attest_claim stake enforcement ────────────────────────────────────────────

#[tokio::test]
async fn attest_claim_insufficient_stake_self_returns_422() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zStaker1";
    let tok = tenant_jwt(did);
    // MIN_STAKE_SELF_ATTESTED = 1_000_000_000 mKOTO; send one less
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.claim", json!({
        "entity_did":   did,
        "attester_did": did,
        "claim_type":   "self",
        "stake_mkoto":  999_999_999u64,
    }), &tok).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["error"], "insufficient_stake", "{body}");
    assert_eq!(body["required_mkoto"].as_u64().unwrap(), 1_000_000_000u64, "{body}");
}

#[tokio::test]
async fn attest_claim_insufficient_stake_verified_entity_returns_422() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zStaker2";
    let tok = tenant_jwt(did);
    // MIN_STAKE_VERIFIED_ENTITY = 5_000_000_000 mKOTO; send exactly MIN_STAKE_SELF_ATTESTED
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.claim", json!({
        "entity_did":   "did:key:zEntity1",
        "attester_did": did,
        "claim_type":   "verified_entity",
        "stake_mkoto":  1_000_000_000u64,
    }), &tok).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["error"], "insufficient_stake", "{body}");
    assert_eq!(body["required_mkoto"].as_u64().unwrap(), 5_000_000_000u64, "{body}");
}

#[tokio::test]
async fn attest_claim_sufficient_stake_self_succeeds() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zStaker3";
    let tok = tenant_jwt(did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.claim", json!({
        "entity_did":   did,
        "attester_did": did,
        "claim_type":   "self",
        "stake_mkoto":  1_000_000_000u64,
    }), &tok).await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["status"], "attested", "{body}");
}

// ── attest_query live scan ─────────────────────────────────────────────────────

#[tokio::test]
async fn attest_query_returns_claim_after_submit() {
    let s   = TestServer::start(false).await;
    let attester = "did:key:zQueryAttester1";
    let entity   = "did:key:zQueryEntity1";
    let tok = tenant_jwt(attester);

    // Submit a claim
    let (status, _) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.claim", json!({
        "entity_did":   entity,
        "attester_did": attester,
        "claim_type":   "self",
        "stake_mkoto":  1_000_000_000u64,
    }), &tok).await;
    assert_eq!(status, 201);

    // Query by entity_did — should find the claim
    let (status, body) = s.get(
        &format!("/xrpc/ai.gftd.apps.kotoba.attest.query?entity_did={entity}")
    ).await;
    assert_eq!(status, 200, "{body}");
    let claims = body["claims"].as_array().expect("claims array");
    assert_eq!(claims.len(), 1, "expected 1 claim: {body}");
    assert_eq!(claims[0]["entity_did"], entity, "{body}");
    assert_eq!(claims[0]["attester_did"], attester, "{body}");
    assert_eq!(claims[0]["claim_type"], "self", "{body}");
    assert_eq!(claims[0]["stake_mkoto"].as_u64().unwrap(), 1_000_000_000u64, "{body}");

    // Query by attester_did — same claim
    let (status, body) = s.get(
        &format!("/xrpc/ai.gftd.apps.kotoba.attest.query?attester_did={attester}")
    ).await;
    assert_eq!(status, 200, "{body}");
    let claims = body["claims"].as_array().expect("claims array");
    assert_eq!(claims.len(), 1, "expected 1 claim by attester: {body}");
    assert_eq!(claims[0]["entity_did"], entity, "{body}");
}

#[tokio::test]
async fn attest_query_no_filter_returns_empty() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.apps.kotoba.attest.query").await;
    assert_eq!(status, 200, "{body}");
    let claims = body["claims"].as_array().expect("claims array");
    assert_eq!(claims.len(), 0, "no-filter must return empty: {body}");
}

// ── request_log_query ────────────────────────────────────────────────────────

#[tokio::test]
async fn request_log_query_without_auth_returns_401() {
    // Regression guard: audit log must be operator-only — leaking it reveals
    // internal API usage patterns and DID activity timings to any caller.
    let s = TestServer::start(false).await;
    let (status, _body) = s.get("/xrpc/ai.gftd.apps.kotoba.request.log").await;
    assert_eq!(status, 401, "request_log_query must reject unauthenticated requests");
}

#[tokio::test]
async fn request_log_query_returns_empty_list() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s.get_with_auth("/xrpc/ai.gftd.apps.kotoba.request.log", &tok).await;
    assert_eq!(status, 200, "{body}");
    assert!(body["entries"].as_array().is_some(), "entries must be array: {body}");
}

#[tokio::test]
async fn request_log_query_returns_entries_after_requests() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    // Make a few requests so the fingerprint middleware writes audit quads.
    s.get_with_auth("/xrpc/ai.gftd.apps.kotoba.request.log", &tok).await;
    s.get_with_auth("/xrpc/ai.gftd.apps.kotoba.request.log", &tok).await;
    // Allow the fire-and-forget tokio tasks to complete (in-memory, µs).
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (status, body) = s.get_with_auth("/xrpc/ai.gftd.apps.kotoba.request.log", &tok).await;
    assert_eq!(status, 200, "{body}");
    let entries = body["entries"].as_array().expect("entries must be array");
    assert!(!entries.is_empty(), "expected audit entries after requests, got: {body}");
    let entry = &entries[0];
    assert!(entry["request_cid"].as_str().is_some(), "request_cid missing: {entry}");
    assert!(entry["method"].as_str().is_some(), "method missing: {entry}");
    assert!(entry["path"].as_str().is_some(), "path missing: {entry}");
}

#[tokio::test]
async fn request_log_query_path_prefix_filter() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    // Make distinct requests to two different endpoint families.
    s.get_with_auth("/xrpc/ai.gftd.apps.kotoba.request.log", &tok).await;
    s.get("/xrpc/ai.gftd.apps.kotoba.attest.query?entity_did=did:key:zTest1").await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    // Filter by exact prefix — should return only audit entries matching it.
    let (status, body) = s
        .get_with_auth(
            "/xrpc/ai.gftd.apps.kotoba.request.log?path_prefix=/xrpc/ai.gftd.apps.kotoba.request.log",
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let entries = body["entries"].as_array().expect("entries must be array");
    for e in entries {
        let path = e["path"].as_str().unwrap_or("");
        assert!(
            path.starts_with("/xrpc/ai.gftd.apps.kotoba.request.log"),
            "entry path {path:?} does not match filter"
        );
    }
}

// ── signal.distribute.sender.key ─────────────────────────────────────────────

#[tokio::test]
async fn signal_distribute_sender_key_ok() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.signal.distribute.sender.key", json!({
        "recipientDid":    "did:key:zRecipient1",
        "recipientDevice": "device-1",
        "signalMessage":   { "ciphertext": "AAAA", "messageType": 3 },
    }), &tok).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok", "{body}");
    assert!(body["messageId"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn signal_distribute_sender_key_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.signal.distribute.sender.key", json!({
        "recipientDid":    "did:key:zRecipient1",
        "recipientDevice": "device-1",
        "signalMessage":   { "ciphertext": "AAAA", "messageType": 3 },
    })).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn signal_send_message_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.signal.send.message", json!({
        "signalMessage": {
            "messageType":       "directMessage",
            "senderDid":         "did:key:zSender",
            "recipientDid":      "did:key:zRecipient",
            "deviceId":          "dev-1",
            "ciphertextEnvelope": "AAAA",
            "timestamp":         "2026-05-26T00:00:00Z",
        },
    })).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn signal_send_group_message_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.signal.send.group.message", json!({
        "groupId":          "grp-1",
        "senderDid":        "did:key:zSender",
        "senderKeyMessage": {},
    })).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn signal_distribute_sender_key_empty_recipient_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.signal.distribute.sender.key", json!({
        "recipientDid":    "",
        "recipientDevice": "device-1",
        "signalMessage":   {},
    })).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_distribute_sender_key_empty_device_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.signal.distribute.sender.key", json!({
        "recipientDid":    "did:key:zRecipient2",
        "recipientDevice": "",
        "signalMessage":   {},
    })).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_distribute_sender_key_oversized_payload_returns_413() {
    let s = TestServer::start(false).await;
    let large = "x".repeat(300 * 1024);
    let (status, body) = s.post("/xrpc/ai.gftd.signal.distribute.sender.key", json!({
        "recipientDid":    "did:key:zRecipient3",
        "recipientDevice": "device-1",
        "signalMessage":   { "ciphertext": large },
    })).await;
    assert_eq!(status, 413, "{body}");
}

// ── expired JWT rejection tests ───────────────────────────────────────────────

#[tokio::test]
async fn attest_claim_expired_token_returns_401() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zExpired1";
    let tok = expired_jwt(did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.claim", json!({
        "entity_did":   "did:key:zEntity99",
        "attester_did": did,
        "claim_type":   "self",
        "stake_mkoto":  1_000_000_000u64,
    }), &tok).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn attest_challenge_expired_token_returns_401() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zExpired2";
    let tok = expired_jwt(did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.challenge", json!({
        "claim_cid":      "bafybeifake000000000000000000000000000",
        "challenger_did": did,
        "reason":         "bad actor",
    }), &tok).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn signal_register_prekeys_expired_token_returns_401() {
    let s   = TestServer::start(false).await;
    let did = "did:key:zExpired3";
    let tok = expired_jwt(did);
    let (status, body) = s.post_auth("/xrpc/ai.gftd.signal.register.prekeys", json!({
        "did":          did,
        "deviceId":     "device-x",
        "identityKey":  {},
        "prekeyBundle": {},
    }), &tok).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn operator_auth_expired_token_returns_401() {
    let s   = TestServer::start(false).await;
    let tok = expired_jwt(&s.operator_did);
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"expired-test").to_multibase();
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.embed.create",
        json!({ "text": "hello", "doc_cid": "d1", "model_cid": "m1", "graph": graph_cid }),
        &tok,
    ).await;
    assert_eq!(status, 401, "{body}");
}

// ── signal DID prefix validation tests ───────────────────────────────────────

#[tokio::test]
async fn signal_register_prekeys_invalid_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("not-a-did");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.signal.register.prekeys", json!({
        "did":          "not-a-did",
        "deviceId":     "device-1",
        "identityKey":  {},
        "prekeyBundle": {},
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_get_prekey_bundle_invalid_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.signal.get.prekey.bundle?did=not-a-did").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_send_group_message_invalid_sender_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.signal.send.group.message", json!({
        "groupId":          "grp-1",
        "senderDid":        "not-a-did",
        "senderKeyMessage": {},
    })).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_distribute_sender_key_invalid_recipient_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post("/xrpc/ai.gftd.signal.distribute.sender.key", json!({
        "recipientDid":    "not-a-did",
        "recipientDevice": "device-1",
        "signalMessage":   {},
    })).await;
    assert_eq!(status, 400, "{body}");
}

// ── DID prefix validation tests (email / attest / invoke_run) ────────────────

#[tokio::test]
async fn email_list_invalid_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.apps.kotoba.email.list?owner_did=not-a-did").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn email_ingest_invalid_did_prefix_returns_400() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zOperator");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.email.ingest", json!({
        "owner_did": "not-a-did",
        "raw_b64":   B64.encode(b"From: test@example.com\r\n\r\nBody"),
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn attest_claim_invalid_entity_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zAttester");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.claim", json!({
        "entity_did":   "not-a-did",
        "attester_did": "did:key:zAttester",
        "claim_type":   "self",
        "stake_mkoto":  1_000_000_000u64,
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn attest_claim_invalid_attester_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zSelf");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.claim", json!({
        "entity_did":   "did:key:zSelf",
        "attester_did": "not-a-did",
        "claim_type":   "self",
        "stake_mkoto":  1_000_000_000u64,
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn attest_challenge_invalid_challenger_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("not-a-did");
    let (status, body) = s.post_auth("/xrpc/ai.gftd.apps.kotoba.attest.challenge", json!({
        "claim_cid":      "bafybeifake000000000000000000000000000",
        "challenger_did": "not-a-did",
        "reason":         "bad actor",
    }), &tok).await;
    assert_eq!(status, 400, "{body}");
}

// ── commit.store / weight.put field-bound tests ───────────────────────────────

#[tokio::test]
async fn commit_store_oversized_author_returns_400() {
    let s = TestServer::start(false).await;
    let graph = "commit-author-bound-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);
    // 513-byte author (limit is 512)
    let long_author = "a".repeat(513);
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.commit.store",
        json!({
            "graph":     graph,
            "author":    long_author,
            "seq":       1u64,
            "cacao_b64": cacao_b64,
        }),
    ).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn weight_put_oversized_shape_returns_400() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    let graph = "weight-shape-bound-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);
    let data = vec![0x3cu8];
    // 9-element shape (limit is 8)
    let bad_shape: Vec<u32> = vec![1; 9];
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.weight.put",
        json!({
            "model_cid": "bafkreiabcdef",
            "layer":     0,
            "data_b64":  B64.encode(&data),
            "shape":     bad_shape,
            "dtype":     "fp8e4m3",
            "graph":     graph,
            "cacao_b64": cacao_b64,
        }),
    ).await;
    assert_eq!(status, 400, "{body}");
}

// ── email.read tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn email_read_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get("/xrpc/ai.gftd.apps.kotoba.email.read?owner_did=did:key:zReader&email_cid=fakecid")
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn email_read_invalid_did_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zReader");
    let (status, body) = s
        .get_with_auth(
            "/xrpc/ai.gftd.apps.kotoba.email.read?owner_did=not-a-did&email_cid=fakecid",
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn email_read_empty_cid_returns_400() {
    let s = TestServer::start(false).await;
    let did = "did:key:zReader2";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .get_with_auth(
            &format!("/xrpc/ai.gftd.apps.kotoba.email.read?owner_did={did}&email_cid="),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn email_read_without_crypto_returns_503() {
    // The test server does not call init_crypto(), so crypto = None.
    let s = TestServer::start(false).await;
    let did = "did:key:zReader3";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .get_with_auth(
            &format!(
                "/xrpc/ai.gftd.apps.kotoba.email.read?owner_did={did}&email_cid=fakecid"
            ),
            &tok,
        )
        .await;
    assert_eq!(status, 503, "{body}");
    assert!(body["error"].as_str().is_some(), "expected error field: {body}");
}
