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
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({ "graph": "e2e", "subject": "alice", "predicate": "knows", "object": "bob" }),
    ).await;
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

    s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({ "graph": "qtest", "subject": "x", "predicate": "rel", "object": "y" }),
    ).await;

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
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.retract",
        json!({ "graph": "e2e", "subject": "alice", "predicate": "knows", "object": "bob" }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
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

    s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({ "graph": "commit-e2e", "subject": "s", "predicate": "p", "object": "o" }),
    ).await;

    let (status, store) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.commit.store",
        json!({ "graph": graph_cid, "author": "did:plc:e2e", "seq": 1 }),
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
    assert_eq!(tools.len(), 13);
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
        let (st, b) = s.post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({ "graph": g, "subject": subj, "predicate": pred, "object": obj }),
        ).await;
        assert_eq!(st, 200, "seed failed for {pred}: {b}");
    }

    // Seed one claim
    let (st, _) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({ "graph": g, "subject": subj, "predicate": "kg/claim/birthYear", "object": "1990" }),
    ).await;
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
        s.post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({ "graph": g, "subject": subj, "predicate": pred, "object": obj }),
        ).await;
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

#[tokio::test]
async fn quad_create_without_cacao_still_works() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({ "graph": "public", "subject": "alice", "predicate": "knows", "object": "bob" }),
    ).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn quad_create_invalid_cacao_b64_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({
            "graph": "private-graph",
            "subject": "alice",
            "predicate": "knows",
            "object": "bob",
            "cacao_b64": "not-valid-base64!!!"
        }),
    ).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn quad_create_cacao_cbor_parse_error_returns_400() {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let s = TestServer::start(false).await;
    // Valid base64 but not valid DAG-CBOR
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.quad.create",
        json!({
            "graph": "private-graph",
            "subject": "alice",
            "predicate": "knows",
            "object": "bob",
            "cacao_b64": B64.encode(b"this is not cbor")
        }),
    ).await;
    assert_eq!(status, 400, "{body}");
}
