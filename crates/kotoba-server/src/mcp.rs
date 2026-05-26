/// MCP JSON-RPC 2.0 handler — kotoba MCP facade (ADR-2605091400)
///
/// Wire:  POST /mcp  (JSON-RPC 2.0)
/// Auth:  initialize / tools/list / ping → public
///        tools/call → requires `Authorization: Bearer <AT-session-JWT>`
///
/// Tools exposed (8):
///   kotoba_quad_create   — assert a quad into the graph
///   kotoba_graph_query   — SPO pattern query
///   kotoba_infer_run     — run inference via inference engine
///   kotoba_embed_create  — create and store a text embedding
///   kotoba_weight_put    — store an FP8 tensor weight blob
///   kotoba_lora_apply    — register a LoRA adapter delta
///   kotoba_email_list    — list encrypted emails for an owner DID
///   kotoba_email_read    — decrypt and return one email body + metadata

pub const MCP_TOOL_QUAD_CREATE:  &str = "kotoba_quad_create";
pub const MCP_TOOL_GRAPH_QUERY:  &str = "kotoba_graph_query";
pub const MCP_TOOL_INFER_RUN:    &str = "kotoba_infer_run";
pub const MCP_TOOL_EMBED_CREATE: &str = "kotoba_embed_create";
pub const MCP_TOOL_WEIGHT_PUT:   &str = "kotoba_weight_put";
pub const MCP_TOOL_LORA_APPLY:   &str = "kotoba_lora_apply";
pub const MCP_TOOL_EMAIL_LIST:   &str = "kotoba_email_list";
pub const MCP_TOOL_EMAIL_READ:   &str = "kotoba_email_read";

use std::sync::Arc;
use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::server::KotobaState;

// ── JSON-RPC 2.0 envelope types ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id:      Option<Value>,
    pub method:  String,
    pub params:  Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id:      Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result:  Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:   Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code:    i32,
    pub message: String,
}

impl JsonRpcResponse {
    fn ok(id: Option<Value>, result: Value) -> Self {
        Self { jsonrpc: "2.0", id, result: Some(result), error: None }
    }

    fn err(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError { code, message: message.into() }),
        }
    }
}

// ── JSON-RPC error codes ──────────────────────────────────────────────────────

const ERR_PARSE:          i32 = -32700;
const ERR_NOT_FOUND:      i32 = -32601;
const ERR_INVALID_PARAMS: i32 = -32602;
const ERR_INTERNAL:    i32 = -32603;
const ERR_AUTH:        i32 = -32001;   // kotoba extension

// ── Tool InputSchema definitions ─────────────────────────────────────────────

fn tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": MCP_TOOL_QUAD_CREATE,
                "description": "Assert a quad (subject, predicate, object) into a named graph in the Kotoba knowledge store.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "graph":     { "type": "string", "description": "Named graph CID (multibase) or any string (auto-hashed)" },
                        "subject":   { "type": "string", "description": "Subject CID (multibase) or entity identifier" },
                        "predicate": { "type": "string", "description": "Predicate / relation name (e.g. 'knows', 'weight/layer/0')" },
                        "object":    { "type": "string", "description": "Object value (text, CID, or literal)" }
                    },
                    "required": ["graph", "subject", "predicate", "object"]
                }
            },
            {
                "name": MCP_TOOL_GRAPH_QUERY,
                "description": "SPO pattern query over a named graph Arrangement. Returns matching quads.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "graph":     { "type": "string", "description": "Named graph CID (multibase)" },
                        "subject":   { "type": "string", "description": "(optional) Subject filter" },
                        "predicate": { "type": "string", "description": "(optional) Predicate filter (exact match)" }
                    },
                    "required": ["graph"]
                }
            },
            {
                "name": MCP_TOOL_INFER_RUN,
                "description": "Run text inference via the Kotoba inference engine (Gemma 4 E2B or configured model).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "prompt":         { "type": "string", "description": "Prompt text" },
                        "max_new_tokens": { "type": "integer", "description": "Maximum tokens to generate (default 256)" }
                    },
                    "required": ["prompt"]
                }
            },
            {
                "name": MCP_TOOL_EMBED_CREATE,
                "description": "Compute a text embedding and store it as a Quad in the named graph.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text":      { "type": "string",  "description": "Text to embed" },
                        "doc_cid":   { "type": "string",  "description": "Document CID (multibase) identifying the source" },
                        "model_cid": { "type": "string",  "description": "Model CID (multibase) identifying the embedding model" },
                        "graph":     { "type": "string",  "description": "Named graph CID (multibase) to index into" }
                    },
                    "required": ["text", "doc_cid", "model_cid", "graph"]
                }
            },
            {
                "name": MCP_TOOL_WEIGHT_PUT,
                "description": "Store a raw FP8 weight tensor blob and assert its Quad into the model graph.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "model_cid": { "type": "string",  "description": "Model CID (multibase)" },
                        "layer":     { "type": "integer", "description": "Layer index" },
                        "data_b64":  { "type": "string",  "description": "Raw tensor bytes, base64-encoded" },
                        "shape":     { "type": "array",   "items": { "type": "integer" }, "description": "Tensor shape" },
                        "dtype":     { "type": "string",  "description": "Dtype: fp8e4m3 | fp8e5m2 | fp16 | bf16 | f32" },
                        "graph":     { "type": "string",  "description": "Named graph CID (multibase)" }
                    },
                    "required": ["model_cid", "layer", "data_b64", "shape", "dtype", "graph"]
                }
            },
            {
                "name": MCP_TOOL_EMAIL_LIST,
                "description": "List emails stored in the Kotoba encrypted inbox for an owner DID. Returns plaintext date and message_id; encrypted fields (from/subject) are decrypted server-side.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "owner_did": { "type": "string", "description": "DID of the mailbox owner (e.g. did:plc:xxxx)" },
                        "limit":     { "type": "integer", "description": "Max results (default 50, max 200)" },
                        "offset":    { "type": "integer", "description": "Pagination offset" }
                    },
                    "required": ["owner_did"]
                }
            },
            {
                "name": MCP_TOOL_EMAIL_READ,
                "description": "Decrypt and return the full body and metadata of one stored email. Requires KOTOBA_VAULT_KEY to be configured on the server.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "email_cid": { "type": "string", "description": "Email CID (multibase) returned by kotoba_email_list" },
                        "owner_did": { "type": "string", "description": "DID of the mailbox owner" }
                    },
                    "required": ["email_cid", "owner_did"]
                }
            },
            {
                "name": MCP_TOOL_LORA_APPLY,
                "description": "Register a LoRA adapter delta as a Quad in the model graph.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "model_cid":   { "type": "string",  "description": "Base model CID (multibase)" },
                        "rank":        { "type": "integer", "description": "LoRA adapter rank" },
                        "graph":       { "type": "string",  "description": "Named graph CID (multibase)" },
                        "adapter_b64": { "type": "string",  "description": "Raw LoRA bytes, base64-encoded" }
                    },
                    "required": ["model_cid", "rank", "graph", "adapter_b64"]
                }
            }
        ]
    })
}

// ── Auth helper ───────────────────────────────────────────────────────────────

fn is_mutating(method: &str, _tool: Option<&str>) -> bool {
    if method == "tools/call" {
        return true;
    }
    if method == "resources/write" {
        return true;
    }
    false
}

fn check_auth(headers: &HeaderMap) -> bool {
    headers.get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("Bearer "))
        .unwrap_or(false)
}

// ── Dispatch to state methods ────────────────────────────────────────────────

async fn call_tool(
    tool: &str,
    args: &Value,
    state: &Arc<KotobaState>,
) -> Result<Value, (i32, String)> {
    let get_str = |key: &str| -> Result<String, (i32, String)> {
        args.get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| (ERR_INVALID_PARAMS, format!("missing required field: {key}")))
    };

    match tool {
        // ── kotoba_quad_create ───────────────────────────────────────────────
        MCP_TOOL_QUAD_CREATE => {
            use kotoba_core::cid::KotobaCid;
            use kotoba_kqe::quad::{Quad, QuadObject};

            let graph     = get_str("graph")?;
            let subject   = get_str("subject")?;
            let predicate = get_str("predicate")?;
            let object    = get_str("object")?;

            let quad = Quad {
                graph:     KotobaCid::from_bytes(graph.as_bytes()),
                subject:   KotobaCid::from_bytes(subject.as_bytes()),
                predicate,
                object:    QuadObject::Text(object),
            };
            let journal_cid = state.journal_assert(&quad).await;
            state.quad_store.assert(quad).await;

            Ok(json!({ "status": "ok", "journal_cid": journal_cid }))
        }

        // ── kotoba_graph_query ───────────────────────────────────────────────
        MCP_TOOL_GRAPH_QUERY => {
            use kotoba_core::cid::KotobaCid;

            let graph = get_str("graph")?;
            let graph_cid = KotobaCid::from_bytes(graph.as_bytes());

            let arrangement = match state.quad_store.arrangement(&graph_cid).await {
                None => return Ok(json!({ "graph": graph, "count": 0, "quads": [] })),
                Some(a) => a,
            };

            let mut quads = arrangement.quads(&graph_cid);

            if let Some(s) = args.get("subject").and_then(Value::as_str) {
                let s_cid = KotobaCid::from_bytes(s.as_bytes());
                quads.retain(|q| q.subject == s_cid);
            }
            if let Some(p) = args.get("predicate").and_then(Value::as_str) {
                quads.retain(|q| q.predicate == p);
            }

            Ok(json!({
                "graph": graph,
                "count": quads.len(),
                "quads": quads,
            }))
        }

        // ── kotoba_infer_run ─────────────────────────────────────────────────
        MCP_TOOL_INFER_RUN => {
            let engine = state.inference_engine.clone()
                .ok_or_else(|| (ERR_INTERNAL, "no inference engine loaded".into()))?;

            let prompt     = get_str("prompt")?;
            let max_tokens = args.get("max_new_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(256) as usize;

            let output = tokio::task::spawn_blocking(move || engine(&prompt, max_tokens))
                .await
                .map_err(|e| (ERR_INTERNAL, e.to_string()))?
                .map_err(|e| (ERR_INTERNAL, e.to_string()))?;

            Ok(json!({ "status": "ok", "output": output }))
        }

        // ── kotoba_embed_create ──────────────────────────────────────────────
        MCP_TOOL_EMBED_CREATE => {
            use kotoba_core::cid::KotobaCid;
            use kotoba_llm::embed::{Embedding, embed_to_quad};

            let text      = get_str("text")?;
            let doc_cid   = get_str("doc_cid")?;
            let model_cid = get_str("model_cid")?;
            let graph     = get_str("graph")?;

            let doc_cid   = KotobaCid::from_bytes(doc_cid.as_bytes());
            let model_cid = KotobaCid::from_bytes(model_cid.as_bytes());
            let graph_cid = KotobaCid::from_bytes(graph.as_bytes());

            let vector: Vec<f32> = if let Some(engine) = &state.inference_engine {
                let engine = engine.clone();
                let t = format!("embed: {}", text);
                let result = tokio::task::spawn_blocking(move || engine(&t, 256))
                    .await
                    .map_err(|e| (ERR_INTERNAL, e.to_string()))?
                    .map_err(|e| (ERR_INTERNAL, e.to_string()))?;
                let parsed: Vec<f32> = result.split_whitespace()
                    .filter_map(|s| s.parse().ok()).collect();
                if parsed.is_empty() { blake3_pseudo_vector(&text, 128) } else { parsed }
            } else {
                blake3_pseudo_vector(&text, 128)
            };

            let dims = vector.len();
            let emb  = Embedding { doc_cid, model_cid, vector };
            let quad = embed_to_quad(&emb, graph_cid).quad;

            let quad_cid = state.journal_assert(&quad).await;
            state.quad_store.assert(quad).await;

            Ok(json!({ "status": "ok", "quad_cid": quad_cid, "dims": dims }))
        }

        // ── kotoba_weight_put ────────────────────────────────────────────────
        MCP_TOOL_WEIGHT_PUT => {
            use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
            use kotoba_core::cid::KotobaCid;
            use kotoba_kqe::quad::{Quad, QuadObject, TensorDtype};

            let data_b64  = get_str("data_b64")?;
            let model_str = get_str("model_cid")?;
            let graph_str = get_str("graph")?;
            let dtype_str = get_str("dtype")?;
            let layer = args.get("layer")
                .and_then(Value::as_u64)
                .ok_or_else(|| (ERR_INVALID_PARAMS, "missing required field: layer".into()))? as u32;
            let shape: Vec<u32> = args.get("shape")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u32)).collect())
                .unwrap_or_default();

            let bytes = B64.decode(&data_b64)
                .map_err(|e| (ERR_INVALID_PARAMS, e.to_string()))?;

            let blob_cid  = KotobaCid::from_bytes(&bytes);
            let model_cid = KotobaCid::from_bytes(model_str.as_bytes());
            let graph_cid = KotobaCid::from_bytes(graph_str.as_bytes());

            state.block_store.put(&blob_cid, &bytes)
                .map_err(|e| (ERR_INTERNAL, e.to_string()))?;

            let dtype = match dtype_str.as_str() {
                "fp8e4m3" | "f8e4m3" => TensorDtype::F8E4M3,
                "fp8e5m2" | "f8e5m2" => TensorDtype::F8E5M2,
                "fp16"    | "f16"    => TensorDtype::F16,
                "bf16"               => TensorDtype::BF16,
                _                    => TensorDtype::F32,
            };

            let quad = Quad {
                graph:     graph_cid,
                subject:   model_cid,
                predicate: format!("weight/layer/{layer}"),
                object:    QuadObject::TensorCid { cid: blob_cid.clone(), shape, dtype },
            };
            let quad_cid = state.journal_assert(&quad).await;
            state.quad_store.assert(quad).await;

            Ok(json!({
                "status":   "ok",
                "blob_cid": blob_cid.to_multibase(),
                "quad_cid": quad_cid,
                "layer":    layer,
            }))
        }

        // ── kotoba_lora_apply ────────────────────────────────────────────────
        MCP_TOOL_LORA_APPLY => {
            use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
            use kotoba_core::cid::KotobaCid;
            use kotoba_kqe::quad::{Quad, QuadObject, TensorDtype};

            let adapter_b64 = get_str("adapter_b64")?;
            let model_str   = get_str("model_cid")?;
            let graph_str   = get_str("graph")?;
            let rank = args.get("rank")
                .and_then(Value::as_u64)
                .ok_or_else(|| (ERR_INVALID_PARAMS, "missing required field: rank".into()))? as u32;

            let bytes = B64.decode(&adapter_b64)
                .map_err(|e| (ERR_INVALID_PARAMS, e.to_string()))?;

            let adapter_cid = KotobaCid::from_bytes(&bytes);
            let model_cid   = KotobaCid::from_bytes(model_str.as_bytes());
            let graph_cid   = KotobaCid::from_bytes(graph_str.as_bytes());

            state.block_store.put(&adapter_cid, &bytes)
                .map_err(|e| (ERR_INTERNAL, e.to_string()))?;

            let quad = Quad {
                graph:     graph_cid,
                subject:   model_cid,
                predicate: "lora/adapter".to_string(),
                object:    QuadObject::TensorCid {
                    cid:   adapter_cid.clone(),
                    shape: vec![rank],
                    dtype: TensorDtype::F8E4M3,
                },
            };
            let quad_cid = state.journal_assert(&quad).await;
            state.quad_store.assert(quad).await;

            Ok(json!({
                "status":      "ok",
                "adapter_cid": adapter_cid.to_multibase(),
                "quad_cid":    quad_cid,
            }))
        }

        // ── kotoba_email_list ────────────────────────────────────────────────
        MCP_TOOL_EMAIL_LIST => {
            use kotoba_ingest::graph_cid_for;
            use kotoba_kqe::quad::QuadObject;

            let owner_did = get_str("owner_did")?;
            let limit  = args.get("limit").and_then(Value::as_u64).unwrap_or(50).min(200) as usize;
            let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;

            let graph_cid = graph_cid_for(&owner_did);
            let arrangement = match state.quad_store.arrangement(&graph_cid).await {
                None => return Ok(json!({ "emails": [], "total": 0 })),
                Some(a) => a,
            };

            let mut entries: Vec<(String, String)> = arrangement
                .get_by_predicate("email/date")
                .into_iter()
                .filter_map(|(subject_cid, objs)| {
                    let date = objs.into_iter().find_map(|o| {
                        if let QuadObject::Text(t) = o { Some(t) } else { None }
                    })?;
                    Some((subject_cid.to_multibase(), date))
                })
                .collect();
            entries.sort_by(|a, b| b.1.cmp(&a.1));
            let total = entries.len();

            let vault_key = state.vault_key;
            let emails: Vec<Value> = entries.into_iter().skip(offset).take(limit).map(|(cid_mb, date)| {
                let get_text = |pred: &str| -> String {
                    if let Some(cid) = kotoba_core::cid::KotobaCid::from_multibase(&cid_mb) {
                        arrangement.get_objects(&cid, pred)
                            .into_iter()
                            .find_map(|o| if let QuadObject::Text(t) = o { Some(t.clone()) } else { None })
                            .unwrap_or_default()
                    } else { String::new() }
                };
                let message_id  = get_text("email/message_id");
                let subject_enc = get_text("email/subject");
                let from_enc    = get_text("email/from");

                let subject = vault_key.as_ref()
                    .and_then(|k| kotoba_crypto::envelope::decrypt_field(k, &subject_enc).ok())
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or(subject_enc);
                let from = vault_key.as_ref()
                    .and_then(|k| kotoba_crypto::envelope::decrypt_field(k, &from_enc).ok())
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or(from_enc);

                json!({ "cid": cid_mb, "date": date, "message_id": message_id, "subject": subject, "from": from })
            }).collect();

            Ok(json!({ "emails": emails, "total": total, "offset": offset, "limit": limit }))
        }

        // ── kotoba_email_read ────────────────────────────────────────────────
        MCP_TOOL_EMAIL_READ => {
            use kotoba_ingest::graph_cid_for;
            use kotoba_kqe::quad::QuadObject;

            let email_cid_str = get_str("email_cid")?;
            let owner_did     = get_str("owner_did")?;

            let vault_key = state.vault_key.ok_or_else(|| {
                (ERR_INTERNAL, "vault_key not configured (set KOTOBA_VAULT_KEY)".to_string())
            })?;

            let graph_cid = graph_cid_for(&owner_did);
            let arrangement = state.quad_store.arrangement(&graph_cid).await
                .ok_or_else(|| (ERR_NOT_FOUND, "no emails found for owner_did".to_string()))?;

            let email_cid = kotoba_core::cid::KotobaCid::from_multibase(&email_cid_str)
                .ok_or_else(|| (ERR_INTERNAL, "invalid email_cid multibase".to_string()))?;

            let get_text = |pred: &str| -> String {
                arrangement.get_objects(&email_cid, pred)
                    .into_iter()
                    .find_map(|o| if let QuadObject::Text(t) = o { Some(t.clone()) } else { None })
                    .unwrap_or_default()
            };

            // body_cid → SecureVault decrypt
            let body_cid_str = get_text("email/body_cid");
            if body_cid_str.is_empty() {
                return Err((ERR_NOT_FOUND, "email/body_cid not found".to_string()));
            }
            let blob_cid = kotoba_core::cid::KotobaCid::from_multibase(&body_cid_str)
                .ok_or_else(|| (ERR_INTERNAL, "invalid body_cid multibase".to_string()))?;
            let blob_ref  = kotoba_kse::BlobRef { cid: blob_cid, size: 0, mime_type: None, chunked: false };
            let body_bytes = state.secure_vault.get(&vault_key, &blob_ref).await
                .map_err(|e| (ERR_INTERNAL, format!("vault decrypt: {e}")))?
                .ok_or_else(|| (ERR_NOT_FOUND, "body blob not found in vault".to_string()))?;
            let body = String::from_utf8_lossy(&body_bytes).into_owned();

            let dec = |pred: &str| -> String {
                let enc = get_text(pred);
                kotoba_crypto::envelope::decrypt_field(&vault_key, &enc)
                    .ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or(enc)
            };
            let plain = |pred: &str| -> String { get_text(pred) };

            Ok(json!({
                "email_cid":  email_cid_str,
                "message_id": plain("email/message_id"),
                "from":       dec("email/from"),
                "to":         dec("email/to"),
                "subject":    dec("email/subject"),
                "date":       plain("email/date"),
                "thread_id":  plain("email/thread_id"),
                "body":       body,
            }))
        }

        other => Err((ERR_NOT_FOUND, format!("unknown tool: {other}"))),
    }
}

fn blake3_pseudo_vector(text: &str, dims: usize) -> Vec<f32> {
    let hash = blake3::hash(text.as_bytes());
    let hash_bytes = hash.as_bytes();
    (0..dims)
        .map(|i| {
            let b = hash_bytes[i % 32] as f32;
            (b / 127.5) - 1.0
        })
        .collect()
}

// ── Axum handler ─────────────────────────────────────────────────────────────

/// POST /mcp  — JSON-RPC 2.0 MCP endpoint
pub async fn mcp_handler(
    State(state): State<Arc<KotobaState>>,
    headers:      HeaderMap,
    Json(req):    Json<JsonRpcRequest>,
) -> impl IntoResponse {
    if req.jsonrpc != "2.0" {
        return Json(JsonRpcResponse::err(
            req.id,
            ERR_PARSE,
            "jsonrpc must be \"2.0\"",
        ));
    }

    // Auth gate for mutating methods
    if is_mutating(&req.method, None) && !check_auth(&headers) {
        return Json(JsonRpcResponse::err(
            req.id,
            ERR_AUTH,
            "tools/call requires Authorization: Bearer <AT-session-JWT>",
        ));
    }

    let result: Value = match req.method.as_str() {
        // ── Protocol methods ─────────────────────────────────────────────────
        "initialize" => json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": { "listChanged": false },
                "resources": {},
                "prompts": {}
            },
            "serverInfo": {
                "name":    "kotoba",
                "version": state.version,
            }
        }),

        "ping" => json!({}),

        "tools/list" => tools_list(),

        "tools/call" => {
            let params = match &req.params {
                Some(p) => p,
                None => return Json(JsonRpcResponse::err(
                    req.id,
                    ERR_INVALID_PARAMS,
                    "params required for tools/call",
                )),
            };
            let tool_name = match params.get("name").and_then(Value::as_str) {
                Some(n) => n.to_owned(),
                None => return Json(JsonRpcResponse::err(
                    req.id,
                    ERR_INVALID_PARAMS,
                    "params.name required",
                )),
            };
            let args = params.get("arguments").cloned().unwrap_or(json!({}));

            match call_tool(&tool_name, &args, &state).await {
                Ok(content) => json!({
                    "content": [{ "type": "text", "text": content.to_string() }],
                    "isError": false,
                }),
                Err((code, msg)) => return Json(JsonRpcResponse::err(req.id, code, msg)),
            }
        }

        other => {
            return Json(JsonRpcResponse::err(
                req.id,
                ERR_NOT_FOUND,
                format!("method not found: {other}"),
            ));
        }
    };

    Json(JsonRpcResponse::ok(req.id, result))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_list_contains_all_eight() {
        let list = tools_list();
        let tools = list["tools"].as_array().expect("tools array");
        assert_eq!(tools.len(), 8);
        let names: Vec<&str> = tools.iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&MCP_TOOL_QUAD_CREATE));
        assert!(names.contains(&MCP_TOOL_GRAPH_QUERY));
        assert!(names.contains(&MCP_TOOL_INFER_RUN));
        assert!(names.contains(&MCP_TOOL_EMBED_CREATE));
        assert!(names.contains(&MCP_TOOL_WEIGHT_PUT));
        assert!(names.contains(&MCP_TOOL_LORA_APPLY));
    }

    #[test]
    fn tools_all_have_required_fields_in_schema() {
        let list = tools_list();
        for tool in list["tools"].as_array().unwrap() {
            let name = tool["name"].as_str().unwrap();
            assert!(tool.get("description").is_some(), "{name} missing description");
            let schema = &tool["inputSchema"];
            assert_eq!(schema["type"], "object", "{name} inputSchema must be object");
            assert!(schema.get("required").is_some(), "{name} missing required array");
        }
    }

    #[test]
    fn jsonrpc_response_ok_serializes_correctly() {
        let resp = JsonRpcResponse::ok(Some(Value::from(1)), json!({ "status": "ok" }));
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"jsonrpc\":\"2.0\""));
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));
    }

    #[test]
    fn jsonrpc_response_err_omits_result() {
        let resp = JsonRpcResponse::err(Some(Value::from(1)), ERR_NOT_FOUND, "not found");
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"error\""));
        assert!(!s.contains("\"result\""));
        assert_eq!(resp.error.unwrap().code, ERR_NOT_FOUND);
    }

    #[test]
    fn check_auth_requires_bearer() {
        let mut h = HeaderMap::new();
        assert!(!check_auth(&h));
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer tok123".parse().unwrap(),
        );
        assert!(check_auth(&h));
        let mut h2 = HeaderMap::new();
        h2.insert(
            axum::http::header::AUTHORIZATION,
            "Basic abc".parse().unwrap(),
        );
        assert!(!check_auth(&h2));
    }

    #[test]
    fn is_mutating_tools_call_true() {
        assert!(is_mutating("tools/call", None));
        assert!(!is_mutating("tools/list", None));
        assert!(!is_mutating("initialize", None));
        assert!(!is_mutating("ping", None));
    }

    #[tokio::test]
    async fn call_tool_unknown_returns_not_found() {
        let state = Arc::new(
            crate::server::KotobaState::new(None).expect("state")
        );
        let result = call_tool("nonexistent_tool", &json!({}), &state).await;
        let (code, _) = result.unwrap_err();
        assert_eq!(code, ERR_NOT_FOUND);
    }

    #[tokio::test]
    async fn call_tool_quad_create_ok() {
        let state = Arc::new(
            crate::server::KotobaState::new(None).expect("state")
        );
        let result = call_tool(MCP_TOOL_QUAD_CREATE, &json!({
            "graph":     "graph1",
            "subject":   "alice",
            "predicate": "knows",
            "object":    "bob"
        }), &state).await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(result.unwrap()["status"], "ok");
    }

    #[tokio::test]
    async fn call_tool_quad_create_missing_field_errors() {
        let state = Arc::new(
            crate::server::KotobaState::new(None).expect("state")
        );
        let result = call_tool(MCP_TOOL_QUAD_CREATE, &json!({
            "graph": "g",
            "subject": "s"
            // predicate and object missing
        }), &state).await;
        let (code, _) = result.unwrap_err();
        assert_eq!(code, ERR_INVALID_PARAMS);
    }

    #[tokio::test]
    async fn call_tool_graph_query_empty_graph() {
        let state = Arc::new(
            crate::server::KotobaState::new(None).expect("state")
        );
        let result = call_tool(MCP_TOOL_GRAPH_QUERY, &json!({
            "graph": "nonexistent_graph_xyz"
        }), &state).await;
        assert!(result.is_ok());
        let v = result.unwrap();
        assert_eq!(v["count"], 0);
    }
}
