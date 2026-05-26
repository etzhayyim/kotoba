/// XRPC endpoint declarations and handlers for Kotoba
/// NSIDs follow ai.gftd.apps.kotoba.* namespace

pub const NSID_QUAD_CREATE:  &str = "ai.gftd.apps.kotoba.quad.create";
pub const NSID_QUAD_RETRACT: &str = "ai.gftd.apps.kotoba.quad.retract";
pub const NSID_GRAPH_QUERY:  &str = "ai.gftd.apps.kotoba.graph.query";
pub const NSID_COMMIT_GET:   &str = "ai.gftd.apps.kotoba.commit.get";
pub const NSID_INVOKE_RUN:   &str = "ai.gftd.apps.kotoba.invoke.run";
pub const NSID_INFER_RUN:    &str = "ai.gftd.apps.kotoba.infer.run";
pub const NSID_WEIGHT_PUT:   &str = "ai.gftd.apps.kotoba.weight.put";
pub const NSID_LORA_APPLY:   &str = "ai.gftd.apps.kotoba.lora.apply";
pub const NSID_EMBED_CREATE: &str = "ai.gftd.apps.kotoba.embed.create";
pub const NSID_NODE_STATUS:  &str = "ai.gftd.apps.kotoba.node.status";
pub const NSID_BLOCK_PUT:    &str = "ai.gftd.apps.kotoba.block.put";
pub const NSID_BLOCK_GET:    &str = "ai.gftd.apps.kotoba.block.get";
pub const NSID_COMMIT_STORE: &str = "ai.gftd.apps.kotoba.commit.store";
pub const NSID_AGENT_RUN:        &str = "ai.gftd.apps.kotoba.agent.run";
pub const NSID_AGENT_SYNC_OPEN:  &str = "ai.gftd.apps.kotoba.agent.syncopen";
pub const NSID_AGENT_SYNC_ADV:   &str = "ai.gftd.apps.kotoba.agent.syncadvance";
pub const NSID_AGENT_SYNC_CLOSE: &str = "ai.gftd.apps.kotoba.agent.syncclose";
pub const NSID_VAULT_PUT:        &str = "ai.gftd.apps.kotoba.vault.put";
pub const NSID_VAULT_GET:        &str = "ai.gftd.apps.kotoba.vault.get";

use std::sync::Arc;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use crate::server::KotobaState;

// ── Request / Response types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct QuadCreateReq {
    pub graph:     String,
    pub subject:   String,
    pub predicate: String,
    pub object:    String,
    /// Optional CACAO warrant (DAG-CBOR, base64-standard encoded).
    /// When present: verified before write; `cacao.p.graph_cid()` must match `graph`.
    /// Issuer DID becomes the authoritative namespace for this write.
    pub cacao_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VaultPutReq {
    /// Raw blob encoded as standard base64.
    pub data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct VaultPutResp {
    pub cid:  String,
    pub size: usize,
}

#[derive(Debug, Serialize)]
pub struct VaultGetResp {
    pub cid:      String,
    pub data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct QuadCreateResp {
    pub status:     &'static str,
    pub journal_cid: String,
}

#[derive(Debug, Deserialize)]
pub struct InvokeRunReq {
    pub program_cid:  String,
    /// "wasm-node" | "wasm-udf" | "datalog"
    pub program_type: String,
    pub agent_did:    String,
    pub wasm_b64:     Option<String>,
    pub ctx_b64:      Option<String>,
    /// Named graph CID (multibase) — when supplied, the graph's Arrangement is
    /// snapshotted into HostState so WASM guests can call `kqe.query`.
    pub graph_cid:    Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvokeRunResp {
    pub status:         &'static str,
    pub gas_used:       u64,
    pub output_b64:     String,
    pub assert_count:   usize,
    pub retract_count:  usize,
    /// CIDs of Journal entries created for each asserted quad
    pub journal_cids:   Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResp {
    pub status:      &'static str,
    pub version:     &'static str,
    pub subsystems:  SubsystemStatus,
    pub node:        NodeInfo,
}

#[derive(Debug, Serialize)]
pub struct SubsystemStatus {
    pub kse_journal:   &'static str,
    pub kse_shelf:     &'static str,
    pub wasm_executor: &'static str,
    pub udf_executor:  &'static str,
    pub invoke_router: &'static str,
}

#[derive(Debug, Serialize)]
pub struct NodeInfo {
    pub node_id:    String,
    pub peer_count: usize,
}

// ── Handlers ───────────────────────────────────────────────────────────────

/// GET /_app/meta  /  GET /health
pub async fn health(State(state): State<Arc<KotobaState>>) -> impl IntoResponse {
    let neighborhood = state.neighborhood.read().await;
    Json(HealthResp {
        status:  "ok",
        version: state.version,
        subsystems: SubsystemStatus {
            kse_journal:   "ready",
            kse_shelf:     "ready",
            wasm_executor: "ready",
            udf_executor:  "ready",
            invoke_router: "ready",
        },
        node: NodeInfo {
            node_id:    hex::encode(state.local_node_id.0),
            peer_count: neighborhood.peers.len(),
        },
    })
}

fn map_delegation_error(e: kotoba_auth::DelegationError) -> (StatusCode, String) {
    use kotoba_auth::DelegationError;
    match &e {
        DelegationError::Expired => (StatusCode::UNAUTHORIZED, "cacao expired".to_string()),
        DelegationError::GraphMismatch { expected, got } => (
            StatusCode::UNAUTHORIZED,
            format!("cacao graph mismatch: warrant covers {expected}, request targets {got}"),
        ),
        _ => (StatusCode::UNAUTHORIZED, format!("cacao delegation: {e}")),
    }
}

/// Resolve a `did:web:` DID document over HTTPS, extract the Ed25519 public key,
/// verify the CACAO signature, and check expiry + graph scope.
///
/// `did:web:domain`       → `https://domain/.well-known/did.json`
/// `did:web:domain:path`  → `https://domain/path/did.json`
async fn resolve_and_verify_did_web(
    cacao: &kotoba_auth::Cacao,
    graph: &str,
    client: &reqwest::Client,
) -> Result<String, (StatusCode, String)> {
    use kotoba_auth::DidDocument;

    // P3 — expiry check (DelegationChain path handles this for non-web DIDs)
    if cacao.is_expired() {
        return Err((StatusCode::UNAUTHORIZED, "cacao expired".to_string()));
    }

    // P3 — capability check
    if let Some(cap) = cacao.p.capability() {
        if cap != "quad:write" {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("capability denied: need 'quad:write', CACAO grants '{cap}'"),
            ));
        }
    }

    // P3 — graph scope check
    if let Some(cacao_graph) = cacao.p.graph_cid() {
        if cacao_graph != graph {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("cacao graph mismatch: warrant covers {cacao_graph}, request targets {graph}"),
            ));
        }
    }

    // Build did:web fetch URL
    let suffix = cacao.p.iss.strip_prefix("did:web:").unwrap_or(&cacao.p.iss);
    let url = if suffix.contains(':') {
        format!("https://{}/did.json", suffix.replace(':', "/"))
    } else {
        format!("https://{}/.well-known/did.json", suffix)
    };

    let resp = client.get(&url).send().await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("did:web fetch {url}: {e}")))?;
    if !resp.status().is_success() {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("did:web fetch {url}: HTTP {}", resp.status()),
        ));
    }
    let doc: DidDocument = resp.json().await
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("did:web document parse: {e}")))?;

    let pubkey = doc.ed25519_public_key()
        .ok_or_else(|| (
            StatusCode::UNAUTHORIZED,
            format!("no Ed25519 key in DID document for {}", cacao.p.iss),
        ))?;

    cacao.verify_with_pubkey(&pubkey)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("did:web sig: {e}")))
}

/// POST /xrpc/ai.gftd.apps.kotoba.quad.create
/// Publish a Quad assert to the KSE Journal (SPO topic).
///
/// `cacao_b64` is required. The CACAO is verified before the write:
/// - Signature must be valid (EdDSA or eip191)
/// - `cacao.p.graph_cid()` must match the requested `graph` field when present
/// - Issuer DID is stored as a `meta/author` quad on the same graph for provenance
pub async fn quad_create(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<QuadCreateReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::quad::{Quad, QuadObject};
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

    // ── CACAO verification (required) ────────────────────────────────────
    let b64 = req.cacao_b64.as_deref()
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "cacao_b64 is required for quad.create".to_string()))?;

    let cbor = B64.decode(b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao_b64 decode: {e}")))?;
    let cacao = kotoba_auth::Cacao::from_cbor(&cbor)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao parse: {e}")))?;

    // Dispatch on issuer DID method:
    //   did:web:*  → P3: resolve DID document over HTTP, verify with extracted key
    //   everything else → P1: DelegationChain verifies expiry + capability + graph + sig
    let issuer_did = if cacao.p.iss.starts_with("did:web:") {
        resolve_and_verify_did_web(&cacao, &req.graph, &state.http_client).await?
    } else {
        kotoba_auth::DelegationChain::new(cacao)
            .verify(&req.graph, "quad:write")
            .map_err(map_delegation_error)?
    };

    tracing::info!(issuer = %issuer_did, graph = %req.graph, "quad.create: CACAO verified");

    let quad = Quad {
        graph:     KotobaCid::from_bytes(req.graph.as_bytes()),
        subject:   KotobaCid::from_bytes(req.subject.as_bytes()),
        predicate: req.predicate.clone(),
        object:    QuadObject::Text(req.object.clone()),
    };

    // Journal (B2 persistence + GossipSub) AND QuadStore (Arrangement + ProllyTree)
    let journal_cid = state.journal_assert(&quad).await;
    state.quad_store.assert(quad).await;

    // ── Store author provenance ───────────────────────────────────────────
    // Subject = journal CID of the write so (graph, journal_cid, meta/author) is
    // globally unique and references the exact write event.
    // Use from_multibase so the subject CID matches what graph.query decodes.
    let author_subject = KotobaCid::from_multibase(&journal_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(journal_cid.as_bytes()));
    let author_quad = Quad {
        graph:     KotobaCid::from_bytes(req.graph.as_bytes()),
        subject:   author_subject,
        predicate: "meta/author".to_string(),
        object:    QuadObject::Text(issuer_did.clone()),
    };
    state.quad_store.assert(author_quad).await;

    tracing::info!(
        graph     = %req.graph,
        subject   = %req.subject,
        predicate = %req.predicate,
        cid       = %journal_cid,
        author    = %issuer_did,
        "quad.create → Journal + QuadStore"
    );

    Ok((StatusCode::OK, Json(QuadCreateResp { status: "ok", journal_cid })))
}

/// POST /xrpc/ai.gftd.apps.kotoba.vault.put
/// Store an opaque blob in the private Vault.  Returns a CID (multibase blake3).
/// No GossipSub propagation — vault blobs stay local (or in B2 when configured).
pub async fn vault_put(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<VaultPutReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use bytes::Bytes;

    let data = B64.decode(&req.data_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("data_b64 decode: {e}")))?;

    let blob_ref = state.vault.put(Bytes::from(data)).await;
    tracing::info!(cid = %blob_ref.cid.to_multibase(), size = blob_ref.size, "vault.put");

    Ok((StatusCode::OK, Json(VaultPutResp {
        cid:  blob_ref.cid.to_multibase(),
        size: blob_ref.size,
    })))
}

/// GET /xrpc/ai.gftd.apps.kotoba.vault.get?cid=<multibase>
/// Retrieve a blob from the Vault by CID.  Returns 404 if not found.
pub async fn vault_get(
    State(state): State<Arc<KotobaState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use kotoba_core::cid::KotobaCid;

    let cid_str = params.get("cid")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing `cid` query param".to_string()))?;

    let cid = KotobaCid::from_multibase(cid_str)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid CID: {cid_str}")))?;

    let data = state.vault.get(&cid).await
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("vault: CID not found: {cid_str}")))?;

    Ok((StatusCode::OK, Json(VaultGetResp {
        cid:      cid_str.to_string(),
        data_b64: B64.encode(&data),
    })))
}

/// GET /xrpc/ai.gftd.apps.kotoba.node.status
pub async fn node_status(State(state): State<Arc<KotobaState>>) -> impl IntoResponse {
    let nb = state.neighborhood.read().await;
    Json(serde_json::json!({
        "node_id":    hex::encode(state.local_node_id.0),
        "peer_count": nb.peers.len(),
        "peers":      nb.peers.iter().map(|p| hex::encode(p.0)).collect::<Vec<_>>(),
        "k":          kotoba_dht::neighborhood::K,
    }))
}

/// POST /xrpc/ai.gftd.apps.kotoba.invoke.run
/// Execute a WASM component or Datalog program, then publish resulting quads to Journal.
pub async fn invoke_run(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<InvokeRunReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_dht::source_chain::ProgramType;
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

    let program_type = match req.program_type.as_str() {
        "wasm-node" => ProgramType::WasmNode,
        "wasm-udf"  => ProgramType::WasmUdf,
        "datalog"   => ProgramType::Datalog,
        other => return Err((StatusCode::BAD_REQUEST, format!("unknown program_type: {other}"))),
    };

    let wasm_bytes: Vec<u8> = match &req.wasm_b64 {
        Some(b64) => B64.decode(b64).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
        None if program_type != ProgramType::Datalog => {
            return Err((StatusCode::BAD_REQUEST, "wasm_b64 required for wasm programs".into()));
        }
        None => vec![],
    };

    let ctx_cbor: Vec<u8> = match &req.ctx_b64 {
        Some(b64) => B64.decode(b64).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
        None => vec![],
    };

    use kotoba_core::cid::KotobaCid;
    use kotoba_vm::DispatchResult;
    use kotoba_kqe::quad::{Quad, QuadObject};
    use kotoba_runtime::host::WitQuad;

    // Build quad snapshot from the named graph's Arrangement for kqe.query in WASM guests.
    let graph_cid_for_snapshot = req.graph_cid.as_deref()
        .map(KotobaCid::from_multibase)
        .and_then(|x| x);
    let quad_snapshot: Vec<WitQuad> = if let Some(gcid) = &graph_cid_for_snapshot {
        state.quad_store.arrangement(gcid).await
            .map(|arr| arr.quads(gcid).into_iter().map(|q| WitQuad {
                graph:       q.graph.to_multibase(),
                subject:     q.subject.to_multibase(),
                predicate:   q.predicate,
                object_cbor: serde_json::to_vec(&q.object).unwrap_or_default(),
            }).collect())
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Build head commits map for kqe.get-head in WASM guests.
    let head_commits = state.quad_store.head_commit_map().await;

    // Move owned data into spawn_blocking — dispatch is CPU-bound (Cranelift JIT)
    let program_cid = req.program_cid.clone();
    let agent_did   = req.agent_did.clone();
    let router      = Arc::clone(&state.router);
    let wasm_owned  = if wasm_bytes.is_empty() { None } else { Some(wasm_bytes) };

    let result = tokio::task::spawn_blocking(move || {
        let wasm_ref = wasm_owned.as_deref();
        router.dispatch_with_snapshot(
            &program_cid,
            program_type,
            &agent_did,
            0,
            wasm_ref,
            ctx_cbor,
            None,
            None,
            &[],
            10_000,
            quad_snapshot,
            head_commits,
        )
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match result {
        DispatchResult::Wasm(r) => {
            // Publish each asserted quad to KSE Journal
            let mut journal_cids = Vec::with_capacity(r.assert_quads.len());
            for sq in &r.assert_quads {
                let quad = Quad {
                    graph:     KotobaCid::from_bytes(sq.graph.as_bytes()),
                    subject:   KotobaCid::from_bytes(sq.subject.as_bytes()),
                    predicate: sq.predicate.clone(),
                    object:    QuadObject::Bytes(sq.object_cbor.clone()),
                };
                let cid = state.journal_assert(&quad).await;
                journal_cids.push(cid);
            }
            // Publish retracts
            for sq in &r.retract_quads {
                let quad = Quad {
                    graph:     KotobaCid::from_bytes(sq.graph.as_bytes()),
                    subject:   KotobaCid::from_bytes(sq.subject.as_bytes()),
                    predicate: sq.predicate.clone(),
                    object:    QuadObject::Bytes(sq.object_cbor.clone()),
                };
                state.journal_retract(&quad).await;
            }
            // Apply kse.publish calls buffered by guest WASM
            for (topic, payload) in &r.pending_publishes {
                use kotoba_kse::Topic;
                state.journal.publish(
                    Topic(topic.clone()),
                    bytes::Bytes::from(payload.clone()),
                ).await;
            }

            tracing::info!(
                program_cid = %req.program_cid,
                gas_used    = r.gas_used,
                asserts     = r.assert_quads.len(),
                retracts    = r.retract_quads.len(),
                kse_publishes = r.pending_publishes.len(),
                chain_entries = r.pending_chain_entries.len(),
                "invoke.run → Journal published"
            );

            Ok(Json(InvokeRunResp {
                status:        "ok",
                gas_used:      r.gas_used,
                output_b64:    B64.encode(&r.output_cbor),
                assert_count:  r.assert_quads.len(),
                retract_count: r.retract_quads.len(),
                journal_cids,
            }))
        }

        DispatchResult::Datalog(r) => {
            Ok(Json(InvokeRunResp {
                status:        "ok",
                gas_used:      r.steps_used as u64,
                output_b64:    B64.encode(format!("{:?}", r.status)),
                assert_count:  r.out_deltas.len(),
                retract_count: 0,
                journal_cids:  vec![],
            }))
        }
    }
}

// ── Block store endpoints ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BlockPutReq {
    /// base64-encoded raw block bytes
    pub data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct BlockPutResp {
    pub cid: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockGetReq {
    pub cid: String,
}

#[derive(Debug, Serialize)]
pub struct BlockGetResp {
    pub cid:      String,
    pub data_b64: String,
}

/// POST /xrpc/ai.gftd.apps.kotoba.block.put
/// Write raw bytes into the block store, returning the CID.
pub async fn block_put(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<BlockPutReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use kotoba_core::cid::KotobaCid;

    let bytes = B64.decode(&req.data_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let cid = KotobaCid::from_bytes(&bytes);
    state.block_store.put(&cid, &bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Fire-and-forget IPFS pin (E) — no-op if KOTOBA_IPFS_PIN_ENDPOINT not set
    if let Some(pin) = &state.ipfs_pin {
        let pin  = std::sync::Arc::clone(pin);
        let cid_str = cid.to_multibase();
        tokio::spawn(async move { pin.pin(&cid_str).await });
    }

    Ok(Json(BlockPutResp { cid: cid.to_multibase() }))
}

/// GET /xrpc/ai.gftd.apps.kotoba.block.get?cid=<multibase>
pub async fn block_get(
    State(state): State<Arc<KotobaState>>,
    axum::extract::Query(req): axum::extract::Query<BlockGetReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use kotoba_core::cid::KotobaCid;

    let cid = KotobaCid::from_multibase(&req.cid)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid CID".into()))?;
    match state.block_store.get(&cid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        None => Err((StatusCode::NOT_FOUND, "block not found".into())),
        Some(bytes) => Ok(Json(BlockGetResp {
            cid:      req.cid.clone(),
            data_b64: B64.encode(&bytes),
        })),
    }
}

// ── Commit endpoints ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CommitGetReq {
    pub graph: String,
}

#[derive(Debug, Serialize)]
pub struct CommitGetResp {
    pub cid:    String,
    pub graph:  String,
    pub root:   String,
    pub prev:   Option<String>,
    pub author: String,
    pub seq:    u64,
    pub ts:     u64,
}

/// GET /xrpc/ai.gftd.apps.kotoba.commit.get?graph=<multibase>
pub async fn commit_get(
    State(state): State<Arc<KotobaState>>,
    axum::extract::Query(req): axum::extract::Query<CommitGetReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;

    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid graph CID".into()))?;
    match state.quad_store.head_commit(&graph_cid).await {
        None => Err((StatusCode::NOT_FOUND, "no commit for graph".into())),
        Some(c) => Ok(Json(CommitGetResp {
            cid:    c.cid.to_multibase(),
            graph:  c.graph.to_multibase(),
            root:   c.root.to_multibase(),
            prev:   c.prev.map(|p| p.to_multibase()),
            author: c.author,
            seq:    c.seq,
            ts:     c.ts,
        })),
    }
}

/// POST /xrpc/ai.gftd.apps.kotoba.commit.store
/// Flush current Arrangement for the given graph into BlockStore and create a Commit.
#[derive(Debug, Deserialize)]
pub struct CommitStoreReq {
    pub graph:  String,
    pub author: String,
    pub seq:    u64,
}

pub async fn commit_store(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<CommitStoreReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;

    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid graph CID".into()))?;
    let cid = state.quad_store
        .commit(&req.author, graph_cid, req.seq)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if let Some(pin) = state.ipfs_pin.clone() {
        let cid_str = cid.to_multibase();
        tokio::spawn(async move { pin.pin(&cid_str).await });
    }

    Ok(Json(serde_json::json!({ "cid": cid.to_multibase() })))
}

// ── Graph query (B) ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GraphQueryReq {
    /// Named graph CID (multibase base32lower)
    pub graph:     String,
    /// Optional subject CID filter (multibase or raw string)
    pub subject:   Option<String>,
    /// Optional predicate filter (exact string match)
    pub predicate: Option<String>,
    /// Datalog rules reserved for invoke.run; graph.query returns SPO matches only
    pub rules:     Option<String>,
    /// CACAO delegation chain for private graphs (DAG-CBOR, base64-standard encoded).
    pub cacao_b64: Option<String>,
}

/// GET /xrpc/ai.gftd.apps.kotoba.graph.query
/// SPO pattern query over the in-memory Arrangement.
/// Full Datalog evaluation: use invoke.run with program_type=datalog.
pub async fn graph_query(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(req): axum::extract::Query<GraphQueryReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;
    use crate::graph_auth::{AccessDenied, check_read_access};

    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid graph CID".into()))?;

    // ── Read-access gate ─────────────────────────────────────────────────────
    let visibility = state.graph_visibility(&graph_cid).await;
    check_read_access(&visibility, &headers, req.cacao_b64.as_deref())
        .map_err(AccessDenied::into_response)?;

    let arrangement = match state.quad_store.arrangement(&graph_cid).await {
        None => {
            return Ok(Json(serde_json::json!({ "graph": req.graph, "count": 0, "quads": [] })));
        }
        Some(a) => a,
    };

    let mut quads = arrangement.quads(&graph_cid);

    // Subject filter (accept multibase CID or raw string → hash to CID)
    if let Some(s) = &req.subject {
        let s_cid = KotobaCid::from_multibase(s)
            .unwrap_or_else(|| KotobaCid::from_bytes(s.as_bytes()));
        quads.retain(|q| q.subject == s_cid);
    }

    // Predicate filter
    if let Some(p) = &req.predicate {
        quads.retain(|q| &q.predicate == p);
    }

    Ok(Json(serde_json::json!({
        "graph": req.graph,
        "count": quads.len(),
        "quads": quads,
        "note":  if req.rules.is_some() { "use invoke.run for Datalog evaluation" } else { "" },
    })))
}

// ── Weight put (C) ────────────────────────────────────────────────────────

pub const NSID_WEIGHT_GET:  &str = "ai.gftd.apps.kotoba.weight.get";

#[derive(Debug, Deserialize)]
pub struct WeightPutReq {
    /// model CID (multibase) — identifies the model this weight belongs to
    pub model_cid: String,
    /// layer index
    pub layer:     u32,
    /// raw FP8 tensor bytes, base64-encoded
    pub data_b64:  String,
    /// tensor shape e.g. [4096, 4096]
    pub shape:     Vec<u32>,
    /// dtype string: "fp8e4m3" | "fp8e5m2" | "fp16" | "bf16" | "f32"
    pub dtype:     String,
    /// named graph CID (multibase) to index this weight in
    pub graph:     String,
}

#[derive(Debug, Serialize)]
pub struct WeightPutResp {
    pub blob_cid:    String,
    pub quad_cid:    String,
    pub layer:       u32,
}

/// POST /xrpc/ai.gftd.apps.kotoba.weight.put
pub async fn weight_put(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<WeightPutReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::quad::{Quad, QuadObject, TensorDtype};

    let bytes = B64.decode(&req.data_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // 1. Store raw tensor bytes in BlockStore (content-addressed)
    let blob_cid = KotobaCid::from_bytes(&bytes);
    state.block_store.put(&blob_cid, &bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 2. IPFS pin the tensor blob
    if let Some(pin) = &state.ipfs_pin {
        let pin  = std::sync::Arc::clone(pin);
        let cs   = blob_cid.to_multibase();
        tokio::spawn(async move { pin.pin(&cs).await });
    }

    // 3. Parse CIDs
    let model_cid = KotobaCid::from_multibase(&req.model_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.model_cid.as_bytes()));
    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.graph.as_bytes()));

    let dtype = match req.dtype.as_str() {
        "fp8e4m3" | "f8e4m3" => TensorDtype::F8E4M3,
        "fp8e5m2" | "f8e5m2" => TensorDtype::F8E5M2,
        "fp16"    | "f16"    => TensorDtype::F16,
        "bf16"               => TensorDtype::BF16,
        _                    => TensorDtype::F32,
    };

    // 4. Assert WeightRef Quad: (graph, model_cid) --weight/layer/N--> blob_cid
    let quad = Quad {
        graph:     graph_cid,
        subject:   model_cid,
        predicate: format!("weight/layer/{}", req.layer),
        object:    QuadObject::TensorCid {
            cid:   blob_cid.clone(),
            shape: req.shape.clone(),
            dtype,
        },
    };
    let quad_cid = state.journal_assert(&quad).await;
    state.quad_store.assert(quad).await;

    tracing::info!(
        blob_cid = %blob_cid.to_multibase(),
        layer    = req.layer,
        bytes    = bytes.len(),
        "weight.put stored"
    );

    Ok(Json(WeightPutResp {
        blob_cid: blob_cid.to_multibase(),
        quad_cid,
        layer:    req.layer,
    }))
}

// ── Quad retract (D) ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct QuadRetractReq {
    pub graph:     String,
    pub subject:   String,
    pub predicate: String,
    pub object:    String,
}

#[derive(Debug, Serialize)]
pub struct QuadRetractResp {
    pub status:      &'static str,
    pub journal_cid: String,
}

/// POST /xrpc/ai.gftd.apps.kotoba.quad.retract
pub async fn quad_retract(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<QuadRetractReq>,
) -> impl IntoResponse {
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::quad::{Quad, QuadObject};

    let quad = Quad {
        graph:     KotobaCid::from_bytes(req.graph.as_bytes()),
        subject:   KotobaCid::from_bytes(req.subject.as_bytes()),
        predicate: req.predicate.clone(),
        object:    QuadObject::Text(req.object.clone()),
    };

    let journal_cid = state.journal_retract(&quad).await;
    state.quad_store.retract(quad).await;

    tracing::info!(
        graph     = %req.graph,
        subject   = %req.subject,
        predicate = %req.predicate,
        cid       = %journal_cid,
        "quad.retract → Journal + QuadStore"
    );

    (StatusCode::OK, Json(QuadRetractResp { status: "ok", journal_cid }))
}

// ── Weight get (E) ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct WeightGetReq {
    pub cid: String,
}

#[derive(Debug, Serialize)]
pub struct WeightGetResp {
    pub cid:      String,
    pub data_b64: String,
}

/// GET /xrpc/ai.gftd.apps.kotoba.weight.get?cid=<multibase>
pub async fn weight_get(
    State(state): State<Arc<KotobaState>>,
    axum::extract::Query(req): axum::extract::Query<WeightGetReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use kotoba_core::cid::KotobaCid;

    let cid = KotobaCid::from_multibase(&req.cid)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid CID".into()))?;
    match state.block_store.get(&cid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        None => Err((StatusCode::NOT_FOUND, "weight blob not found".into())),
        Some(bytes) => Ok(Json(WeightGetResp {
            cid:      req.cid.clone(),
            data_b64: B64.encode(&bytes),
        })),
    }
}

// ── LoRA apply (F) ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoraApplyReq {
    /// Base model CID (multibase)
    pub model_cid:   String,
    /// LoRA adapter rank
    pub rank:        u32,
    /// Named graph CID (multibase) to index this adapter in
    pub graph:       String,
    /// Raw LoRA adapter bytes, base64-encoded
    pub adapter_b64: String,
}

#[derive(Debug, Serialize)]
pub struct LoraApplyResp {
    pub adapter_cid: String,
    pub quad_cid:    String,
}

/// POST /xrpc/ai.gftd.apps.kotoba.lora.apply
pub async fn lora_apply(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<LoraApplyReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::quad::{Quad, QuadObject, TensorDtype};

    let bytes = B64.decode(&req.adapter_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Store adapter bytes in block store
    let adapter_cid = KotobaCid::from_bytes(&bytes);
    state.block_store.put(&adapter_cid, &bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let model_cid = KotobaCid::from_multibase(&req.model_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.model_cid.as_bytes()));
    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.graph.as_bytes()));

    // Assert LoRA Quad: (graph, model_cid) --lora/adapter--> adapter_cid
    let quad = Quad {
        graph:     graph_cid,
        subject:   model_cid,
        predicate: "lora/adapter".to_string(),
        object:    QuadObject::TensorCid {
            cid:   adapter_cid.clone(),
            shape: vec![req.rank],
            dtype: TensorDtype::F8E4M3,
        },
    };
    let quad_cid = state.journal_assert(&quad).await;
    state.quad_store.assert(quad).await;

    tracing::info!(
        adapter_cid = %adapter_cid.to_multibase(),
        model_cid   = %req.model_cid,
        rank        = req.rank,
        "lora.apply stored"
    );

    Ok(Json(LoraApplyResp {
        adapter_cid: adapter_cid.to_multibase(),
        quad_cid,
    }))
}

// ── Embed create (G) ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EmbedCreateReq {
    /// Text to embed
    pub text:      String,
    /// Document CID (multibase) — identifies the source document
    pub doc_cid:   String,
    /// Model CID (multibase) — identifies the embedding model
    pub model_cid: String,
    /// Named graph CID (multibase) to index this embedding in
    pub graph:     String,
}

#[derive(Debug, Serialize)]
pub struct EmbedCreateResp {
    pub status:   &'static str,
    pub quad_cid: String,
    pub dims:     usize,
}

/// POST /xrpc/ai.gftd.apps.kotoba.embed.create
pub async fn embed_create(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<EmbedCreateReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;
    use kotoba_llm::embed::{Embedding, embed_to_quad};

    let doc_cid   = KotobaCid::from_multibase(&req.doc_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.doc_cid.as_bytes()));
    let model_cid = KotobaCid::from_multibase(&req.model_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.model_cid.as_bytes()));
    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.graph.as_bytes()));

    // Compute embedding vector — use inference engine if available, else blake3 pseudo-vector
    let vector: Vec<f32> = if let Some(engine) = &state.inference_engine {
        let engine = engine.clone();
        let text   = format!("embed: {}", req.text);
        let result = tokio::task::spawn_blocking(move || engine(&text, 256))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // Parse space-separated floats from engine output, fallback to blake3 pseudo-vector
        let parsed: Vec<f32> = result.split_whitespace()
            .filter_map(|s| s.parse::<f32>().ok())
            .collect();
        if parsed.is_empty() {
            // Inference engine returned non-numeric output — build blake3 pseudo-vector
            blake3_pseudo_vector(&req.text, 128)
        } else {
            parsed
        }
    } else {
        // No inference engine: 128-dim blake3 pseudo-embedding
        blake3_pseudo_vector(&req.text, 128)
    };

    let dims = vector.len();
    let emb = Embedding { doc_cid, model_cid, vector };
    let delta = embed_to_quad(&emb, graph_cid);
    let quad  = delta.quad;

    let quad_cid = state.journal_assert(&quad).await;
    state.quad_store.assert(quad).await;

    Ok(Json(EmbedCreateResp { status: "ok", quad_cid, dims }))
}

/// Build a deterministic pseudo-embedding from blake3 hash bytes.
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

// ── Infer run (H) ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct InferRunReq {
    /// Prompt text
    pub prompt:         String,
    /// Maximum tokens to generate
    pub max_new_tokens: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct InferRunResp {
    pub status: &'static str,
    pub output: String,
}

/// POST /xrpc/ai.gftd.apps.kotoba.infer.run
pub async fn infer_run(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<InferRunReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let engine = state.inference_engine.clone()
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "no inference engine loaded".into()))?;

    let max_tokens = req.max_new_tokens.unwrap_or(256);
    let prompt     = req.prompt.clone();

    let output = tokio::task::spawn_blocking(move || engine(&prompt, max_tokens))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(InferRunResp { status: "ok", output }))
}

// ── Agent ReAct loop ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AgentRunReq {
    pub task:      String,
    pub graph_cid: Option<String>,
    pub max_steps: Option<u32>,
    /// Maximum tokens per LLM thought step (default 256)
    pub max_tokens: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AgentRunResp {
    pub status:        &'static str,
    pub session_cid:   String,
    pub steps:         Vec<kotoba_vm::ReActStep>,
    pub final_answer:  Option<String>,
    pub supersteps:    usize,
    /// Commit CID of the session history flushed to BlockStore (ProllyTree)
    pub commit_cid:    Option<String>,
}

/// POST /xrpc/ai.gftd.apps.kotoba.agent.run
///
/// Runs a ReAct agent loop using the Kotoba **Pregel BSP** engine:
///   - vertex_id  = session CID
///   - superstep  = one cycle: Thought → Action → Observation
///   - self-message  → advance to next superstep
///   - vote_halt  → finish action or max_steps reached
///
/// Requires `KOTOBA_LOAD_GEMMA` (or another inference engine) to be loaded.
pub async fn agent_run(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<AgentRunReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;
    use kotoba_vm::{AgentSession, PregelReActRunner, ReActStep, session_to_quads};

    let engine = state.inference_engine.clone()
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE,
            "no inference engine loaded (set KOTOBA_LOAD_GEMMA)".into()))?;

    let graph_cid = req.graph_cid
        .as_deref()
        .map(|s| KotobaCid::from_bytes(s.as_bytes()))
        .unwrap_or_else(|| KotobaCid::from_bytes(b"agent-default-graph"));

    let max_steps  = req.max_steps.unwrap_or(10);
    let max_tokens = req.max_tokens.unwrap_or(256);
    let task       = req.task.clone();
    let graph_cid2 = graph_cid.clone();
    let qs         = Arc::clone(&state.quad_store);
    let journal    = Arc::clone(&state.journal);

    // Run the Pregel ReAct loop in a blocking thread (LLM is sync).
    // Each BSP superstep = one Thought+Action+Observation cycle.
    let (session, superstep_results) = tokio::task::spawn_blocking(move || {
        use kotoba_vm::agent::{Tool, ToolOutput};

        // Override the default no-op kse.publish with a real Journal write.
        let journal2 = Arc::clone(&journal);
        let kse_publish_tool = Tool::from_fn(
            "kse.publish",
            "Publish a KSE event — kse.publish(topic,message)",
            move |input, _snap| {
                let (topic_str, msg) = input.split_once(',')
                    .map(|(t, m)| (t.trim().to_string(), m.trim().to_string()))
                    .unwrap_or_else(|| ("agent".to_string(), input.trim().to_string()));
                let j = Arc::clone(&journal2);
                let topic_str2 = topic_str.clone();
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async move {
                        j.publish(
                            kotoba_kse::Topic(topic_str2),
                            bytes::Bytes::from(msg),
                        ).await;
                    });
                });
                ToolOutput { observation: format!("published to '{topic_str}'"), done: false, route: None }
            },
        );

        let runner  = PregelReActRunner::new(engine, max_tokens);
        let session = AgentSession::new(task, graph_cid2, max_steps)
            .with_tool(kse_publish_tool);
        runner.run(session)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let supersteps = superstep_results.len();

    // Extract final answer from last Finish step
    let final_answer = session.steps.iter().rev().find_map(|s| {
        if let ReActStep::Finish { answer } = s { Some(answer.clone()) } else { None }
    });

    // Store session steps as Quads in the QuadStore
    let deltas = session_to_quads(&session);
    for delta in &deltas {
        if delta.is_assert() {
            qs.assert(delta.quad.clone()).await;
        }
    }

    // Commit session history to BlockStore (ProllyTree)
    let commit_cid = qs
        .commit("agent", graph_cid.clone(), session.steps.len() as u64)
        .await
        .ok()
        .map(|c| c.to_multibase());

    // If IPFS pinning is enabled, pin the commit block in the background
    if let (Some(cid_str), Some(pin)) = (commit_cid.clone(), state.ipfs_pin.clone()) {
        tokio::spawn(async move { pin.pin(&cid_str).await });
    }

    let session_cid = session.session_cid.to_multibase();
    let steps       = session.steps;

    Ok(Json(AgentRunResp {
        status: "ok",
        session_cid,
        steps,
        final_answer,
        supersteps,
        commit_cid,
    }))
}

// ── Agent SyncWindow session management (C) ───────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AgentSyncOpenReq {
    /// Caller-assigned session identifier (UUIDv4 recommended).
    pub session_id: String,
    /// Named graph CID to sync (multibase).
    pub graph_cid:  String,
    /// Journal sequence watermark — the agent has already processed all entries before this.
    pub since_seq:  u64,
    /// Last commit head the agent has processed. `None` = fresh agent.
    pub head_cid:   Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentSyncOpenResp {
    pub status:     &'static str,
    pub session_id: String,
    pub since_seq:  u64,
}

/// POST /xrpc/ai.gftd.apps.kotoba.agent.syncopen
///
/// Opens a SyncWindow session.  The graph and head CIDs are pinned in the
/// BudgetedBlockStore so they survive eviction for the duration of the session.
pub async fn agent_sync_open(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<AgentSyncOpenReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;
    use kotoba_kse::sync_window::SyncWindow;

    let graph_cid = KotobaCid::from_multibase(&req.graph_cid)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid graph_cid".into()))?;
    let head_cid = req.head_cid.as_deref()
        .map(|s| KotobaCid::from_multibase(s)
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid head_cid".into())))
        .transpose()?;

    let window = SyncWindow::new(graph_cid.clone(), req.since_seq, head_cid.clone());

    // Pin anchors directly (avoids dyn-coercion issues)
    state.block_store.pin(&graph_cid);
    if let Some(h) = &head_cid {
        state.block_store.pin(h);
    }

    let since_seq = window.since_seq;
    state.agent_sessions.write().await.insert(req.session_id.clone(), window);

    tracing::info!(session_id = %req.session_id, since_seq, "agent.syncopen");

    Ok(Json(AgentSyncOpenResp { status: "ok", session_id: req.session_id, since_seq }))
}

#[derive(Debug, Deserialize)]
pub struct AgentSyncAdvReq {
    pub session_id:   String,
    /// New commit head CID (multibase) the agent has processed.
    pub new_head_cid: String,
    /// Updated journal watermark.
    pub new_seq:      u64,
}

#[derive(Debug, Serialize)]
pub struct AgentSyncAdvResp {
    pub status:     &'static str,
    pub session_id: String,
    pub since_seq:  u64,
}

/// POST /xrpc/ai.gftd.apps.kotoba.agent.syncadvance
///
/// Advance the SyncWindow: unpin the old head, pin the new head.
pub async fn agent_sync_advance(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<AgentSyncAdvReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;

    let new_head = KotobaCid::from_multibase(&req.new_head_cid)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid new_head_cid".into()))?;

    let mut sessions = state.agent_sessions.write().await;
    let window = sessions.get_mut(&req.session_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("session not found: {}", req.session_id)))?;

    // Unpin old head, pin new head
    if let Some(old) = &window.head_cid {
        state.block_store.unpin(old);
    }
    state.block_store.pin(&new_head);
    window.head_cid  = Some(new_head);
    window.since_seq = req.new_seq;

    let since_seq = window.since_seq;
    tracing::info!(session_id = %req.session_id, since_seq, "agent.syncadvance");

    Ok(Json(AgentSyncAdvResp { status: "ok", session_id: req.session_id, since_seq }))
}

#[derive(Debug, Deserialize)]
pub struct AgentSyncCloseReq {
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub struct AgentSyncCloseResp {
    pub status:     &'static str,
    pub session_id: String,
}

/// POST /xrpc/ai.gftd.apps.kotoba.agent.syncclose
///
/// Close the SyncWindow session, unpinning all anchors.
pub async fn agent_sync_close(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<AgentSyncCloseReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut sessions = state.agent_sessions.write().await;
    let window = sessions.remove(&req.session_id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("session not found: {}", req.session_id)))?;

    state.block_store.unpin(&window.graph_cid);
    if let Some(h) = &window.head_cid {
        state.block_store.unpin(h);
    }

    tracing::info!(session_id = %req.session_id, "agent.syncclose");

    Ok(Json(AgentSyncCloseResp { status: "ok", session_id: req.session_id }))
}
