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

/// POST /xrpc/ai.gftd.apps.kotoba.quad.create
/// Publish a Quad assert to the KSE Journal (SPO topic).
pub async fn quad_create(
    State(state): State<Arc<KotobaState>>,
    Json(req):    Json<QuadCreateReq>,
) -> impl IntoResponse {
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::quad::{Quad, QuadObject};

    let quad = Quad {
        graph:     KotobaCid::from_bytes(req.graph.as_bytes()),
        subject:   KotobaCid::from_bytes(req.subject.as_bytes()),
        predicate: req.predicate.clone(),
        object:    QuadObject::Text(req.object.clone()),
    };

    let journal_cid = state.journal_assert(&quad).await;

    tracing::info!(
        graph    = %req.graph,
        subject  = %req.subject,
        predicate = %req.predicate,
        cid      = %journal_cid,
        "quad.create → KSE Journal"
    );

    (StatusCode::OK, Json(QuadCreateResp { status: "ok", journal_cid }))
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

    let wasm_ref: Option<&[u8]> = if wasm_bytes.is_empty() { None } else { Some(&wasm_bytes) };

    let result = state
        .router
        .dispatch(
            &req.program_cid,
            program_type,
            &req.agent_did,
            0,
            wasm_ref,
            ctx_cbor,
            None,
            None,
            &[],
            10_000,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    use kotoba_core::cid::KotobaCid;
    use kotoba_vm::DispatchResult;
    use kotoba_kqe::quad::{Quad, QuadObject};

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

            tracing::info!(
                program_cid = %req.program_cid,
                gas_used    = r.gas_used,
                asserts     = r.assert_quads.len(),
                retracts    = r.retract_quads.len(),
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
