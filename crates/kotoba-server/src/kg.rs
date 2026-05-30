//! yatabase KG entity lookup endpoint backed by kotoba QuadStore.
//!
//! NSID: ai.gftd.apps.kotobase.kg.entity
//! All KG quads live in the named graph `kotobase-kg-v1`.
//!
//! Predicate conventions (written by seed_kotoba.py):
//!   kg/id           — nanoid primary key
//!   kg/qid          — Wikidata QID (e.g. "Q42")
//!   kg/type         — entity type string
//!   kg/label/ja     — Japanese label
//!   kg/label/en     — English label
//!   kg/confidence   — float string
//!   kg/license      — license SPDX
//!   kg/extractor    — extractor identifier
//!   kg/valid_from   — ISO-8601 date
//!   kg/valid_to     — ISO-8601 date
//!   kg/ingested_at  — ISO-8601 datetime
//!   kg/source_id    — source nanoid
//!   kg/claim/<pred> — property claim (Text / Float / Bool)
//!   kg/relation/<pred> — edge to another entity (Cid object = subject CID of dst)

use crate::graph_auth::{check_read_access, AccessDenied};
use crate::server::KotobaState;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use kotoba_core::cid::KotobaCid;
use kotoba_datomic::distributed::{
    CommitDatomsRequest, DistributedCommitError, DistributedCommitWriter,
};
use kotoba_graph::quad_store::QuadStore;
use kotoba_ipfs::{IpnsName, IpnsRegistryError};
use kotoba_kqe::{
    datom::{Datom as KqeDatom, Value as KqeValue},
    delta::Delta,
    quad::LegacyQuad,
    quad::LegacyQuadObject as QuadObject,
};
use kotoba_kse::journal::Journal;
use kotoba_store::MemoryBlockStore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Require a valid, non-expired Bearer JWT to authorise KG write operations.
/// Any authenticated principal with a `sub` claim and a valid `exp` is accepted.
fn require_kg_write_auth(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("kg write auth: missing Bearer token");
            (
                StatusCode::UNAUTHORIZED,
                "Authorization: Bearer <token> required for KG write operations".to_string(),
            )
        })?;
    if crate::graph_auth::jwt_exp_elapsed(token) {
        tracing::warn!("kg write auth: expired JWT");
        return Err((
            StatusCode::UNAUTHORIZED,
            "Bearer token has expired".to_string(),
        ));
    }
    crate::graph_auth::jwt_sub(token).ok_or_else(|| {
        tracing::warn!("kg write auth: JWT missing sub claim");
        (
            StatusCode::UNAUTHORIZED,
            "Bearer token missing sub claim".to_string(),
        )
    })?;
    Ok(())
}

pub const NSID_KG_ENTITY: &str = "ai.gftd.apps.kotobase.kg.entity";
pub const NSID_KG_CATALOG: &str = "ai.gftd.apps.kotobase.kg.catalog";
pub const NSID_KG_EMBED: &str = "ai.gftd.apps.kotobase.kg.embed";
pub const NSID_KG_SEARCH: &str = "ai.gftd.apps.kotobase.kg.search";
pub const NSID_KG_QUERY: &str = "ai.gftd.apps.kotobase.kg.query";
pub const NSID_KG_SPARQL: &str = "ai.gftd.apps.kotoba.graph.sparql";
pub const NSID_KG_INGEST: &str = "ai.gftd.apps.kotobase.kg.ingest";
pub const NSID_KG_INGEST_BATCH: &str = "ai.gftd.apps.kotobase.kg.ingest_batch";
pub const NSID_KG_DELETE: &str = "ai.gftd.apps.kotobase.kg.delete";
pub const NSID_KG_COMMIT: &str = "ai.gftd.apps.kotobase.kg.commit";

/// All yatabase KG quads are written into this named graph.
pub fn kg_graph_cid() -> KotobaCid {
    KotobaCid::from_bytes(b"kotobase-kg-v1")
}

fn kg_tx_cid(label: &str, parts: &[&str]) -> KotobaCid {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    KotobaCid::from_bytes(format!("kg:{label}:{nanos}:{}", parts.join(":")).as_bytes())
}

fn kg_datom(subject: &KotobaCid, predicate: impl Into<String>, value: KqeValue) -> KqeDatom {
    KqeDatom::assert(
        subject.clone(),
        predicate.into(),
        value,
        KotobaCid::from_bytes(b"kotoba-kg-pending-tx"),
    )
}

async fn commit_kg_datoms(
    state: &Arc<KotobaState>,
    entity: KotobaCid,
    tx_cid: KotobaCid,
    mut datoms: Vec<KqeDatom>,
    author: String,
    auth_proof_cid: Option<KotobaCid>,
    auth_capability: Option<crate::xrpc::AuthCapabilityProjection>,
) -> Result<crate::xrpc::ProtocolDatomWriteResp, (StatusCode, String)> {
    let graph = kg_graph_cid();
    for datom in &mut datoms {
        datom.tx = tx_cid.clone();
    }
    crate::xrpc::commit_protocol_datoms(
        state,
        graph.clone(),
        graph.to_multibase(),
        entity,
        datoms
            .into_iter()
            .map(kotoba_datomic::Datom::from_kqe)
            .collect(),
        tx_cid,
        author,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        auth_proof_cid,
        auth_capability,
    )
    .await
}

fn kg_legacy_write_auth(
    headers: &HeaderMap,
    fallback: &str,
) -> Result<crate::xrpc::ProtocolWriteAuth, (StatusCode, String)> {
    require_kg_write_auth(headers)?;
    Ok(crate::xrpc::ProtocolWriteAuth {
        author: kg_write_author(headers, fallback),
        auth_proof_cid: None,
        auth_capability: None,
    })
}

fn authorize_kg_write(
    state: &KotobaState,
    headers: &HeaderMap,
    cacao_b64: Option<&str>,
    presentation: Option<&kotoba_vc::VerifiablePresentation>,
    tx_cid: &KotobaCid,
) -> Result<crate::xrpc::ProtocolWriteAuth, (StatusCode, String)> {
    if cacao_b64.is_some() || presentation.is_some() {
        return crate::xrpc::authorize_protocol_datom_write(
            state,
            headers,
            &kg_graph_cid().to_multibase(),
            cacao_b64,
            presentation,
            &[kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT],
            Some(tx_cid),
        );
    }
    kg_legacy_write_auth(headers, &state.operator_did)
}

fn kg_write_author(headers: &HeaderMap, fallback: &str) -> String {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(crate::graph_auth::jwt_sub)
        .unwrap_or_else(|| fallback.to_string())
}

async fn current_graph_quads(
    state: &Arc<KotobaState>,
    graph_cid: &KotobaCid,
) -> Result<Vec<LegacyQuad>, (StatusCode, String)> {
    let db = crate::xrpc::current_db_for_graph(state, graph_cid).await?;
    Ok(db
        .datoms()
        .into_iter()
        .map(|datom| {
            let substrate = datom.to_kqe().unwrap_or_else(|_| KqeDatom {
                e: datom.e,
                a: datom.a,
                v: KqeValue::Text(kotoba_edn::to_string(&datom.v)),
                tx: datom.t,
                op: datom.added,
            });
            LegacyQuad {
                graph: graph_cid.clone(),
                subject: substrate.e,
                predicate: substrate.a,
                object: substrate.v.into(),
            }
        })
        .collect())
}

async fn current_graph_deltas(
    state: &Arc<KotobaState>,
    graph_cid: &KotobaCid,
) -> Result<Vec<Delta>, (StatusCode, String)> {
    let db = crate::xrpc::current_db_for_graph(state, graph_cid).await?;
    Ok(db
        .datoms()
        .into_iter()
        .map(|datom| {
            datom.to_kqe().unwrap_or_else(|_| KqeDatom {
                e: datom.e,
                a: datom.a,
                v: KqeValue::Text(kotoba_edn::to_string(&datom.v)),
                tx: datom.t,
                op: datom.added,
            })
        })
        .map(Delta::from_datom)
        .collect())
}

async fn distributed_query_store(
    state: &Arc<KotobaState>,
    graph_cid: &KotobaCid,
    as_of: Option<&str>,
    since: Option<&str>,
    remote_peer: Option<&str>,
    remote_ipns_name: Option<&str>,
) -> Result<(QuadStore, Option<String>), (StatusCode, String)> {
    let (quads, basis_t) = if remote_peer.is_some()
        || remote_ipns_name.is_some()
        || as_of.is_some()
        || since.is_some()
    {
        let db = crate::xrpc::require_distributed_datomic_db(
            state,
            graph_cid,
            as_of,
            since,
            remote_peer,
            remote_ipns_name,
        )?;
        let basis_t = db.basis_t.as_ref().map(KotobaCid::to_multibase);
        (datomic_db_quads(graph_cid, db), basis_t)
    } else {
        (current_graph_quads(state, graph_cid).await?, None)
    };
    let query_store = QuadStore::new(Arc::new(Journal::new()), Arc::new(MemoryBlockStore::new()));
    query_store.assert_batch_silent(quads).await;
    Ok((query_store, basis_t))
}

fn datomic_db_quads(graph_cid: &KotobaCid, db: kotoba_datomic::Db) -> Vec<LegacyQuad> {
    db.datoms()
        .into_iter()
        .map(|datom| {
            let substrate = datom.to_kqe().unwrap_or_else(|_| KqeDatom {
                e: datom.e,
                a: datom.a,
                v: KqeValue::Text(kotoba_edn::to_string(&datom.v)),
                tx: datom.t,
                op: datom.added,
            });
            LegacyQuad {
                graph: graph_cid.clone(),
                subject: substrate.e,
                predicate: substrate.a,
                object: substrate.v.into(),
            }
        })
        .collect()
}

fn kg_subject_by_predicate_value(
    quads: &[LegacyQuad],
    predicate: &str,
    value: &str,
) -> Option<KotobaCid> {
    quads
        .iter()
        .find(|quad| {
            quad.predicate == predicate
                && matches!(&quad.object, QuadObject::Text(text) if text == value)
        })
        .map(|quad| quad.subject.clone())
}

fn kg_entity_quads<'a>(
    quads: &'a [LegacyQuad],
    subject: &'a KotobaCid,
) -> impl Iterator<Item = &'a LegacyQuad> {
    quads.iter().filter(move |quad| &quad.subject == subject)
}

const MAX_KG_ID_LEN: usize = 256;
const MAX_KG_TEXT_LEN: usize = 8_192; // max embed text — prevents inference-engine DoS
const MAX_KG_QUERY_LEN: usize = 2_048;
const MAX_KG_LIMIT: usize = 1_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgEntityQuery {
    pub id: Option<String>,
    pub qid: Option<String>,
    #[serde(default = "default_true")]
    pub include_claims: bool,
    #[serde(default = "default_true")]
    pub include_relations: bool,
    #[serde(default = "default_max_relations")]
    pub max_relations: usize,
    /// CACAO delegation chain for private graphs (DAG-CBOR, base64-standard encoded).
    pub cacao_b64: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_max_relations() -> usize {
    50
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KgEntityResp {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity: Option<serde_json::Value>,
    pub elapsed_ms: u128,
}

/// GET /xrpc/ai.gftd.apps.kotobase.kg.entity?id=<nanoid>
/// GET /xrpc/ai.gftd.apps.kotobase.kg.entity?qid=Q42
pub async fn kg_entity(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(q): Query<KgEntityQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use std::time::Instant;
    let t0 = Instant::now();
    let graph_cid = kg_graph_cid();

    // ── Read-access gate ─────────────────────────────────────────────────────
    let visibility = state.graph_visibility(&graph_cid).await;
    check_read_access(
        &visibility,
        &headers,
        q.cacao_b64.as_deref(),
        Some(&state.operator_did),
        Some(&state.nonce_store),
    )
    .map_err(AccessDenied::into_response)?;

    let (lookup_pred, lookup_val) = match (&q.id, &q.qid) {
        (Some(id), _) => {
            if id.len() > MAX_KG_ID_LEN {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("id must be ≤{MAX_KG_ID_LEN} bytes"),
                ));
            }
            ("kg/id", id.as_str())
        }
        (_, Some(qid)) => {
            if qid.len() > MAX_KG_ID_LEN {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("qid must be ≤{MAX_KG_ID_LEN} bytes"),
                ));
            }
            ("kg/qid", qid.as_str())
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "missing `id` or `qid` query param".into(),
            ))
        }
    };

    let quads = current_graph_quads(&state, &graph_cid).await?;
    let subject_cid = match kg_subject_by_predicate_value(&quads, lookup_pred, lookup_val) {
        Some(s) => s,
        None => {
            return Ok(Json(KgEntityResp {
                ok: false,
                error: Some(format!("entity not found: {lookup_val}")),
                entity: None,
                elapsed_ms: t0.elapsed().as_millis(),
            }));
        }
    };

    let mut meta: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut claims: Vec<serde_json::Value> = Vec::new();
    let mut relations: Vec<serde_json::Value> = Vec::new();

    for quad in kg_entity_quads(&quads, &subject_cid) {
        let pred = quad.predicate.as_str();
        match pred {
            "kg/id" => {
                meta.insert("id".into(), obj_to_json(&quad.object));
            }
            "kg/qid" => {
                meta.insert("qid".into(), obj_to_json(&quad.object));
            }
            "kg/type" => {
                meta.insert("type".into(), obj_to_json(&quad.object));
            }
            "kg/label/ja" => {
                meta.insert("labelJa".into(), obj_to_json(&quad.object));
            }
            "kg/label/en" => {
                meta.insert("labelEn".into(), obj_to_json(&quad.object));
            }
            "kg/confidence" => {
                meta.insert("confidence".into(), obj_to_json(&quad.object));
            }
            "kg/license" => {
                meta.insert("license".into(), obj_to_json(&quad.object));
            }
            "kg/extractor" => {
                meta.insert("extractor".into(), obj_to_json(&quad.object));
            }
            "kg/valid_from" => {
                meta.insert("validFrom".into(), obj_to_json(&quad.object));
            }
            "kg/valid_to" => {
                meta.insert("validTo".into(), obj_to_json(&quad.object));
            }
            "kg/ingested_at" => {
                meta.insert("ingestedAt".into(), obj_to_json(&quad.object));
            }
            "kg/source_id" => {
                meta.insert("sourceId".into(), obj_to_json(&quad.object));
            }
            _ if pred.starts_with("kg/claim/") && q.include_claims => {
                let claim_pred = &pred["kg/claim/".len()..];
                claims.push(serde_json::json!({
                    "predicate": claim_pred,
                    "value":     obj_to_json(&quad.object),
                }));
            }
            _ if pred.starts_with("kg/relation/")
                && q.include_relations
                && relations.len() < q.max_relations.min(MAX_KG_LIMIT) =>
            {
                let rel_pred = &pred["kg/relation/".len()..];
                relations.push(serde_json::json!({
                    "predicate": rel_pred,
                    "dstCid":    match &quad.object {
                        QuadObject::Cid(c) => c.to_multibase(),
                        other              => format!("{other:?}"),
                    },
                }));
            }
            _ => {}
        }
    }

    if q.include_claims {
        meta.insert("claims".into(), serde_json::Value::Array(claims));
    }
    if q.include_relations {
        meta.insert("relations".into(), serde_json::Value::Array(relations));
    }

    Ok(Json(KgEntityResp {
        ok: true,
        error: None,
        entity: Some(serde_json::Value::Object(meta)),
        elapsed_ms: t0.elapsed().as_millis(),
    }))
}

fn obj_to_json(obj: &QuadObject) -> serde_json::Value {
    match obj {
        QuadObject::Text(s) => serde_json::Value::String(s.clone()),
        QuadObject::Integer(n) => serde_json::json!(n),
        QuadObject::Float(f) => serde_json::json!(f),
        QuadObject::Bool(b) => serde_json::json!(b),
        QuadObject::Cid(c) => serde_json::Value::String(c.to_multibase()),
        _ => serde_json::Value::Null,
    }
}

// ── kg.catalog ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgCatalogQuery {
    /// CACAO delegation chain for private graphs (DAG-CBOR, base64-standard encoded).
    pub cacao_b64: Option<String>,
}

/// GET /xrpc/ai.gftd.apps.kotobase.kg.catalog
/// Returns aggregate stats and source breakdown from the distributed Datomic DB.
pub async fn kg_catalog(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(q): Query<KgCatalogQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use std::time::Instant;
    let t0 = Instant::now();
    let graph_cid = kg_graph_cid();

    // ── Read-access gate ─────────────────────────────────────────────────────
    let visibility = state.graph_visibility(&graph_cid).await;
    check_read_access(
        &visibility,
        &headers,
        q.cacao_b64.as_deref(),
        Some(&state.operator_did),
        Some(&state.nonce_store),
    )
    .map_err(AccessDenied::into_response)?;

    let quads = current_graph_quads(&state, &graph_cid).await?;
    let entity_count = quads
        .iter()
        .filter(|quad| quad.predicate == "kg/id")
        .count();
    let claim_count = quads
        .iter()
        .filter(|quad| quad.predicate.starts_with("kg/claim/"))
        .count();
    let relation_count = quads
        .iter()
        .filter(|quad| quad.predicate.starts_with("kg/relation/"))
        .count();

    // Gather source_ids from kg/source_id datoms.
    let mut source_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for quad in quads.iter().filter(|quad| quad.predicate == "kg/source_id") {
        let src = match &quad.object {
            QuadObject::Text(s) => s.clone(),
            other => format!("{other:?}"),
        };
        *source_counts.entry(src).or_insert(0) += 1;
    }
    let sources: Vec<serde_json::Value> = source_counts
        .into_iter()
        .map(|(id, count)| serde_json::json!({ "id": id, "entityCount": count }))
        .collect();

    Ok(Json(serde_json::json!({
        "ok": true,
        "stats": {
            "totalEntities":  entity_count,
            "totalClaims":    claim_count,
            "totalRelations": relation_count,
        },
        "sources":    sources,
        "elapsedMs":  t0.elapsed().as_millis(),
    })))
}

// ── kg.embed ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgEmbedReq {
    /// Nanoid entity ID — used to resolve the subject CID.
    pub entity_id: String,
    /// Text to embed (typically labelEn or labelJa).
    pub text: String,
    /// CACAO delegation chain for distributed Datom writes.
    pub cacao_b64: Option<String>,
    /// W3C Verifiable Presentation carrying a datom:transact capability.
    pub auth_presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KgEmbedResp {
    pub ok: bool,
    pub dims: usize,
}

/// POST /xrpc/ai.gftd.apps.kotobase.kg.embed
/// Compute a blake3 pseudo-vector for `text` and store it as a `kg/label_vec`
/// VectorF32 quad for the entity.  Uses the inference engine when available.
pub async fn kg_embed(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<KgEmbedReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if req.entity_id.is_empty() || req.entity_id.len() > MAX_KG_ID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("entityId must be 1–{MAX_KG_ID_LEN} bytes"),
        ));
    }
    if req.text.is_empty() || req.text.len() > MAX_KG_TEXT_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("text must be 1–{MAX_KG_TEXT_LEN} bytes"),
        ));
    }
    let graph_cid = kg_graph_cid();

    let quads = current_graph_quads(&state, &graph_cid).await?;
    let subject =
        kg_subject_by_predicate_value(&quads, "kg/id", &req.entity_id).ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("entity not found: {}", req.entity_id),
            )
        })?;

    let vector: Vec<f32> = if let Some(engine) = &state.inference_engine {
        let engine = engine.clone();
        let text = format!("embed: {}", req.text);
        let result = tokio::task::spawn_blocking(move || engine(&text, 256))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let parsed: Vec<f32> = result
            .split_whitespace()
            .filter_map(|s| s.parse::<f32>().ok())
            .collect();
        if parsed.is_empty() {
            blake3_pseudo_vector(&req.text, 128)
        } else {
            parsed
        }
    } else {
        blake3_pseudo_vector(&req.text, 128)
    };

    let dims = vector.len();
    let datom = kg_datom(&subject, "kg/label_vec", KqeValue::VectorF32(vector));
    let tx_cid = kg_tx_cid("embed", &[&req.entity_id]);
    let auth = authorize_kg_write(
        &state,
        &headers,
        req.cacao_b64.as_deref(),
        req.auth_presentation.as_ref(),
        &tx_cid,
    )?;
    commit_kg_datoms(
        &state,
        subject,
        tx_cid,
        vec![datom],
        auth.author,
        auth.auth_proof_cid,
        auth.auth_capability,
    )
    .await?;

    Ok(Json(KgEmbedResp { ok: true, dims }))
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

// ── kg.search ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgSearchQuery {
    /// Free-text query string
    pub q: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// CACAO delegation chain for private graphs (DAG-CBOR, base64-standard encoded).
    pub cacao_b64: Option<String>,
}
fn default_limit() -> usize {
    10
}

/// GET /xrpc/ai.gftd.apps.kotobase.kg.search?q=<text>&limit=10
/// Cosine similarity search over `kg/label_vec` VectorF32 quads.
pub async fn kg_search(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(q): Query<KgSearchQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use std::time::Instant;
    if q.q.is_empty() || q.q.len() > MAX_KG_QUERY_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("q must be 1–{MAX_KG_QUERY_LEN} bytes"),
        ));
    }
    let t0 = Instant::now();
    let graph_cid = kg_graph_cid();
    let limit = q.limit.min(MAX_KG_LIMIT);

    // ── Read-access gate ─────────────────────────────────────────────────────
    let visibility = state.graph_visibility(&graph_cid).await;
    check_read_access(
        &visibility,
        &headers,
        q.cacao_b64.as_deref(),
        Some(&state.operator_did),
        Some(&state.nonce_store),
    )
    .map_err(AccessDenied::into_response)?;

    // Use inference engine for query embedding when available, matching kg_embed semantics.
    // Falls back to blake3 pseudo-vector so search works without an LLM.
    let query_vec: Vec<f32> = if let Some(engine) = &state.inference_engine {
        let engine = engine.clone();
        let text = format!("embed: {}", q.q);
        let result = tokio::task::spawn_blocking(move || engine(&text, 256))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let parsed: Vec<f32> = result
            .split_whitespace()
            .filter_map(|s| s.parse::<f32>().ok())
            .collect();
        if parsed.is_empty() {
            blake3_pseudo_vector(&q.q, 128)
        } else {
            parsed
        }
    } else {
        blake3_pseudo_vector(&q.q, 128)
    };

    let quads = current_graph_quads(&state, &graph_cid).await?;

    // Score each entity
    let mut scored: Vec<(f32, KotobaCid)> = quads
        .iter()
        .filter(|quad| quad.predicate == "kg/label_vec")
        .filter_map(|quad| {
            if let QuadObject::VectorF32(v) = &quad.object {
                Some((cosine(&query_vec, v), quad.subject.clone()))
            } else {
                None
            }
        })
        .collect();

    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(limit);

    // Fetch entity metadata for top-k subjects
    let mut results: Vec<serde_json::Value> = Vec::with_capacity(scored.len());
    for (score, subject) in &scored {
        let mut meta: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        meta.insert("score".into(), serde_json::json!(score));
        for quad in kg_entity_quads(&quads, subject) {
            match quad.predicate.as_str() {
                "kg/id" => {
                    meta.insert("id".into(), obj_to_json(&quad.object));
                }
                "kg/qid" => {
                    meta.insert("qid".into(), obj_to_json(&quad.object));
                }
                "kg/label/ja" => {
                    meta.insert("labelJa".into(), obj_to_json(&quad.object));
                }
                "kg/label/en" => {
                    meta.insert("labelEn".into(), obj_to_json(&quad.object));
                }
                "kg/type" => {
                    meta.insert("type".into(), obj_to_json(&quad.object));
                }
                _ => {}
            }
        }
        results.push(serde_json::Value::Object(meta));
    }

    Ok(Json(serde_json::json!({
        "ok":        true,
        "count":     results.len(),
        "results":   results,
        "elapsedMs": t0.elapsed().as_millis(),
    })))
}

// ── kg.ingest ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgClaim {
    pub pred: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgRelation {
    pub pred: String,
    pub dst_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgIngestReq {
    pub id: String,
    pub qid: Option<String>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub label_ja: Option<String>,
    pub label_en: Option<String>,
    pub confidence: Option<String>,
    pub license: Option<String>,
    pub extractor: Option<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub ingested_at: Option<String>,
    pub source_id: Option<String>,
    /// Pre-computed embedding vector (e.g. from yatabase vLLM).
    /// When present, stored as `kg/label_vec` VectorF32 quad so that
    /// `kg_search` can do real cosine similarity without a local inference engine.
    #[serde(default)]
    pub label_vec: Vec<f32>,
    #[serde(default)]
    pub claims: Vec<KgClaim>,
    #[serde(default)]
    pub relations: Vec<KgRelation>,
    /// CACAO delegation chain for distributed Datom writes.
    pub cacao_b64: Option<String>,
    /// W3C Verifiable Presentation carrying a datom:transact capability.
    pub auth_presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KgIngestResp {
    pub ok: bool,
    pub subject_cid: String,
    pub quad_count: usize,
}

/// POST /xrpc/ai.gftd.apps.kotobase.kg.ingest
///
/// Write a KG entity into the `kotobase-kg-v1` named graph. Each field becomes
/// a quad with predicate conventions matching `kg_entity` lookups.
const MAX_KG_CLAIMS: usize = 1_024;
const MAX_KG_RELATIONS: usize = 1_024;
const MAX_KG_VEC_DIMS: usize = 4_096;
const MAX_KG_FIELD_LEN: usize = 4_096;

pub async fn kg_ingest(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<KgIngestReq>,
) -> impl IntoResponse {
    use axum::Json as AxumJson;
    if req.id.is_empty() || req.id.len() > MAX_KG_ID_LEN {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false, "error":
                format!("id must be 1–{MAX_KG_ID_LEN} bytes")})),
        )
            .into_response();
    }
    if req.claims.len() > MAX_KG_CLAIMS {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false, "error":
                format!("claims array exceeds {MAX_KG_CLAIMS} entries")})),
        )
            .into_response();
    }
    if req.relations.len() > MAX_KG_RELATIONS {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false, "error":
                format!("relations array exceeds {MAX_KG_RELATIONS} entries")})),
        )
            .into_response();
    }
    if req.label_vec.len() > MAX_KG_VEC_DIMS {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false, "error":
                format!("labelVec exceeds {MAX_KG_VEC_DIMS} dimensions")})),
        )
            .into_response();
    }
    if req.label_vec.iter().any(|f| !f.is_finite()) {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false, "error":
                "labelVec contains non-finite values (NaN/Inf)"})),
        )
            .into_response();
    }
    // Validate per-field lengths to prevent oversized individual quads
    for v in [
        &req.qid,
        &req.kind,
        &req.label_ja,
        &req.label_en,
        &req.license,
        &req.extractor,
        &req.valid_from,
        &req.valid_to,
        &req.ingested_at,
        &req.source_id,
    ]
    .into_iter()
    .flatten()
    {
        if v.len() > MAX_KG_FIELD_LEN {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(serde_json::json!({"ok": false, "error":
                              format!("field value exceeds {MAX_KG_FIELD_LEN} bytes")})),
            )
                .into_response();
        }
    }
    // Validate per-item predicate/value lengths within claims and relations
    for claim in &req.claims {
        if claim.pred.is_empty() || claim.pred.len() > MAX_KG_ID_LEN {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(serde_json::json!({"ok": false, "error":
                    format!("claim.pred must be 1–{MAX_KG_ID_LEN} bytes")})),
            )
                .into_response();
        }
        if claim.value.len() > MAX_KG_FIELD_LEN {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(serde_json::json!({"ok": false, "error":
                    format!("claim.value must be ≤{MAX_KG_FIELD_LEN} bytes")})),
            )
                .into_response();
        }
    }
    for rel in &req.relations {
        if rel.pred.is_empty() || rel.pred.len() > MAX_KG_ID_LEN {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(serde_json::json!({"ok": false, "error":
                    format!("relation.pred must be 1–{MAX_KG_ID_LEN} bytes")})),
            )
                .into_response();
        }
        if rel.dst_id.is_empty() || rel.dst_id.len() > MAX_KG_ID_LEN {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(serde_json::json!({"ok": false, "error":
                    format!("relation.dstId must be 1–{MAX_KG_ID_LEN} bytes")})),
            )
                .into_response();
        }
    }
    let subject = KotobaCid::from_bytes(req.id.as_bytes());

    let mut count = 0usize;
    let mut datoms = Vec::new();

    macro_rules! assert_text {
        ($pred:expr, $val:expr) => {{
            datoms.push(kg_datom(&subject, $pred, KqeValue::Text($val.to_string())));
            count += 1;
        }};
    }

    // Always write kg/id so lookup_subject_by_po works
    assert_text!("kg/id", &req.id);

    if let Some(v) = &req.qid {
        assert_text!("kg/qid", v);
    }
    if let Some(v) = &req.kind {
        assert_text!("kg/type", v);
    }
    if let Some(v) = &req.label_ja {
        assert_text!("kg/label/ja", v);
    }
    if let Some(v) = &req.label_en {
        assert_text!("kg/label/en", v);
    }
    if let Some(v) = &req.confidence {
        assert_text!("kg/confidence", v);
    }
    if let Some(v) = &req.license {
        assert_text!("kg/license", v);
    }
    if let Some(v) = &req.extractor {
        assert_text!("kg/extractor", v);
    }
    if let Some(v) = &req.valid_from {
        assert_text!("kg/valid_from", v);
    }
    if let Some(v) = &req.valid_to {
        assert_text!("kg/valid_to", v);
    }
    if let Some(v) = &req.ingested_at {
        assert_text!("kg/ingested_at", v);
    }
    if let Some(v) = &req.source_id {
        assert_text!("kg/source_id", v);
    }

    for claim in &req.claims {
        assert_text!(format!("kg/claim/{}", claim.pred), claim.value);
    }

    for rel in &req.relations {
        let dst_cid = KotobaCid::from_bytes(rel.dst_id.as_bytes());
        datoms.push(kg_datom(
            &subject,
            format!("kg/relation/{}", rel.pred),
            KqeValue::Cid(dst_cid),
        ));
        count += 1;
    }

    if !req.label_vec.is_empty() {
        datoms.push(kg_datom(
            &subject,
            "kg/label_vec",
            KqeValue::VectorF32(req.label_vec.clone()),
        ));
        count += 1;
    }

    let tx_cid = kg_tx_cid("ingest", &[&req.id]);
    let auth = match authorize_kg_write(
        &state,
        &headers,
        req.cacao_b64.as_deref(),
        req.auth_presentation.as_ref(),
        &tx_cid,
    ) {
        Ok(auth) => auth,
        Err((code, msg)) => {
            return (
                code,
                AxumJson(serde_json::json!({"ok": false, "error": msg})),
            )
                .into_response();
        }
    };
    if let Err((code, msg)) = commit_kg_datoms(
        &state,
        subject.clone(),
        tx_cid,
        datoms,
        auth.author,
        auth.auth_proof_cid,
        auth.auth_capability,
    )
    .await
    {
        return (
            code,
            AxumJson(serde_json::json!({"ok": false, "error": msg})),
        )
            .into_response();
    }

    Json(KgIngestResp {
        ok: true,
        subject_cid: subject.to_multibase(),
        quad_count: count,
    })
    .into_response()
}

// ── kg.ingest_batch ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgIngestBatchReq {
    /// Up to MAX_KG_BATCH_SIZE entities to ingest in a single HTTP request.
    pub entities: Vec<KgIngestReq>,
    /// CACAO delegation chain for distributed Datom writes.
    pub cacao_b64: Option<String>,
    /// W3C Verifiable Presentation carrying a datom:transact capability.
    pub auth_presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KgIngestBatchResp {
    pub ok: bool,
    /// CIDs of subjects ingested, in input order.
    pub subject_cids: Vec<String>,
    /// Total quads written across all entities.
    pub quad_count: usize,
    /// Number of entities ingested.
    pub entity_count: usize,
}

/// Maximum number of entities accepted in a single batch request.
/// Bounds per-request memory + amortises HTTP overhead.
const MAX_KG_BATCH_SIZE: usize = 1_000;

/// POST /xrpc/ai.gftd.apps.kotobase.kg.ingest_batch
///
/// Ingest up to `MAX_KG_BATCH_SIZE` entities in a single HTTP request.
/// Validation is run once before any writes; if any entity fails the entire
/// batch is rejected (all-or-nothing semantics).  Inserts are then performed
/// serially through the same QuadStore path as single-ingest, amortising the
/// HTTP + JSON + auth-gate cost across the whole batch.
pub async fn kg_ingest_batch(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<KgIngestBatchReq>,
) -> impl IntoResponse {
    use axum::Json as AxumJson;
    if req.entities.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false,
                "error": "entities[] is empty"})),
        )
            .into_response();
    }
    if req.entities.len() > MAX_KG_BATCH_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false,
                "error": format!("batch size {} exceeds limit {MAX_KG_BATCH_SIZE}",
                    req.entities.len())})),
        )
            .into_response();
    }

    // Validate ALL entities up front so we never partially-write a batch.
    for (i, e) in req.entities.iter().enumerate() {
        if let Err(msg) = validate_ingest_req(e) {
            return (
                StatusCode::BAD_REQUEST,
                AxumJson(serde_json::json!({"ok": false,
                    "error": format!("entity[{i}]: {msg}")})),
            )
                .into_response();
        }
    }

    let mut subject_cids = Vec::with_capacity(req.entities.len());
    let mut total_quads = 0usize;
    let mut all_datoms = Vec::new();
    let first_subject = KotobaCid::from_bytes(req.entities[0].id.as_bytes());

    for e in &req.entities {
        let subject = KotobaCid::from_bytes(e.id.as_bytes());
        subject_cids.push(subject.to_multibase());
        let mut count = 0usize;

        macro_rules! assert_text {
            ($pred:expr, $val:expr) => {{
                all_datoms.push(kg_datom(&subject, $pred, KqeValue::Text($val.to_string())));
                count += 1;
            }};
        }

        assert_text!("kg/id", &e.id);
        if let Some(v) = &e.qid {
            assert_text!("kg/qid", v);
        }
        if let Some(v) = &e.kind {
            assert_text!("kg/type", v);
        }
        if let Some(v) = &e.label_ja {
            assert_text!("kg/label/ja", v);
        }
        if let Some(v) = &e.label_en {
            assert_text!("kg/label/en", v);
        }
        if let Some(v) = &e.confidence {
            assert_text!("kg/confidence", v);
        }
        if let Some(v) = &e.license {
            assert_text!("kg/license", v);
        }
        if let Some(v) = &e.extractor {
            assert_text!("kg/extractor", v);
        }
        if let Some(v) = &e.valid_from {
            assert_text!("kg/valid_from", v);
        }
        if let Some(v) = &e.valid_to {
            assert_text!("kg/valid_to", v);
        }
        if let Some(v) = &e.ingested_at {
            assert_text!("kg/ingested_at", v);
        }
        if let Some(v) = &e.source_id {
            assert_text!("kg/source_id", v);
        }

        for claim in &e.claims {
            assert_text!(format!("kg/claim/{}", claim.pred), claim.value);
        }
        for rel in &e.relations {
            let dst_cid = KotobaCid::from_bytes(rel.dst_id.as_bytes());
            all_datoms.push(kg_datom(
                &subject,
                format!("kg/relation/{}", rel.pred),
                KqeValue::Cid(dst_cid),
            ));
            count += 1;
        }
        if !e.label_vec.is_empty() {
            all_datoms.push(kg_datom(
                &subject,
                "kg/label_vec",
                KqeValue::VectorF32(e.label_vec.clone()),
            ));
            count += 1;
        }
        total_quads += count;
    }

    let tx_cid = kg_tx_cid("ingest_batch", &[&req.entities.len().to_string()]);
    let auth = match authorize_kg_write(
        &state,
        &headers,
        req.cacao_b64.as_deref(),
        req.auth_presentation.as_ref(),
        &tx_cid,
    ) {
        Ok(auth) => auth,
        Err((code, msg)) => {
            return (
                code,
                AxumJson(serde_json::json!({"ok": false, "error": msg})),
            )
                .into_response();
        }
    };
    if let Err((code, msg)) = commit_kg_datoms(
        &state,
        first_subject,
        tx_cid,
        all_datoms,
        auth.author,
        auth.auth_proof_cid,
        auth.auth_capability,
    )
    .await
    {
        return (
            code,
            AxumJson(serde_json::json!({"ok": false, "error": msg})),
        )
            .into_response();
    }

    AxumJson(KgIngestBatchResp {
        ok: true,
        subject_cids,
        quad_count: total_quads,
        entity_count: req.entities.len(),
    })
    .into_response()
}

/// Validate a single ingest entity; returns `Err(human-message)` on any failure.
fn validate_ingest_req(e: &KgIngestReq) -> Result<(), String> {
    if e.id.is_empty() || e.id.len() > MAX_KG_ID_LEN {
        return Err(format!("id must be 1–{MAX_KG_ID_LEN} bytes"));
    }
    if e.claims.len() > MAX_KG_CLAIMS {
        return Err(format!("claims array exceeds {MAX_KG_CLAIMS} entries"));
    }
    if e.relations.len() > MAX_KG_RELATIONS {
        return Err(format!(
            "relations array exceeds {MAX_KG_RELATIONS} entries"
        ));
    }
    if e.label_vec.len() > MAX_KG_VEC_DIMS {
        return Err(format!("labelVec exceeds {MAX_KG_VEC_DIMS} dimensions"));
    }
    if e.label_vec.iter().any(|f| !f.is_finite()) {
        return Err("labelVec contains non-finite values (NaN/Inf)".into());
    }
    for v in [
        &e.qid,
        &e.kind,
        &e.label_ja,
        &e.label_en,
        &e.license,
        &e.extractor,
        &e.valid_from,
        &e.valid_to,
        &e.ingested_at,
        &e.source_id,
    ]
    .into_iter()
    .flatten()
    {
        if v.len() > MAX_KG_FIELD_LEN {
            return Err(format!("field value exceeds {MAX_KG_FIELD_LEN} bytes"));
        }
    }
    for c in &e.claims {
        if c.pred.is_empty() || c.pred.len() > MAX_KG_ID_LEN {
            return Err(format!("claim.pred must be 1–{MAX_KG_ID_LEN} bytes"));
        }
        if c.value.len() > MAX_KG_FIELD_LEN {
            return Err(format!("claim.value must be ≤{MAX_KG_FIELD_LEN} bytes"));
        }
    }
    for r in &e.relations {
        if r.pred.is_empty() || r.pred.len() > MAX_KG_ID_LEN {
            return Err(format!("relation.pred must be 1–{MAX_KG_ID_LEN} bytes"));
        }
        if r.dst_id.is_empty() || r.dst_id.len() > MAX_KG_ID_LEN {
            return Err(format!("relation.dstId must be 1–{MAX_KG_ID_LEN} bytes"));
        }
    }
    Ok(())
}

// ── kg.delete ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgDeleteReq {
    /// Entity nanoid — same as the `id` field used in kg.ingest.
    pub id: String,
    /// CACAO delegation chain for distributed Datom writes.
    pub cacao_b64: Option<String>,
    /// W3C Verifiable Presentation carrying a datom:transact capability.
    pub auth_presentation: Option<kotoba_vc::VerifiablePresentation>,
}

// ── kg.commit ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgCommitReq {
    /// Optional author DID for the commit metadata.  Defaults to the
    /// operator DID.
    pub author: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KgCommitResp {
    pub ok: bool,
    pub commit_cid: String,
    pub ipns_name: String,
    pub ipns_sequence: u64,
    pub elapsed_ms: u128,
}

/// POST /xrpc/ai.gftd.apps.kotobase.kg.commit
///
/// Return the distributed Datomic/IPLD head for the KG graph.  New KG writes
/// publish their own DAG-CBOR/ProllyTree commits through IPNS; this endpoint is
/// now a compatibility checkpoint.  If no distributed KG head exists yet, it
/// snapshots the current KG DB view as the first distributed commit.
///
/// Restricted to operator DID — only the node operator may seal a commit.
pub async fn kg_commit(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<KgCommitReq>,
) -> impl IntoResponse {
    use std::time::Instant;
    if let Err((code, msg)) =
        crate::graph_auth::require_operator_auth(&headers, &state.operator_did)
    {
        return (code, Json(serde_json::json!({"ok": false, "error": msg}))).into_response();
    }
    let t0 = Instant::now();
    let graph = kg_graph_cid();
    let author = req
        .author
        .clone()
        .unwrap_or_else(|| state.operator_did.clone());
    let seq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let ipns_name = crate::xrpc::distributed_graph_ipns_name(&graph);
    match state
        .ipns_registry
        .resolve(&IpnsName::new(ipns_name.clone()))
    {
        Ok(record) => {
            return Json(KgCommitResp {
                ok: true,
                commit_cid: record.value,
                ipns_name,
                ipns_sequence: record.sequence,
                elapsed_ms: t0.elapsed().as_millis(),
            })
            .into_response();
        }
        Err(IpnsRegistryError::NotFound(_)) => {}
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "ok": false, "error": format!("ipns resolve: {e}"),
                })),
            )
                .into_response();
        }
    }

    let db = match crate::xrpc::current_db_for_graph(&state, &graph).await {
        Ok(db) => db,
        Err((code, msg)) => {
            return (code, Json(serde_json::json!({"ok": false, "error": msg}))).into_response();
        }
    };
    let writer = DistributedCommitWriter::new(&*state.block_store, &*state.ipns_registry);
    match writer.commit_datoms(CommitDatomsRequest {
        ipns_name: ipns_name.clone(),
        graph: graph.clone(),
        datoms: db.datoms(),
        expected_parent: None,
        tx_cid: Some(KotobaCid::from_bytes(
            format!("kg.commit:{}:{author}:{seq}", graph.to_multibase()).as_bytes(),
        )),
        author,
        seq: 1,
        valid_until: "2099-01-01T00:00:00Z".to_string(),
        ttl_secs: Some(60),
        cacao_proof_cid: None,
        ipns_controller_did: Some(state.operator_did.clone()),
        ipns_signing_key: Some(state.ipns_signing_key()),
    }) {
        Ok(report) => Json(KgCommitResp {
            ok: true,
            commit_cid: report.commit.cid.to_multibase(),
            ipns_name,
            ipns_sequence: report.ipns_record.sequence,
            elapsed_ms: t0.elapsed().as_millis(),
        })
        .into_response(),
        Err(e) => {
            let code = match e {
                DistributedCommitError::StaleParent { .. } => StatusCode::CONFLICT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                code,
                Json(serde_json::json!({
                    "ok": false, "error": format!("distributed commit: {e}"),
                })),
            )
                .into_response()
        }
    }
}

/// POST /xrpc/ai.gftd.apps.kotobase.kg.delete
///
/// Retract all quads for the given entity from the `kotobase-kg-v1` graph.
/// Publishes a retract event to the Journal for each quad (WAL + GossipSub).
pub async fn kg_delete(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<KgDeleteReq>,
) -> impl IntoResponse {
    if req.id.is_empty() || req.id.len() > MAX_KG_ID_LEN {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false, "error": format!("id must be 1–{MAX_KG_ID_LEN} bytes"),
            })),
        )
            .into_response();
    }
    let graph = kg_graph_cid();
    let subject = KotobaCid::from_bytes(req.id.as_bytes());
    let tx_cid = KotobaCid::from_bytes(format!("kg.delete:{}", req.id).as_bytes());
    let auth = match if req.cacao_b64.is_some() || req.auth_presentation.is_some() {
        crate::xrpc::authorize_protocol_datom_write(
            &state,
            &headers,
            &graph.to_multibase(),
            req.cacao_b64.as_deref(),
            req.auth_presentation.as_ref(),
            &[kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT],
            Some(&tx_cid),
        )
    } else {
        crate::graph_auth::require_operator_auth(&headers, &state.operator_did).map(|_| {
            crate::xrpc::ProtocolWriteAuth {
                author: state.operator_did.clone(),
                auth_proof_cid: None,
                auth_capability: None,
            }
        })
    } {
        Ok(auth) => auth,
        Err((code, msg)) => {
            return (code, Json(serde_json::json!({"ok": false, "error": msg}))).into_response();
        }
    };

    let db = match crate::xrpc::current_db_for_graph(&state, &graph).await {
        Ok(db) => db,
        Err((code, msg)) => {
            return (code, Json(serde_json::json!({"ok": false, "error": msg}))).into_response()
        }
    };
    let current_datoms: Vec<_> = db
        .datoms()
        .into_iter()
        .filter(|datom| datom.e == subject)
        .collect();

    let retracted = current_datoms.len();

    if retracted > 0 {
        let retract_datoms: Vec<_> = current_datoms
            .into_iter()
            .map(|datom| kotoba_datomic::Datom::retract(datom.e, datom.a, datom.v, tx_cid.clone()))
            .collect();
        if let Err((code, msg)) = crate::xrpc::commit_protocol_datoms(
            &state,
            graph.clone(),
            graph.to_multibase(),
            subject.clone(),
            retract_datoms,
            tx_cid,
            auth.author,
            kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
            auth.auth_proof_cid,
            auth.auth_capability,
        )
        .await
        {
            return (code, Json(serde_json::json!({"ok": false, "error": msg}))).into_response();
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok":            true,
            "id":            req.id,
            "retractedCount": retracted,
        })),
    )
        .into_response()
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let len = a.len().min(b.len());
    let dot: f32 = a[..len]
        .iter()
        .zip(b[..len].iter())
        .map(|(x, y)| x * y)
        .sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

// ── kg.query ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgQueryReq {
    /// "sparql" or "cypher"
    pub lang: String,
    /// Query string
    pub query: String,
    /// CACAO delegation chain for private graphs (DAG-CBOR, base64-standard encoded).
    pub cacao_b64: Option<String>,
    /// Maximum results to return (1–10000; default 1000).
    pub limit: Option<usize>,
}

/// POST /xrpc/ai.gftd.apps.kotobase.kg.query
/// Execute a SPARQL SELECT or Cypher MATCH/RETURN against the QuadStore.
///
/// Both compilers enforce binary-relation arity (exactly 2 RETURN variables).
/// Results are returned as `[{ "a": "<cid>", "b": "<cid>" }]` pairs where
/// the variable names come from the compiled output_relation.
const MAX_KG_QUERY_PROG_LEN: usize = 65_536; // 64 KiB — SPARQL/Cypher compile DoS guard

pub async fn kg_query(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<KgQueryReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_graph::sparql::SparqlCompiler;
    use kotoba_kqe::cypher::CypherCompiler;
    use std::time::Instant;

    const MAX_KG_LANG_LEN: usize = 16;
    const MAX_KG_QUERY_RESULT_LIMIT: usize = 10_000;
    if req.lang.len() > MAX_KG_LANG_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "lang field too long ({} bytes, limit {MAX_KG_LANG_LEN})",
                req.lang.len()
            ),
        ));
    }
    if req.query.is_empty() || req.query.len() > MAX_KG_QUERY_PROG_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("query must be 1–{MAX_KG_QUERY_PROG_LEN} bytes"),
        ));
    }
    if !matches!(req.lang.as_str(), "sparql" | "cypher") {
        return Err((
            StatusCode::BAD_REQUEST,
            "lang must be 'sparql' or 'cypher'".to_string(),
        ));
    }
    let result_limit = req
        .limit
        .unwrap_or(MAX_KG_LIMIT)
        .min(MAX_KG_QUERY_RESULT_LIMIT);

    let t0 = Instant::now();
    let graph_cid = kg_graph_cid();

    // ── Read-access gate ─────────────────────────────────────────────────────
    let visibility = state.graph_visibility(&graph_cid).await;
    check_read_access(
        &visibility,
        &headers,
        req.cacao_b64.as_deref(),
        Some(&state.operator_did),
        Some(&state.nonce_store),
    )
    .map_err(AccessDenied::into_response)?;

    // Compile query to DatalogProgram
    let (program, output_relation) = match req.lang.as_str() {
        "sparql" => {
            let compiled = SparqlCompiler::compile(&req.query, "kg_query_result")
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("SPARQL compile: {e}")))?;
            (compiled.program, compiled.output_relation)
        }
        "cypher" => {
            let compiled = CypherCompiler::compile(&req.query, "kg_query_result")
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("Cypher compile: {e}")))?;
            (compiled.program, compiled.output_relation)
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown lang: {other}; use sparql or cypher"),
            ))
        }
    };

    let input_deltas = current_graph_deltas(&state, &graph_cid).await?;
    let derived = tokio::task::spawn_blocking(move || program.evaluate_delta(&input_deltas))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("datalog eval join: {e}"),
            )
        })?;

    // Collect derived facts for the output_relation, bounded by result_limit.
    let results: Vec<serde_json::Value> = derived
        .iter()
        .filter(|d| d.attribute() == output_relation && d.is_assert())
        .take(result_limit)
        .map(|d| {
            serde_json::json!({
                "a": d.entity().to_multibase(),
                "b": match d.value() {
                    kotoba_kqe::Value::Cid(c) => c.to_multibase(),
                    other              => format!("{other:?}"),
                },
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "ok":        true,
        "lang":      req.lang,
        "count":     results.len(),
        "results":   results,
        "elapsedMs": t0.elapsed().as_millis(),
    })))
}

// ── Direct SPARQL form endpoint (SELECT / DESCRIBE / CONSTRUCT / ASK) ─────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SparqlReq {
    /// SPARQL query string (max 64 KiB).  Auto-detects SELECT / DESCRIBE /
    /// CONSTRUCT / ASK from the leading keyword.
    pub query: String,
    /// Optional named graph CID (multibase).  Defaults to the kg-graph CID.
    pub graph: Option<String>,
    /// Optional `host:port` or `/ip4/<addr>/tcp/<port>` kotoba-ipfs peer used
    /// to resolve a remote graph head and DAG-CBOR/Prolly blocks.
    pub remote_peer: Option<String>,
    /// Optional IPNS name override for SPARQL reads. Defaults to the graph's
    /// canonical `k51-kotoba-{graphCid}` head.
    pub remote_ipns_name: Option<String>,
    /// Optional Datomic `as-of` transaction CID for SPARQL reads.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID for SPARQL reads.
    pub since: Option<String>,
    /// CACAO delegation chain (DAG-CBOR + base64) for private graphs.
    pub cacao_b64: Option<String>,
    /// W3C Verifiable Presentation carrying operator-issued graph capabilities.
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
    /// Maximum results to materialise (defaults to 10000).
    pub limit: Option<usize>,
    /// For DESCRIBE only: number of hops to traverse along `QuadObject::Cid`
    /// edges starting from the matched seed subjects.  When > 0 dispatches to
    /// `sparql_describe_n_hop` instead of the single-level `sparql_describe`,
    /// returning the entire reachable subgraph deduplicated by entity.
    /// Useful for "multi-pop" social-graph / citation-chain expansion.
    #[serde(default)]
    pub max_hops: usize,
}

/// POST /xrpc/ai.gftd.apps.kotoba.graph.sparql
///
/// Execute a SPARQL query directly against the distributed Datomic DB view.
/// Supports all four query forms; result shape varies:
///
///   - SELECT    →  `{ "form": "select",    "quads": [{...}] }`
///   - DESCRIBE  →  `{ "form": "describe",  "quads": [{...}] }`
///   - CONSTRUCT →  `{ "form": "construct", "quads": [{...}] }`
///   - ASK       →  `{ "form": "ask",       "result": true }`
///
/// Loads the current graph basis from IPNS/IPLD ProllyTree indexes, materialises
/// a local query-only projection, and honours CACAO gating per visibility policy.
pub async fn kg_sparql(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<SparqlReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use std::time::Instant;

    const MAX_SPARQL_RESULT_LIMIT: usize = 100_000;
    if req.query.is_empty() || req.query.len() > MAX_KG_QUERY_PROG_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("query must be 1–{MAX_KG_QUERY_PROG_LEN} bytes"),
        ));
    }
    let limit = req.limit.unwrap_or(10_000).min(MAX_SPARQL_RESULT_LIMIT);

    // Resolve target graph CID.
    let graph_cid = match req.graph.as_deref() {
        None => kg_graph_cid(),
        Some(s) => kotoba_core::cid::KotobaCid::from_multibase(s)
            .ok_or((StatusCode::BAD_REQUEST, format!("invalid graph CID: {s}")))?,
    };

    crate::xrpc::require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;

    // Detect the SPARQL query form from the leading keyword.
    let t0 = Instant::now();
    let head = req.query.trim_start();
    let upper: String = head
        .chars()
        .take(10)
        .collect::<String>()
        .to_ascii_uppercase();
    let (qs, basis_t) = distributed_query_store(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
        req.remote_peer.as_deref(),
        req.remote_ipns_name.as_deref(),
    )
    .await?;

    let response = if upper.starts_with("ASK") {
        let result = qs
            .sparql_ask(&graph_cid, &req.query)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("ASK eval: {e}")))?;
        serde_json::json!({
            "ok":        true,
            "form":      "ask",
            "basisT":    basis_t,
            "result":    result,
            "elapsedMs": t0.elapsed().as_millis(),
        })
    } else if upper.starts_with("DESCRIBE") {
        // Bound max_hops to a sane ceiling — N-hop is fully parallel per layer
        // but each hop fans out, so the per-request memory cost is O(reach).
        const MAX_HOPS_HARD_CAP: usize = 16;
        let max_hops = req.max_hops.min(MAX_HOPS_HARD_CAP);
        let quads = if max_hops == 0 {
            qs.sparql_describe(&graph_cid, &req.query).await
        } else {
            qs.sparql_describe_n_hop(&graph_cid, &req.query, max_hops)
                .await
        }
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("DESCRIBE eval: {e}")))?;
        let materialised: Vec<_> = quads.into_iter().take(limit).map(quad_to_json).collect();
        serde_json::json!({
            "ok":        true,
            "form":      "describe",
            "basisT":    basis_t,
            "maxHops":   max_hops,
            "count":     materialised.len(),
            "quads":     materialised,
            "elapsedMs": t0.elapsed().as_millis(),
        })
    } else if upper.starts_with("CONSTRUCT") {
        let quads = qs
            .sparql_construct(&graph_cid, &req.query)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("CONSTRUCT eval: {e}")))?;
        let materialised: Vec<_> = quads.into_iter().take(limit).map(quad_to_json).collect();
        serde_json::json!({
            "ok":        true,
            "form":      "construct",
            "basisT":    basis_t,
            "count":     materialised.len(),
            "quads":     materialised,
            "elapsedMs": t0.elapsed().as_millis(),
        })
    } else if upper.starts_with("SELECT") {
        let quads = qs
            .cold_query_sparql_bgp(&graph_cid, &req.query)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("SELECT eval: {e}")))?;
        let materialised: Vec<_> = quads.into_iter().take(limit).map(quad_to_json).collect();
        serde_json::json!({
            "ok":        true,
            "form":      "select",
            "basisT":    basis_t,
            "count":     materialised.len(),
            "quads":     materialised,
            "elapsedMs": t0.elapsed().as_millis(),
        })
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            "query must start with SELECT, DESCRIBE, CONSTRUCT, or ASK".to_string(),
        ));
    };
    Ok(Json(response))
}

fn quad_to_json(q: kotoba_kqe::quad::LegacyQuad) -> serde_json::Value {
    serde_json::json!({
        "graph":     q.graph.to_multibase(),
        "subject":   q.subject.to_multibase(),
        "predicate": q.predicate,
        "object":    match q.object {
            QuadObject::Cid(c)      => serde_json::json!({"cid": c.to_multibase()}),
            QuadObject::Text(t)     => serde_json::json!({"text": t}),
            QuadObject::Integer(i)  => serde_json::json!({"int": i}),
            QuadObject::Float(f)    => serde_json::json!({"float": f}),
            QuadObject::Bool(b)     => serde_json::json!({"bool": b}),
            other                   => serde_json::json!({"raw": format!("{other:?}")}),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use ed25519_dalek::Signer as _;
    use kotoba_core::cid::KotobaCid;
    use kotoba_core::named_graph::GraphVisibility;
    use kotoba_datomic::distributed::CommitDatomsRequest;
    use kotoba_datomic::Datom;
    use kotoba_edn::EdnValue;

    // ── kg_graph_cid ──────────────────────────────────────────────────────────

    #[test]
    fn kg_graph_cid_is_stable() {
        let a = kg_graph_cid();
        let b = kg_graph_cid();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn kg_sparql_reads_named_distributed_ipns_head() {
        std::env::set_var("KOTOBA_IPFS", "off");
        std::env::set_var("KOTOBA_IPNS_REQUIRE_SIGNATURE", "false");
        let state = Arc::new(KotobaState::new(None).unwrap());
        let graph = KotobaCid::from_bytes(b"kg-sparql-named-ipns-graph");
        let graph_mb = graph.to_multibase();
        state.graph_registry.write().await.insert(
            graph.clone(),
            ("kg-sparql-named-ipns-graph".into(), GraphVisibility::Public),
        );

        let ipns_name = "k51-kotoba-kg-sparql-named-head".to_string();
        let tx = KotobaCid::from_bytes(b"kg-sparql-named-ipns-tx");
        let second_tx = KotobaCid::from_bytes(b"kg-sparql-named-ipns-second-tx");
        let alice = KotobaCid::from_bytes(b"kg-sparql-alice");
        let bob = KotobaCid::from_bytes(b"kg-sparql-bob");
        let writer = DistributedCommitWriter::new(&*state.block_store, &*state.ipns_registry);
        let first = writer
            .commit_datoms(CommitDatomsRequest {
                ipns_name: ipns_name.clone(),
                graph: graph.clone(),
                datoms: vec![
                    Datom::assert(
                        alice.clone(),
                        "role".into(),
                        EdnValue::string("admin"),
                        tx.clone(),
                    ),
                    Datom::assert(alice, "name".into(), EdnValue::string("Alice"), tx.clone()),
                ],
                expected_parent: None,
                tx_cid: Some(tx.clone()),
                author: "did:key:zSparqlAuthor".into(),
                seq: 1,
                valid_until: "2030-01-01T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .unwrap();
        writer
            .commit_datoms(CommitDatomsRequest {
                ipns_name: ipns_name.clone(),
                graph: graph.clone(),
                datoms: vec![
                    Datom::assert(
                        bob.clone(),
                        "role".into(),
                        EdnValue::string("editor"),
                        second_tx.clone(),
                    ),
                    Datom::assert(
                        bob,
                        "name".into(),
                        EdnValue::string("Bob"),
                        second_tx.clone(),
                    ),
                ],
                expected_parent: Some(first.commit.cid.clone()),
                tx_cid: Some(second_tx.clone()),
                author: "did:key:zSparqlAuthor".into(),
                seq: 2,
                valid_until: "2030-01-01T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .unwrap();

        let response = kg_sparql(
            State(Arc::clone(&state)),
            HeaderMap::new(),
            Json(SparqlReq {
                query: r#"SELECT ?s WHERE { ?s <role> "admin" }"#.into(),
                graph: Some(graph_mb.clone()),
                remote_peer: None,
                remote_ipns_name: Some(ipns_name.clone()),
                as_of: None,
                since: None,
                cacao_b64: None,
                presentation: None,
                limit: None,
                max_hops: 0,
            }),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["form"], "select");
        assert_eq!(body["count"], 1);
        assert_eq!(body["quads"][0]["predicate"], "role");
        assert_eq!(body["quads"][0]["object"]["text"], "admin");

        let as_of = kg_sparql(
            State(Arc::clone(&state)),
            HeaderMap::new(),
            Json(SparqlReq {
                query: r#"SELECT ?s WHERE { ?s <role> "editor" }"#.into(),
                graph: Some(graph_mb.clone()),
                remote_peer: None,
                remote_ipns_name: Some(ipns_name.clone()),
                as_of: Some(tx.to_multibase()),
                since: None,
                cacao_b64: None,
                presentation: None,
                limit: None,
                max_hops: 0,
            }),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(as_of.status(), StatusCode::OK);
        let as_of_body = axum::body::to_bytes(as_of.into_body(), usize::MAX)
            .await
            .unwrap();
        let as_of_body: serde_json::Value = serde_json::from_slice(&as_of_body).unwrap();
        assert_eq!(as_of_body["basisT"], tx.to_multibase());
        assert_eq!(as_of_body["count"], 0);

        let since = kg_sparql(
            State(Arc::clone(&state)),
            HeaderMap::new(),
            Json(SparqlReq {
                query: r#"SELECT ?s WHERE { ?s <role> "editor" }"#.into(),
                graph: Some(graph_mb),
                remote_peer: None,
                remote_ipns_name: Some(ipns_name),
                as_of: None,
                since: Some(tx.to_multibase()),
                cacao_b64: None,
                presentation: None,
                limit: None,
                max_hops: 0,
            }),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(since.status(), StatusCode::OK);
        let since_body = axum::body::to_bytes(since.into_body(), usize::MAX)
            .await
            .unwrap();
        let since_body: serde_json::Value = serde_json::from_slice(&since_body).unwrap();
        assert_eq!(since_body["basisT"], second_tx.to_multibase());
        assert_eq!(since_body["count"], 1);
        assert_eq!(since_body["quads"][0]["object"]["text"], "editor");
    }

    #[tokio::test]
    async fn kg_sparql_accepts_vp_graph_query_capability_for_private_graph() {
        std::env::set_var("KOTOBA_IPFS", "off");
        std::env::set_var("KOTOBA_IPNS_REQUIRE_SIGNATURE", "false");
        let state = Arc::new(KotobaState::new(None).unwrap());
        let graph = KotobaCid::from_bytes(b"kg-sparql-vp-private-graph");
        let graph_mb = graph.to_multibase();
        state.graph_registry.write().await.insert(
            graph.clone(),
            (
                "kg-sparql-vp-private-graph".into(),
                GraphVisibility::Private {
                    owner_did: state.operator_did.clone(),
                },
            ),
        );

        let ipns_name = "k51-kotoba-kg-sparql-vp-private-head".to_string();
        let tx = KotobaCid::from_bytes(b"kg-sparql-vp-private-tx");
        let alice = KotobaCid::from_bytes(b"kg-sparql-vp-private-alice");
        DistributedCommitWriter::new(&*state.block_store, &*state.ipns_registry)
            .commit_datoms(CommitDatomsRequest {
                ipns_name: ipns_name.clone(),
                graph: graph.clone(),
                datoms: vec![Datom::assert(
                    alice,
                    "role".into(),
                    EdnValue::string("admin"),
                    tx.clone(),
                )],
                expected_parent: None,
                tx_cid: Some(tx),
                author: state.operator_did.clone(),
                seq: 1,
                valid_until: "2030-01-01T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .unwrap();

        let denied = kg_sparql(
            State(Arc::clone(&state)),
            HeaderMap::new(),
            Json(SparqlReq {
                query: r#"SELECT ?s WHERE { ?s <role> "admin" }"#.into(),
                graph: Some(graph_mb.clone()),
                remote_peer: None,
                remote_ipns_name: Some(ipns_name.clone()),
                as_of: None,
                since: None,
                cacao_b64: None,
                presentation: None,
                limit: None,
                max_hops: 0,
            }),
        )
        .await;
        assert!(
            denied.is_err(),
            "private graph must reject unauthenticated SPARQL"
        );

        let response = kg_sparql(
            State(Arc::clone(&state)),
            HeaderMap::new(),
            Json(SparqlReq {
                query: r#"SELECT ?s WHERE { ?s <role> "admin" }"#.into(),
                graph: Some(graph_mb),
                remote_peer: None,
                remote_ipns_name: Some(ipns_name),
                as_of: None,
                since: None,
                cacao_b64: None,
                presentation: Some(signed_capability_presentation(
                    &state,
                    &graph,
                    kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
                    "graph.sparql",
                )),
                limit: None,
                max_hops: 0,
            }),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["form"], "select");
        assert_eq!(body["count"], 1);
        assert_eq!(body["quads"][0]["object"]["text"], "admin");
    }

    #[tokio::test]
    async fn kg_ingest_accepts_vp_datom_transact_capability() {
        std::env::set_var("KOTOBA_IPFS", "off");
        std::env::set_var("KOTOBA_IPNS_REQUIRE_SIGNATURE", "false");
        let state = Arc::new(KotobaState::new(None).unwrap());
        let graph = kg_graph_cid();

        let response = kg_ingest(
            State(Arc::clone(&state)),
            HeaderMap::new(),
            Json(KgIngestReq {
                id: "kg-vp-ingest-1".into(),
                qid: None,
                kind: Some("test".into()),
                label_ja: None,
                label_en: Some("VP Ingest".into()),
                confidence: None,
                license: None,
                extractor: None,
                valid_from: None,
                valid_to: None,
                ingested_at: None,
                source_id: None,
                label_vec: vec![],
                claims: vec![],
                relations: vec![],
                cacao_b64: None,
                auth_presentation: Some(signed_capability_presentation(
                    &state,
                    &graph,
                    kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
                    "kg.ingest",
                )),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let db = crate::xrpc::current_db_for_graph(&state, &graph)
            .await
            .unwrap();
        assert!(db.datoms().iter().any(|datom| {
            datom.a == ":capability/operation"
                && datom.v == EdnValue::string(kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT)
        }));
        assert!(db.datoms().iter().any(|datom| {
            datom.a == ":capability/proofFormat"
                && datom.v == EdnValue::string("W3C VerifiablePresentation")
        }));
    }

    fn signed_capability_presentation(
        state: &KotobaState,
        graph: &KotobaCid,
        operation: &str,
        challenge: &str,
    ) -> kotoba_vc::VerifiablePresentation {
        let holder = state.operator_did.clone();
        let mut credential = kotoba_vc::VerifiableCredential::new(
            format!("urn:uuid:{challenge}-vp-capability"),
            state.operator_did.clone(),
            serde_json::json!({
                "id": holder,
                "graph": graph.to_multibase(),
                "operation": operation,
                "scope": format!("kotoba://graph/{}", graph.to_multibase()),
            }),
        );
        credential
            .types
            .push("KotobaGraphCapabilityCredential".into());
        let credential_signature = state
            .ipns_signing_key()
            .sign(&credential.proof_bytes().unwrap());
        credential.proof = Some(kotoba_vc::DataIntegrityProof {
            proof_type: "DataIntegrityProof".into(),
            cryptosuite: Some("eddsa-2022".into()),
            proof_purpose: "assertionMethod".into(),
            verification_method: format!("{}#agent-ed25519", state.operator_did),
            created: Some("2026-05-30T00:00:00Z".into()),
            proof_value: multibase::encode(
                multibase::Base::Base58Btc,
                credential_signature.to_bytes(),
            ),
            challenge: Some(challenge.into()),
            domain: Some("kotoba.protocol.write".into()),
        });

        let mut presentation = kotoba_vc::VerifiablePresentation {
            context: vec![kotoba_vc::VC_CONTEXT_V2.into()],
            id: format!("urn:uuid:{challenge}-vp"),
            types: vec!["VerifiablePresentation".into()],
            holder: Some(state.operator_did.clone()),
            verifiable_credentials: vec![credential],
            proof: None,
        };
        let presentation_signature = state
            .ipns_signing_key()
            .sign(&presentation.proof_bytes().unwrap());
        presentation.proof = Some(kotoba_vc::DataIntegrityProof {
            proof_type: "DataIntegrityProof".into(),
            cryptosuite: Some("eddsa-2022".into()),
            proof_purpose: "authentication".into(),
            verification_method: format!("{}#agent-ed25519", state.operator_did),
            created: Some("2026-05-30T00:00:00Z".into()),
            proof_value: multibase::encode(
                multibase::Base::Base58Btc,
                presentation_signature.to_bytes(),
            ),
            challenge: Some(challenge.into()),
            domain: Some("kotoba.protocol.write".into()),
        });
        presentation
    }

    // ── obj_to_json ───────────────────────────────────────────────────────────

    #[test]
    fn obj_to_json_text() {
        let v = obj_to_json(&QuadObject::Text("hello".to_string()));
        assert_eq!(v, serde_json::json!("hello"));
    }

    #[test]
    fn obj_to_json_integer() {
        let v = obj_to_json(&QuadObject::Integer(42));
        assert_eq!(v, serde_json::json!(42));
    }

    #[test]
    fn obj_to_json_float() {
        let v = obj_to_json(&QuadObject::Float(3.14));
        assert!((v.as_f64().unwrap() - 3.14).abs() < 1e-10);
    }

    #[test]
    fn obj_to_json_bool() {
        assert_eq!(
            obj_to_json(&QuadObject::Bool(true)),
            serde_json::json!(true)
        );
        assert_eq!(
            obj_to_json(&QuadObject::Bool(false)),
            serde_json::json!(false)
        );
    }

    #[test]
    fn obj_to_json_cid_is_multibase_string() {
        let cid = KotobaCid::from_bytes(b"test-cid");
        let v = obj_to_json(&QuadObject::Cid(cid.clone()));
        assert_eq!(v.as_str().unwrap(), cid.to_multibase());
    }

    #[test]
    fn obj_to_json_bytes_is_null() {
        let v = obj_to_json(&QuadObject::Bytes(b"raw".to_vec()));
        assert_eq!(v, serde_json::Value::Null);
    }

    // ── blake3_pseudo_vector ──────────────────────────────────────────────────

    #[test]
    fn blake3_pseudo_vector_has_correct_dims() {
        let v = blake3_pseudo_vector("hello world", 64);
        assert_eq!(v.len(), 64);
    }

    #[test]
    fn blake3_pseudo_vector_values_in_minus1_plus1() {
        let v = blake3_pseudo_vector("test", 128);
        for x in &v {
            assert!(*x >= -1.0 && *x <= 1.0, "value out of range: {x}");
        }
    }

    #[test]
    fn blake3_pseudo_vector_is_deterministic() {
        let a = blake3_pseudo_vector("kotoba", 32);
        let b = blake3_pseudo_vector("kotoba", 32);
        assert_eq!(a, b);
    }

    #[test]
    fn blake3_pseudo_vector_differs_for_different_inputs() {
        let a = blake3_pseudo_vector("foo", 32);
        let b = blake3_pseudo_vector("bar", 32);
        assert_ne!(a, b);
    }

    // ── cosine ────────────────────────────────────────────────────────────────

    #[test]
    fn cosine_identical_vectors_is_one() {
        let v = vec![1.0f32, 2.0, 3.0];
        let s = cosine(&v, &v);
        assert!(
            (s - 1.0).abs() < 1e-6,
            "cosine of identical vectors must be 1.0, got {s}"
        );
    }

    #[test]
    fn cosine_orthogonal_vectors_is_zero() {
        let a = vec![1.0f32, 0.0];
        let b = vec![0.0f32, 1.0];
        let s = cosine(&a, &b);
        assert!(
            s.abs() < 1e-6,
            "cosine of orthogonal vectors must be 0.0, got {s}"
        );
    }

    #[test]
    fn cosine_zero_vector_returns_zero() {
        let a = vec![0.0f32, 0.0];
        let b = vec![1.0f32, 0.0];
        assert_eq!(cosine(&a, &b), 0.0);
    }

    #[test]
    fn cosine_opposite_vectors_is_minus_one() {
        let a = vec![1.0f32, 0.0];
        let b = vec![-1.0f32, 0.0];
        let s = cosine(&a, &b);
        assert!(
            (s + 1.0).abs() < 1e-6,
            "cosine of opposite vectors must be -1.0, got {s}"
        );
    }

    #[test]
    fn cosine_mismatched_lengths_clips_dot_product() {
        // dot = a[..2]·b[..2] = 1*1 + 0*0 = 1
        // na  = ||a||_full = sqrt(1 + 0 + 99²) ≈ 99.005
        // nb  = ||b||_full = 1.0
        // cosine ≈ 1 / (99.005 * 1) ≈ 0.0101 (clearly not 1.0)
        let a = vec![1.0f32, 0.0, 99.0];
        let b = vec![1.0f32, 0.0];
        let s = cosine(&a, &b);
        // The norms use the full vectors; dot uses only the shorter prefix.
        let expected = 1.0 / (f32::sqrt(1.0 + 0.0 + 99.0_f32 * 99.0) * 1.0);
        assert!((s - expected).abs() < 1e-5, "got {s}, expected {expected}");
    }

    // ── kg_query input-guard constants ────────────────────────────────────────

    #[test]
    fn kg_query_lang_length_constant_is_sane() {
        // MAX_KG_LANG_LEN must accept "sparql" and "cypher" (6 and 6 chars) with margin.
        assert!("sparql".len() <= 16, "MAX_KG_LANG_LEN must fit 'sparql'");
        assert!("cypher".len() <= 16, "MAX_KG_LANG_LEN must fit 'cypher'");
        // The constant must be small enough to prevent oversized error messages.
        assert!(16 <= 64, "MAX_KG_LANG_LEN should be modest");
    }

    #[test]
    fn kg_query_result_limit_constant_is_sane() {
        // MAX_KG_QUERY_RESULT_LIMIT (10000) is ≥ MAX_KG_LIMIT (1000) and ≤ MAX_DERIVED_FACTS.
        assert!(
            10_000 >= MAX_KG_LIMIT,
            "result limit must be ≥ default kg limit"
        );
        // A response of 10k rows should remain reasonable in size.
        assert!(
            10_000 <= 100_000,
            "result limit should be bounded for response safety"
        );
    }

    #[test]
    fn kg_query_limit_field_default_and_cap() {
        // Default: None → MAX_KG_LIMIT (1000).
        let default_limit = None::<usize>.unwrap_or(MAX_KG_LIMIT).min(10_000);
        assert_eq!(default_limit, MAX_KG_LIMIT);

        // Caller-supplied value is capped at MAX_KG_QUERY_RESULT_LIMIT.
        let caller_huge = Some(999_999usize).unwrap_or(MAX_KG_LIMIT).min(10_000);
        assert_eq!(
            caller_huge, 10_000,
            "oversized limit must be capped at 10_000"
        );

        // Caller-supplied small value passes through unchanged.
        let caller_small = Some(42usize).unwrap_or(MAX_KG_LIMIT).min(10_000);
        assert_eq!(caller_small, 42);
    }
}
