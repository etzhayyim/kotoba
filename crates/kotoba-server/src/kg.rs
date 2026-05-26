/// yatabase KG entity lookup endpoint backed by kotoba QuadStore.
///
/// NSID: ai.gftd.apps.yata.kg.entity
/// All KG quads live in the named graph `yatabase-kg-v1`.
///
/// Predicate conventions (written by seed_kotoba.py):
///   kg/id           — nanoid primary key
///   kg/qid          — Wikidata QID (e.g. "Q42")
///   kg/type         — entity type string
///   kg/label/ja     — Japanese label
///   kg/label/en     — English label
///   kg/confidence   — float string
///   kg/license      — license SPDX
///   kg/extractor    — extractor identifier
///   kg/valid_from   — ISO-8601 date
///   kg/valid_to     — ISO-8601 date
///   kg/ingested_at  — ISO-8601 datetime
///   kg/source_id    — source nanoid
///   kg/claim/<pred> — property claim (Text / Float / Bool)
///   kg/relation/<pred> — edge to another entity (Cid object = subject CID of dst)

use std::sync::Arc;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::QuadObject;
use crate::server::KotobaState;
use crate::graph_auth::{AccessDenied, check_read_access};

/// Require a valid, non-expired Bearer JWT to authorise KG write operations.
/// Any authenticated principal with a `sub` claim and a valid `exp` is accepted.
fn require_kg_write_auth(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("kg write auth: missing Bearer token");
            (StatusCode::UNAUTHORIZED,
                "Authorization: Bearer <token> required for KG write operations".to_string())
        })?;
    if crate::graph_auth::jwt_exp_elapsed(token) {
        tracing::warn!("kg write auth: expired JWT");
        return Err((StatusCode::UNAUTHORIZED, "Bearer token has expired".to_string()));
    }
    crate::graph_auth::jwt_sub(token)
        .ok_or_else(|| {
            tracing::warn!("kg write auth: JWT missing sub claim");
            (StatusCode::UNAUTHORIZED, "Bearer token missing sub claim".to_string())
        })?;
    Ok(())
}

pub const NSID_KG_ENTITY:  &str = "ai.gftd.apps.yata.kg.entity";
pub const NSID_KG_CATALOG: &str = "ai.gftd.apps.yata.kg.catalog";
pub const NSID_KG_EMBED:   &str = "ai.gftd.apps.yata.kg.embed";
pub const NSID_KG_SEARCH:  &str = "ai.gftd.apps.yata.kg.search";
pub const NSID_KG_QUERY:   &str = "ai.gftd.apps.yata.kg.query";
pub const NSID_KG_INGEST:  &str = "ai.gftd.apps.yata.kg.ingest";
pub const NSID_KG_DELETE:  &str = "ai.gftd.apps.yata.kg.delete";

/// All yatabase KG quads are written into this named graph.
pub fn kg_graph_cid() -> KotobaCid {
    KotobaCid::from_bytes(b"yatabase-kg-v1")
}

const MAX_KG_ID_LEN:    usize = 256;
const MAX_KG_TEXT_LEN:  usize = 8_192;  // max embed text — prevents inference-engine DoS
const MAX_KG_QUERY_LEN: usize = 2_048;
const MAX_KG_LIMIT:     usize = 1_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgEntityQuery {
    pub id:  Option<String>,
    pub qid: Option<String>,
    #[serde(default = "default_true")]
    pub include_claims:    bool,
    #[serde(default = "default_true")]
    pub include_relations: bool,
    #[serde(default = "default_max_relations")]
    pub max_relations: usize,
    /// CACAO delegation chain for private graphs (DAG-CBOR, base64-standard encoded).
    pub cacao_b64: Option<String>,
}

fn default_true()         -> bool  { true }
fn default_max_relations() -> usize { 50   }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KgEntityResp {
    pub ok:        bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:     Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity:    Option<serde_json::Value>,
    pub elapsed_ms: u128,
}

/// GET /xrpc/ai.gftd.apps.yata.kg.entity?id=<nanoid>
/// GET /xrpc/ai.gftd.apps.yata.kg.entity?qid=Q42
pub async fn kg_entity(
    State(state): State<Arc<KotobaState>>,
    headers:      HeaderMap,
    Query(q):     Query<KgEntityQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use std::time::Instant;
    let t0        = Instant::now();
    let graph_cid = kg_graph_cid();

    // ── Read-access gate ─────────────────────────────────────────────────────
    let visibility = state.graph_visibility(&graph_cid).await;
    check_read_access(&visibility, &headers, q.cacao_b64.as_deref(), Some(&state.operator_did), Some(&state.nonce_store))
        .map_err(AccessDenied::into_response)?;

    let (lookup_pred, lookup_val) = match (&q.id, &q.qid) {
        (Some(id), _) => {
            if id.len() > MAX_KG_ID_LEN {
                return Err((StatusCode::BAD_REQUEST,
                    format!("id must be ≤{MAX_KG_ID_LEN} bytes")));
            }
            ("kg/id", id.as_str())
        }
        (_, Some(qid)) => {
            if qid.len() > MAX_KG_ID_LEN {
                return Err((StatusCode::BAD_REQUEST,
                    format!("qid must be ≤{MAX_KG_ID_LEN} bytes")));
            }
            ("kg/qid", qid.as_str())
        }
        _ => return Err((StatusCode::BAD_REQUEST, "missing `id` or `qid` query param".into())),
    };

    let subjects = state.quad_store
        .lookup_subject_by_po(Some(&graph_cid), lookup_pred, lookup_val)
        .await;

    let subject_cid = match subjects.into_iter().next() {
        Some(s) => s,
        None => {
            return Ok(Json(KgEntityResp {
                ok:         false,
                error:      Some(format!("entity not found: {lookup_val}")),
                entity:     None,
                elapsed_ms: t0.elapsed().as_millis(),
            }));
        }
    };

    let quads = state.quad_store
        .get_entity_quads(Some(&graph_cid), &subject_cid)
        .await;

    let mut meta: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    let mut claims:    Vec<serde_json::Value> = Vec::new();
    let mut relations: Vec<serde_json::Value> = Vec::new();

    for quad in &quads {
        let pred = quad.predicate.as_str();
        match pred {
            "kg/id"          => { meta.insert("id".into(),          obj_to_json(&quad.object)); }
            "kg/qid"         => { meta.insert("qid".into(),         obj_to_json(&quad.object)); }
            "kg/type"        => { meta.insert("type".into(),        obj_to_json(&quad.object)); }
            "kg/label/ja"    => { meta.insert("labelJa".into(),     obj_to_json(&quad.object)); }
            "kg/label/en"    => { meta.insert("labelEn".into(),     obj_to_json(&quad.object)); }
            "kg/confidence"  => { meta.insert("confidence".into(),  obj_to_json(&quad.object)); }
            "kg/license"     => { meta.insert("license".into(),     obj_to_json(&quad.object)); }
            "kg/extractor"   => { meta.insert("extractor".into(),   obj_to_json(&quad.object)); }
            "kg/valid_from"  => { meta.insert("validFrom".into(),   obj_to_json(&quad.object)); }
            "kg/valid_to"    => { meta.insert("validTo".into(),     obj_to_json(&quad.object)); }
            "kg/ingested_at" => { meta.insert("ingestedAt".into(),  obj_to_json(&quad.object)); }
            "kg/source_id"   => { meta.insert("sourceId".into(),    obj_to_json(&quad.object)); }
            _ if pred.starts_with("kg/claim/") && q.include_claims => {
                let claim_pred = &pred["kg/claim/".len()..];
                claims.push(serde_json::json!({
                    "predicate": claim_pred,
                    "value":     obj_to_json(&quad.object),
                }));
            }
            _ if pred.starts_with("kg/relation/") && q.include_relations
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

    if q.include_claims    { meta.insert("claims".into(),    serde_json::Value::Array(claims));    }
    if q.include_relations { meta.insert("relations".into(), serde_json::Value::Array(relations)); }

    Ok(Json(KgEntityResp {
        ok:         true,
        error:      None,
        entity:     Some(serde_json::Value::Object(meta)),
        elapsed_ms: t0.elapsed().as_millis(),
    }))
}

fn obj_to_json(obj: &QuadObject) -> serde_json::Value {
    match obj {
        QuadObject::Text(s)    => serde_json::Value::String(s.clone()),
        QuadObject::Integer(n) => serde_json::json!(n),
        QuadObject::Float(f)   => serde_json::json!(f),
        QuadObject::Bool(b)    => serde_json::json!(b),
        QuadObject::Cid(c)     => serde_json::Value::String(c.to_multibase()),
        _                      => serde_json::Value::Null,
    }
}

// ── kg.catalog ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgCatalogQuery {
    /// CACAO delegation chain for private graphs (DAG-CBOR, base64-standard encoded).
    pub cacao_b64: Option<String>,
}

/// GET /xrpc/ai.gftd.apps.yata.kg.catalog
/// Returns aggregate stats and source breakdown from the QuadStore.
pub async fn kg_catalog(
    State(state): State<Arc<KotobaState>>,
    headers:      HeaderMap,
    Query(q):     Query<KgCatalogQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use std::time::Instant;
    let t0        = Instant::now();
    let graph_cid = kg_graph_cid();

    // ── Read-access gate ─────────────────────────────────────────────────────
    let visibility = state.graph_visibility(&graph_cid).await;
    check_read_access(&visibility, &headers, q.cacao_b64.as_deref(), Some(&state.operator_did), Some(&state.nonce_store))
        .map_err(AccessDenied::into_response)?;

    let entity_count   = state.quad_store.count_by_predicate_prefix(&graph_cid, "kg/id").await;
    let claim_count    = state.quad_store.count_by_predicate_prefix(&graph_cid, "kg/claim/").await;
    let relation_count = state.quad_store.count_by_predicate_prefix(&graph_cid, "kg/relation/").await;

    // Gather source_ids from kg/source_id quads
    let source_quads = state.quad_store
        .quads_by_predicate_prefix(Some(&graph_cid), "kg/source_id")
        .await;
    let mut source_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for q in &source_quads {
        let src = match &q.object {
            QuadObject::Text(s) => s.clone(),
            other               => format!("{other:?}"),
        };
        *source_counts.entry(src).or_insert(0) += 1;
    }
    let sources: Vec<serde_json::Value> = source_counts.into_iter()
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
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KgEmbedResp {
    pub ok:   bool,
    pub dims: usize,
}

/// POST /xrpc/ai.gftd.apps.yata.kg.embed
/// Compute a blake3 pseudo-vector for `text` and store it as a `kg/label_vec`
/// VectorF32 quad for the entity.  Uses the inference engine when available.
pub async fn kg_embed(
    State(state): State<Arc<KotobaState>>,
    headers:      HeaderMap,
    Json(req):    Json<KgEmbedReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    require_kg_write_auth(&headers)?;
    use kotoba_kqe::quad::Quad;
    if req.entity_id.is_empty() || req.entity_id.len() > MAX_KG_ID_LEN {
        return Err((StatusCode::BAD_REQUEST,
            format!("entityId must be 1–{MAX_KG_ID_LEN} bytes")));
    }
    if req.text.is_empty() || req.text.len() > MAX_KG_TEXT_LEN {
        return Err((StatusCode::BAD_REQUEST,
            format!("text must be 1–{MAX_KG_TEXT_LEN} bytes")));
    }
    let graph_cid = kg_graph_cid();

    let subjects = state.quad_store
        .lookup_subject_by_po(Some(&graph_cid), "kg/id", &req.entity_id)
        .await;
    let subject = subjects.into_iter().next()
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("entity not found: {}", req.entity_id)))?;

    let vector: Vec<f32> = if let Some(engine) = &state.inference_engine {
        let engine = engine.clone();
        let text = format!("embed: {}", req.text);
        let result = tokio::task::spawn_blocking(move || engine(&text, 256))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let parsed: Vec<f32> = result.split_whitespace()
            .filter_map(|s| s.parse::<f32>().ok())
            .collect();
        if parsed.is_empty() { blake3_pseudo_vector(&req.text, 128) } else { parsed }
    } else {
        blake3_pseudo_vector(&req.text, 128)
    };

    let dims = vector.len();
    let quad = Quad {
        graph:     graph_cid,
        subject,
        predicate: "kg/label_vec".to_string(),
        object:    QuadObject::VectorF32(vector),
    };
    state.quad_store.assert(quad).await;

    Ok(Json(KgEmbedResp { ok: true, dims }))
}

fn blake3_pseudo_vector(text: &str, dims: usize) -> Vec<f32> {
    let hash = blake3::hash(text.as_bytes());
    let hash_bytes = hash.as_bytes();
    (0..dims).map(|i| {
        let b = hash_bytes[i % 32] as f32;
        (b / 127.5) - 1.0
    }).collect()
}

// ── kg.search ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgSearchQuery {
    /// Free-text query string
    pub q:     String,
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// CACAO delegation chain for private graphs (DAG-CBOR, base64-standard encoded).
    pub cacao_b64: Option<String>,
}
fn default_limit() -> usize { 10 }

/// GET /xrpc/ai.gftd.apps.yata.kg.search?q=<text>&limit=10
/// Cosine similarity search over `kg/label_vec` VectorF32 quads.
pub async fn kg_search(
    State(state): State<Arc<KotobaState>>,
    headers:      HeaderMap,
    Query(q):     Query<KgSearchQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use std::time::Instant;
    if q.q.is_empty() || q.q.len() > MAX_KG_QUERY_LEN {
        return Err((StatusCode::BAD_REQUEST,
            format!("q must be 1–{MAX_KG_QUERY_LEN} bytes")));
    }
    let t0        = Instant::now();
    let graph_cid = kg_graph_cid();
    let limit     = q.limit.min(MAX_KG_LIMIT);

    // ── Read-access gate ─────────────────────────────────────────────────────
    let visibility = state.graph_visibility(&graph_cid).await;
    check_read_access(&visibility, &headers, q.cacao_b64.as_deref(), Some(&state.operator_did), Some(&state.nonce_store))
        .map_err(AccessDenied::into_response)?;

    // Use inference engine for query embedding when available, matching kg_embed semantics.
    // Falls back to blake3 pseudo-vector so search works without an LLM.
    let query_vec: Vec<f32> = if let Some(engine) = &state.inference_engine {
        let engine = engine.clone();
        let text   = format!("embed: {}", q.q);
        let result = tokio::task::spawn_blocking(move || engine(&text, 256))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let parsed: Vec<f32> = result.split_whitespace()
            .filter_map(|s| s.parse::<f32>().ok())
            .collect();
        if parsed.is_empty() { blake3_pseudo_vector(&q.q, 128) } else { parsed }
    } else {
        blake3_pseudo_vector(&q.q, 128)
    };

    let vec_quads = state.quad_store
        .quads_by_predicate_prefix(Some(&graph_cid), "kg/label_vec")
        .await;

    // Score each entity
    let mut scored: Vec<(f32, KotobaCid)> = vec_quads.iter()
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
        let quads = state.quad_store
            .get_entity_quads(Some(&graph_cid), subject)
            .await;
        let mut meta: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        meta.insert("score".into(), serde_json::json!(score));
        for quad in &quads {
            match quad.predicate.as_str() {
                "kg/id"       => { meta.insert("id".into(),      obj_to_json(&quad.object)); }
                "kg/qid"      => { meta.insert("qid".into(),     obj_to_json(&quad.object)); }
                "kg/label/ja" => { meta.insert("labelJa".into(), obj_to_json(&quad.object)); }
                "kg/label/en" => { meta.insert("labelEn".into(), obj_to_json(&quad.object)); }
                "kg/type"     => { meta.insert("type".into(),    obj_to_json(&quad.object)); }
                _             => {}
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
    pub pred:  String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgRelation {
    pub pred:   String,
    pub dst_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgIngestReq {
    pub id:          String,
    pub qid:         Option<String>,
    #[serde(rename = "type")]
    pub kind:        Option<String>,
    pub label_ja:    Option<String>,
    pub label_en:    Option<String>,
    pub confidence:  Option<String>,
    pub license:     Option<String>,
    pub extractor:   Option<String>,
    pub valid_from:  Option<String>,
    pub valid_to:    Option<String>,
    pub ingested_at: Option<String>,
    pub source_id:   Option<String>,
    /// Pre-computed embedding vector (e.g. from yatabase vLLM).
    /// When present, stored as `kg/label_vec` VectorF32 quad so that
    /// `kg_search` can do real cosine similarity without a local inference engine.
    #[serde(default)]
    pub label_vec: Vec<f32>,
    #[serde(default)]
    pub claims:    Vec<KgClaim>,
    #[serde(default)]
    pub relations: Vec<KgRelation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KgIngestResp {
    pub ok:          bool,
    pub subject_cid: String,
    pub quad_count:  usize,
}

/// POST /xrpc/ai.gftd.apps.yata.kg.ingest
///
/// Write a KG entity into the `yatabase-kg-v1` named graph. Each field becomes
/// a quad with predicate conventions matching `kg_entity` lookups.
const MAX_KG_CLAIMS:      usize = 1_024;
const MAX_KG_RELATIONS:   usize = 1_024;
const MAX_KG_VEC_DIMS:    usize = 4_096;
const MAX_KG_FIELD_LEN:   usize = 4_096;

pub async fn kg_ingest(
    State(state): State<Arc<KotobaState>>,
    headers:      HeaderMap,
    Json(req):    Json<KgIngestReq>,
) -> impl IntoResponse {
    if let Err((code, msg)) = require_kg_write_auth(&headers) {
        return (code, axum::Json(serde_json::json!({"ok": false, "error": msg}))).into_response();
    }
    use axum::Json as AxumJson;
    if req.id.is_empty() || req.id.len() > MAX_KG_ID_LEN {
        return (StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false, "error":
                format!("id must be 1–{MAX_KG_ID_LEN} bytes")}))).into_response();
    }
    if req.claims.len() > MAX_KG_CLAIMS {
        return (StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false, "error":
                format!("claims array exceeds {MAX_KG_CLAIMS} entries")}))).into_response();
    }
    if req.relations.len() > MAX_KG_RELATIONS {
        return (StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false, "error":
                format!("relations array exceeds {MAX_KG_RELATIONS} entries")}))).into_response();
    }
    if req.label_vec.len() > MAX_KG_VEC_DIMS {
        return (StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false, "error":
                format!("labelVec exceeds {MAX_KG_VEC_DIMS} dimensions")}))).into_response();
    }
    // Validate per-field lengths to prevent oversized individual quads
    for f in [&req.qid, &req.kind, &req.label_ja, &req.label_en, &req.license,
              &req.extractor, &req.valid_from, &req.valid_to, &req.ingested_at, &req.source_id] {
        if let Some(v) = f {
            if v.len() > MAX_KG_FIELD_LEN {
                return (StatusCode::BAD_REQUEST,
                    AxumJson(serde_json::json!({"ok": false, "error":
                        format!("field value exceeds {MAX_KG_FIELD_LEN} bytes")}))).into_response();
            }
        }
    }
    use kotoba_kqe::quad::Quad;

    let graph   = kg_graph_cid();
    let subject = KotobaCid::from_bytes(req.id.as_bytes());

    let mut count = 0usize;

    macro_rules! assert_text {
        ($pred:expr, $val:expr) => {{
            state.quad_store.assert(Quad {
                graph:     graph.clone(),
                subject:   subject.clone(),
                predicate: $pred.to_string(),
                object:    QuadObject::Text($val.to_string()),
            }).await;
            count += 1;
        }};
    }

    // Always write kg/id so lookup_subject_by_po works
    assert_text!("kg/id", req.id);

    if let Some(v) = &req.qid         { assert_text!("kg/qid",         v); }
    if let Some(v) = &req.kind        { assert_text!("kg/type",        v); }
    if let Some(v) = &req.label_ja    { assert_text!("kg/label/ja",    v); }
    if let Some(v) = &req.label_en    { assert_text!("kg/label/en",    v); }
    if let Some(v) = &req.confidence  { assert_text!("kg/confidence",  v); }
    if let Some(v) = &req.license     { assert_text!("kg/license",     v); }
    if let Some(v) = &req.extractor   { assert_text!("kg/extractor",   v); }
    if let Some(v) = &req.valid_from  { assert_text!("kg/valid_from",  v); }
    if let Some(v) = &req.valid_to    { assert_text!("kg/valid_to",    v); }
    if let Some(v) = &req.ingested_at { assert_text!("kg/ingested_at", v); }
    if let Some(v) = &req.source_id   { assert_text!("kg/source_id",   v); }

    for claim in &req.claims {
        assert_text!(format!("kg/claim/{}", claim.pred), claim.value);
    }

    for rel in &req.relations {
        let dst_cid = KotobaCid::from_bytes(rel.dst_id.as_bytes());
        state.quad_store.assert(Quad {
            graph:     graph.clone(),
            subject:   subject.clone(),
            predicate: format!("kg/relation/{}", rel.pred),
            object:    QuadObject::Cid(dst_cid),
        }).await;
        count += 1;
    }

    if !req.label_vec.is_empty() {
        state.quad_store.assert(Quad {
            graph:     graph.clone(),
            subject:   subject.clone(),
            predicate: "kg/label_vec".to_string(),
            object:    QuadObject::VectorF32(req.label_vec.clone()),
        }).await;
        count += 1;
    }

    Json(KgIngestResp {
        ok:          true,
        subject_cid: subject.to_multibase(),
        quad_count:  count,
    }).into_response()
}

// ── kg.delete ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgDeleteReq {
    /// Entity nanoid — same as the `id` field used in kg.ingest.
    pub id: String,
}

/// POST /xrpc/ai.gftd.apps.yata.kg.delete
///
/// Retract all quads for the given entity from the `yatabase-kg-v1` graph.
/// Publishes a retract event to the Journal for each quad (WAL + GossipSub).
pub async fn kg_delete(
    State(state): State<Arc<KotobaState>>,
    headers:      HeaderMap,
    Json(req):    Json<KgDeleteReq>,
) -> impl IntoResponse {
    if let Err((code, msg)) = require_kg_write_auth(&headers) {
        return (code, Json(serde_json::json!({"ok": false, "error": msg}))).into_response();
    }
    if req.id.is_empty() || req.id.len() > MAX_KG_ID_LEN {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "ok": false, "error": format!("id must be 1–{MAX_KG_ID_LEN} bytes"),
        }))).into_response();
    }
    let graph   = kg_graph_cid();
    let subject = KotobaCid::from_bytes(req.id.as_bytes());

    let quads = state.quad_store
        .get_entity_quads(Some(&graph), &subject)
        .await;

    let retracted = quads.len();

    for quad in quads {
        state.journal_retract(&quad).await;
        state.quad_store.retract(quad).await;
    }

    (StatusCode::OK, Json(serde_json::json!({
        "ok":            true,
        "id":            req.id,
        "retractedCount": retracted,
    }))).into_response()
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let len = a.len().min(b.len());
    let dot: f32 = a[..len].iter().zip(b[..len].iter()).map(|(x, y)| x * y).sum();
    let na:  f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb:  f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 { 0.0 } else { dot / (na * nb) }
}

// ── kg.query ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KgQueryReq {
    /// "sparql" or "cypher"
    pub lang:  String,
    /// Query string
    pub query: String,
    /// CACAO delegation chain for private graphs (DAG-CBOR, base64-standard encoded).
    pub cacao_b64: Option<String>,
}

/// POST /xrpc/ai.gftd.apps.yata.kg.query
/// Execute a SPARQL SELECT or Cypher MATCH/RETURN against the QuadStore.
///
/// Both compilers enforce binary-relation arity (exactly 2 RETURN variables).
/// Results are returned as `[{ "a": "<cid>", "b": "<cid>" }]` pairs where
/// the variable names come from the compiled output_relation.
const MAX_KG_QUERY_PROG_LEN: usize = 65_536;  // 64 KiB — SPARQL/Cypher compile DoS guard

pub async fn kg_query(
    State(state): State<Arc<KotobaState>>,
    headers:      HeaderMap,
    Json(req):    Json<KgQueryReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use std::time::Instant;
    use kotoba_kqe::cypher::CypherCompiler;
    use kotoba_graph::sparql::SparqlCompiler;

    if req.query.is_empty() || req.query.len() > MAX_KG_QUERY_PROG_LEN {
        return Err((StatusCode::BAD_REQUEST,
            format!("query must be 1–{MAX_KG_QUERY_PROG_LEN} bytes")));
    }
    if !matches!(req.lang.as_str(), "sparql" | "cypher") {
        return Err((StatusCode::BAD_REQUEST,
            "lang must be 'sparql' or 'cypher'".to_string()));
    }

    let t0        = Instant::now();
    let graph_cid = kg_graph_cid();

    // ── Read-access gate ─────────────────────────────────────────────────────
    let visibility = state.graph_visibility(&graph_cid).await;
    check_read_access(&visibility, &headers, req.cacao_b64.as_deref(), Some(&state.operator_did), Some(&state.nonce_store))
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
        other => return Err((StatusCode::BAD_REQUEST, format!("unknown lang: {other}; use sparql or cypher"))),
    };

    // Snapshot all quads as Assert deltas (Datalog fact base)
    let deltas = state.quad_store.snapshot_deltas(&graph_cid).await;

    // Evaluate Datalog rules against the fact base
    let derived = program.evaluate_delta(&deltas);

    // Collect derived facts for the output_relation
    let results: Vec<serde_json::Value> = derived.iter()
        .filter(|d| d.quad.predicate == output_relation && d.is_assert())
        .map(|d| serde_json::json!({
            "a": d.quad.subject.to_multibase(),
            "b": match &d.quad.object {
                QuadObject::Cid(c) => c.to_multibase(),
                other              => format!("{other:?}"),
            },
        }))
        .collect();

    Ok(Json(serde_json::json!({
        "ok":        true,
        "lang":      req.lang,
        "count":     results.len(),
        "results":   results,
        "elapsedMs": t0.elapsed().as_millis(),
    })))
}
