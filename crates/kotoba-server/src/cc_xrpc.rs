//! XRPC handlers for Common Crawl vector search and knowledge query.
//!
//! NSIDs:
//!   ai.gftd.apps.kotoba.cc.search  — ANN vector search over CC chunks (GET)
//!   ai.gftd.apps.kotoba.cc.rag     — RAG: search + LLM synthesis (POST)
//!   ai.gftd.apps.kotoba.cc.ingest  — trigger CC parquet ingest job (POST)
//!   ai.gftd.apps.kotoba.cc.status  — ingest / index status (GET)

pub const NSID_CC_SEARCH: &str = "ai.gftd.apps.kotoba.cc.search";
pub const NSID_CC_RAG:    &str = "ai.gftd.apps.kotoba.cc.rag";
pub const NSID_CC_INGEST: &str = "ai.gftd.apps.kotoba.cc.ingest";
pub const NSID_CC_STATUS: &str = "ai.gftd.apps.kotoba.cc.status";

use std::sync::Arc;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::QuadObject;
use kotoba_ingest::cc::{cc_chunks_graph, cc_pages_graph};
use kotoba_ingest::ivf::IvfIndex;
use kotoba_ingest::embed_client::EmbedClient;

use crate::server::KotobaState;

// ── helpers ───────────────────────────────────────────────────────────────────

fn cosine_score(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32  = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let na:  f32  = a.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-9);
    let nb:  f32  = b.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-9);
    dot / (na * nb)
}

fn brute_force_cosine(
    query:      &[f32],
    embeddings: &[(KotobaCid, Vec<f32>)],
    top_k:      usize,
) -> Vec<(f32, usize)> {
    let mut scored: Vec<(f32, usize)> = embeddings
        .iter()
        .enumerate()
        .map(|(i, (_, v))| (cosine_score(query, v), i))
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(top_k);
    scored
}

/// Collect (subject, embedding_vec) pairs from Arrangement via "cc/embed/" prefix scan.
fn collect_chunk_embeddings(
    arrangement: &kotoba_kqe::arrangement::Arrangement,
    graph_cid:   &KotobaCid,
) -> Vec<(KotobaCid, Vec<f32>)> {
    let quads = arrangement.quads_with_predicate_prefix(graph_cid, "cc/embed/");
    let mut out: Vec<(KotobaCid, Vec<f32>)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for quad in quads {
        if !seen.insert(quad.subject.to_multibase()) { continue; }
        if let QuadObject::VectorF32(v) = quad.object {
            out.push((quad.subject, v));
        }
    }
    out
}

fn get_chunk_field(
    arrangement: &kotoba_kqe::arrangement::Arrangement,
    graph_cid:   &KotobaCid,
    subject:     &KotobaCid,
    predicate:   &str,
) -> Option<String> {
    arrangement.get_subject_quads(graph_cid, subject)
        .into_iter()
        .find(|q| q.predicate == predicate)
        .and_then(|q| if let QuadObject::Text(t) = q.object { Some(t) } else { None })
}

// ── cc.search ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CcSearchQuery {
    pub q:      String,
    #[serde(default = "default_top_k")]
    pub top_k:  usize,
    #[serde(default = "default_nprobe")]
    pub nprobe: usize,
    pub lang:   Option<String>,
}

fn default_top_k()  -> usize { 10 }
fn default_nprobe() -> usize { 8 }

const MAX_QUERY_LEN:   usize = 8_192;  // 8 KiB — prevents embed-client DoS
const MAX_LANG_LEN:    usize =   16;
const MAX_SYSTEM_LEN:  usize = 4_096;
const MAX_TOP_K:       usize =  100;
const MAX_PARQUET_DIR: usize = 1_024;

#[derive(Serialize)]
pub struct CcSearchResult {
    pub url:    String,
    pub domain: String,
    pub score:  f32,
    pub text:   String,
    pub lang:   Option<String>,
}

pub async fn cc_search(
    State(state): State<Arc<KotobaState>>,
    Query(q): Query<CcSearchQuery>,
) -> impl IntoResponse {
    if q.q.is_empty() || q.q.len() > MAX_QUERY_LEN {
        return (StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("q must be 1–{MAX_QUERY_LEN} bytes")}))).into_response();
    }
    if let Some(ref lang) = q.lang {
        if lang.len() > MAX_LANG_LEN {
            return (StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("lang exceeds {MAX_LANG_LEN} characters")}))).into_response();
        }
    }
    let embed_client = match state.cc_embed_client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "embed client not configured; set KOTOBA_EMBED_URL"})),
        ).into_response(),
    };

    let vecs = match embed_client.embed_batch(&[q.q.as_str()]).await {
        Ok(v)  => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("embedding failed: {e}")}))).into_response(),
    };
    let query_vec = &vecs[0];
    let graph_cid = cc_chunks_graph();

    let arrangement = match state.quad_store.arrangement(&graph_cid).await {
        Some(a) => a,
        None    => return Json(json!({ "results": [], "total": 0,
                                       "note": "no cc chunks indexed" })).into_response(),
    };

    let chunk_embeddings = collect_chunk_embeddings(&arrangement, &graph_cid);
    if chunk_embeddings.is_empty() {
        return Json(json!({ "results": [], "total": 0, "note": "no embeddings found" })).into_response();
    }

    let top_k = q.top_k.min(100);

    // Use IVF if centroids were persisted, else brute-force
    let ivf_quads = arrangement.quads_with_predicate_prefix(&graph_cid, "cc/ivf/");
    let ranked: Vec<(f32, usize)> = if !ivf_quads.is_empty() {
        match IvfIndex::from_quads(&ivf_quads) {
            Some(ivf) => {
                // IVF search needs cluster assignments — fall back for now
                // since the Arrangement doesn't store per-chunk cluster IDs in indexed form
                let _ = ivf;
                brute_force_cosine(query_vec, &chunk_embeddings, top_k)
            }
            None => brute_force_cosine(query_vec, &chunk_embeddings, top_k),
        }
    } else {
        brute_force_cosine(query_vec, &chunk_embeddings, top_k)
    };

    let mut results: Vec<CcSearchResult> = Vec::new();
    for (score, idx) in ranked {
        let Some((subj, _)) = chunk_embeddings.get(idx) else { continue };
        let lang = get_chunk_field(&arrangement, &graph_cid, subj, "cc/chunk/lang");
        if let Some(ref lf) = q.lang {
            if lang.as_deref() != Some(lf.as_str()) { continue; }
        }
        results.push(CcSearchResult {
            url:    get_chunk_field(&arrangement, &graph_cid, subj, "cc/chunk/url").unwrap_or_default(),
            domain: get_chunk_field(&arrangement, &graph_cid, subj, "cc/chunk/domain").unwrap_or_default(),
            text:   get_chunk_field(&arrangement, &graph_cid, subj, "cc/chunk/text").unwrap_or_default(),
            score,
            lang,
        });
    }

    Json(json!({ "results": results, "total": results.len() })).into_response()
}

// ── cc.rag ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CcRagBody {
    pub query:     String,
    #[serde(default = "default_rag_k")]
    pub context_k: usize,
    #[serde(default = "default_nprobe")]
    pub nprobe:    usize,
    pub lang:      Option<String>,
    pub system:    Option<String>,
}

fn default_rag_k() -> usize { 5 }

pub async fn cc_rag(
    State(state): State<Arc<KotobaState>>,
    Json(body): Json<CcRagBody>,
) -> impl IntoResponse {
    if body.query.is_empty() || body.query.len() > MAX_QUERY_LEN {
        return (StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("query must be 1–{MAX_QUERY_LEN} bytes")}))).into_response();
    }
    if let Some(ref sys) = body.system {
        if sys.len() > MAX_SYSTEM_LEN {
            return (StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("system prompt exceeds {MAX_SYSTEM_LEN} characters")}))).into_response();
        }
    }
    let embed_client = match state.cc_embed_client.as_ref() {
        Some(c) => Arc::clone(c),
        None => return (StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "embed client not configured"}))).into_response(),
    };

    let vecs = match embed_client.embed_batch(&[body.query.as_str()]).await {
        Ok(v)  => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("embedding failed: {e}")}))).into_response(),
    };
    let query_vec  = &vecs[0];
    let graph_cid  = cc_chunks_graph();

    let arrangement = match state.quad_store.arrangement(&graph_cid).await {
        Some(a) => a,
        None    => return Json(json!({
            "answer":  "(no CC data indexed)",
            "context": [],
            "query":   body.query,
        })).into_response(),
    };

    let chunk_embeddings = collect_chunk_embeddings(&arrangement, &graph_cid);
    let ranked = brute_force_cosine(query_vec, &chunk_embeddings, body.context_k);

    let mut context_texts: Vec<String> = Vec::new();
    let mut context_meta:  Vec<Value>  = Vec::new();

    for (score, idx) in &ranked {
        let Some((subj, _)) = chunk_embeddings.get(*idx) else { continue };
        let lang = get_chunk_field(&arrangement, &graph_cid, subj, "cc/chunk/lang");
        if let Some(ref lf) = body.lang {
            if lang.as_deref() != Some(lf.as_str()) { continue; }
        }
        let text   = get_chunk_field(&arrangement, &graph_cid, subj, "cc/chunk/text").unwrap_or_default();
        let url    = get_chunk_field(&arrangement, &graph_cid, subj, "cc/chunk/url").unwrap_or_default();
        let domain = get_chunk_field(&arrangement, &graph_cid, subj, "cc/chunk/domain").unwrap_or_default();
        context_texts.push(text.clone());
        context_meta.push(json!({ "url": url, "domain": domain, "score": score, "text": text }));
    }

    let answer = if let Some(ref infer) = state.inference_engine {
        let system = body.system.as_deref()
            .unwrap_or("You are a knowledgeable assistant. Answer concisely based on the provided context.");
        let prompt = format!(
            "{system}\n\nContext from Common Crawl:\n{}\n\nQuestion: {}\n\nAnswer:",
            context_texts.join("\n\n---\n\n"),
            body.query
        );
        match (infer)(&prompt, 512) {
            Ok(t)  => t,
            Err(e) => { tracing::warn!(err = %e, "cc_rag: inference failed"); format!("[inference error: {e}]") }
        }
    } else {
        context_texts.join("\n\n")
    };

    Json(json!({
        "answer":  answer,
        "context": context_meta,
        "query":   body.query,
    })).into_response()
}

// ── cc.ingest ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CcIngestBody {
    pub parquet_dir:  String,
    pub max_batches:  Option<usize>,
    #[serde(default = "default_ingest_mode")]
    pub mode:         String,
    #[serde(default = "default_owner_did")]
    pub owner_did:    String,
}

fn default_ingest_mode() -> String { "chunks".to_string() }
fn default_owner_did()   -> String { "did:plc:unknown".to_string() }

pub async fn cc_ingest(
    State(state): State<Arc<KotobaState>>,
    Json(body): Json<CcIngestBody>,
) -> impl IntoResponse {
    use kotoba_ingest::cc::{CcPageIngestor, CcChunkIngestor};
    use kotoba_ingest::embed_client::Blake3EmbedClient;

    if body.parquet_dir.is_empty() || body.parquet_dir.len() > MAX_PARQUET_DIR {
        return (StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("parquetDir must be 1–{MAX_PARQUET_DIR} bytes")}))).into_response();
    }
    if !matches!(body.mode.as_str(), "chunks" | "pages" | "both") {
        return (StatusCode::BAD_REQUEST,
            Json(json!({"error": "mode must be 'chunks', 'pages', or 'both'"}))).into_response();
    }

    let quad_store   = Arc::clone(&state.quad_store);
    let embed_client = state.cc_embed_client.clone();
    let parquet_dir  = body.parquet_dir.clone();
    let max_batches  = body.max_batches;
    let mode         = body.mode.clone();
    let _owner_did   = body.owner_did.clone();

    // Use a timestamp-based job_id without chrono
    let job_id = format!("cc-ingest-{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));

    tokio::spawn(async move {
        let dir = std::path::Path::new(&parquet_dir);
        if mode == "pages" || mode == "both" {
            let ingestor = CcPageIngestor::new(Arc::clone(&quad_store));
            match ingestor.ingest_dir(dir, max_batches).await {
                Ok(s)  => tracing::info!(?s, "CC pages ingest complete"),
                Err(e) => tracing::error!(err = %e, "CC pages ingest failed"),
            }
        }
        if mode == "chunks" || mode == "both" {
            let client: Arc<dyn EmbedClient> = embed_client.unwrap_or_else(|| {
                Arc::new(Blake3EmbedClient::new(384))
            });
            let ingestor = CcChunkIngestor::new(Arc::clone(&quad_store), client);
            match ingestor.ingest_dir(dir, max_batches).await {
                Ok(s)  => tracing::info!(?s, "CC chunks ingest complete"),
                Err(e) => tracing::error!(err = %e, "CC chunks ingest failed"),
            }
        }
    });

    Json(json!({
        "job_id":      job_id,
        "status":      "started",
        "parquet_dir": body.parquet_dir,
        "mode":        body.mode,
    })).into_response()
}

// ── cc.status ────────────────────────────────────────────────────────────────

pub async fn cc_status(
    State(state): State<Arc<KotobaState>>,
) -> impl IntoResponse {
    let chunks_graph = cc_chunks_graph();
    let pages_graph  = cc_pages_graph();

    let chunk_count = state.quad_store.arrangement(&chunks_graph).await
        .map(|a| a.get_by_predicate("cc/chunk/text").len())
        .unwrap_or(0);

    let page_count = state.quad_store.arrangement(&pages_graph).await
        .map(|a| a.get_by_predicate("cc/url").len())
        .unwrap_or(0);

    let ivf_centroids = state.quad_store.arrangement(&chunks_graph).await
        .map(|a| a.get_by_predicate("cc/ivf/centroid_id").len())
        .unwrap_or(0);

    Json(json!({
        "chunks_indexed":   chunk_count,
        "pages_indexed":    page_count,
        "ivf_centroids":    ivf_centroids,
        "embed_configured": state.cc_embed_client.is_some(),
        "chunks_graph_cid": chunks_graph.to_multibase(),
        "pages_graph_cid":  pages_graph.to_multibase(),
    }))
}
