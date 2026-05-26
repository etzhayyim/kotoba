//! XRPC handlers for encrypted email storage and retrieval.
//!
//! NSIDs:
//!   ai.gftd.apps.kotoba.email.list   — list email metadata (GET)
//!   ai.gftd.apps.kotoba.email.read   — decrypt and return one email (GET)
//!   ai.gftd.apps.kotoba.email.ingest — manually ingest a raw message (POST)

pub const NSID_EMAIL_LIST:   &str = "ai.gftd.apps.kotoba.email.list";
pub const NSID_EMAIL_READ:   &str = "ai.gftd.apps.kotoba.email.read";
pub const NSID_EMAIL_INGEST: &str = "ai.gftd.apps.kotoba.email.ingest";

use std::sync::Arc;
use axum::{Json, extract::{Query, State}, http::{HeaderMap, StatusCode}, response::IntoResponse};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::QuadObject;
use kotoba_ingest::{graph_cid_for, EmailIngestor};

use crate::server::KotobaState;

const MAX_OWNER_DID_LEN: usize = 512;
const MAX_EMAIL_CID_LEN: usize = 256;
// 25 MiB raw ≈ 33 MiB base64 (Gmail attachment limit)
const MAX_RAW_B64_LEN:   usize = 34 * 1024 * 1024;

fn require_email_auth(
    headers: &HeaderMap,
    owner_did: &str,
    operator_did: &str,
) -> Result<(), (StatusCode, String)> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("email auth: missing Bearer token");
            (StatusCode::UNAUTHORIZED, "Authorization: Bearer <token> required".to_string())
        })?;
    if crate::graph_auth::jwt_exp_elapsed(token) {
        tracing::warn!("email auth: expired JWT");
        return Err((StatusCode::UNAUTHORIZED, "Bearer token has expired".to_string()));
    }
    let sub = crate::graph_auth::jwt_sub(token)
        .ok_or_else(|| {
            tracing::warn!("email auth: JWT missing sub claim");
            (StatusCode::UNAUTHORIZED, "Bearer token missing sub claim".to_string())
        })?;
    if sub == owner_did || sub == operator_did {
        Ok(())
    } else {
        tracing::warn!(sub = %sub, owner_did = %owner_did, "email auth: sub mismatch");
        Err((StatusCode::UNAUTHORIZED,
            format!("Bearer sub does not match owner_did {owner_did:?}")))
    }
}

// ── email.list ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EmailListQuery {
    pub owner_did: String,
    pub limit:     Option<usize>,
    pub offset:    Option<usize>,
}

pub async fn email_list(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(q): Query<EmailListQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if q.owner_did.is_empty() || q.owner_did.len() > MAX_OWNER_DID_LEN {
        return Err((StatusCode::BAD_REQUEST,
            format!("owner_did must be 1–{MAX_OWNER_DID_LEN} bytes")));
    }
    require_email_auth(&headers, &q.owner_did, &state.operator_did)?;

    let graph_cid = graph_cid_for(&q.owner_did);
    let arrangement = match state.quad_store.arrangement(&graph_cid).await {
        None => return Ok(Json(json!({ "emails": [], "total": 0 })).into_response()),
        Some(a) => a,
    };

    // All email subjects come from the PSO index on "email/date"
    let mut entries: Vec<(String, String)> = arrangement
        .get_by_predicate("email/date")
        .into_iter()
        .filter_map(|(subject_cid, objs)| {
            let date = objs.first().and_then(|o| {
                if let QuadObject::Text(t) = o { Some(t.clone()) } else { None }
            })?;
            Some((subject_cid.to_multibase(), date))
        })
        .collect();

    // Sort descending by date (Unix timestamp string — lexicographic works for equal-width)
    entries.sort_by(|a, b| b.1.cmp(&a.1));

    let total = entries.len();
    let offset = q.offset.unwrap_or(0);
    let limit  = q.limit.unwrap_or(50).min(200);

    let page: Vec<Value> = entries.into_iter().skip(offset).take(limit).map(|(cid_mb, date)| {
        let message_id = KotobaCid::from_multibase(&cid_mb).map(|cid| {
            arrangement.get_objects(&cid, "email/message_id")
                .into_iter().find_map(|o| if let QuadObject::Text(t) = o { Some(t.clone()) } else { None })
                .unwrap_or_default()
        }).unwrap_or_default();
        json!({ "cid": cid_mb, "date": date, "message_id": message_id })
    }).collect();

    Ok(Json(json!({ "emails": page, "total": total, "offset": offset, "limit": limit })).into_response())
}

// ── email.read ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EmailReadQuery {
    pub email_cid: String,
    pub owner_did: String,
}

pub async fn email_read(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(q): Query<EmailReadQuery>,
) -> impl IntoResponse {
    if q.owner_did.is_empty() || q.owner_did.len() > MAX_OWNER_DID_LEN {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("owner_did must be 1–{MAX_OWNER_DID_LEN} bytes") }))).into_response();
    }
    if q.email_cid.is_empty() || q.email_cid.len() > MAX_EMAIL_CID_LEN {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("email_cid must be 1–{MAX_EMAIL_CID_LEN} bytes") }))).into_response();
    }
    if let Err((code, msg)) = require_email_auth(&headers, &q.owner_did, &state.operator_did) {
        return (code, Json(json!({ "error": msg }))).into_response();
    }

    let crypto = match &state.crypto {
        Some(c) => Arc::clone(c),
        None => return (StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "crypto not initialised" }))).into_response(),
    };

    let graph_cid = graph_cid_for(&q.owner_did);
    let arrangement = match state.quad_store.arrangement(&graph_cid).await {
        None => return (StatusCode::NOT_FOUND,
            Json(json!({ "error": "no emails found for owner_did" }))).into_response(),
        Some(a) => a,
    };

    let email_cid = KotobaCid::from_bytes(q.email_cid.as_bytes());

    // Fetch body_cid → Vault decrypt via AgentCrypto
    let body_text = {
        let blob_cid_str = arrangement
            .get_objects(&email_cid, "email/body_cid")
            .into_iter()
            .find_map(|o| if let QuadObject::Text(t) = o { Some(t.clone()) } else { None });

        match blob_cid_str {
            None => return (StatusCode::NOT_FOUND,
                Json(json!({ "error": "email body_cid not found" }))).into_response(),
            Some(cid_str) => {
                let blob_cid = match KotobaCid::from_multibase(&cid_str) {
                    Some(c) => c,
                    None => return (StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "invalid body_cid multibase" }))).into_response(),
                };
                let enc_bytes = match state.vault.get(&blob_cid).await {
                    Some(b) => b,
                    None => return (StatusCode::NOT_FOUND,
                        Json(json!({ "error": "body blob not found in vault" }))).into_response(),
                };
                match crypto.decrypt_blob(&enc_bytes).await {
                    Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": format!("decrypt body: {e}") }))).into_response(),
                    Ok(pt) => String::from_utf8_lossy(&pt).into_owned(),
                }
            }
        }
    };

    // Decrypt PII fields using AgentCrypto::open_field
    let from = open_field_safe(&*crypto, b"email/from",
        &get_text_field(&arrangement, &email_cid, "email/from")).await;
    let to   = open_field_safe(&*crypto, b"email/to",
        &get_text_field(&arrangement, &email_cid, "email/to")).await;
    let subj = open_field_safe(&*crypto, b"email/subject",
        &get_text_field(&arrangement, &email_cid, "email/subject")).await;
    let date = get_text_field(&arrangement, &email_cid, "email/date");
    let thread_id  = get_text_field(&arrangement, &email_cid, "email/thread_id");
    let message_id = get_text_field(&arrangement, &email_cid, "email/message_id");

    Json(json!({
        "email_cid":  q.email_cid,
        "message_id": message_id,
        "from":       from,
        "to":         to,
        "subject":    subj,
        "date":       date,
        "thread_id":  thread_id,
        "body":       body_text,
    })).into_response()
}

// ── email.ingest (manual POST) ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EmailIngestBody {
    /// Base64-encoded raw RFC 2822 message
    pub raw_b64:   String,
    pub thread_id: Option<String>,
    pub owner_did: String,
}

#[derive(Serialize)]
pub struct EmailIngestResponse {
    pub status:    &'static str,
    pub email_cid: String,
}

pub async fn email_ingest(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(body): Json<EmailIngestBody>,
) -> impl IntoResponse {
    if body.owner_did.is_empty() || body.owner_did.len() > MAX_OWNER_DID_LEN {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("owner_did must be 1–{MAX_OWNER_DID_LEN} bytes") }))).into_response();
    }
    if body.raw_b64.is_empty() {
        return (StatusCode::BAD_REQUEST,
            Json(json!({ "error": "raw_b64 must not be empty" }))).into_response();
    }
    if body.raw_b64.len() > MAX_RAW_B64_LEN {
        return (StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": format!("raw_b64 exceeds {MAX_RAW_B64_LEN} bytes") }))).into_response();
    }
    if let Err((code, msg)) = require_email_auth(&headers, &body.owner_did, &state.operator_did) {
        return (code, Json(json!({ "error": msg }))).into_response();
    }

    let crypto = match &state.crypto {
        Some(c) => Arc::clone(c),
        None => return (StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "crypto not initialised" }))).into_response(),
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let raw = match B64.decode(&body.raw_b64) {
        Ok(b)  => b,
        Err(e) => return (StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("base64 decode: {e}") }))).into_response(),
    };

    let ingestor = EmailIngestor::new(
        crypto,
        Arc::clone(&state.vault),
        Arc::clone(&state.quad_store),
        body.owner_did,
    );

    let thread_id = body.thread_id.as_deref().unwrap_or("");
    match ingestor.ingest_raw(&raw, thread_id).await {
        Ok(cid) => Json(json!({
            "status": "ok",
            "email_cid": cid.to_multibase(),
        })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("{e}") }))).into_response(),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_text_field(
    arr: &kotoba_kqe::arrangement::Arrangement,
    subject: &KotobaCid,
    predicate: &str,
) -> String {
    arr.get_objects(subject, predicate)
        .into_iter()
        .find_map(|o| if let QuadObject::Text(t) = o { Some(t.clone()) } else { None })
        .unwrap_or_default()
}

/// Open a `signal:v1:` envelope using AgentCrypto; returns ciphertext on failure
/// (same fallback as the old decrypt_text_field).
async fn open_field_safe(
    crypto:   &dyn kotoba_crypto::AgentCrypto,
    scope:    &[u8],
    envelope: &str,
) -> String {
    if envelope.is_empty() { return envelope.to_string(); }
    if !envelope.starts_with("signal:v1:") {
        // Plain-text legacy value — return as-is
        return envelope.to_string();
    }
    crypto.open_field(scope, envelope).await
        .unwrap_or_else(|_| envelope.to_string()) // return ciphertext if decrypt fails
}
