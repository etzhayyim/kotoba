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
    crate::graph_auth::validate_did(&q.owner_did, "owner_did", MAX_OWNER_DID_LEN)?;
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
    if let Err((code, msg)) = crate::graph_auth::validate_did(&q.owner_did, "owner_did", MAX_OWNER_DID_LEN) {
        return (code, Json(json!({ "error": msg }))).into_response();
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
    if let Err((code, msg)) = crate::graph_auth::validate_did(&body.owner_did, "owner_did", MAX_OWNER_DID_LEN) {
        return (code, Json(json!({ "error": msg }))).into_response();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsid_constants_have_correct_prefix() {
        let prefix = "ai.gftd.apps.kotoba.email.";
        assert!(NSID_EMAIL_LIST.starts_with(prefix));
        assert!(NSID_EMAIL_READ.starts_with(prefix));
        assert!(NSID_EMAIL_INGEST.starts_with(prefix));
    }

    #[test]
    fn size_limits_are_sane() {
        assert!(MAX_OWNER_DID_LEN >= 64);
        assert!(MAX_EMAIL_CID_LEN >= 32);
        assert!(MAX_RAW_B64_LEN >= 1024);
    }

    #[test]
    fn nsid_email_list_exact_value() {
        assert_eq!(NSID_EMAIL_LIST, "ai.gftd.apps.kotoba.email.list");
    }

    #[test]
    fn nsid_email_read_exact_value() {
        assert_eq!(NSID_EMAIL_READ, "ai.gftd.apps.kotoba.email.read");
    }

    #[test]
    fn nsid_email_ingest_exact_value() {
        assert_eq!(NSID_EMAIL_INGEST, "ai.gftd.apps.kotoba.email.ingest");
    }

    #[test]
    fn nsid_email_constants_are_unique() {
        let mut set = std::collections::HashSet::new();
        assert!(set.insert(NSID_EMAIL_LIST));
        assert!(set.insert(NSID_EMAIL_READ));
        assert!(set.insert(NSID_EMAIL_INGEST));
    }

    #[test]
    fn max_raw_b64_len_is_34_mib() {
        assert_eq!(MAX_RAW_B64_LEN, 34 * 1024 * 1024);
    }

    #[test]
    fn email_cid_len_cap_smaller_than_did_len_cap() {
        assert!(MAX_EMAIL_CID_LEN < MAX_OWNER_DID_LEN,
            "email CID length cap should be tighter than DID length cap");
    }

    #[test]
    fn max_owner_did_len_is_512() {
        assert_eq!(MAX_OWNER_DID_LEN, 512);
    }

    #[test]
    fn max_email_cid_len_is_256() {
        assert_eq!(MAX_EMAIL_CID_LEN, 256);
    }

    // ── open_field_safe ───────────────────────────────────────────────────────
    //
    // open_field_safe branches:
    //   1. empty envelope → passthrough (no crypto call)
    //   2. no "signal:v1:" prefix → passthrough (legacy plaintext)
    //   3. "signal:v1:" prefix + valid ciphertext → decrypted plaintext
    //   4. "signal:v1:" prefix + bad ciphertext → original envelope returned

    #[tokio::test]
    async fn open_field_safe_empty_returns_empty() {
        use kotoba_crypto::{AgentCrypto, VaultKeyedCrypto};
        use zeroize::Zeroizing;
        let crypto = VaultKeyedCrypto::new(Zeroizing::new([0xAAu8; 32]));
        let result = open_field_safe(&crypto, b"scope", "").await;
        assert_eq!(result, "");
    }

    #[tokio::test]
    async fn open_field_safe_plaintext_returns_unchanged() {
        use kotoba_crypto::{AgentCrypto, VaultKeyedCrypto};
        use zeroize::Zeroizing;
        let crypto = VaultKeyedCrypto::new(Zeroizing::new([0xAAu8; 32]));
        let result = open_field_safe(&crypto, b"scope", "alice@example.com").await;
        assert_eq!(result, "alice@example.com");
    }

    #[tokio::test]
    async fn open_field_safe_signal_roundtrip_with_real_crypto() {
        use kotoba_crypto::{AgentCrypto, VaultKeyedCrypto};
        use zeroize::Zeroizing;
        let crypto = VaultKeyedCrypto::new(Zeroizing::new([0x11u8; 32]));
        let scope = b"email/from";
        let plaintext = "test@example.com";
        // seal_field produces a signal:v1: envelope
        let envelope = crypto.seal_field(scope, plaintext).await.unwrap();
        assert!(envelope.starts_with("signal:v1:"));
        // open_field_safe should decrypt it correctly
        let recovered = open_field_safe(&crypto, scope, &envelope).await;
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn open_field_safe_bad_ciphertext_returns_original() {
        use kotoba_crypto::{AgentCrypto, VaultKeyedCrypto};
        use zeroize::Zeroizing;
        let crypto = VaultKeyedCrypto::new(Zeroizing::new([0x11u8; 32]));
        // "signal:v1:" prefix but not valid ciphertext → decrypt will fail → fallback
        let envelope = "signal:v1:not-valid-ciphertext";
        let result = open_field_safe(&crypto, b"scope", envelope).await;
        assert_eq!(result, envelope);
    }

    #[tokio::test]
    async fn open_field_safe_non_signal_prefix_with_colon_passthrough() {
        use kotoba_crypto::{AgentCrypto, VaultKeyedCrypto};
        use zeroize::Zeroizing;
        let crypto = VaultKeyedCrypto::new(Zeroizing::new([0xAAu8; 32]));
        // A string that has a colon but not the signal:v1: prefix
        let result = open_field_safe(&crypto, b"scope", "mailto:user@example.com").await;
        assert_eq!(result, "mailto:user@example.com");
    }
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
