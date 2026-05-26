//! Entity attestation with stake enforcement.
//!
//! XRPC endpoints:
//! - POST `ai.gftd.apps.kotoba.attest.claim`      — submit or renew an attestation
//! - POST `ai.gftd.apps.kotoba.attest.challenge`  — challenge an existing attestation
//! - GET  `ai.gftd.apps.kotoba.attest.query`      — query attestation status
//! - GET  `ai.gftd.apps.kotoba.request.log`       — query audit log for requests
//!
//! Stake thresholds (mKOTO):
//! - Self-attested claim:    1,000 KOTO  = 1_000_000_000 mKOTO
//! - Verified-entity claim:  5,000 KOTO  = 5_000_000_000 mKOTO

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::{Quad, QuadObject};

use crate::server::KotobaState;

const MAX_ATTEST_DID_LEN:      usize = 512;
const MAX_ATTEST_CLAIM_TYPE:   usize =  64;
const MAX_ATTEST_EVIDENCE_LEN: usize = 2_048;
const MAX_ATTEST_REASON_LEN:   usize = 4_096;
const MAX_ATTEST_CID_LEN:      usize =  256;

fn require_attester_auth(
    headers: &HeaderMap,
    attester_did: &str,
    operator_did: &str,
) -> Result<(), (StatusCode, String)> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("attester auth: missing Bearer token");
            (StatusCode::UNAUTHORIZED, "Authorization: Bearer <token> required".to_string())
        })?;
    if crate::graph_auth::jwt_exp_elapsed(token) {
        tracing::warn!("attester auth: expired JWT");
        return Err((StatusCode::UNAUTHORIZED, "Bearer token has expired".to_string()));
    }
    let sub = crate::graph_auth::jwt_sub(token)
        .ok_or_else(|| {
            tracing::warn!("attester auth: JWT missing sub claim");
            (StatusCode::UNAUTHORIZED, "Bearer token missing sub claim".to_string())
        })?;
    if sub == attester_did || sub == operator_did {
        Ok(())
    } else {
        tracing::warn!(sub = %sub, attester_did = %attester_did, "attester auth: sub mismatch");
        Err((StatusCode::UNAUTHORIZED,
            format!("Bearer sub does not match attester_did {attester_did:?}")))
    }
}

// ── NSID constants ────────────────────────────────────────────────────────────

pub const NSID_ATTEST_CLAIM:     &str = "ai.gftd.apps.kotoba.attest.claim";
pub const NSID_ATTEST_CHALLENGE: &str = "ai.gftd.apps.kotoba.attest.challenge";
pub const NSID_ATTEST_QUERY:     &str = "ai.gftd.apps.kotoba.attest.query";
pub const NSID_REQUEST_LOG:      &str = "ai.gftd.apps.kotoba.request.log";

// ── Stake constants (mKOTO) ───────────────────────────────────────────────────

/// Minimum stake for a self-attested claim: 1,000 KOTO in mKOTO.
pub const MIN_STAKE_SELF_ATTESTED: u64 = 1_000 * 1_000_000;

/// Minimum stake for a verified-entity claim: 5,000 KOTO in mKOTO.
pub const MIN_STAKE_VERIFIED_ENTITY: u64 = 5_000 * 1_000_000;

// ── Named graph helpers ───────────────────────────────────────────────────────

fn attest_graph_cid() -> KotobaCid {
    KotobaCid::from_bytes(b"kotoba/attestation/v1")
}

fn audit_graph_cid() -> KotobaCid {
    KotobaCid::from_bytes(b"kotoba/audit/requests/v1")
}

/// Extract a displayable string from a QuadObject: Text → clone, Cid → multibase, others → empty.
fn quad_object_text(obj: &QuadObject) -> String {
    match obj {
        QuadObject::Text(s)   => s.clone(),
        QuadObject::Cid(c)    => c.to_multibase(),
        _                     => String::new(),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AttestClaimReq {
    /// DID of the entity being attested.
    pub entity_did: String,
    /// Type of claim: "self" | "verified_entity" | "delegation".
    pub claim_type: String,
    /// Attester DID (who is submitting this claim).
    pub attester_did: String,
    /// Stake locked for this attestation in mKOTO.
    pub stake_mkoto: u64,
    /// Optional human-readable evidence string (URL, CID multibase, etc.).
    pub evidence: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AttestClaimResp {
    pub status: &'static str,
    /// Multibase CID of the attestation quad (journal entry).
    pub claim_cid: String,
}

#[derive(Debug, Deserialize)]
pub struct AttestChallengeReq {
    /// Multibase CID of the claim being challenged.
    pub claim_cid: String,
    /// DID of the challenger.
    pub challenger_did: String,
    /// Reason for the challenge.
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct AttestChallengeResp {
    pub status: &'static str,
    /// Multibase CID of the challenge quad.
    pub challenge_cid: String,
}

#[derive(Debug, Deserialize)]
pub struct AttestQueryParams {
    /// Entity DID to query.
    pub entity_did: Option<String>,
    /// Attester DID to filter by.
    pub attester_did: Option<String>,
    /// Maximum results (default 20, max 100).
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AttestQueryResp {
    pub claims: Vec<AttestRecord>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct AttestRecord {
    pub claim_cid: String,
    pub entity_did: String,
    pub claim_type: String,
    pub attester_did: String,
    pub stake_mkoto: u64,
    pub ts_unix: u64,
}

#[derive(Debug, Deserialize)]
pub struct RequestLogQueryParams {
    /// Filter by path prefix.
    pub path_prefix: Option<String>,
    /// Maximum results (default 20, max 100).
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct RequestLogResp {
    pub entries: Vec<RequestLogEntry>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct RequestLogEntry {
    pub request_cid: String,
    pub method: String,
    pub path: String,
    pub ts_unix: u64,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// POST `ai.gftd.apps.kotoba.attest.claim`
///
/// Validates stake thresholds and writes the attestation as Datoms.
pub async fn attest_claim(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<AttestClaimReq>,
) -> impl IntoResponse {
    if let Err((code, msg)) = crate::graph_auth::validate_did(&req.entity_did, "entity_did", MAX_ATTEST_DID_LEN) {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    if let Err((code, msg)) = crate::graph_auth::validate_did(&req.attester_did, "attester_did", MAX_ATTEST_DID_LEN) {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    if req.claim_type.is_empty() || req.claim_type.len() > MAX_ATTEST_CLAIM_TYPE {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "claim_type must be 'self', 'verified_entity', or 'delegation'" }))).into_response();
    }
    if !matches!(req.claim_type.as_str(), "self" | "verified_entity" | "delegation") {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "claim_type must be 'self', 'verified_entity', or 'delegation'" }))).into_response();
    }
    if let Some(ev) = &req.evidence {
        if ev.len() > MAX_ATTEST_EVIDENCE_LEN {
            return (StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("evidence exceeds {MAX_ATTEST_EVIDENCE_LEN} bytes") }))).into_response();
        }
    }
    if let Err((code, msg)) = require_attester_auth(&headers, &req.attester_did, &state.operator_did) {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }

    // Enforce stake threshold based on claim type.
    let min_stake = match req.claim_type.as_str() {
        "verified_entity" | "delegation" => MIN_STAKE_VERIFIED_ENTITY,
        _ => MIN_STAKE_SELF_ATTESTED, // "self" or any unknown type
    };

    if req.stake_mkoto < min_stake {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "insufficient_stake",
                "required_mkoto": min_stake,
                "provided_mkoto": req.stake_mkoto,
            })),
        )
            .into_response();
    }

    let ts = now_unix();
    let graph = attest_graph_cid();

    // Stable CID for this claim: derived from entity_did + attester_did + ts.
    let claim_seed = format!("attest/{}/{}/{}", req.entity_did, req.attester_did, ts);
    let claim_cid = KotobaCid::from_bytes(claim_seed.as_bytes());

    // Store entity/attester as Text so the DID string is recoverable in queries.
    // (KotobaCid::from_bytes is a blake3 hash — non-invertible.)
    let mut quads = vec![
        Quad {
            graph: graph.clone(),
            subject: claim_cid.clone(),
            predicate: "attest/entity".to_string(),
            object: QuadObject::Text(req.entity_did.clone()),
        },
        Quad {
            graph: graph.clone(),
            subject: claim_cid.clone(),
            predicate: "attest/type".to_string(),
            object: QuadObject::Text(req.claim_type.clone()),
        },
        Quad {
            graph: graph.clone(),
            subject: claim_cid.clone(),
            predicate: "attest/attester".to_string(),
            object: QuadObject::Text(req.attester_did.clone()),
        },
        Quad {
            graph: graph.clone(),
            subject: claim_cid.clone(),
            predicate: "attest/stake_mkoto".to_string(),
            object: QuadObject::Integer(req.stake_mkoto as i64),
        },
        Quad {
            graph: graph.clone(),
            subject: claim_cid.clone(),
            predicate: "attest/ts_unix".to_string(),
            object: QuadObject::Integer(ts as i64),
        },
    ];

    if let Some(evidence) = req.evidence {
        quads.push(Quad {
            graph: graph.clone(),
            subject: claim_cid.clone(),
            predicate: "attest/evidence".to_string(),
            object: QuadObject::Text(evidence),
        });
    }

    for quad in quads {
        state.quad_store.assert(quad).await;
    }

    let claim_cid_str = claim_cid.to_multibase();
    tracing::info!(
        entity_did = %req.entity_did,
        attester_did = %req.attester_did,
        claim_type = %req.claim_type,
        stake_mkoto = req.stake_mkoto,
        claim_cid = %claim_cid_str,
        "attestation claim recorded"
    );

    (
        StatusCode::CREATED,
        Json(AttestClaimResp {
            status: "attested",
            claim_cid: claim_cid_str,
        }),
    )
        .into_response()
}

/// POST `ai.gftd.apps.kotoba.attest.challenge`
///
/// Records a challenge against an existing attestation claim.
pub async fn attest_challenge(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<AttestChallengeReq>,
) -> impl IntoResponse {
    if req.claim_cid.is_empty() || req.claim_cid.len() > MAX_ATTEST_CID_LEN {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("claim_cid must be 1–{MAX_ATTEST_CID_LEN} bytes") }))).into_response();
    }
    if let Err((code, msg)) = crate::graph_auth::validate_did(&req.challenger_did, "challenger_did", MAX_ATTEST_DID_LEN) {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    if req.reason.is_empty() || req.reason.len() > MAX_ATTEST_REASON_LEN {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("reason must be 1–{MAX_ATTEST_REASON_LEN} bytes") }))).into_response();
    }
    if let Err((code, msg)) = require_attester_auth(&headers, &req.challenger_did, &state.operator_did) {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }

    // Decode the claim CID from multibase (base32lower 'b' prefix).
    let claim_cid = match KotobaCid::from_multibase(&req.claim_cid) {
        Some(c) => c,
        None => {
            // Fallback: treat the string itself as content to hash.
            KotobaCid::from_bytes(req.claim_cid.as_bytes())
        }
    };

    let ts = now_unix();
    let graph = attest_graph_cid();

    // CID for this challenge.
    let challenge_seed = format!("challenge/{}/{}/{}", req.claim_cid, req.challenger_did, ts);
    let challenge_cid = KotobaCid::from_bytes(challenge_seed.as_bytes());

    let challenger_cid = KotobaCid::from_bytes(req.challenger_did.as_bytes());

    let quads = vec![
        Quad {
            graph: graph.clone(),
            subject: challenge_cid.clone(),
            predicate: "challenge/claim".to_string(),
            object: QuadObject::Cid(claim_cid),
        },
        Quad {
            graph: graph.clone(),
            subject: challenge_cid.clone(),
            predicate: "challenge/challenger".to_string(),
            object: QuadObject::Cid(challenger_cid),
        },
        Quad {
            graph: graph.clone(),
            subject: challenge_cid.clone(),
            predicate: "challenge/reason".to_string(),
            object: QuadObject::Text(req.reason.clone()),
        },
        Quad {
            graph: graph.clone(),
            subject: challenge_cid.clone(),
            predicate: "challenge/ts_unix".to_string(),
            object: QuadObject::Integer(ts as i64),
        },
    ];

    for quad in quads {
        state.quad_store.assert(quad).await;
    }

    let challenge_cid_str = challenge_cid.to_multibase();
    tracing::info!(
        claim_cid = %req.claim_cid,
        challenger_did = %req.challenger_did,
        challenge_cid = %challenge_cid_str,
        "attestation challenge recorded"
    );

    (
        StatusCode::CREATED,
        Json(AttestChallengeResp {
            status: "challenged",
            challenge_cid: challenge_cid_str,
        }),
    )
        .into_response()
}

/// GET `ai.gftd.apps.kotoba.attest.query`
///
/// Query attestation records by entity_did or attester_did.
/// Scans the hot Arrangement via AVET (POS) index; returns empty when neither
/// filter is provided (full-scan is intentionally not supported to bound cost).
pub async fn attest_query(
    State(state): State<Arc<KotobaState>>,
    Query(params): Query<AttestQueryParams>,
) -> impl IntoResponse {
    if params.entity_did.as_deref().map(|s| s.len() > MAX_ATTEST_DID_LEN).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("entity_did exceeds {MAX_ATTEST_DID_LEN} bytes") }))).into_response();
    }
    if params.attester_did.as_deref().map(|s| s.len() > MAX_ATTEST_DID_LEN).unwrap_or(false) {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("attester_did exceeds {MAX_ATTEST_DID_LEN} bytes") }))).into_response();
    }
    let limit = params.limit.unwrap_or(20).min(100);
    let graph = attest_graph_cid();

    // Resolve claim CIDs via AVET (POS) reverse lookup.
    // entity/attester are stored as Text (not Cid), so the object_key is the DID string.
    let claim_cids: Vec<kotoba_core::cid::KotobaCid> = if let Some(ref did) = params.entity_did {
        state.quad_store.lookup_subject_by_po(Some(&graph), "attest/entity", did).await
    } else if let Some(ref did) = params.attester_did {
        state.quad_store.lookup_subject_by_po(Some(&graph), "attest/attester", did).await
    } else {
        // No filter: return empty to avoid unbounded full-scan.
        return Json(AttestQueryResp { claims: Vec::new(), total: 0 }).into_response();
    };

    let mut claims: Vec<AttestRecord> = Vec::new();
    for claim_cid in claim_cids.into_iter().take(limit) {
        let quads = state.quad_store.get_entity_quads(Some(&graph), &claim_cid).await;
        let mut rec = AttestRecord {
            claim_cid:    claim_cid.to_multibase(),
            entity_did:   String::new(),
            claim_type:   String::new(),
            attester_did: String::new(),
            stake_mkoto:  0,
            ts_unix:      0,
        };
        for q in &quads {
            match q.predicate.as_str() {
                "attest/entity"      => rec.entity_did   = quad_object_text(&q.object),
                "attest/type"        => rec.claim_type   = quad_object_text(&q.object),
                "attest/attester"    => rec.attester_did = quad_object_text(&q.object),
                "attest/stake_mkoto" => {
                    if let kotoba_kqe::quad::QuadObject::Integer(n) = &q.object {
                        rec.stake_mkoto = *n as u64;
                    }
                }
                "attest/ts_unix" => {
                    if let kotoba_kqe::quad::QuadObject::Integer(n) = &q.object {
                        rec.ts_unix = *n as u64;
                    }
                }
                _ => {}
            }
        }
        if !rec.entity_did.is_empty() {
            claims.push(rec);
        }
    }

    let total = claims.len();
    tracing::debug!(
        entity_did = ?params.entity_did,
        attester_did = ?params.attester_did,
        limit,
        total,
        "attest.query result"
    );
    Json(AttestQueryResp { claims, total }).into_response()
}

/// GET `ai.gftd.apps.kotoba.request.log`
///
/// Query the request audit log stored by the fingerprint middleware.
/// Scans the audit graph Arrangement via predicate-prefix lookup.
/// Requires operator auth — audit logs are internal security instruments.
pub async fn request_log_query(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(params): Query<RequestLogQueryParams>,
) -> impl IntoResponse {
    if let Err((code, msg)) = crate::graph_auth::require_operator_auth(&headers, &state.operator_did) {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    let limit = params.limit.unwrap_or(20).min(100);
    let graph = audit_graph_cid();

    // Fetch all quads in the audit graph whose predicate starts with "request/".
    // Group by subject CID → hydrate each RequestLogEntry.
    let all_quads = state.quad_store
        .quads_by_predicate_prefix(Some(&graph), "request/")
        .await;

    // Build per-request-cid entry map.
    let mut map: std::collections::HashMap<String, RequestLogEntry> =
        std::collections::HashMap::new();
    for q in &all_quads {
        let subj_key = q.subject.to_multibase();
        let entry = map.entry(subj_key.clone()).or_insert_with(|| RequestLogEntry {
            request_cid: subj_key,
            method: String::new(),
            path: String::new(),
            ts_unix: 0,
        });
        match q.predicate.as_str() {
            "request/method"  => { entry.method  = quad_object_text(&q.object); }
            "request/path"    => { entry.path     = quad_object_text(&q.object); }
            "request/ts_unix" => {
                if let QuadObject::Integer(n) = &q.object {
                    entry.ts_unix = *n as u64;
                }
            }
            _ => {}
        }
    }

    // Apply optional path_prefix filter, then sort by ts_unix descending (newest first).
    let mut entries: Vec<RequestLogEntry> = map.into_values()
        .filter(|e| {
            params.path_prefix.as_deref()
                .is_none_or(|pfx| e.path.starts_with(pfx))
        })
        .collect();
    entries.sort_by(|a, b| b.ts_unix.cmp(&a.ts_unix));
    entries.truncate(limit);

    let total = entries.len();
    tracing::debug!(
        path_prefix = ?params.path_prefix,
        limit,
        total,
        "request.log query result"
    );
    Json(RequestLogResp { entries, total }).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stake_constants_in_mkoto() {
        // 1,000 KOTO × 1,000,000 mKOTO/KOTO = 1_000_000_000
        assert_eq!(MIN_STAKE_SELF_ATTESTED, 1_000_000_000);
        // 5,000 KOTO × 1,000,000 mKOTO/KOTO = 5_000_000_000
        assert_eq!(MIN_STAKE_VERIFIED_ENTITY, 5_000_000_000);
    }

    #[test]
    fn nsids_have_correct_prefix() {
        for nsid in &[
            NSID_ATTEST_CLAIM,
            NSID_ATTEST_CHALLENGE,
            NSID_ATTEST_QUERY,
            NSID_REQUEST_LOG,
        ] {
            assert!(
                nsid.starts_with("ai.gftd.apps.kotoba."),
                "NSID does not start with ai.gftd.apps.kotoba.: {nsid}"
            );
        }
    }

    #[test]
    fn attest_graph_cid_is_stable() {
        let a = attest_graph_cid();
        let b = attest_graph_cid();
        assert_eq!(a.0, b.0);
    }

    #[test]
    fn audit_graph_cid_is_stable() {
        let a = audit_graph_cid();
        let b = audit_graph_cid();
        assert_eq!(a.0, b.0);
    }

    #[test]
    fn attest_and_audit_graph_cids_differ() {
        let attest = attest_graph_cid();
        let audit  = audit_graph_cid();
        assert_ne!(attest.0, audit.0, "attestation and audit graphs must have different CIDs");
    }

    #[test]
    fn quad_object_text_returns_text_clone() {
        let obj = QuadObject::Text("hello world".to_string());
        assert_eq!(quad_object_text(&obj), "hello world");
    }

    #[test]
    fn quad_object_text_returns_cid_multibase() {
        let cid = KotobaCid::from_bytes(b"test-cid-seed");
        let obj = QuadObject::Cid(cid.clone());
        let result = quad_object_text(&obj);
        assert_eq!(result, cid.to_multibase());
        assert!(!result.is_empty(), "multibase should be non-empty");
    }

    #[test]
    fn quad_object_text_returns_empty_for_integer() {
        let obj = QuadObject::Integer(42);
        assert_eq!(quad_object_text(&obj), "", "Integer variant should yield empty string");
    }

    #[test]
    fn max_constants_values() {
        assert_eq!(MAX_ATTEST_DID_LEN, 512);
        assert_eq!(MAX_ATTEST_CLAIM_TYPE, 64);
        assert_eq!(MAX_ATTEST_EVIDENCE_LEN, 2_048);
        assert_eq!(MAX_ATTEST_REASON_LEN, 4_096);
        assert_eq!(MAX_ATTEST_CID_LEN, 256);
    }

    #[test]
    fn verified_entity_stake_exceeds_self_attested() {
        assert!(MIN_STAKE_VERIFIED_ENTITY > MIN_STAKE_SELF_ATTESTED,
            "verified_entity stake threshold must be higher than self-attested");
    }

    #[test]
    fn nsids_are_distinct() {
        let nsids = [
            NSID_ATTEST_CLAIM,
            NSID_ATTEST_CHALLENGE,
            NSID_ATTEST_QUERY,
            NSID_REQUEST_LOG,
        ];
        let unique: std::collections::HashSet<&&str> = nsids.iter().collect();
        assert_eq!(unique.len(), nsids.len(), "all NSIDs must be distinct");
    }
}
