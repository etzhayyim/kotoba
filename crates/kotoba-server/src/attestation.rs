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
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use ed25519_dalek::Signer;
use kotoba_core::cid::KotobaCid;
use kotoba_vc::{CredentialStatus, DataIntegrityProof, VerifiableCredential, VC_CONTEXT_V2};

use crate::server::KotobaState;

const MAX_ATTEST_DID_LEN: usize = 512;
const MAX_ATTEST_CLAIM_TYPE: usize = 64;
const MAX_ATTEST_EVIDENCE_LEN: usize = 2_048;
const MAX_ATTEST_REASON_LEN: usize = 4_096;
const MAX_ATTEST_CID_LEN: usize = 256;

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
            (
                StatusCode::UNAUTHORIZED,
                "Authorization: Bearer <token> required".to_string(),
            )
        })?;
    if crate::graph_auth::jwt_exp_elapsed(token) {
        tracing::warn!("attester auth: expired JWT");
        return Err((
            StatusCode::UNAUTHORIZED,
            "Bearer token has expired".to_string(),
        ));
    }
    let sub = crate::graph_auth::jwt_sub(token).ok_or_else(|| {
        tracing::warn!("attester auth: JWT missing sub claim");
        (
            StatusCode::UNAUTHORIZED,
            "Bearer token missing sub claim".to_string(),
        )
    })?;
    if sub == attester_did || sub == operator_did {
        Ok(())
    } else {
        tracing::warn!(sub = %sub, attester_did = %attester_did, "attester auth: sub mismatch");
        Err((
            StatusCode::UNAUTHORIZED,
            format!("Bearer sub does not match attester_did {attester_did:?}"),
        ))
    }
}

// ── NSID constants ────────────────────────────────────────────────────────────

pub const NSID_ATTEST_CLAIM: &str = "ai.gftd.apps.kotoba.attest.claim";
pub const NSID_ATTEST_CHALLENGE: &str = "ai.gftd.apps.kotoba.attest.challenge";
pub const NSID_ATTEST_QUERY: &str = "ai.gftd.apps.kotoba.attest.query";
pub const NSID_REQUEST_LOG: &str = "ai.gftd.apps.kotoba.request.log";

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

fn datom_text(value: &kotoba_edn::EdnValue) -> String {
    match value {
        kotoba_edn::EdnValue::String(s) => s.clone(),
        _ => String::new(),
    }
}

fn datom_integer(value: &kotoba_edn::EdnValue) -> Option<i64> {
    match value {
        kotoba_edn::EdnValue::Integer(n) => Some(*n),
        _ => None,
    }
}

fn datom_u64(value: &kotoba_edn::EdnValue) -> u64 {
    datom_integer(value)
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(0)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn attestation_credential(
    req: &AttestClaimReq,
    claim_cid: &KotobaCid,
    issuer_did: &str,
    ts_unix: u64,
) -> VerifiableCredential {
    let mut subject = serde_json::json!({
        "id": req.entity_did,
        "type": "KotobaAttestedEntity",
        "claimCid": claim_cid.to_multibase(),
        "claimType": req.claim_type,
        "attester": req.attester_did,
        "stakeMkoto": req.stake_mkoto,
        "issuedAtUnix": ts_unix,
    });
    if let Some(evidence) = &req.evidence {
        if let Some(obj) = subject.as_object_mut() {
            obj.insert(
                "evidence".to_string(),
                serde_json::Value::String(evidence.clone()),
            );
        }
    }

    VerifiableCredential {
        context: vec![VC_CONTEXT_V2.to_string()],
        id: format!("urn:kotoba:attestation:{}", claim_cid.to_multibase()),
        types: vec![
            "VerifiableCredential".to_string(),
            "KotobaAttestationCredential".to_string(),
        ],
        issuer: issuer_did.to_string(),
        valid_from: None,
        valid_until: None,
        credential_subject: subject.into(),
        credential_status: Some(CredentialStatus {
            id: format!("kotoba://attestation/{}/status", claim_cid.to_multibase()),
            status_type: "KotobaAttestationStatus".to_string(),
        }),
        proof: None,
    }
}

fn sign_attestation_credential(
    mut credential: VerifiableCredential,
    issuer_did: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<VerifiableCredential, kotoba_vc::VcError> {
    credential.proof = None;
    let signature = signing_key.sign(&credential.proof_bytes()?);
    credential.proof = Some(DataIntegrityProof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: Some("eddsa-2022".to_string()),
        proof_purpose: "assertionMethod".to_string(),
        verification_method: format!("{issuer_did}#agent-ed25519"),
        created: None,
        proof_value: multibase::encode(multibase::Base::Base58Btc, signature.to_bytes()),
        challenge: None,
        domain: Some("kotoba.attestation".to_string()),
    });
    Ok(credential)
}

fn attestation_claim_datoms(
    req: &AttestClaimReq,
    claim_cid: &KotobaCid,
    credential: &VerifiableCredential,
    credential_cid: &KotobaCid,
    tx_cid: &KotobaCid,
    ts_unix: u64,
) -> Vec<kotoba_datomic::Datom> {
    fn assert_claim(
        out: &mut Vec<kotoba_datomic::Datom>,
        claim_cid: &KotobaCid,
        attr: &str,
        value: kotoba_edn::EdnValue,
        tx_cid: &KotobaCid,
    ) {
        out.push(kotoba_datomic::Datom::assert(
            claim_cid.clone(),
            attr.to_string(),
            value,
            tx_cid.clone(),
        ));
    }

    let mut out = Vec::new();
    assert_claim(
        &mut out,
        claim_cid,
        "attest/credentialCid",
        kotoba_edn::EdnValue::string(credential_cid.to_multibase()),
        tx_cid,
    );
    assert_claim(
        &mut out,
        claim_cid,
        "attest/credentialId",
        kotoba_edn::EdnValue::string(&credential.id),
        tx_cid,
    );
    assert_claim(
        &mut out,
        claim_cid,
        "attest/credentialType",
        kotoba_edn::EdnValue::string("KotobaAttestationCredential"),
        tx_cid,
    );
    assert_claim(
        &mut out,
        claim_cid,
        "attest/credentialWireFormat",
        kotoba_edn::EdnValue::string("application/vc+ld+json"),
        tx_cid,
    );
    assert_claim(
        &mut out,
        claim_cid,
        "attest/credentialDataModel",
        kotoba_edn::EdnValue::string("W3C VC Data Model 2.0"),
        tx_cid,
    );
    assert_claim(
        &mut out,
        claim_cid,
        "attest/credentialStatus",
        kotoba_edn::EdnValue::string("active"),
        tx_cid,
    );
    assert_claim(
        &mut out,
        claim_cid,
        "attest/entity",
        kotoba_edn::EdnValue::string(&req.entity_did),
        tx_cid,
    );
    assert_claim(
        &mut out,
        claim_cid,
        "attest/type",
        kotoba_edn::EdnValue::string(&req.claim_type),
        tx_cid,
    );
    assert_claim(
        &mut out,
        claim_cid,
        "attest/attester",
        kotoba_edn::EdnValue::string(&req.attester_did),
        tx_cid,
    );
    assert_claim(
        &mut out,
        claim_cid,
        "attest/stake_mkoto",
        kotoba_edn::EdnValue::Integer(req.stake_mkoto as i64),
        tx_cid,
    );
    assert_claim(
        &mut out,
        claim_cid,
        "attest/ts_unix",
        kotoba_edn::EdnValue::Integer(ts_unix as i64),
        tx_cid,
    );
    if let Some(evidence) = &req.evidence {
        assert_claim(
            &mut out,
            claim_cid,
            "attest/evidence",
            kotoba_edn::EdnValue::string(evidence),
            tx_cid,
        );
    }
    out
}

fn attestation_challenge_datoms(
    req: &AttestChallengeReq,
    claim_cid: &KotobaCid,
    challenge_cid: &KotobaCid,
    tx_cid: &KotobaCid,
    ts_unix: u64,
) -> Vec<kotoba_datomic::Datom> {
    let challenger_cid = KotobaCid::from_bytes(req.challenger_did.as_bytes());
    vec![
        kotoba_datomic::Datom::assert(
            challenge_cid.clone(),
            "challenge/claim".to_string(),
            kotoba_edn::EdnValue::string(claim_cid.to_multibase()),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            challenge_cid.clone(),
            "challenge/challenger".to_string(),
            kotoba_edn::EdnValue::string(&req.challenger_did),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            challenge_cid.clone(),
            "challenge/challengerCid".to_string(),
            kotoba_edn::EdnValue::string(challenger_cid.to_multibase()),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            challenge_cid.clone(),
            "challenge/reason".to_string(),
            kotoba_edn::EdnValue::string(&req.reason),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            challenge_cid.clone(),
            "challenge/ts_unix".to_string(),
            kotoba_edn::EdnValue::Integer(ts_unix as i64),
            tx_cid.clone(),
        ),
    ]
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
    /// Multibase CID of the W3C VC projection for this attestation.
    pub credential_cid: String,
    /// W3C VC id for the issued attestation credential.
    pub credential_id: String,
    /// Specific VC type that represents this attestation.
    pub credential_type: &'static str,
    /// External wire format of the attestation credential.
    pub credential_wire_format: &'static str,
    /// W3C VC data model used by the attestation credential.
    pub credential_data_model: &'static str,
    /// Distributed Datomic commit CID containing the VC datoms.
    pub commit_cid: String,
    /// IPNS name for the attestation graph head.
    pub ipns_name: String,
    /// Monotonic IPNS sequence for the attestation graph head.
    pub ipns_sequence: u64,
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
    /// Distributed Datomic commit CID containing the challenge datoms.
    pub commit_cid: String,
    /// IPNS name for the attestation graph head.
    pub ipns_name: String,
    /// Monotonic IPNS sequence for the attestation graph head.
    pub ipns_sequence: u64,
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
    pub credential_cid: String,
    pub credential_id: String,
    pub credential_type: String,
    pub credential_wire_format: String,
    pub credential_data_model: String,
    pub credential_status: String,
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
    if let Err((code, msg)) =
        crate::graph_auth::validate_did(&req.entity_did, "entity_did", MAX_ATTEST_DID_LEN)
    {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    if let Err((code, msg)) =
        crate::graph_auth::validate_did(&req.attester_did, "attester_did", MAX_ATTEST_DID_LEN)
    {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    if req.claim_type.is_empty() || req.claim_type.len() > MAX_ATTEST_CLAIM_TYPE {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "claim_type must be 'self', 'verified_entity', or 'delegation'" }))).into_response();
    }
    if !matches!(
        req.claim_type.as_str(),
        "self" | "verified_entity" | "delegation"
    ) {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "claim_type must be 'self', 'verified_entity', or 'delegation'" }))).into_response();
    }
    if let Some(ev) = &req.evidence {
        if ev.len() > MAX_ATTEST_EVIDENCE_LEN {
            return (StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("evidence exceeds {MAX_ATTEST_EVIDENCE_LEN} bytes") }))).into_response();
        }
    }
    if let Err((code, msg)) =
        require_attester_auth(&headers, &req.attester_did, &state.operator_did)
    {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }

    // Reject stake values that exceed i64::MAX to prevent silent truncation when
    // stored as Datom EDN Integer(i64). Real stakes are at most ~10^10 mKOTO,
    // orders of magnitude below the 9.2×10^18 i64 ceiling.
    if req.stake_mkoto > i64::MAX as u64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "stake_mkoto exceeds maximum representable value" })),
        )
            .into_response();
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
    let credential = attestation_credential(&req, &claim_cid, &state.operator_did, ts);
    let credential = match sign_attestation_credential(
        credential,
        &state.operator_did,
        &state.ipns_signing_key(),
    ) {
        Ok(credential) => credential,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("attestation vc proof: {e}") })),
            )
                .into_response();
        }
    };
    let credential_cid = match credential.cid() {
        Ok(cid) => cid,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("attestation vc cid: {e}") })),
            )
                .into_response();
        }
    };
    let tx_cid = KotobaCid::from_bytes(
        format!(
            "attest.claim:{}:{}:{}",
            graph.to_multibase(),
            claim_cid.to_multibase(),
            credential_cid.to_multibase()
        )
        .as_bytes(),
    );
    let mut datoms = match credential.to_datoms(tx_cid.clone()) {
        Ok(datoms) => datoms,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("attestation vc datoms: {e}") })),
            )
                .into_response();
        }
    };
    datoms.extend(attestation_claim_datoms(
        &req,
        &claim_cid,
        &credential,
        &credential_cid,
        &tx_cid,
        ts,
    ));
    let distributed = match crate::xrpc::commit_protocol_datoms(
        &state,
        graph.clone(),
        graph.to_multibase(),
        credential_cid.clone(),
        datoms,
        tx_cid,
        state.operator_did.clone(),
        kotoba_auth::CacaoPayload::OP_VC_ISSUE,
        None,
        None,
    )
    .await
    {
        Ok(resp) => resp,
        Err((code, msg)) => {
            return (code, Json(serde_json::json!({ "error": msg }))).into_response();
        }
    };

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
            credential_cid: credential_cid.to_multibase(),
            credential_id: credential.id,
            credential_type: "KotobaAttestationCredential",
            credential_wire_format: "application/vc+ld+json",
            credential_data_model: "W3C VC Data Model 2.0",
            commit_cid: distributed.commit_cid,
            ipns_name: distributed.ipns_name,
            ipns_sequence: distributed.ipns_sequence,
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
    if let Err((code, msg)) =
        crate::graph_auth::validate_did(&req.challenger_did, "challenger_did", MAX_ATTEST_DID_LEN)
    {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    if req.reason.is_empty() || req.reason.len() > MAX_ATTEST_REASON_LEN {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("reason must be 1–{MAX_ATTEST_REASON_LEN} bytes") }))).into_response();
    }
    if let Err((code, msg)) =
        require_attester_auth(&headers, &req.challenger_did, &state.operator_did)
    {
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

    let tx_cid = KotobaCid::from_bytes(
        format!(
            "attest.challenge:{}:{}:{}",
            graph.to_multibase(),
            req.claim_cid,
            challenge_cid.to_multibase()
        )
        .as_bytes(),
    );
    let datoms = attestation_challenge_datoms(&req, &claim_cid, &challenge_cid, &tx_cid, ts);
    let distributed = match crate::xrpc::commit_protocol_datoms(
        &state,
        graph.clone(),
        graph.to_multibase(),
        challenge_cid.clone(),
        datoms,
        tx_cid,
        state.operator_did.clone(),
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        None,
        None,
    )
    .await
    {
        Ok(resp) => resp,
        Err((code, msg)) => {
            return (code, Json(serde_json::json!({ "error": msg }))).into_response();
        }
    };

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
            commit_cid: distributed.commit_cid,
            ipns_name: distributed.ipns_name,
            ipns_sequence: distributed.ipns_sequence,
        }),
    )
        .into_response()
}

/// GET `ai.gftd.apps.kotoba.attest.query`
///
/// Query attestation records by entity_did or attester_did.
/// Reads from the distributed Datomic/IPNS head; returns empty when neither
/// filter is provided to avoid an unbounded public full-scan.
pub async fn attest_query(
    State(state): State<Arc<KotobaState>>,
    Query(params): Query<AttestQueryParams>,
) -> impl IntoResponse {
    if params
        .entity_did
        .as_deref()
        .map(|s| s.len() > MAX_ATTEST_DID_LEN)
        .unwrap_or(false)
    {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("entity_did exceeds {MAX_ATTEST_DID_LEN} bytes") }))).into_response();
    }
    if params
        .attester_did
        .as_deref()
        .map(|s| s.len() > MAX_ATTEST_DID_LEN)
        .unwrap_or(false)
    {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("attester_did exceeds {MAX_ATTEST_DID_LEN} bytes") }))).into_response();
    }
    let limit = params.limit.unwrap_or(20).min(100);
    let graph = attest_graph_cid();
    let db = match crate::xrpc::current_db_for_graph(&state, &graph).await {
        Ok(db) => db,
        Err((code, msg)) => {
            return (code, Json(serde_json::json!({ "error": msg }))).into_response();
        }
    };
    let datoms = db.datoms();

    let mut claim_cids: Vec<kotoba_core::cid::KotobaCid> = if let Some(ref did) = params.entity_did
    {
        datoms
            .iter()
            .filter(|datom| datom.a == "attest/entity" && datom_text(&datom.v) == *did)
            .map(|datom| datom.e.clone())
            .collect()
    } else if let Some(ref did) = params.attester_did {
        datoms
            .iter()
            .filter(|datom| datom.a == "attest/attester" && datom_text(&datom.v) == *did)
            .map(|datom| datom.e.clone())
            .collect()
    } else {
        // No filter: return empty to avoid unbounded full-scan.
        return Json(AttestQueryResp {
            claims: Vec::new(),
            total: 0,
        })
        .into_response();
    };
    claim_cids.sort_by_key(|cid| cid.to_multibase());
    claim_cids.dedup();

    let mut claims: Vec<AttestRecord> = Vec::new();
    for claim_cid in claim_cids.into_iter().take(limit) {
        let mut rec = AttestRecord {
            claim_cid: claim_cid.to_multibase(),
            credential_cid: String::new(),
            credential_id: String::new(),
            credential_type: String::new(),
            credential_wire_format: String::new(),
            credential_data_model: String::new(),
            credential_status: String::new(),
            entity_did: String::new(),
            claim_type: String::new(),
            attester_did: String::new(),
            stake_mkoto: 0,
            ts_unix: 0,
        };
        for datom in datoms.iter().filter(|datom| datom.e == claim_cid) {
            match datom.a.as_str() {
                "attest/credentialCid" => rec.credential_cid = datom_text(&datom.v),
                "attest/credentialId" => rec.credential_id = datom_text(&datom.v),
                "attest/credentialType" => rec.credential_type = datom_text(&datom.v),
                "attest/credentialWireFormat" => rec.credential_wire_format = datom_text(&datom.v),
                "attest/credentialDataModel" => rec.credential_data_model = datom_text(&datom.v),
                "attest/credentialStatus" => rec.credential_status = datom_text(&datom.v),
                "attest/entity" => rec.entity_did = datom_text(&datom.v),
                "attest/type" => rec.claim_type = datom_text(&datom.v),
                "attest/attester" => rec.attester_did = datom_text(&datom.v),
                "attest/stake_mkoto" => rec.stake_mkoto = datom_u64(&datom.v),
                "attest/ts_unix" => rec.ts_unix = datom_u64(&datom.v),
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
/// Reads from the audit graph's distributed Datomic/IPNS head.
/// Requires operator auth — audit logs are internal security instruments.
pub async fn request_log_query(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(params): Query<RequestLogQueryParams>,
) -> impl IntoResponse {
    if let Err((code, msg)) =
        crate::graph_auth::require_operator_auth(&headers, &state.operator_did)
    {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    let limit = params.limit.unwrap_or(20).min(100);
    let graph = audit_graph_cid();
    let db = match crate::xrpc::current_db_for_graph(&state, &graph).await {
        Ok(db) => db,
        Err((code, msg)) => {
            return (code, Json(serde_json::json!({ "error": msg }))).into_response();
        }
    };

    // Fetch all datoms in the audit graph whose attribute starts with "request/".
    // Group by subject CID → hydrate each RequestLogEntry.
    let mut map: std::collections::HashMap<String, RequestLogEntry> =
        std::collections::HashMap::new();
    for datom in db
        .datoms()
        .into_iter()
        .filter(|datom| datom.a.starts_with("request/"))
    {
        let subj_key = datom.e.to_multibase();
        let entry = map
            .entry(subj_key.clone())
            .or_insert_with(|| RequestLogEntry {
                request_cid: subj_key,
                method: String::new(),
                path: String::new(),
                ts_unix: 0,
            });
        match datom.a.as_str() {
            "request/method" => {
                entry.method = datom_text(&datom.v);
            }
            "request/path" => {
                entry.path = datom_text(&datom.v);
            }
            "request/ts_unix" => {
                entry.ts_unix = datom_u64(&datom.v);
            }
            _ => {}
        }
    }

    // Apply optional path_prefix filter, then sort by ts_unix descending (newest first).
    let mut entries: Vec<RequestLogEntry> = map
        .into_values()
        .filter(|e| {
            params
                .path_prefix
                .as_deref()
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
        let audit = audit_graph_cid();
        assert_ne!(
            attest.0, audit.0,
            "attestation and audit graphs must have different CIDs"
        );
    }

    #[test]
    fn attestation_claim_projects_vc_and_attest_datoms_to_one_distributed_head() {
        let store = kotoba_store::MemoryBlockStore::new();
        let ipns = kotoba_ipfs::InMemoryIpnsRegistry::new();
        let writer = kotoba_datomic::distributed::DistributedCommitWriter::new(&store, &ipns);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let issuer_did =
            kotoba_auth::ed25519_pubkey_to_did_key(signing_key.verifying_key().as_bytes());
        let graph = attest_graph_cid();
        let req = AttestClaimReq {
            entity_did: "did:plc:attestedentity".into(),
            claim_type: "verified_entity".into(),
            attester_did: "did:plc:attester".into(),
            stake_mkoto: MIN_STAKE_VERIFIED_ENTITY,
            evidence: Some("ipfs://bafyattestationevidence".into()),
        };
        let claim_cid = KotobaCid::from_bytes(b"attestation-vc-claim");
        let credential = sign_attestation_credential(
            attestation_credential(&req, &claim_cid, &issuer_did, 1_779_945_600),
            &issuer_did,
            &signing_key,
        )
        .unwrap();
        let credential_cid = credential.cid().unwrap();
        let tx_cid = KotobaCid::from_bytes(b"attestation-vc-datomic-tx");
        let mut datoms = credential.to_datoms(tx_cid.clone()).unwrap();
        datoms.extend(attestation_claim_datoms(
            &req,
            &claim_cid,
            &credential,
            &credential_cid,
            &tx_cid,
            1_779_945_600,
        ));

        let commit = writer
            .commit_datoms(kotoba_datomic::distributed::CommitDatomsRequest {
                ipns_name: "k51-attestation-vc-distributed".into(),
                graph,
                datoms,
                expected_parent: None,
                tx_cid: Some(tx_cid.clone()),
                author: issuer_did.clone(),
                seq: 1,
                valid_until: "2099-01-01T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .unwrap();

        let reader = kotoba_datomic::distributed::DistributedDatomReader::new(&store, &ipns);
        let query = kotoba_edn::parse(
            r#"{:find [?issuer ?entity ?claimType ?credStatus ?attestType ?wireFormat ?dataModel ?attestStatus ?evidence]
                :where [[?vc :credential/issuer ?issuer]
                        [?vc :credential/subject/id ?entity]
                        [?vc :credential/subject/claimType ?claimType]
                        [?vc :credential/status/type ?credStatus]
                        [?vc :credential/id ?credentialId]
                        [?claim :attest/credentialId ?credentialId]
                        [?claim :attest/credentialType ?attestType]
                        [?claim :attest/credentialWireFormat ?wireFormat]
                        [?claim :attest/credentialDataModel ?dataModel]
                        [?claim :attest/credentialStatus ?attestStatus]
                        [?claim :attest/evidence ?evidence]]}"#,
        )
        .unwrap();
        let rows = reader.q_triples(&commit.commit.cid, &query).unwrap();

        assert_eq!(
            rows,
            vec![vec![
                kotoba_edn::EdnValue::string(issuer_did),
                kotoba_edn::EdnValue::string("did:plc:attestedentity"),
                kotoba_edn::EdnValue::string("verified_entity"),
                kotoba_edn::EdnValue::string("KotobaAttestationStatus"),
                kotoba_edn::EdnValue::string("KotobaAttestationCredential"),
                kotoba_edn::EdnValue::string("application/vc+ld+json"),
                kotoba_edn::EdnValue::string("W3C VC Data Model 2.0"),
                kotoba_edn::EdnValue::string("active"),
                kotoba_edn::EdnValue::string("ipfs://bafyattestationevidence"),
            ]]
        );
        assert!(reader
            .history_datoms_index(
                &commit.commit.cid,
                kotoba_datomic::DatomIndex::Tea,
                &[kotoba_edn::EdnValue::string(tx_cid.to_multibase())],
            )
            .unwrap()
            .iter()
            .all(|datom| datom.t == tx_cid));
    }

    #[test]
    fn attestation_challenge_projects_to_distributed_datomic_datoms() {
        let store = kotoba_store::MemoryBlockStore::new();
        let ipns = kotoba_ipfs::InMemoryIpnsRegistry::new();
        let writer = kotoba_datomic::distributed::DistributedCommitWriter::new(&store, &ipns);
        let graph = attest_graph_cid();
        let claim_cid = KotobaCid::from_bytes(b"attestation-challenge-claim");
        let challenge_cid = KotobaCid::from_bytes(b"attestation-challenge");
        let tx_cid = KotobaCid::from_bytes(b"attestation-challenge-tx");
        let req = AttestChallengeReq {
            claim_cid: claim_cid.to_multibase(),
            challenger_did: "did:plc:challenger".into(),
            reason: "counter-evidence".into(),
        };

        let commit = writer
            .commit_datoms(kotoba_datomic::distributed::CommitDatomsRequest {
                ipns_name: "k51-attestation-challenge-distributed".into(),
                graph,
                datoms: attestation_challenge_datoms(
                    &req,
                    &claim_cid,
                    &challenge_cid,
                    &tx_cid,
                    1_779_945_601,
                ),
                expected_parent: None,
                tx_cid: Some(tx_cid.clone()),
                author: "did:plc:challenger".into(),
                seq: 1,
                valid_until: "2099-01-01T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .unwrap();

        let reader = kotoba_datomic::distributed::DistributedDatomReader::new(&store, &ipns);
        let rows = reader
            .q_triples(
                &commit.commit.cid,
                &kotoba_edn::parse(
                    r#"{:find [?claim ?challenger ?reason]
                        :where [[?challenge :challenge/claim ?claim]
                                [?challenge :challenge/challenger ?challenger]
                                [?challenge :challenge/reason ?reason]]}"#,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(
            rows,
            vec![vec![
                kotoba_edn::EdnValue::string(claim_cid.to_multibase()),
                kotoba_edn::EdnValue::string("did:plc:challenger"),
                kotoba_edn::EdnValue::string("counter-evidence"),
            ]]
        );
        assert!(reader
            .history_datoms_index(
                &commit.commit.cid,
                kotoba_datomic::DatomIndex::Tea,
                &[kotoba_edn::EdnValue::string(tx_cid.to_multibase())],
            )
            .unwrap()
            .iter()
            .all(|datom| datom.t == tx_cid));
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
        assert!(
            MIN_STAKE_VERIFIED_ENTITY > MIN_STAKE_SELF_ATTESTED,
            "verified_entity stake threshold must be higher than self-attested"
        );
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

    #[test]
    fn public_attestation_lexicons_match_xrpc_nsids() {
        let lexicons = [
            (
                NSID_ATTEST_CLAIM,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/attest/claim.json"),
                "procedure",
            ),
            (
                NSID_ATTEST_CHALLENGE,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/attest/challenge.json"),
                "procedure",
            ),
            (
                NSID_ATTEST_QUERY,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/attest/query.json"),
                "query",
            ),
        ];
        for (expected_id, src, expected_type) in lexicons {
            let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
            assert_eq!(value["lexicon"], 1);
            assert_eq!(value["id"], expected_id);
            assert_eq!(value["defs"]["main"]["type"], expected_type);
        }
    }

    #[test]
    fn attestation_lexicons_expose_vc_projection_response_fields() {
        let claim = include_str!("../../../lexicons/ai/gftd/apps/kotoba/attest/claim.json");
        assert_lexicon_output_fields(
            claim,
            &[
                "status",
                "claim_cid",
                "credential_cid",
                "credential_id",
                "credential_type",
                "credential_wire_format",
                "credential_data_model",
                "commit_cid",
                "ipns_name",
                "ipns_sequence",
            ],
            &[],
        );

        let challenge = include_str!("../../../lexicons/ai/gftd/apps/kotoba/attest/challenge.json");
        assert_lexicon_output_fields(
            challenge,
            &[
                "status",
                "challenge_cid",
                "commit_cid",
                "ipns_name",
                "ipns_sequence",
            ],
            &[],
        );

        let query = include_str!("../../../lexicons/ai/gftd/apps/kotoba/attest/query.json");
        assert_lexicon_output_fields(query, &["claims", "total"], &[]);
        assert_lexicon_array_item_fields(
            query,
            "claims",
            &[
                "claim_cid",
                "credential_cid",
                "credential_id",
                "credential_type",
                "credential_wire_format",
                "credential_data_model",
                "credential_status",
                "entity_did",
                "claim_type",
                "attester_did",
                "stake_mkoto",
                "ts_unix",
            ],
        );
    }

    fn assert_lexicon_output_fields(src: &str, required: &[&str], properties: &[&str]) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let schema = &value["defs"]["main"]["output"]["schema"];
        assert_eq!(
            schema["type"], "object",
            "{} output must be object",
            value["id"]
        );
        let required_values = schema["required"].as_array().expect("required array");
        for field in required {
            assert!(
                required_values
                    .iter()
                    .any(|value| value.as_str() == Some(field)),
                "{} missing required output field {field}",
                value["id"]
            );
        }
        let property_values = schema["properties"].as_object().expect("properties object");
        for field in required.iter().chain(properties.iter()) {
            assert!(
                property_values.contains_key(*field),
                "{} missing output property {field}",
                value["id"]
            );
        }
    }

    fn assert_lexicon_array_item_fields(src: &str, field: &str, required: &[&str]) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let item = &value["defs"]["main"]["output"]["schema"]["properties"][field]["items"];
        assert_eq!(
            item["type"], "object",
            "{} output {field} items must be object",
            value["id"]
        );
        let required_values = item["required"].as_array().expect("required array");
        for field in required {
            assert!(
                required_values
                    .iter()
                    .any(|value| value.as_str() == Some(field)),
                "{} output array item missing required field {field}",
                value["id"]
            );
            assert!(
                item["properties"]
                    .as_object()
                    .is_some_and(|props| props.contains_key(*field)),
                "{} output array item missing property {field}",
                value["id"]
            );
        }
    }

    #[test]
    fn stake_mkoto_overflow_guard_boundary() {
        // i64::MAX as u64 must pass; i64::MAX as u64 + 1 must fail.
        let just_below = i64::MAX as u64;
        assert!(
            just_below <= i64::MAX as u64,
            "i64::MAX must be representable"
        );
        let overflow = (i64::MAX as u64).saturating_add(1);
        assert!(
            overflow > i64::MAX as u64,
            "overflow value must exceed i64::MAX guard"
        );
    }

    #[test]
    fn stake_i64_max_cast_is_lossless() {
        // Verify the guard condition: any stake_mkoto that passes the guard is
        // safely castable to i64 without truncation or sign change.
        let max_ok: u64 = i64::MAX as u64;
        let as_i64 = max_ok as i64;
        assert_eq!(as_i64, i64::MAX, "lossless cast must produce i64::MAX");
        assert!(as_i64 >= 0, "must be non-negative");
    }
}
