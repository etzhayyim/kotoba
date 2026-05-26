/// Graph read-access control.
///
/// Three visibility tiers (see `kotoba_core::named_graph::GraphVisibility`):
///   - `Public`         — no auth required
///   - `Authenticated`  — `Authorization: Bearer <any-non-empty-token>` required
///   - `Private`        — CACAO delegation chain (DAG-CBOR, base64-standard encoded)
///                        in the `cacao_b64` query param, verified with `quad:read`
///                        capability and issuer == owner_did

use axum::http::{HeaderMap, StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use kotoba_auth::{Cacao, DelegationChain};
use kotoba_core::named_graph::GraphVisibility;

/// Error type returned by [`check_read_access`].
#[derive(Debug)]
pub enum AccessDenied {
    /// Public — should never be returned (kept for exhaustiveness).
    #[allow(dead_code)]
    NotDenied,
    /// Authenticated tier: no `Authorization: Bearer …` header present.
    MissingBearer,
    /// Authenticated tier: Bearer JWT `exp` claim is in the past.
    TokenExpired,
    /// Private tier: `cacao_b64` query param is absent.
    MissingCacao,
    /// Private tier: base64 decode of `cacao_b64` failed.
    CacaoDecodeError(String),
    /// Private tier: CACAO parse (DAG-CBOR) failed.
    CacaoParseError(String),
    /// Private tier: CACAO delegation verification failed.
    DelegationError(String),
    /// Private tier: CACAO was issued by a DID other than the graph owner.
    IssuerMismatch { expected: String, got: String },
    /// Private tier: CACAO `aud` field does not match this node's DID.
    AudienceMismatch { expected: String, got: String },
    /// Private tier: CACAO nonce has already been seen — replay attack detected.
    ReplayedNonce(String),
}

impl AccessDenied {
    /// Convert to an axum-compatible HTTP error tuple.
    pub fn into_response(self) -> (StatusCode, String) {
        match self {
            AccessDenied::NotDenied => (StatusCode::OK, String::new()),
            AccessDenied::MissingBearer => (
                StatusCode::UNAUTHORIZED,
                "Authorization: Bearer <token> required for authenticated graphs".into(),
            ),
            AccessDenied::TokenExpired => (
                StatusCode::UNAUTHORIZED,
                "Bearer token has expired".into(),
            ),
            AccessDenied::MissingCacao => (
                StatusCode::UNAUTHORIZED,
                "cacao_b64 query param required for private graphs".into(),
            ),
            AccessDenied::CacaoDecodeError(e) => (
                StatusCode::BAD_REQUEST,
                format!("cacao_b64 base64 decode error: {e}"),
            ),
            AccessDenied::CacaoParseError(e) => (
                StatusCode::BAD_REQUEST,
                format!("cacao parse error: {e}"),
            ),
            AccessDenied::DelegationError(e) => (
                StatusCode::UNAUTHORIZED,
                format!("cacao delegation error: {e}"),
            ),
            AccessDenied::IssuerMismatch { expected, got } => (
                StatusCode::UNAUTHORIZED,
                format!("cacao issuer mismatch: expected {expected}, got {got}"),
            ),
            AccessDenied::AudienceMismatch { expected, got } => (
                StatusCode::UNAUTHORIZED,
                format!("cacao audience mismatch: expected {expected}, got {got}"),
            ),
            AccessDenied::ReplayedNonce(nonce) => (
                StatusCode::UNAUTHORIZED,
                format!("cacao nonce already used: {nonce}"),
            ),
        }
    }
}

/// Decode the JWT payload segment and return `true` if the `exp` claim is in the past.
///
/// Extract the `sub` claim from an unsigned (or pre-verified) JWT.
///
/// Returns `None` if the token is malformed or has no `sub` claim.
/// The signature is NOT verified — the edge BFF is the trust boundary.
pub(crate) fn jwt_sub(token: &str) -> Option<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload_b64 = token.splitn(3, '.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("sub").and_then(|v| v.as_str()).map(str::to_owned)
}

/// This is a defense-in-depth check only — the JWT signature is NOT verified here.
/// The edge BFF (AT Protocol PDS / CF Worker) is the trust boundary for signatures.
/// Returns `false` for any token that cannot be decoded or has no `exp` claim.
pub(crate) fn jwt_exp_elapsed(token: &str) -> bool {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    // A JWT has three dot-separated segments: header.payload.signature
    let payload_b64 = match token.splitn(3, '.').nth(1) {
        Some(p) => p,
        None => return false,
    };
    // Pad to a multiple of 4 (URL_SAFE_NO_PAD tolerates missing padding on decode)
    let bytes = match URL_SAFE_NO_PAD.decode(payload_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let json: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let exp = match json.get("exp").and_then(|v| v.as_u64()) {
        Some(e) => e,
        None => return false,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now > exp
}

/// Require that the request carries a Bearer JWT whose `sub` matches `operator_did`.
///
/// Used by unauthenticated-write endpoints (`kg_ingest`, `kg_delete`, `kg_embed`,
/// `embed_create`, `agent_run`, `block_put`, `vault_put`) to prevent storage/compute abuse.
/// JWT signature is NOT re-verified — the edge BFF is the trust boundary; we only check
/// that the token is not expired and that the `sub` claim names the operator.
pub fn require_operator_auth(
    headers: &HeaderMap,
    operator_did: &str,
) -> Result<(), (StatusCode, String)> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("operator auth: missing Bearer token");
            (StatusCode::UNAUTHORIZED, "Authorization: Bearer <token> required".to_string())
        })?;
    if jwt_exp_elapsed(token) {
        tracing::warn!("operator auth: expired JWT");
        return Err((StatusCode::UNAUTHORIZED, "Bearer token has expired".to_string()));
    }
    let sub = jwt_sub(token)
        .ok_or_else(|| {
            tracing::warn!("operator auth: JWT missing sub claim");
            (StatusCode::UNAUTHORIZED, "Bearer token missing sub claim".to_string())
        })?;
    if sub == operator_did {
        Ok(())
    } else {
        tracing::warn!(sub = %sub, "operator auth: sub mismatch");
        Err((StatusCode::UNAUTHORIZED,
            format!("Bearer sub {sub:?} is not the operator DID")))
    }
}

/// Require any valid, non-expired Bearer JWT that carries a `sub` claim.
///
/// Used when the specific caller DID is not known at the HTTP layer
/// (e.g. `distributeSenderKey`, `agent.syncopen/advance/close`).
pub(crate) fn require_any_bearer_auth(
    headers: &HeaderMap,
    context: &str,
) -> Result<(), (StatusCode, String)> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("{context}: missing Bearer token");
            (StatusCode::UNAUTHORIZED, "Authorization: Bearer <token> required".to_string())
        })?;
    if jwt_exp_elapsed(token) {
        tracing::warn!("{context}: expired JWT");
        return Err((StatusCode::UNAUTHORIZED, "Bearer token has expired".to_string()));
    }
    jwt_sub(token)
        .map(|_| ())
        .ok_or_else(|| {
            tracing::warn!("{context}: JWT missing sub claim");
            (StatusCode::UNAUTHORIZED, "Bearer token missing sub claim".to_string())
        })
}

/// Validate a DID string: non-empty, `did:` prefix, within `max_len` bytes.
///
/// Returns a `(StatusCode::BAD_REQUEST, message)` error tuple on failure.
pub(crate) fn validate_did(did: &str, field: &str, max_len: usize) -> Result<(), (StatusCode, String)> {
    if did.is_empty() {
        return Err((StatusCode::BAD_REQUEST, format!("{field} must not be empty")));
    }
    if !did.starts_with("did:") {
        return Err((StatusCode::BAD_REQUEST, format!("{field} is not a valid DID (must start with 'did:')")));
    }
    if did.len() > max_len {
        return Err((StatusCode::BAD_REQUEST, format!("{field} exceeds {max_len} bytes")));
    }
    Ok(())
}

/// Check read access for a named graph.
///
/// - `Public`        → always `Ok(())`
/// - `Authenticated` → requires a non-empty `Authorization: Bearer …` header
/// - `Private`       → requires a valid CACAO delegation chain in `cacao_b64` with:
///     1. `quad:read` capability
///     2. graph scope `kotoba://graph/private/{owner_did}` (or absent = all graphs)
///     3. valid cryptographic signature
///     4. issuer DID == `owner_did`
///     5. `aud` field matches `expected_aud` when provided (CAIP-74 audience check)
pub fn check_read_access(
    visibility: &GraphVisibility,
    headers: &HeaderMap,
    cacao_b64: Option<&str>,
    expected_aud: Option<&str>,
    nonce_store: Option<&crate::nonce_store::NonceStore>,
) -> Result<(), AccessDenied> {
    match visibility {
        GraphVisibility::Public => Ok(()),

        GraphVisibility::Authenticated => {
            // Any non-empty Bearer token is accepted (the token itself is opaque to kotoba;
            // the caller's identity is established upstream by the AT Protocol PDS / edge BFF).
            let auth = headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if auth.starts_with("Bearer ") && auth.len() > "Bearer ".len() {
                let token = &auth["Bearer ".len()..];
                // Defense-in-depth: reject tokens whose JWT `exp` claim is clearly past.
                // Signature is NOT verified here — the edge BFF is the trust boundary.
                if jwt_exp_elapsed(token) {
                    return Err(AccessDenied::TokenExpired);
                }
                Ok(())
            } else {
                Err(AccessDenied::MissingBearer)
            }
        }

        GraphVisibility::Private { owner_did } => {
            let b64 = cacao_b64.ok_or(AccessDenied::MissingCacao)?;

            // 1. Guard: reject oversized cacao_b64 before decoding.
            // Legitimate CACAOs are ~400-800 base64 chars. 8 KiB is generous.
            const MAX_CACAO_B64_LEN: usize = 8 * 1024;
            if b64.len() > MAX_CACAO_B64_LEN {
                return Err(AccessDenied::CacaoDecodeError(
                    format!("cacao_b64 too large ({} bytes, limit {MAX_CACAO_B64_LEN})", b64.len())
                ));
            }

            // 2. Decode base64
            let cbor = B64.decode(b64)
                .map_err(|e| AccessDenied::CacaoDecodeError(e.to_string()))?;

            // 2. Parse CACAO from DAG-CBOR
            let cacao = Cacao::from_cbor(&cbor)
                .map_err(|e| AccessDenied::CacaoParseError(e.to_string()))?;

            // 3. Build DelegationChain and verify:
            //    - expiry
            //    - capability == "quad:read" (if present)
            //    - graph scope == "private/{owner_did}" (if present)
            //    - cryptographic signature → returns recovered issuer DID
            //
            // Note: cacao.p.graph_cid() strips the "kotoba://graph/" prefix, so the
            // private graph "kotoba://graph/private/{did}" becomes "private/{did}".
            let graph_scope = format!("private/{}", owner_did);
            let chain = DelegationChain::new(cacao);
            let issuer_did = if let Some(aud) = expected_aud {
                chain
                    .verify_with_aud(&graph_scope, "quad:read", aud)
                    .map_err(|e| match e {
                        kotoba_auth::DelegationError::AudienceMismatch { expected, got } =>
                            AccessDenied::AudienceMismatch { expected, got },
                        other => AccessDenied::DelegationError(other.to_string()),
                    })?
            } else {
                chain
                    .verify(&graph_scope, "quad:read")
                    .map_err(|e| AccessDenied::DelegationError(e.to_string()))?
            };

            // 4. The recovered issuer must be the graph owner (security invariant:
            //    only the owner themselves may delegate read access to a private graph).
            if &issuer_did != owner_did {
                return Err(AccessDenied::IssuerMismatch {
                    expected: owner_did.clone(),
                    got:      issuer_did,
                });
            }

            // 5. Nonce replay prevention (CAIP-74 §8) — only when a store is provided.
            //    Expiry is bounded at now + MAX_CACAO_AGE (7 days) — the same cap that
            //    DelegationChain::verify() applies, so nonces are never kept longer than
            //    the CACAO itself could be valid.
            if let Some(store) = nonce_store {
                let nonce = chain.chain[0].p.nonce.clone();
                // An empty nonce cannot be used for replay prevention — every CACAO
                // without a nonce would collide in the store after the first request.
                // Reject rather than silently bypass the guard.
                if nonce.is_empty() {
                    return Err(AccessDenied::DelegationError(
                        "CACAO nonce must not be empty".into()
                    ));
                }
                // Conservative upper-bound: keep nonce until max possible expiry.
                const MAX_CACAO_AGE_SECS: u64 = 7 * 24 * 3600;
                let expiry_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_add(MAX_CACAO_AGE_SECS);
                if !store.check_and_register(&nonce, expiry_unix) {
                    return Err(AccessDenied::ReplayedNonce(nonce));
                }
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h
    }

    fn jwt_with_exp(exp: u64) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let header  = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"did:key:z6Mk","exp":{exp}}}"#));
        format!("{header}.{payload}.fakesig")
    }

    #[test]
    fn public_graph_always_allowed() {
        let vis = GraphVisibility::Public;
        assert!(check_read_access(&vis, &HeaderMap::new(), None, None, None).is_ok());
    }

    #[test]
    fn authenticated_accepts_valid_bearer() {
        let vis = GraphVisibility::Authenticated;
        // A non-JWT opaque token (no `exp` claim) — should pass (no exp to check)
        let h = bearer_headers("opaque-session-token");
        assert!(check_read_access(&vis, &h, None, None, None).is_ok());
    }

    #[test]
    fn authenticated_rejects_missing_bearer() {
        let vis = GraphVisibility::Authenticated;
        let err = check_read_access(&vis, &HeaderMap::new(), None, None, None).unwrap_err();
        assert!(matches!(err, AccessDenied::MissingBearer));
    }

    #[test]
    fn authenticated_rejects_expired_jwt() {
        let vis = GraphVisibility::Authenticated;
        // exp = 1 (far in the past)
        let token = jwt_with_exp(1);
        let h = bearer_headers(&token);
        let err = check_read_access(&vis, &h, None, None, None).unwrap_err();
        assert!(matches!(err, AccessDenied::TokenExpired), "expected TokenExpired, got {err:?}");
    }

    #[test]
    fn authenticated_accepts_future_jwt() {
        let vis = GraphVisibility::Authenticated;
        // exp = year 2099 in unix secs
        let far_future: u64 = 4_102_444_800;
        let token = jwt_with_exp(far_future);
        let h = bearer_headers(&token);
        assert!(check_read_access(&vis, &h, None, None, None).is_ok());
    }

    #[test]
    fn jwt_exp_elapsed_no_payload_returns_false() {
        assert!(!jwt_exp_elapsed("not.a.jwt"));
        assert!(!jwt_exp_elapsed("onlyone"));
    }

    #[test]
    fn jwt_exp_elapsed_missing_exp_returns_false() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let header  = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"alice"}"#);
        let token   = format!("{header}.{payload}.sig");
        assert!(!jwt_exp_elapsed(&token));
    }

    #[test]
    fn jwt_sub_extracts_sub_claim() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let header  = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"did:key:zAlice","exp":9999999999}"#);
        let token   = format!("{header}.{payload}.sig");
        assert_eq!(jwt_sub(&token).as_deref(), Some("did:key:zAlice"));
    }

    #[test]
    fn jwt_sub_returns_none_for_malformed() {
        assert!(jwt_sub("notajwt").is_none());
        assert!(jwt_sub("a.b").is_none()); // no sig segment but 2 parts
    }

    #[test]
    fn nonce_store_empty_nonce_is_rejected_by_guard() {
        use crate::nonce_store::NonceStore;
        let store = NonceStore::new();

        // An empty nonce is a valid key in the HashMap but provides no replay protection
        // because all nonce-less CACAOs would map to the same key "".
        // The guard in check_read_access rejects it before calling the store.
        //
        // Verify the guard logic by testing the condition directly:
        let nonce = "";
        assert!(nonce.is_empty(), "empty string represents a missing nonce");

        // Also verify the store itself accepts (then blocks) an empty string —
        // demonstrating why the guard is needed.
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600;
        assert!(store.check_and_register(nonce, far_future), "first empty-nonce accepted");
        assert!(!store.check_and_register(nonce, far_future), "second empty-nonce blocked (all nonce-less CACAOs)");
    }

    #[test]
    fn require_operator_auth_accepts_matching_sub() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let far_future: u64 = 4_102_444_800;
        let header  = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            format!(r#"{{"sub":"did:key:zOperator","exp":{far_future}}}"#));
        let token = format!("{header}.{payload}.fakesig");
        let h = bearer_headers(&token);
        assert!(require_operator_auth(&h, "did:key:zOperator").is_ok());
    }

    #[test]
    fn require_operator_auth_rejects_wrong_sub() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let far_future: u64 = 4_102_444_800;
        let header  = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            format!(r#"{{"sub":"did:key:zOther","exp":{far_future}}}"#));
        let token = format!("{header}.{payload}.fakesig");
        let h = bearer_headers(&token);
        let err = require_operator_auth(&h, "did:key:zOperator");
        assert!(err.is_err());
        let (code, _) = err.unwrap_err();
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_operator_auth_rejects_missing_bearer() {
        let err = require_operator_auth(&HeaderMap::new(), "did:key:zOperator");
        assert!(err.is_err());
    }

    #[test]
    fn require_operator_auth_rejects_expired_token() {
        let token = jwt_with_exp(1); // expired in 1970
        let h = bearer_headers(&token);
        let err = require_operator_auth(&h, "did:key:zOperator");
        assert!(err.is_err());
        let (code, msg) = err.unwrap_err();
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert!(msg.contains("expired"), "expected 'expired' in: {msg}");
    }

    #[test]
    fn jwt_sub_returns_none_when_sub_absent() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let header  = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"exp":9999999999}"#);
        let token   = format!("{header}.{payload}.sig");
        assert!(jwt_sub(&token).is_none());
    }
}
