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
        }
    }
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
pub fn check_read_access(
    visibility: &GraphVisibility,
    headers: &HeaderMap,
    cacao_b64: Option<&str>,
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
                Ok(())
            } else {
                Err(AccessDenied::MissingBearer)
            }
        }

        GraphVisibility::Private { owner_did } => {
            let b64 = cacao_b64.ok_or(AccessDenied::MissingCacao)?;

            // 1. Decode base64
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
            let issuer_did = chain
                .verify(&graph_scope, "quad:read")
                .map_err(|e| AccessDenied::DelegationError(e.to_string()))?;

            // 4. The recovered issuer must be the graph owner (security invariant:
            //    only the owner themselves may delegate read access to a private graph).
            if &issuer_did != owner_did {
                return Err(AccessDenied::IssuerMismatch {
                    expected: owner_did.clone(),
                    got:      issuer_did,
                });
            }

            Ok(())
        }
    }
}
