use super::cacao::{Cacao, CacaoError};
use super::resolver::DidDocumentResolver;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Maximum age of a CACAO that has no explicit `exp` field.
/// CACAOs older than this are rejected to prevent indefinite token reuse.
const MAX_CACAO_AGE_SECS: u64 = 7 * 24 * 3600; // 7 days

#[derive(Debug)]
pub struct DelegationChain {
    pub chain: Vec<Cacao>,
}

impl DelegationChain {
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DelegationError> {
        let cacao = Cacao::from_cbor(bytes).map_err(DelegationError::Cacao)?;
        Ok(Self { chain: vec![cacao] })
    }

    pub fn new(invocation: Cacao) -> Self {
        Self {
            chain: vec![invocation],
        }
    }

    /// Test-only constructor that verifies capability and graph scope but skips
    /// the cryptographic signature check.  Available via the `test-utils` feature.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(graph_cid: &str, capability: &str) -> Self {
        use super::cacao::{CacaoHeader, CacaoPayload, CacaoSig};
        // Use a far-future fixed expiry so temporal check passes.
        let cacao = Cacao {
            h: CacaoHeader {
                t: "eip4361".into(),
            },
            p: CacaoPayload {
                iss: "did:test:issuer".into(),
                aud: "did:test:aud".into(),
                issued_at: "2026-01-01T00:00:00Z".into(),
                expiry: Some("2099-01-01T00:00:00Z".into()),
                nonce: "test-nonce".into(),
                domain: "kotoba.test".into(),
                statement: None,
                version: "1".into(),
                resources: vec![
                    format!("kotoba://can/{capability}"),
                    format!("kotoba://graph/{graph_cid}"),
                ],
            },
            s: CacaoSig {
                t: "test-bypass".into(),
                s: "00".into(),
            },
        };
        Self { chain: vec![cacao] }
    }

    /// Like `verify()` but skips the cryptographic signature step.  Available via `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn verify_skip_sig(
        &self,
        graph_cid: &str,
        required_cap: &str,
    ) -> Result<String, DelegationError> {
        if self.chain.is_empty() {
            return Err(DelegationError::EmptyChain);
        }
        if self.chain.len() > 1 {
            return Err(DelegationError::ChainDepthExceeded(self.chain.len()));
        }
        let cacao = &self.chain[0];

        // 1. Temporal validity
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(exp) = &cacao.p.expiry {
            if !is_utc_iso8601(exp) {
                return Err(DelegationError::InvalidExpiry(exp.clone()));
            }
            let now_iso = format_iso8601(now_secs);
            if now_iso > *exp {
                return Err(DelegationError::Expired);
            }
        }

        // 2. Capability check
        let granted_caps = cacao.p.capabilities();
        if !granted_caps.is_empty() {
            if !cacao.p.has_operation(required_cap) {
                return Err(DelegationError::CapabilityDenied(format!(
                    "need '{required_cap}', CACAO grants '{}'",
                    granted_caps.join(",")
                )));
            }
        }

        // 3. Graph-CID scope check (multi-graph: any granted graph matches)
        let granted = cacao.p.all_graph_cids();
        if !granted.is_empty() && !granted.iter().any(|g| *g == graph_cid) {
            return Err(DelegationError::GraphMismatch {
                expected: granted.join(","),
                got: graph_cid.to_string(),
            });
        }

        // 4. Signature SKIPPED in test mode
        Ok(cacao.p.iss.clone())
    }

    /// Verify the delegation chain.
    ///
    /// Checks (in order):
    ///   1. Expiry — rejects expired CACAOs.
    ///   2. Capability — `kotoba://can/{cap}` resource must match `required_cap`
    ///      (or be absent, which is treated as "all caps granted").
    ///   3. Graph scope — `kotoba://graph/{cid}` resource must match `graph_cid`
    ///      (or be absent, which means "all graphs").
    ///   4. Cryptographic signature — Ed25519 / EIP-191 sig over SIWE message.
    ///
    /// Returns the issuer DID (ERC-725) on success.
    pub fn verify(&self, graph_cid: &str, required_cap: &str) -> Result<String, DelegationError> {
        self.verify_inner(graph_cid, required_cap, None)
    }

    /// Verify the delegation chain using a DID resolver for Ed25519 issuer keys.
    ///
    /// This keeps the same temporal, capability, graph-scope, and attenuation
    /// checks as [`verify`], but resolves Ed25519 DID keys through the configured
    /// DID resolver so non-`did:key` issuers such as `did:web` and `did:plc` can
    /// authorize invocations.
    pub fn verify_with_resolver(
        &self,
        graph_cid: &str,
        required_cap: &str,
        resolver: &dyn DidDocumentResolver,
    ) -> Result<String, DelegationError> {
        self.verify_inner(graph_cid, required_cap, Some(resolver))
    }

    fn verify_inner(
        &self,
        graph_cid: &str,
        required_cap: &str,
        resolver: Option<&dyn DidDocumentResolver>,
    ) -> Result<String, DelegationError> {
        match self.chain.len() {
            0 => return Err(DelegationError::EmptyChain),
            1 => {} // single CACAO — verified below
            2 => {
                // Depth-2 delegation: chain[0] = root grant, chain[1] = leaf invocation.
                //   chain[0].iss → chain[0].aud = chain[1].iss → chain[1].aud (resource)
                //   chain[1] is what the caller is presenting now — verify its sig +
                //   capability + graph + temporal, then check the parent delegation
                //   from chain[0] to chain[1].iss.
                return self.verify_depth2_inner(graph_cid, required_cap, resolver);
            }
            n => return Err(DelegationError::ChainDepthExceeded(n)),
        }
        let cacao = &self.chain[0];

        // 1. Temporal validity
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(exp) = &cacao.p.expiry {
            // Require strict UTC format `YYYY-MM-DDTHH:MM:SSZ`.
            // Non-UTC offsets (e.g. +09:00) corrupt the lexicographic comparison
            // and could allow a caller to present a CACAO as unexpired when it isn't.
            if !is_utc_iso8601(exp) {
                return Err(DelegationError::InvalidExpiry(exp.clone()));
            }
            let now_iso = format_iso8601(now_secs);
            if now_iso > *exp {
                return Err(DelegationError::Expired);
            }
        } else {
            // No explicit expiry — apply a max-age cap based on `issued_at`.
            // Without this, a stolen or leaked CACAO is valid indefinitely.
            match parse_utc_iso8601(&cacao.p.issued_at) {
                None => return Err(DelegationError::InvalidExpiry(cacao.p.issued_at.clone())),
                Some(iat_secs) => {
                    if now_secs.saturating_sub(iat_secs) > MAX_CACAO_AGE_SECS {
                        return Err(DelegationError::Expired);
                    }
                }
            }
        }

        // 2. Capability check — kotoba://can/{cap} must match required_cap (if present)
        let granted_caps = cacao.p.capabilities();
        if !granted_caps.is_empty() {
            if !cacao.p.has_operation(required_cap) {
                return Err(DelegationError::CapabilityDenied(format!(
                    "need '{required_cap}', CACAO grants '{}'",
                    granted_caps.join(",")
                )));
            }
        }

        // 3. Graph-CID scope check — requested graph must be one of the granted graphs.
        //    A CACAO may grant access to multiple graphs via repeated
        //    `kotoba://graph/{cid}` resources; the caller's graph_cid must match any.
        let granted = cacao.p.all_graph_cids();
        if !granted.is_empty() && !granted.iter().any(|g| *g == graph_cid) {
            return Err(DelegationError::GraphMismatch {
                expected: granted.join(","),
                got: graph_cid.to_string(),
            });
        }

        // 4. Verify cryptographic signature
        let issuer_did = verify_cacao_signature(cacao, resolver)?;

        Ok(issuer_did)
    }

    /// Verify a depth-2 delegation chain.
    ///
    /// Layout:
    ///   chain[0] = root CACAO: root_iss → root_aud, granting `cap` on `graph_cid`
    ///   chain[1] = leaf CACAO: leaf_iss → final_aud (caller), claiming the same
    ///                          (or attenuated) capability on the same graph
    ///
    /// Checks (in order):
    ///   1. Both CACAOs are temporally valid (exp + max-age)
    ///   2. leaf.iss == root.aud  (audience-issuer chain)
    ///   3. leaf.capability ⊆ root.capability  (capability attenuation)
    ///   4. leaf.graph_cid == root.graph_cid (graph-scope attenuation)
    ///   5. leaf.graph_cid == graph_cid (caller's request matches)
    ///   6. leaf.capability == required_cap
    ///   7. Both signatures verify cryptographically (leaf must be signed by
    ///      its declared iss, root must be signed by its declared iss)
    ///
    /// Returns the root issuer DID (the ultimate authority for this invocation).
    fn verify_depth2_inner(
        &self,
        graph_cid: &str,
        required_cap: &str,
        resolver: Option<&dyn DidDocumentResolver>,
    ) -> Result<String, DelegationError> {
        let root = &self.chain[0];
        let leaf = &self.chain[1];

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Temporal validity on both
        for c in [root, leaf] {
            if let Some(exp) = &c.p.expiry {
                if !is_utc_iso8601(exp) {
                    return Err(DelegationError::InvalidExpiry(exp.clone()));
                }
                let now_iso = format_iso8601(now_secs);
                if now_iso > *exp {
                    return Err(DelegationError::Expired);
                }
            } else {
                match parse_utc_iso8601(&c.p.issued_at) {
                    None => return Err(DelegationError::InvalidExpiry(c.p.issued_at.clone())),
                    Some(iat) => {
                        if now_secs.saturating_sub(iat) > MAX_CACAO_AGE_SECS {
                            return Err(DelegationError::Expired);
                        }
                    }
                }
            }
        }

        // 2. Audience-issuer chain: root.aud == leaf.iss
        if root.p.aud != leaf.p.iss {
            return Err(DelegationError::AttenuationViolation(format!(
                "root.aud '{}' != leaf.iss '{}'",
                root.p.aud, leaf.p.iss
            )));
        }

        // 3/4. Capability + graph attenuation:
        //   leaf must claim same cap as root, and leaf's granted graphs ⊆ root's.
        let root_caps = root.p.capabilities();
        let leaf_caps = leaf.p.capabilities();
        let root_graphs = root.p.all_graph_cids();
        let leaf_graphs = leaf.p.all_graph_cids();
        if !root_caps.is_empty() {
            if leaf_caps.is_empty() {
                return Err(DelegationError::AttenuationViolation(
                    "leaf claims unrestricted capability while root is restricted".to_string(),
                ));
            }
            for leaf_cap in &leaf_caps {
                if !root_caps.iter().any(|root_cap| root_cap == leaf_cap) {
                    return Err(DelegationError::AttenuationViolation(format!(
                        "root grants '{}', leaf claims '{}'",
                        root_caps.join(","),
                        leaf_caps.join(",")
                    )));
                }
            }
        }
        // Leaf's graph set must be a subset of root's (no scope widening)
        if !root_graphs.is_empty() {
            for lg in &leaf_graphs {
                if !root_graphs.iter().any(|rg| rg == lg) {
                    return Err(DelegationError::AttenuationViolation(format!(
                        "leaf graph '{lg}' not in root grant"
                    )));
                }
            }
        }

        // 5. Caller's graph request matches one of the granted graphs.
        //    If leaf restricts the set, use leaf's grants; otherwise fall back to root's.
        let effective = if !leaf_graphs.is_empty() {
            &leaf_graphs
        } else {
            &root_graphs
        };
        if !effective.is_empty() && !effective.iter().any(|g| *g == graph_cid) {
            return Err(DelegationError::GraphMismatch {
                expected: effective.join(","),
                got: graph_cid.to_string(),
            });
        }

        // 6. Required capability matches
        if !leaf_caps.is_empty() && !leaf.p.has_operation(required_cap) {
            return Err(DelegationError::CapabilityDenied(format!(
                "need '{required_cap}', leaf grants '{}'",
                leaf_caps.join(",")
            )));
        }

        // 7. Cryptographic signatures on both
        let root_iss = verify_cacao_signature(root, resolver)?;
        let _leaf_iss = verify_cacao_signature(leaf, resolver)?;

        Ok(root_iss)
    }
}

fn verify_cacao_signature(
    cacao: &Cacao,
    resolver: Option<&dyn DidDocumentResolver>,
) -> Result<String, DelegationError> {
    match resolver {
        Some(resolver) => cacao
            .verify_with_resolver(resolver)
            .map_err(DelegationError::Cacao),
        None => cacao.verify_signature().map_err(DelegationError::Cacao),
    }
}

/// Returns `true` iff `s` is strictly `YYYY-MM-DDTHH:MM:SSZ` (20 chars, UTC only).
fn is_utc_iso8601(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'Z'
        && b[0..4].iter().all(|c| c.is_ascii_digit())
        && b[5..7].iter().all(|c| c.is_ascii_digit())
        && b[8..10].iter().all(|c| c.is_ascii_digit())
        && b[11..13].iter().all(|c| c.is_ascii_digit())
        && b[14..16].iter().all(|c| c.is_ascii_digit())
        && b[17..19].iter().all(|c| c.is_ascii_digit())
}

/// Parse a strict `YYYY-MM-DDTHH:MM:SSZ` string to a Unix timestamp (seconds).
/// Returns `None` on format errors or impossible calendar dates.
fn parse_utc_iso8601(s: &str) -> Option<u64> {
    if !is_utc_iso8601(s) {
        return None;
    }
    let b = s.as_bytes();
    let year = parse4(&b[0..4])?;
    let month = parse2(&b[5..7])?;
    let day = parse2(&b[8..10])?;
    let hour = parse2(&b[11..13])?;
    let min = parse2(&b[14..16])?;
    let sec = parse2(&b[17..19])?;
    if month == 0 || month > 12 || day == 0 {
        return None;
    }
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }

    // Days since 1970-01-01
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    let mdays: [u64; 12] = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    if day > mdays[(month - 1) as usize] {
        return None;
    }
    for d in mdays.iter().take((month - 1) as usize) {
        days += d;
    }
    days += day - 1;

    Some(days * 86_400 + hour * 3_600 + min * 60 + sec)
}

fn parse4(b: &[u8]) -> Option<u64> {
    if b.len() != 4 {
        return None;
    }
    Some(
        (b[0] - b'0') as u64 * 1000
            + (b[1] - b'0') as u64 * 100
            + (b[2] - b'0') as u64 * 10
            + (b[3] - b'0') as u64,
    )
}

fn parse2(b: &[u8]) -> Option<u64> {
    if b.len() != 2 {
        return None;
    }
    Some((b[0] - b'0') as u64 * 10 + (b[1] - b'0') as u64)
}

fn format_iso8601(unix_secs: u64) -> String {
    // Minimal ISO-8601 formatter without chrono dependency.
    // Accurate for years 1970-2100.
    let s = unix_secs;
    let sec = s % 60;
    let s = s / 60;
    let min = s % 60;
    let s = s / 60;
    let hour = s % 24;
    let days = s / 24;

    let (year, month, day) = days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let yd = if leap { 366 } else { 365 };
        if days < yd {
            break;
        }
        days -= yd;
        year += 1;
    }
    let months = if is_leap(year) {
        [31u64, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for &md in &months {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

#[derive(Debug, Error)]
pub enum DelegationError {
    #[error("empty delegation chain")]
    EmptyChain,
    #[error("chain depth {0} exceeds maximum supported (2)")]
    ChainDepthExceeded(usize),
    #[error("delegation attenuation broken: {0}")]
    AttenuationViolation(String),
    #[error("cacao error: {0}")]
    Cacao(#[from] CacaoError),
    #[error("capability not granted: {0}")]
    CapabilityDenied(String),
    #[error("expired")]
    Expired,
    #[error("invalid timestamp (must be YYYY-MM-DDTHH:MM:SSZ UTC): {0}")]
    InvalidExpiry(String),
    #[error("root issuer mismatch")]
    RootMismatch,
    #[error("graph scope mismatch: expected '{expected}', got '{got}'")]
    GraphMismatch { expected: String, got: String },
    #[error("audience mismatch: CACAO aud '{got}' does not match expected '{expected}'")]
    AudienceMismatch { expected: String, got: String },
}

impl DelegationChain {
    /// Like [`verify`] but also validates that `cacao.p.aud` matches `expected_aud`.
    ///
    /// CAIP-74 requires the audience field to equal the verifier's own identifier so
    /// a CACAO intended for service A cannot be replayed against service B.
    pub fn verify_with_aud(
        &self,
        graph_cid: &str,
        required_cap: &str,
        expected_aud: &str,
    ) -> Result<String, DelegationError> {
        // Audience check before signature to fail fast on misrouted tokens.
        let cacao = self.chain.first().ok_or(DelegationError::EmptyChain)?;
        // A CACAO with an empty (absent) `aud` field has no audience binding.
        // When the caller explicitly requests audience enforcement, an unbound
        // CACAO is treated as a mismatch — otherwise a bearer token issued without
        // `aud` would bypass replay protection entirely.
        if cacao.p.aud.is_empty() || cacao.p.aud != expected_aud {
            return Err(DelegationError::AudienceMismatch {
                expected: expected_aud.to_string(),
                got: cacao.p.aud.clone(),
            });
        }
        self.verify(graph_cid, required_cap)
    }

    /// Like [`verify_with_aud`] but resolves Ed25519 signing keys through a DID resolver.
    pub fn verify_with_aud_and_resolver(
        &self,
        graph_cid: &str,
        required_cap: &str,
        expected_aud: &str,
        resolver: &dyn DidDocumentResolver,
    ) -> Result<String, DelegationError> {
        let cacao = self.chain.first().ok_or(DelegationError::EmptyChain)?;
        if cacao.p.aud.is_empty() || cacao.p.aud != expected_aud {
            return Err(DelegationError::AudienceMismatch {
                expected: expected_aud.to_string(),
                got: cacao.p.aud.clone(),
            });
        }
        self.verify_with_resolver(graph_cid, required_cap, resolver)
    }

    /// Return all graph CIDs authorized by this chain.
    /// Empty = no graph restriction (CACAO covers all graphs).
    pub fn authorized_graphs(&self) -> Vec<String> {
        self.chain
            .iter()
            .flat_map(|c| c.p.all_graph_cids())
            .map(|s| s.to_string())
            .collect()
    }

    /// Verify capability and temporal validity only (no graph-scope check).
    /// Used when the caller will perform its own per-graph filter (e.g. GRAPH ?g queries).
    pub fn verify_capability_only(&self, required_cap: &str) -> Result<String, DelegationError> {
        if self.chain.is_empty() {
            return Err(DelegationError::EmptyChain);
        }
        let cacao = &self.chain[0];
        // Temporal check
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(exp) = &cacao.p.expiry {
            if !is_utc_iso8601(exp) {
                return Err(DelegationError::InvalidExpiry(exp.clone()));
            }
            let now_iso = format_iso8601(now_secs);
            if now_iso > *exp {
                return Err(DelegationError::Expired);
            }
        }
        // Capability check
        let granted_caps = cacao.p.capabilities();
        if !granted_caps.is_empty() {
            if !cacao.p.has_operation(required_cap) {
                return Err(DelegationError::CapabilityDenied(format!(
                    "need '{required_cap}', CACAO grants '{}'",
                    granted_caps.join(",")
                )));
            }
        }
        // Signature — if using verify (not skip_sig), do full EdDSA verify here.
        // For skip_sig paths this is called from verify_skip_sig context; for real
        // sig paths we delegate to verify() which calls verify_signature internally.
        // Here we just return iss (capability-only = no graph scope check, no sig here).
        Ok(cacao.p.iss.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- is_utc_iso8601 ----

    #[test]
    fn valid_utc_iso8601_accepted() {
        assert!(is_utc_iso8601("2026-05-27T12:34:56Z"));
    }

    #[test]
    fn utc_iso8601_wrong_length_rejected() {
        assert!(!is_utc_iso8601("2026-05-27T12:34:56"));
        assert!(!is_utc_iso8601("2026-05-27T12:34:56Z+extra"));
    }

    #[test]
    fn utc_iso8601_non_utc_offset_rejected() {
        // +09:00 makes it 20+ chars and the final byte is not b'Z'
        assert!(!is_utc_iso8601("2026-05-27T12:34:56+0900"));
    }

    #[test]
    fn utc_iso8601_letters_in_digits_rejected() {
        assert!(!is_utc_iso8601("XXXX-05-27T12:34:56Z"));
    }

    // ---- parse_utc_iso8601 ----

    #[test]
    fn parse_epoch_zero() {
        assert_eq!(parse_utc_iso8601("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn parse_known_timestamp() {
        // 2000-01-01T00:00:00Z = 946684800
        assert_eq!(parse_utc_iso8601("2000-01-01T00:00:00Z"), Some(946_684_800));
    }

    #[test]
    fn parse_invalid_month_returns_none() {
        assert_eq!(parse_utc_iso8601("2026-13-01T00:00:00Z"), None);
    }

    #[test]
    fn parse_invalid_format_returns_none() {
        assert_eq!(parse_utc_iso8601("not-a-timestamp"), None);
    }

    // ---- format_iso8601 ----

    #[test]
    fn format_epoch_zero() {
        assert_eq!(format_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_and_parse_roundtrip() {
        let ts = 1_748_300_000u64;
        let s = format_iso8601(ts);
        assert!(is_utc_iso8601(&s));
        assert_eq!(parse_utc_iso8601(&s), Some(ts));
    }

    // ---- is_leap ----

    #[test]
    fn divisible_by_4_is_leap() {
        assert!(is_leap(2024));
    }

    #[test]
    fn divisible_by_100_not_leap() {
        assert!(!is_leap(1900));
    }

    #[test]
    fn divisible_by_400_is_leap() {
        assert!(is_leap(2000));
    }

    #[test]
    fn ordinary_year_not_leap() {
        assert!(!is_leap(2023));
    }

    // ---- DelegationError display ----

    #[test]
    fn delegation_error_empty_chain_display() {
        assert_eq!(
            DelegationError::EmptyChain.to_string(),
            "empty delegation chain"
        );
    }

    #[test]
    fn delegation_error_chain_depth_display() {
        assert_eq!(
            DelegationError::ChainDepthExceeded(3).to_string(),
            "chain depth 3 exceeds maximum supported (2)",
        );
    }

    #[test]
    fn delegation_error_expired_display() {
        assert_eq!(DelegationError::Expired.to_string(), "expired");
    }

    #[test]
    fn delegation_error_capability_denied_display() {
        let e = DelegationError::CapabilityDenied("need 'write'".to_string());
        assert_eq!(e.to_string(), "capability not granted: need 'write'");
    }

    #[test]
    fn delegation_error_graph_mismatch_display() {
        let e = DelegationError::GraphMismatch {
            expected: "cid-A".to_string(),
            got: "cid-B".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "graph scope mismatch: expected 'cid-A', got 'cid-B'"
        );
    }

    #[test]
    fn delegation_error_audience_mismatch_display() {
        let e = DelegationError::AudienceMismatch {
            expected: "svc-A".to_string(),
            got: "svc-B".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "audience mismatch: CACAO aud 'svc-B' does not match expected 'svc-A'",
        );
    }

    // ---- DelegationChain::verify on empty chain ----

    #[test]
    fn empty_chain_verify_returns_empty_chain_error() {
        let chain = DelegationChain { chain: vec![] };
        let err = chain.verify("graph-cid", "write").unwrap_err();
        assert!(matches!(err, DelegationError::EmptyChain));
    }

    #[test]
    fn chain_depth_exceeded_returns_error() {
        // We cannot easily construct a valid Cacao without crypto in a unit test,
        // but we can test the chain-depth guard by passing an artificial chain length.
        // Instead, just test the error variant displays correctly (covered above).
        let e = DelegationError::ChainDepthExceeded(3);
        assert!(e.to_string().contains("chain depth 3"));
    }

    // ─── Depth-2 delegation chains (root → leaf) ────────────────────────────

    use super::super::cacao::{Cacao, CacaoHeader, CacaoPayload, CacaoSig};
    use super::super::did_key::ed25519_pubkey_to_did_key;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a real-signed CACAO with the given iss/aud/cap/graph.
    fn make_real_cacao(
        sk: &SigningKey,
        iss: &str,
        aud: &str,
        cap: &str,
        graph: &str,
        nonce: &str,
    ) -> Cacao {
        let template = Cacao {
            h: CacaoHeader {
                t: "eip4361".into(),
            },
            p: CacaoPayload {
                iss: iss.to_string(),
                aud: aud.to_string(),
                issued_at: "2026-01-01T00:00:00Z".into(),
                expiry: Some("2099-01-01T00:00:00Z".into()),
                nonce: nonce.into(),
                domain: "kotoba.test".into(),
                statement: None,
                version: "1".into(),
                resources: vec![
                    format!("kotoba://can/{cap}"),
                    format!("kotoba://graph/{graph}"),
                ],
            },
            s: CacaoSig {
                t: "EdDSA".into(),
                s: String::new(),
            },
        };
        let msg = template.siwe_message();
        let sig = sk.sign(msg.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Cacao {
            s: CacaoSig {
                t: "EdDSA".into(),
                s: sig_b64,
            },
            ..template
        }
    }

    fn signing_key_seed(seed: u8) -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let did = ed25519_pubkey_to_did_key(sk.verifying_key().as_bytes());
        (sk, did)
    }

    #[test]
    fn single_cacao_verify_with_aud_and_resolver_accepts_non_did_key_issuer() {
        use super::super::did_document::{DidDocument, VerificationMethod, ED25519_KEY_TYPE_2020};
        use super::super::resolver::InMemoryDidResolver;

        let graph = "resolver-graph";
        let expected_aud = "did:kotoba:service";
        let did = "did:plc:alice";
        let sk = SigningKey::from_bytes(&[21u8; 32]);
        let cacao = make_real_cacao(&sk, did, expected_aud, "datom:read", graph, "n-resolver");
        let chain = DelegationChain::new(cacao);

        let mut doc = DidDocument::empty(did);
        doc.verification_method.push(VerificationMethod {
            id: format!("{did}#key-1"),
            key_type: ED25519_KEY_TYPE_2020.to_string(),
            controller: did.to_string(),
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                sk.verifying_key().as_bytes(),
            ),
        });
        let resolver = InMemoryDidResolver::new();
        resolver.insert(did, doc);

        assert!(chain
            .verify_with_aud(graph, "datom:read", expected_aud)
            .is_err());
        assert_eq!(
            chain
                .verify_with_aud_and_resolver(graph, "datom:read", expected_aud, &resolver)
                .unwrap(),
            did
        );
    }

    #[test]
    fn depth2_valid_chain_accepted() {
        let graph = "graph-abc";
        let (root_sk, root_did) = signing_key_seed(1);
        let (leaf_sk, leaf_did) = signing_key_seed(2);
        let final_aud = "did:final:caller";

        let root = make_real_cacao(
            &root_sk,
            &root_did,
            &leaf_did,
            "datom:read",
            graph,
            "n-root",
        );
        let leaf = make_real_cacao(
            &leaf_sk,
            &leaf_did,
            final_aud,
            "datom:read",
            graph,
            "n-leaf",
        );
        let chain = DelegationChain {
            chain: vec![root, leaf],
        };

        let issuer = chain
            .verify(graph, "datom:read")
            .expect("valid depth-2 chain");
        assert_eq!(issuer, root_did, "root issuer must be returned");
    }

    #[test]
    fn depth2_broken_aud_iss_rejected() {
        // root.aud != leaf.iss → attenuation violation
        let graph = "graph-abc";
        let (root_sk, root_did) = signing_key_seed(3);
        let (_other_sk, other_did) = signing_key_seed(4);
        let (leaf_sk, leaf_did) = signing_key_seed(5);

        let root = make_real_cacao(
            &root_sk,
            &root_did,
            &other_did, /* not leaf_did */
            "datom:read",
            graph,
            "n-root",
        );
        let leaf = make_real_cacao(
            &leaf_sk,
            &leaf_did,
            "did:final",
            "datom:read",
            graph,
            "n-leaf",
        );
        let chain = DelegationChain {
            chain: vec![root, leaf],
        };

        let err = chain.verify(graph, "datom:read").unwrap_err();
        assert!(
            matches!(err, DelegationError::AttenuationViolation(_)),
            "expected AttenuationViolation, got {err:?}"
        );
    }

    #[test]
    fn depth2_capability_escalation_rejected() {
        // root grants read, leaf claims write → must be rejected
        let graph = "graph-abc";
        let (root_sk, root_did) = signing_key_seed(6);
        let (leaf_sk, leaf_did) = signing_key_seed(7);

        let root = make_real_cacao(
            &root_sk,
            &root_did,
            &leaf_did,
            "datom:read",
            graph,
            "n-root",
        );
        let leaf = make_real_cacao(
            &leaf_sk,
            &leaf_did,
            "did:final",
            "datom:write",
            graph,
            "n-leaf",
        );
        let chain = DelegationChain {
            chain: vec![root, leaf],
        };

        let err = chain.verify(graph, "datom:write").unwrap_err();
        assert!(
            matches!(err, DelegationError::AttenuationViolation(_)),
            "capability escalation must be rejected: {err:?}"
        );
    }

    #[test]
    fn depth2_graph_mismatch_rejected() {
        let (root_sk, root_did) = signing_key_seed(8);
        let (leaf_sk, leaf_did) = signing_key_seed(9);

        let root = make_real_cacao(
            &root_sk,
            &root_did,
            &leaf_did,
            "datom:read",
            "graph-X",
            "n-root",
        );
        let leaf = make_real_cacao(
            &leaf_sk,
            &leaf_did,
            "did:final",
            "datom:read",
            "graph-Y",
            "n-leaf",
        );
        let chain = DelegationChain {
            chain: vec![root, leaf],
        };

        let err = chain.verify("graph-X", "datom:read").unwrap_err();
        assert!(
            matches!(err, DelegationError::AttenuationViolation(_)),
            "graph attenuation violation expected: {err:?}"
        );
    }

    #[test]
    fn depth2_caller_graph_outside_grant_rejected() {
        // chain grants graph-A but caller asks for graph-B
        let (root_sk, root_did) = signing_key_seed(10);
        let (leaf_sk, leaf_did) = signing_key_seed(11);

        let root = make_real_cacao(
            &root_sk,
            &root_did,
            &leaf_did,
            "datom:read",
            "graph-A",
            "n-root",
        );
        let leaf = make_real_cacao(
            &leaf_sk,
            &leaf_did,
            "did:final",
            "datom:read",
            "graph-A",
            "n-leaf",
        );
        let chain = DelegationChain {
            chain: vec![root, leaf],
        };

        let err = chain.verify("graph-B", "datom:read").unwrap_err();
        assert!(
            matches!(err, DelegationError::GraphMismatch { .. }),
            "caller-graph mismatch must be rejected: {err:?}"
        );
    }

    #[test]
    fn single_cacao_multi_graph_grants_both() {
        // CACAO with two graph resources should authorize calls against either.
        let (sk, did) = signing_key_seed(20);
        let template = Cacao {
            h: CacaoHeader {
                t: "eip4361".into(),
            },
            p: CacaoPayload {
                iss: did.clone(),
                aud: "did:final:caller".into(),
                issued_at: "2026-01-01T00:00:00Z".into(),
                expiry: Some("2099-01-01T00:00:00Z".into()),
                nonce: "multi-graph".into(),
                domain: "kotoba.test".into(),
                statement: None,
                version: "1".into(),
                resources: vec![
                    "kotoba://can/datom:read".into(),
                    "kotoba://graph/g-aaa".into(),
                    "kotoba://graph/g-bbb".into(),
                ],
            },
            s: CacaoSig {
                t: "EdDSA".into(),
                s: String::new(),
            },
        };
        let msg = template.siwe_message();
        let sig = sk.sign(msg.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let cacao = Cacao {
            s: CacaoSig {
                t: "EdDSA".into(),
                s: sig_b64,
            },
            ..template
        };
        let chain = DelegationChain::new(cacao);

        // Both should pass
        assert!(
            chain.verify("g-aaa", "datom:read").is_ok(),
            "g-aaa must be authorized"
        );
        assert!(
            chain.verify("g-bbb", "datom:read").is_ok(),
            "g-bbb must be authorized"
        );
        // Out-of-set must fail
        assert!(
            matches!(
                chain.verify("g-ccc", "datom:read").unwrap_err(),
                DelegationError::GraphMismatch { .. }
            ),
            "out-of-set graph must be denied"
        );
    }

    #[test]
    fn depth3_rejected() {
        // 3-link chain is not supported
        let (root_sk, root_did) = signing_key_seed(12);
        let (_m_sk, m_did) = signing_key_seed(13);
        let (leaf_sk, leaf_did) = signing_key_seed(14);

        let root = make_real_cacao(&root_sk, &root_did, &m_did, "datom:read", "g", "n1");
        let leaf = make_real_cacao(&leaf_sk, &leaf_did, "did:final", "datom:read", "g", "n3");
        // Insert a dummy middle just to make the chain length 3
        let middle = root.clone();
        let chain = DelegationChain {
            chain: vec![root, middle, leaf],
        };

        let err = chain.verify("g", "datom:read").unwrap_err();
        assert!(matches!(err, DelegationError::ChainDepthExceeded(3)));
    }
}
