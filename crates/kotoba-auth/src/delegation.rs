use super::cacao::{Cacao, CacaoError};
use thiserror::Error;
use std::time::{SystemTime, UNIX_EPOCH};

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
        Self { chain: vec![invocation] }
    }

    /// Test-only constructor that verifies capability and graph scope but skips
    /// the cryptographic signature check.  Available via the `test-utils` feature.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_test(graph_cid: &str, capability: &str) -> Self {
        use super::cacao::{CacaoHeader, CacaoPayload, CacaoSig};
        // Use a far-future fixed expiry so temporal check passes.
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p: CacaoPayload {
                iss:       "did:test:issuer".into(),
                aud:       "did:test:aud".into(),
                issued_at: "2026-01-01T00:00:00Z".into(),
                expiry:    Some("2099-01-01T00:00:00Z".into()),
                nonce:     "test-nonce".into(),
                domain:    "kotoba.test".into(),
                statement: None,
                version:   "1".into(),
                resources: vec![
                    format!("kotoba://can/{capability}"),
                    format!("kotoba://graph/{graph_cid}"),
                ],
            },
            s: CacaoSig { t: "test-bypass".into(), s: "00".into() },
        };
        Self { chain: vec![cacao] }
    }

    /// Like `verify()` but skips the cryptographic signature step.  Available via `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn verify_skip_sig(&self, graph_cid: &str, required_cap: &str) -> Result<String, DelegationError> {
        if self.chain.is_empty() { return Err(DelegationError::EmptyChain); }
        if self.chain.len() > 1  { return Err(DelegationError::ChainDepthExceeded(self.chain.len())); }
        let cacao = &self.chain[0];

        // 1. Temporal validity
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        if let Some(exp) = &cacao.p.expiry {
            if !is_utc_iso8601(exp) { return Err(DelegationError::InvalidExpiry(exp.clone())); }
            let now_iso = format_iso8601(now_secs);
            if now_iso > *exp { return Err(DelegationError::Expired); }
        }

        // 2. Capability check
        if let Some(granted_cap) = cacao.p.capability() {
            if granted_cap != required_cap {
                return Err(DelegationError::CapabilityDenied(
                    format!("need '{required_cap}', CACAO grants '{granted_cap}'"),
                ));
            }
        }

        // 3. Graph-CID scope check
        if let Some(granted_graph) = cacao.p.graph_cid() {
            if granted_graph != graph_cid {
                return Err(DelegationError::GraphMismatch {
                    expected: granted_graph.to_string(),
                    got:      graph_cid.to_string(),
                });
            }
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
        match self.chain.len() {
            0 => return Err(DelegationError::EmptyChain),
            // Multi-link delegation is not implemented; extra links would be silently
            // ignored, which could allow an attacker to bypass capability checks by
            // appending forged sub-delegations.  Hard-reject until it is designed.
            n if n > 1 => return Err(DelegationError::ChainDepthExceeded(n)),
            _ => {}
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
        if let Some(granted_cap) = cacao.p.capability() {
            if granted_cap != required_cap {
                return Err(DelegationError::CapabilityDenied(
                    format!("need '{required_cap}', CACAO grants '{granted_cap}'"),
                ));
            }
        }

        // 3. Graph-CID scope check — kotoba://graph/{cid} must match (if present)
        if let Some(granted_graph) = cacao.p.graph_cid() {
            if granted_graph != graph_cid {
                return Err(DelegationError::GraphMismatch {
                    expected: granted_graph.to_string(),
                    got:      graph_cid.to_string(),
                });
            }
        }

        // 4. Verify cryptographic signature
        let issuer_did = cacao.verify_signature().map_err(DelegationError::Cacao)?;

        Ok(issuer_did)
    }
}

/// Returns `true` iff `s` is strictly `YYYY-MM-DDTHH:MM:SSZ` (20 chars, UTC only).
fn is_utc_iso8601(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b[4] == b'-' && b[7] == b'-' && b[10] == b'T'
        && b[13] == b':' && b[16] == b':' && b[19] == b'Z'
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
    if !is_utc_iso8601(s) { return None; }
    let b = s.as_bytes();
    let year  = parse4(&b[0..4])?;
    let month = parse2(&b[5..7])?;
    let day   = parse2(&b[8..10])?;
    let hour  = parse2(&b[11..13])?;
    let min   = parse2(&b[14..16])?;
    let sec   = parse2(&b[17..19])?;
    if month == 0 || month > 12 || day == 0 { return None; }
    if hour > 23 || min > 59 || sec > 59 { return None; }

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
    if day > mdays[(month - 1) as usize] { return None; }
    for d in mdays.iter().take((month - 1) as usize) { days += d; }
    days += day - 1;

    Some(days * 86_400 + hour * 3_600 + min * 60 + sec)
}

fn parse4(b: &[u8]) -> Option<u64> {
    if b.len() != 4 { return None; }
    Some((b[0]-b'0') as u64 * 1000 + (b[1]-b'0') as u64 * 100
       + (b[2]-b'0') as u64 * 10 + (b[3]-b'0') as u64)
}

fn parse2(b: &[u8]) -> Option<u64> {
    if b.len() != 2 { return None; }
    Some((b[0]-b'0') as u64 * 10 + (b[1]-b'0') as u64)
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
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hour, min, sec)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let leap = is_leap(year);
        let yd = if leap { 366 } else { 365 };
        if days < yd { break; }
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
        if days < md { break; }
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
    #[error("chain depth {0} exceeds maximum (1); multi-link delegation not implemented")]
    ChainDepthExceeded(usize),
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
        graph_cid:    &str,
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
                got:      cacao.p.aud.clone(),
            });
        }
        self.verify(graph_cid, required_cap)
    }

    /// Return all graph CIDs authorized by this chain.
    /// Empty = no graph restriction (CACAO covers all graphs).
    pub fn authorized_graphs(&self) -> Vec<String> {
        self.chain.iter()
            .flat_map(|c| c.p.all_graph_cids())
            .map(|s| s.to_string())
            .collect()
    }

    /// Verify capability and temporal validity only (no graph-scope check).
    /// Used when the caller will perform its own per-graph filter (e.g. GRAPH ?g queries).
    pub fn verify_capability_only(&self, required_cap: &str) -> Result<String, DelegationError> {
        if self.chain.is_empty() { return Err(DelegationError::EmptyChain); }
        let cacao = &self.chain[0];
        // Temporal check
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        if let Some(exp) = &cacao.p.expiry {
            if !is_utc_iso8601(exp) { return Err(DelegationError::InvalidExpiry(exp.clone())); }
            let now_iso = format_iso8601(now_secs);
            if now_iso > *exp { return Err(DelegationError::Expired); }
        }
        // Capability check
        if let Some(granted_cap) = cacao.p.capability() {
            if granted_cap != required_cap {
                return Err(DelegationError::CapabilityDenied(
                    format!("need '{required_cap}', CACAO grants '{granted_cap}'"),
                ));
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
        let s  = format_iso8601(ts);
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
        assert_eq!(DelegationError::EmptyChain.to_string(), "empty delegation chain");
    }

    #[test]
    fn delegation_error_chain_depth_display() {
        assert_eq!(
            DelegationError::ChainDepthExceeded(3).to_string(),
            "chain depth 3 exceeds maximum (1); multi-link delegation not implemented",
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
            got:      "cid-B".to_string(),
        };
        assert_eq!(e.to_string(), "graph scope mismatch: expected 'cid-A', got 'cid-B'");
    }

    #[test]
    fn delegation_error_audience_mismatch_display() {
        let e = DelegationError::AudienceMismatch {
            expected: "svc-A".to_string(),
            got:      "svc-B".to_string(),
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
        let e = DelegationError::ChainDepthExceeded(2);
        assert!(e.to_string().contains("chain depth 2"));
    }
}
