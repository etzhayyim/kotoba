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
    for m in 0..(month - 1) as usize { days += mdays[m]; }
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
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
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
}
