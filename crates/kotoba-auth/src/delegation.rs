use super::cacao::{Cacao, CacaoError};
use thiserror::Error;
use std::time::{SystemTime, UNIX_EPOCH};

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
        if self.chain.is_empty() {
            return Err(DelegationError::EmptyChain);
        }
        let cacao = &self.chain[0];

        // 1. Check expiry
        if let Some(exp) = &cacao.p.expiry {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // exp format: "2025-01-01T00:00:00Z" — lexicographic comparison is correct for UTC
            let now_iso = format_iso8601(now_secs);
            if now_iso > *exp {
                return Err(DelegationError::Expired);
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
    #[error("cacao error: {0}")]
    Cacao(#[from] CacaoError),
    #[error("capability not granted: {0}")]
    CapabilityDenied(String),
    #[error("expired")]
    Expired,
    #[error("root issuer mismatch")]
    RootMismatch,
    #[error("graph scope mismatch: expected '{expected}', got '{got}'")]
    GraphMismatch { expected: String, got: String },
}
