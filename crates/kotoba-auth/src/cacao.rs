use serde::{Deserialize, Serialize};
use thiserror::Error;
use super::eth;
use super::did_key;

#[derive(Debug, Error)]
pub enum CacaoError {
    #[error("cbor parse: {0}")]
    ParseError(String),
    #[error("unsupported sig type: {0}")]
    UnsupportedSigType(String),
    #[error("eth sig error: {0}")]
    EthSig(#[from] eth::EthError),
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("address mismatch: expected {expected}, got {got}")]
    AddressMismatch { expected: String, got: String },
    #[error("did:key parse error: {0}")]
    DidKeyParse(String),
    #[error("ed25519 verification error: {0}")]
    Ed25519(String),
}

/// CACAO — Chain Agnostic Capability Authorization Object (CAIP-74)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cacao {
    pub h: CacaoHeader,
    pub p: CacaoPayload,
    pub s: CacaoSig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacaoHeader {
    /// "eip4361" | "caip122"
    pub t: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacaoPayload {
    /// Issuer DID (did:pkh:eip155:N:0x... or did:erc725:...)
    pub iss: String,
    /// Audience (this Kotoba node's DID or URI)
    pub aud: String,
    #[serde(rename = "iat")]
    pub issued_at: String,
    #[serde(rename = "exp")]
    pub expiry: Option<String>,
    pub nonce: String,
    /// Requesting domain (e.g. "kotoba.example.com")
    #[serde(default)]
    pub domain: String,
    /// EIP-4361 optional statement
    #[serde(default)]
    pub statement: Option<String>,
    /// Message version (default "1")
    #[serde(default = "default_version")]
    pub version: String,
    /// Capability resources as URIs
    #[serde(default)]
    pub resources: Vec<String>,
}

fn default_version() -> String { "1".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacaoSig {
    /// "eip191" | "EdDSA"
    pub t: String,
    pub s: String, // hex (with or without 0x prefix) or base64
}

impl Cacao {
    /// Parse CACAO from DAG-CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CacaoError> {
        ciborium::from_reader(bytes)
            .map_err(|e| CacaoError::ParseError(e.to_string()))
    }

    /// Reconstruct the EIP-4361 plaintext message that was signed.
    pub fn siwe_message(&self) -> String {
        let p = &self.p;
        // Extract address from iss (last colon-separated segment)
        let address = p.iss.split(':').last().unwrap_or(&p.iss);
        // Extract chain id: did:pkh:eip155:N:0x... → "N"; did:key → "1" (CAIP-122 default)
        let chain_id = if p.iss.starts_with("did:key:") {
            "1"
        } else {
            p.iss.split(':').rev().nth(1).unwrap_or("1")
        };

        let mut lines = Vec::new();
        lines.push(format!("{} wants you to sign in with your Ethereum account:", p.domain));
        lines.push(address.to_string());
        lines.push(String::new());
        if let Some(stmt) = &p.statement {
            lines.push(stmt.clone());
            lines.push(String::new());
        }
        lines.push(format!("URI: {}", p.aud));
        lines.push(format!("Version: {}", p.version));
        lines.push(format!("Chain ID: {}", chain_id));
        lines.push(format!("Nonce: {}", p.nonce));
        lines.push(format!("Issued At: {}", p.issued_at));
        if let Some(exp) = &p.expiry {
            lines.push(format!("Expiration Time: {}", exp));
        }
        if !p.resources.is_empty() {
            lines.push("Resources:".to_string());
            for r in &p.resources {
                lines.push(format!("- {}", r));
            }
        }
        lines.join("\n")
    }

    /// Verify the CACAO signature.
    ///
    /// - `"eip191"` — EIP-191 personal_sign + secp256k1 recovery.
    ///   Returns `did:erc725:gftd:260425:0x{addr}`.
    /// - `"EdDSA"` — Ed25519 signature over the SIWE plaintext.
    ///   Issuer must be `did:key:z6Mk...`. Returns the issuer DID unchanged.
    pub fn verify_signature(&self) -> Result<String, CacaoError> {
        match self.s.t.as_str() {
            "eip191" => {
                let expected_addr = eth::parse_eth_address_from_did(&self.p.iss)?;
                let msg = self.siwe_message();
                let hash = eth::personal_sign_hash(msg.as_bytes());
                let sig_hex = self.s.s.trim_start_matches("0x");
                let sig_bytes = hex::decode(sig_hex)?;
                let recovered = eth::recover_eth_address(&hash, &sig_bytes)?;
                if recovered != expected_addr {
                    return Err(CacaoError::AddressMismatch {
                        expected: hex::encode(expected_addr),
                        got:      hex::encode(recovered),
                    });
                }
                Ok(eth::eth_address_to_erc725_did(&recovered))
            }
            "EdDSA" => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};

                let pubkey_bytes = did_key::parse_ed25519_did_key(&self.p.iss)
                    .map_err(|e| CacaoError::DidKeyParse(e.to_string()))?;
                let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
                    .map_err(|e| CacaoError::Ed25519(e.to_string()))?;

                let msg = self.siwe_message();
                let sig_bytes = decode_sig_bytes(&self.s.s)?;

                let sig_arr: [u8; 64] = sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| CacaoError::Ed25519(format!(
                        "expected 64-byte signature, got {}", sig_bytes.len()
                    )))?;
                let signature = Signature::from_bytes(&sig_arr);

                verifying_key
                    .verify_strict(msg.as_bytes(), &signature)
                    .map_err(|e| CacaoError::Ed25519(e.to_string()))?;

                Ok(self.p.iss.clone())
            }
            other => Err(CacaoError::UnsupportedSigType(other.to_string())),
        }
    }

    /// Returns `true` if the CACAO's `exp` field is set and is in the past.
    ///
    /// A malformed `exp` (non-UTC, wrong length, non-digits) is treated as expired
    /// (fail-safe) to prevent bypasses via timezone-offset corruption of the
    /// lexicographic comparison.
    pub fn is_expired(&self) -> bool {
        match &self.p.expiry {
            None => false,
            Some(exp) => {
                if !is_strict_utc_iso8601(exp) {
                    return true;
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                format_unix_to_iso8601(now) > *exp
            }
        }
    }

    /// Returns the `issued_at` timestamp as Unix seconds, or `None` if malformed.
    pub fn issued_at_secs(&self) -> Option<u64> {
        parse_strict_utc_iso8601(&self.p.issued_at)
    }

    /// Verify the CACAO signature using an externally-resolved Ed25519 public key.
    ///
    /// Intended for issuers whose public key must be fetched from a DID document
    /// (e.g. `did:web:`), where `verify_signature()` cannot resolve the key itself.
    /// Returns the issuer DID string on success.
    pub fn verify_with_pubkey(&self, pubkey: &[u8; 32]) -> Result<String, CacaoError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying_key = VerifyingKey::from_bytes(pubkey)
            .map_err(|e| CacaoError::Ed25519(e.to_string()))?;
        let msg = self.siwe_message();
        let sig_bytes = decode_sig_bytes(&self.s.s)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CacaoError::Ed25519(
                format!("expected 64-byte signature, got {}", sig_bytes.len())
            ))?;
        verifying_key
            .verify_strict(msg.as_bytes(), &Signature::from_bytes(&sig_arr))
            .map_err(|e| CacaoError::Ed25519(e.to_string()))?;
        Ok(self.p.iss.clone())
    }
}

/// Validates that `s` is strictly `YYYY-MM-DDTHH:MM:SSZ` (20 chars, UTC only).
/// Non-UTC offsets (e.g. `+09:00`) corrupt the lexicographic expiry comparison.
fn is_strict_utc_iso8601(s: &str) -> bool {
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

/// Parses a strict `YYYY-MM-DDTHH:MM:SSZ` string to Unix seconds.
fn parse_strict_utc_iso8601(s: &str) -> Option<u64> {
    if !is_strict_utc_iso8601(s) { return None; }
    let b = s.as_bytes();
    let year  = p4(&b[0..4])?;
    let month = p2(&b[5..7])?;
    let day   = p2(&b[8..10])?;
    let hour  = p2(&b[11..13])?;
    let min   = p2(&b[14..16])?;
    let sec   = p2(&b[17..19])?;
    if month == 0 || month > 12 || day == 0 { return None; }
    if hour > 23 || min > 59 || sec > 59 { return None; }
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if unix_is_leap(y) { 366 } else { 365 };
    }
    let mdays: [u64; 12] = if unix_is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    if day > mdays[(month - 1) as usize] { return None; }
    for m in 0..(month - 1) as usize { days += mdays[m]; }
    days += day - 1;
    Some(days * 86_400 + hour * 3_600 + min * 60 + sec)
}

fn p4(b: &[u8]) -> Option<u64> {
    if b.len() != 4 { return None; }
    Some((b[0]-b'0') as u64 * 1000 + (b[1]-b'0') as u64 * 100
       + (b[2]-b'0') as u64 * 10 + (b[3]-b'0') as u64)
}

fn p2(b: &[u8]) -> Option<u64> {
    if b.len() != 2 { return None; }
    Some((b[0]-b'0') as u64 * 10 + (b[1]-b'0') as u64)
}

/// Minimal ISO-8601 UTC formatter — accurate for 1970-2100.
/// Duplicated from `delegation.rs` (not refactored) to keep crates independent.
fn format_unix_to_iso8601(unix_secs: u64) -> String {
    let s = unix_secs;
    let sec  = s % 60; let s = s / 60;
    let min  = s % 60; let s = s / 60;
    let hour = s % 24;
    let days = s / 24;
    let (year, month, day) = unix_days_to_ymd(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hour, min, sec)
}

fn unix_days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let yd = if unix_is_leap(year) { 366 } else { 365 };
        if days < yd { break; }
        days -= yd;
        year += 1;
    }
    let months = if unix_is_leap(year) {
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

fn unix_is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Decode a signature string — tries base64url (no-pad) first, then hex.
fn decode_sig_bytes(s: &str) -> Result<Vec<u8>, CacaoError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    // base64url (no padding) — typical for did:key / EdDSA CACAO
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(s) {
        return Ok(bytes);
    }
    // hex fallback (with or without 0x prefix)
    let s = s.trim_start_matches("0x");
    hex::decode(s).map_err(CacaoError::Hex)
}

impl CacaoPayload {
    pub fn graph_cid(&self) -> Option<&str> {
        self.resources.iter()
            .find(|r| r.starts_with("kotoba://graph/"))
            .map(|r| &r["kotoba://graph/".len()..])
    }

    pub fn capability(&self) -> Option<&str> {
        self.resources.iter()
            .find(|r| r.starts_with("kotoba://can/"))
            .map(|r| &r["kotoba://can/".len()..])
    }

    pub fn proof_cid(&self) -> Option<&str> {
        self.resources.iter()
            .find(|r| r.starts_with("kotoba://prf/"))
            .map(|r| &r["kotoba://prf/".len()..])
    }
}
