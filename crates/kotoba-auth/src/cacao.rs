use super::did_key;
use super::eth;
use super::resolver::{DidDocumentResolver, DidResolverError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    #[error("did resolver error: {0}")]
    DidResolver(String),
}

impl From<DidResolverError> for CacaoError {
    fn from(value: DidResolverError) -> Self {
        Self::DidResolver(value.to_string())
    }
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

fn default_version() -> String {
    "1".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacaoSig {
    /// "eip191" | "EdDSA"
    pub t: String,
    pub s: String, // hex (with or without 0x prefix) or base64
}

impl Cacao {
    /// Parse CACAO from DAG-CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CacaoError> {
        ciborium::from_reader(bytes).map_err(|e| CacaoError::ParseError(e.to_string()))
    }

    /// Reconstruct the EIP-4361 plaintext message that was signed.
    pub fn siwe_message(&self) -> String {
        let p = &self.p;
        // Extract address from iss (last colon-separated segment)
        let address = p.iss.split(':').next_back().unwrap_or(&p.iss);
        // Extract chain id: did:pkh:eip155:N:0x... → "N"; did:key → "1" (CAIP-122 default)
        let chain_id = if p.iss.starts_with("did:key:") {
            "1"
        } else {
            p.iss.split(':').rev().nth(1).unwrap_or("1")
        };

        let mut lines = Vec::new();
        lines.push(format!(
            "{} wants you to sign in with your Ethereum account:",
            p.domain
        ));
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
                        got: hex::encode(recovered),
                    });
                }
                Ok(eth::eth_address_to_erc725_did(&recovered))
            }
            "EdDSA" => {
                use ed25519_dalek::{Signature, VerifyingKey};

                let pubkey_bytes = did_key::parse_ed25519_did_key(&self.p.iss)
                    .map_err(|e| CacaoError::DidKeyParse(e.to_string()))?;
                let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
                    .map_err(|e| CacaoError::Ed25519(e.to_string()))?;

                let msg = self.siwe_message();
                let sig_bytes = decode_sig_bytes(&self.s.s)?;

                let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
                    CacaoError::Ed25519(format!(
                        "expected 64-byte signature, got {}",
                        sig_bytes.len()
                    ))
                })?;
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
        use ed25519_dalek::{Signature, VerifyingKey};

        let verifying_key =
            VerifyingKey::from_bytes(pubkey).map_err(|e| CacaoError::Ed25519(e.to_string()))?;
        let msg = self.siwe_message();
        let sig_bytes = decode_sig_bytes(&self.s.s)?;
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            CacaoError::Ed25519(format!(
                "expected 64-byte signature, got {}",
                sig_bytes.len()
            ))
        })?;
        verifying_key
            .verify_strict(msg.as_bytes(), &Signature::from_bytes(&sig_arr))
            .map_err(|e| CacaoError::Ed25519(e.to_string()))?;
        Ok(self.p.iss.clone())
    }

    /// Verify an Ed25519 CACAO using the configured DID resolver abstraction.
    ///
    /// This covers non-`did:key` issuers such as `did:web` and `did:plc` as long
    /// as the resolver returns a DID Document with an Ed25519 verification method.
    pub fn verify_with_resolver(
        &self,
        resolver: &dyn DidDocumentResolver,
    ) -> Result<String, CacaoError> {
        if self.s.t != "EdDSA" {
            return self.verify_signature();
        }
        let doc = resolver.resolve(&self.p.iss)?;
        let pubkey = doc.ed25519_public_key().ok_or_else(|| {
            CacaoError::DidResolver(format!("no Ed25519 key in DID Document for {}", self.p.iss))
        })?;
        self.verify_with_pubkey(&pubkey)
    }
}

/// Validates that `s` is strictly `YYYY-MM-DDTHH:MM:SSZ` (20 chars, UTC only).
/// Non-UTC offsets (e.g. `+09:00`) corrupt the lexicographic expiry comparison.
fn is_strict_utc_iso8601(s: &str) -> bool {
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

/// Parses a strict `YYYY-MM-DDTHH:MM:SSZ` string to Unix seconds.
fn parse_strict_utc_iso8601(s: &str) -> Option<u64> {
    if !is_strict_utc_iso8601(s) {
        return None;
    }
    let b = s.as_bytes();
    let year = p4(&b[0..4])?;
    let month = p2(&b[5..7])?;
    let day = p2(&b[8..10])?;
    let hour = p2(&b[11..13])?;
    let min = p2(&b[14..16])?;
    let sec = p2(&b[17..19])?;
    if month == 0 || month > 12 || day == 0 {
        return None;
    }
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    let mut days: u64 = 0;
    for y in 1970..year {
        days += if unix_is_leap(y) { 366 } else { 365 };
    }
    let mdays: [u64; 12] = if unix_is_leap(year) {
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

fn p4(b: &[u8]) -> Option<u64> {
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

fn p2(b: &[u8]) -> Option<u64> {
    if b.len() != 2 {
        return None;
    }
    Some((b[0] - b'0') as u64 * 10 + (b[1] - b'0') as u64)
}

/// Minimal ISO-8601 UTC formatter — accurate for 1970-2100.
/// Duplicated from `delegation.rs` (not refactored) to keep crates independent.
fn format_unix_to_iso8601(unix_secs: u64) -> String {
    let s = unix_secs;
    let sec = s % 60;
    let s = s / 60;
    let min = s % 60;
    let s = s / 60;
    let hour = s % 24;
    let days = s / 24;
    let (year, month, day) = unix_days_to_ymd(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
}

fn unix_days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let yd = if unix_is_leap(year) { 366 } else { 365 };
        if days < yd {
            break;
        }
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
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month, days + 1)
}

fn unix_is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Decode a signature string — tries base64url (no-pad) first, then hex.
fn decode_sig_bytes(s: &str) -> Result<Vec<u8>, CacaoError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // base64url (no padding) — typical for did:key / EdDSA CACAO
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(s) {
        return Ok(bytes);
    }
    // hex fallback (with or without 0x prefix)
    let s = s.trim_start_matches("0x");
    hex::decode(s).map_err(CacaoError::Hex)
}

impl CacaoPayload {
    pub const OP_DATOM_TRANSACT: &'static str = "datom:transact";
    pub const OP_DATOM_READ: &'static str = "datom:read";
    pub const OP_TX_CREATE: &'static str = "tx:create";
    pub const OP_GRAPH_QUERY: &'static str = "graph:query";
    pub const OP_VC_ISSUE: &'static str = "vc:issue";
    pub const OP_VC_PRESENT: &'static str = "vc:present";
    pub const OP_DIDCOMM_SEND: &'static str = "didcomm:send";
    pub const OP_ATPROTO_REPO_WRITE: &'static str = "atproto:repo.write";

    pub fn graph_cid(&self) -> Option<&str> {
        self.resources
            .iter()
            .find(|r| r.starts_with("kotoba://graph/"))
            .map(|r| &r["kotoba://graph/".len()..])
    }

    /// Return ALL authorized graph CIDs from `kotoba://graph/{cid}` resources.
    /// Empty = no graph restriction (all graphs authorized).
    pub fn all_graph_cids(&self) -> Vec<&str> {
        self.resources
            .iter()
            .filter(|r| r.starts_with("kotoba://graph/"))
            .map(|r| &r["kotoba://graph/".len()..])
            .collect()
    }

    pub fn capability(&self) -> Option<&str> {
        self.resources.iter().find_map(|r| {
            r.strip_prefix("kotoba://op/")
                .or_else(|| r.strip_prefix("kotoba://can/"))
        })
    }

    pub fn capabilities(&self) -> Vec<&str> {
        self.resources
            .iter()
            .filter_map(|r| {
                r.strip_prefix("kotoba://op/")
                    .or_else(|| r.strip_prefix("kotoba://can/"))
            })
            .collect()
    }

    pub fn operation(&self) -> Option<&str> {
        self.capability()
    }

    pub fn has_operation(&self, operation: &str) -> bool {
        self.capabilities()
            .iter()
            .any(|granted| *granted == operation)
    }

    pub fn tx_cid(&self) -> Option<&str> {
        self.resources
            .iter()
            .find(|r| r.starts_with("kotoba://tx/"))
            .map(|r| &r["kotoba://tx/".len()..])
    }

    pub fn didcomm_thread_ids(&self) -> Vec<&str> {
        self.resources
            .iter()
            .filter_map(|r| r.strip_prefix("didcomm://thread/"))
            .collect()
    }

    pub fn atproto_scopes(&self) -> Vec<&str> {
        self.resources
            .iter()
            .filter_map(|r| r.strip_prefix("at://"))
            .collect()
    }

    pub fn authorizes_scope(&self, scope: &str) -> bool {
        self.resources.iter().any(|r| r == scope)
    }

    pub fn authorizes_graph(&self, graph: &str) -> bool {
        self.authorizes_scope(&format!("kotoba://graph/{graph}"))
    }

    pub fn authorizes_tx(&self, tx: &str) -> bool {
        self.authorizes_scope(&format!("kotoba://tx/{tx}"))
    }

    pub fn authorizes_didcomm_thread(&self, thread_id: &str) -> bool {
        self.authorizes_scope(&format!("didcomm://thread/{thread_id}"))
    }

    pub fn authorizes_atproto_resource(&self, at_uri: &str) -> bool {
        self.authorizes_scope(at_uri) && at_uri.starts_with("at://")
    }

    pub fn has_tx_scope(&self) -> bool {
        self.resources
            .iter()
            .any(|resource| resource.starts_with("kotoba://tx/"))
    }

    pub fn invocation_targets(&self) -> Vec<&str> {
        self.resources
            .iter()
            .filter(|resource| {
                !resource.starts_with("kotoba://op/")
                    && !resource.starts_with("kotoba://can/")
                    && !resource.starts_with("kotoba://prf/")
            })
            .map(String::as_str)
            .collect()
    }

    pub fn proof_cid(&self) -> Option<&str> {
        self.resources
            .iter()
            .find(|r| r.starts_with("kotoba://prf/"))
            .map(|r| &r["kotoba://prf/".len()..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_payload(iss: &str) -> CacaoPayload {
        CacaoPayload {
            iss: iss.to_string(),
            aud: "https://kotoba.example.com".to_string(),
            issued_at: "2024-01-01T00:00:00Z".to_string(),
            expiry: None,
            nonce: "abc123".to_string(),
            domain: "kotoba.example.com".to_string(),
            statement: None,
            version: "1".to_string(),
            resources: vec![],
        }
    }

    fn base_cacao(iss: &str) -> Cacao {
        Cacao {
            h: CacaoHeader {
                t: "eip4361".to_string(),
            },
            p: base_payload(iss),
            s: CacaoSig {
                t: "eip191".to_string(),
                s: "00".repeat(65),
            },
        }
    }

    // ── unix_is_leap ──────────────────────────────────────────────────────────

    #[test]
    fn leap_year_divisible_by_4_not_100() {
        assert!(unix_is_leap(2024));
        assert!(unix_is_leap(1972));
    }

    #[test]
    fn leap_year_divisible_by_400() {
        assert!(unix_is_leap(2000));
    }

    #[test]
    fn not_leap_divisible_by_100_not_400() {
        assert!(!unix_is_leap(1900));
        assert!(!unix_is_leap(2100));
    }

    #[test]
    fn not_leap_odd_year() {
        assert!(!unix_is_leap(2023));
        assert!(!unix_is_leap(1971));
    }

    // ── is_strict_utc_iso8601 ─────────────────────────────────────────────────

    #[test]
    fn strict_utc_valid() {
        assert!(is_strict_utc_iso8601("2024-01-01T00:00:00Z"));
        assert!(is_strict_utc_iso8601("1970-01-01T00:00:00Z"));
        assert!(is_strict_utc_iso8601("2099-12-31T23:59:59Z"));
    }

    #[test]
    fn strict_utc_rejects_non_utc_offset() {
        assert!(!is_strict_utc_iso8601("2024-01-01T09:00:00+09:00"));
    }

    #[test]
    fn strict_utc_rejects_wrong_length() {
        assert!(!is_strict_utc_iso8601("2024-01-01T00:00:00"));
        assert!(!is_strict_utc_iso8601("2024-01-01"));
    }

    #[test]
    fn strict_utc_rejects_non_digit_fields() {
        assert!(!is_strict_utc_iso8601("XXXX-01-01T00:00:00Z"));
    }

    // ── parse_strict_utc_iso8601 ──────────────────────────────────────────────

    #[test]
    fn parse_unix_epoch() {
        assert_eq!(parse_strict_utc_iso8601("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn parse_known_timestamp() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(
            parse_strict_utc_iso8601("2024-01-01T00:00:00Z"),
            Some(1_704_067_200)
        );
    }

    #[test]
    fn parse_returns_none_for_malformed() {
        assert!(parse_strict_utc_iso8601("not-a-date").is_none());
        assert!(parse_strict_utc_iso8601("2024-13-01T00:00:00Z").is_none()); // month 13
    }

    // ── format_unix_to_iso8601 ────────────────────────────────────────────────

    #[test]
    fn format_epoch_zero() {
        assert_eq!(format_unix_to_iso8601(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn format_one_day() {
        assert_eq!(format_unix_to_iso8601(86_400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn format_roundtrips_with_parse() {
        let ts = 1_704_067_200u64;
        let s = format_unix_to_iso8601(ts);
        assert_eq!(parse_strict_utc_iso8601(&s), Some(ts));
    }

    // ── Cacao::is_expired ─────────────────────────────────────────────────────

    #[test]
    fn not_expired_when_no_expiry() {
        let c = base_cacao("did:key:z6Mk");
        assert!(!c.is_expired());
    }

    #[test]
    fn expired_when_past_date() {
        let mut c = base_cacao("did:key:z6Mk");
        c.p.expiry = Some("2020-01-01T00:00:00Z".to_string());
        assert!(c.is_expired());
    }

    #[test]
    fn not_expired_when_far_future() {
        let mut c = base_cacao("did:key:z6Mk");
        c.p.expiry = Some("2099-12-31T23:59:59Z".to_string());
        assert!(!c.is_expired());
    }

    #[test]
    fn expired_when_malformed_expiry() {
        // fail-safe: malformed → treat as expired
        let mut c = base_cacao("did:key:z6Mk");
        c.p.expiry = Some("2024-01-01T00:00:00+09:00".to_string());
        assert!(c.is_expired());
    }

    // ── Cacao::siwe_message ───────────────────────────────────────────────────

    #[test]
    fn siwe_message_contains_required_fields() {
        let c = base_cacao("did:pkh:eip155:1:0xABCDEF");
        let msg = c.siwe_message();
        assert!(msg.contains("kotoba.example.com wants you to sign in"));
        assert!(msg.contains("0xABCDEF"));
        assert!(msg.contains("URI: https://kotoba.example.com"));
        assert!(msg.contains("Chain ID: 1"));
        assert!(msg.contains("Nonce: abc123"));
        assert!(msg.contains("Issued At: 2024-01-01T00:00:00Z"));
    }

    #[test]
    fn siwe_message_includes_statement_when_present() {
        let mut c = base_cacao("did:pkh:eip155:1:0xABCDEF");
        c.p.statement = Some("Access granted".to_string());
        let msg = c.siwe_message();
        assert!(msg.contains("Access granted"));
    }

    #[test]
    fn siwe_message_did_key_uses_chain_id_1() {
        let c = base_cacao("did:key:z6MkTestKey");
        let msg = c.siwe_message();
        assert!(msg.contains("Chain ID: 1"));
    }

    #[test]
    fn siwe_message_includes_resources() {
        let mut c = base_cacao("did:pkh:eip155:1:0xABCD");
        c.p.resources = vec!["kotoba://graph/cid123".to_string()];
        let msg = c.siwe_message();
        assert!(msg.contains("Resources:"));
        assert!(msg.contains("- kotoba://graph/cid123"));
    }

    // ── CacaoPayload resource extractors ─────────────────────────────────────

    #[test]
    fn graph_cid_extracted() {
        let mut p = base_payload("did:key:z");
        p.resources = vec!["kotoba://graph/abc123".to_string()];
        assert_eq!(p.graph_cid(), Some("abc123"));
    }

    #[test]
    fn graph_cid_absent() {
        let p = base_payload("did:key:z");
        assert!(p.graph_cid().is_none());
    }

    #[test]
    fn capability_extracted() {
        let mut p = base_payload("did:key:z");
        p.resources = vec!["kotoba://can/read".to_string()];
        assert_eq!(p.capability(), Some("read"));
    }

    #[test]
    fn operation_extracted_from_w3c_style_operation_resource() {
        let mut p = base_payload("did:key:z");
        p.resources = vec!["kotoba://op/datom:transact".to_string()];
        assert_eq!(p.operation(), Some(CacaoPayload::OP_DATOM_TRANSACT));
        assert!(p.has_operation(CacaoPayload::OP_DATOM_TRANSACT));
    }

    #[test]
    fn multiple_capabilities_are_extracted() {
        let mut p = base_payload("did:key:z");
        p.resources = vec![
            "kotoba://op/datom:transact".to_string(),
            "kotoba://can/tx:create".to_string(),
        ];
        assert_eq!(p.capability(), Some(CacaoPayload::OP_DATOM_TRANSACT));
        assert_eq!(
            p.capabilities(),
            vec![CacaoPayload::OP_DATOM_TRANSACT, CacaoPayload::OP_TX_CREATE]
        );
        assert!(p.has_operation(CacaoPayload::OP_DATOM_TRANSACT));
        assert!(p.has_operation(CacaoPayload::OP_TX_CREATE));
    }

    #[test]
    fn datomic_atproto_and_didcomm_scopes_are_extracted() {
        let mut p = base_payload("did:key:z");
        p.resources = vec![
            "kotoba://graph/bafygraph".to_string(),
            "kotoba://tx/bafytx".to_string(),
            "at://did:plc:alice/app.bsky.feed.post/rkey".to_string(),
            "didcomm://thread/thread-1".to_string(),
        ];
        assert_eq!(p.graph_cid(), Some("bafygraph"));
        assert_eq!(p.tx_cid(), Some("bafytx"));
        assert!(p.authorizes_graph("bafygraph"));
        assert!(p.authorizes_tx("bafytx"));
        assert!(p.authorizes_atproto_resource("at://did:plc:alice/app.bsky.feed.post/rkey"));
        assert!(p.authorizes_didcomm_thread("thread-1"));
        assert!(p.has_tx_scope());
        assert_eq!(
            p.atproto_scopes(),
            vec!["did:plc:alice/app.bsky.feed.post/rkey"]
        );
        assert_eq!(p.didcomm_thread_ids(), vec!["thread-1"]);
        assert!(p.authorizes_scope("kotoba://graph/bafygraph"));
        assert_eq!(
            p.invocation_targets(),
            vec![
                "kotoba://graph/bafygraph",
                "kotoba://tx/bafytx",
                "at://did:plc:alice/app.bsky.feed.post/rkey",
                "didcomm://thread/thread-1"
            ]
        );
    }

    #[test]
    fn proof_cid_extracted() {
        let mut p = base_payload("did:key:z");
        p.resources = vec!["kotoba://prf/proofcid".to_string()];
        assert_eq!(p.proof_cid(), Some("proofcid"));
    }

    // ── CacaoError display ────────────────────────────────────────────────────

    #[test]
    fn cacao_error_unsupported_display() {
        let e = CacaoError::UnsupportedSigType("secp256r1".to_string());
        assert!(e.to_string().contains("secp256r1"));
    }

    #[test]
    fn cacao_error_address_mismatch_display() {
        let e = CacaoError::AddressMismatch {
            expected: "aabb".to_string(),
            got: "ccdd".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("aabb") && s.contains("ccdd"));
    }

    // ── JSON roundtrip ────────────────────────────────────────────────────────

    #[test]
    fn cacao_json_roundtrip() {
        let c = base_cacao("did:pkh:eip155:1:0xDEADBEEF");
        let json = serde_json::to_string(&c).unwrap();
        let back: Cacao = serde_json::from_str(&json).unwrap();
        assert_eq!(back.p.iss, c.p.iss);
        assert_eq!(back.s.t, c.s.t);
    }

    // ── EdDSA CACAO full E2E (real Ed25519 keypair + signature) ──────────────

    /// Build a signed CACAO using a deterministic Ed25519 keypair.
    /// Returns (cacao, did_key_string, signing_key).
    fn make_signed_eddsa_cacao(graph_cid: &str, capability: &str, expiry: Option<&str>) -> Cacao {
        use crate::did_key::ed25519_pubkey_to_did_key;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key();
        let did = ed25519_pubkey_to_did_key(pk.as_bytes());

        let cacao = Cacao {
            h: CacaoHeader {
                t: "eip4361".to_string(),
            },
            p: CacaoPayload {
                iss: did.clone(),
                aud: "https://kotoba.test".to_string(),
                issued_at: "2026-01-01T00:00:00Z".to_string(),
                expiry: expiry.map(str::to_string),
                nonce: "e2e-test-nonce".to_string(),
                domain: "kotoba.test".to_string(),
                statement: None,
                version: "1".to_string(),
                resources: vec![
                    format!("kotoba://can/{capability}"),
                    format!("kotoba://graph/{graph_cid}"),
                ],
            },
            s: CacaoSig {
                t: "EdDSA".to_string(),
                s: String::new(),
            },
        };

        // Sign the SIWE message and embed the real signature.
        let msg = cacao.siwe_message();
        let sig = sk.sign(msg.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Cacao {
            s: CacaoSig {
                t: "EdDSA".to_string(),
                s: sig_b64,
            },
            ..cacao
        }
    }

    #[test]
    fn eddsa_cacao_verify_signature_succeeds() {
        let graph_cid = "bafy2bzaced-test-graph";
        let cacao = make_signed_eddsa_cacao(graph_cid, "datom:read", Some("2099-01-01T00:00:00Z"));
        let result = cacao.verify_signature();
        assert!(
            result.is_ok(),
            "real EdDSA sig must verify: {:?}",
            result.err()
        );
        assert!(
            result.unwrap().starts_with("did:key:z6Mk"),
            "issuer must be did:key:z6Mk..."
        );
    }

    #[test]
    fn eddsa_cacao_verify_with_resolver_accepts_non_did_key_issuer() {
        use crate::did_document::{DidDocument, VerificationMethod, ED25519_KEY_TYPE_2020};
        use crate::resolver::InMemoryDidResolver;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key();
        let did = "did:plc:alice";

        let mut cacao = Cacao {
            h: CacaoHeader {
                t: "eip4361".to_string(),
            },
            p: CacaoPayload {
                iss: did.to_string(),
                aud: "https://kotoba.test".to_string(),
                issued_at: "2026-01-01T00:00:00Z".to_string(),
                expiry: Some("2099-01-01T00:00:00Z".to_string()),
                nonce: "resolver-test-nonce".to_string(),
                domain: "kotoba.test".to_string(),
                statement: None,
                version: "1".to_string(),
                resources: vec!["kotoba://can/datom:read".to_string()],
            },
            s: CacaoSig {
                t: "EdDSA".to_string(),
                s: String::new(),
            },
        };
        cacao.s.s = URL_SAFE_NO_PAD.encode(sk.sign(cacao.siwe_message().as_bytes()).to_bytes());

        let mut doc = DidDocument::empty(did);
        doc.verification_method.push(VerificationMethod {
            id: format!("{did}#key-1"),
            key_type: ED25519_KEY_TYPE_2020.to_string(),
            controller: did.to_string(),
            public_key_multibase: multibase::encode(multibase::Base::Base58Btc, pk.as_bytes()),
        });

        let resolver = InMemoryDidResolver::new();
        resolver.insert(did, doc);

        assert!(
            cacao.verify_signature().is_err(),
            "plain EdDSA verification is intentionally did:key-only"
        );
        assert_eq!(cacao.verify_with_resolver(&resolver).unwrap(), did);
    }

    #[test]
    fn eddsa_cacao_verify_with_resolver_rejects_wrong_document_key() {
        use crate::did_document::{DidDocument, VerificationMethod, ED25519_KEY_TYPE_2020};
        use crate::resolver::InMemoryDidResolver;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let wrong_doc_key = SigningKey::from_bytes(&[9u8; 32]);
        let did = "did:web:alice.example";

        let mut cacao = Cacao {
            h: CacaoHeader {
                t: "eip4361".to_string(),
            },
            p: CacaoPayload {
                iss: did.to_string(),
                aud: "https://kotoba.test".to_string(),
                issued_at: "2026-01-01T00:00:00Z".to_string(),
                expiry: Some("2099-01-01T00:00:00Z".to_string()),
                nonce: "resolver-reject-test-nonce".to_string(),
                domain: "kotoba.test".to_string(),
                statement: None,
                version: "1".to_string(),
                resources: vec!["kotoba://can/datom:read".to_string()],
            },
            s: CacaoSig {
                t: "EdDSA".to_string(),
                s: String::new(),
            },
        };
        cacao.s.s =
            URL_SAFE_NO_PAD.encode(signing_key.sign(cacao.siwe_message().as_bytes()).to_bytes());

        let mut doc = DidDocument::empty(did);
        doc.verification_method.push(VerificationMethod {
            id: format!("{did}#key-1"),
            key_type: ED25519_KEY_TYPE_2020.to_string(),
            controller: did.to_string(),
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                wrong_doc_key.verifying_key().as_bytes(),
            ),
        });

        let resolver = InMemoryDidResolver::new();
        resolver.insert(did, doc);

        assert!(cacao.verify_with_resolver(&resolver).is_err());
    }

    #[test]
    fn eddsa_cacao_wrong_sig_fails() {
        let cacao = make_signed_eddsa_cacao("graph-x", "datom:read", Some("2099-01-01T00:00:00Z"));
        // Corrupt the sig: flip the last byte.
        let bad_sig = {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let mut bytes = URL_SAFE_NO_PAD.decode(&cacao.s.s).unwrap();
            *bytes.last_mut().unwrap() ^= 0xff;
            URL_SAFE_NO_PAD.encode(&bytes)
        };
        let bad = Cacao {
            s: CacaoSig {
                t: "EdDSA".to_string(),
                s: bad_sig,
            },
            ..cacao
        };
        assert!(bad.verify_signature().is_err(), "corrupted sig must fail");
    }

    #[test]
    fn eddsa_cacao_delegation_chain_verify_succeeds() {
        use crate::delegation::DelegationChain;
        let graph_cid = "bafy2bzaced-chain-test";
        let cacao = make_signed_eddsa_cacao(graph_cid, "datom:read", Some("2099-01-01T00:00:00Z"));
        let chain = DelegationChain::new(cacao);
        let result = chain.verify(graph_cid, "datom:read");
        assert!(
            result.is_ok(),
            "DelegationChain::verify with real EdDSA sig must succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn eddsa_cacao_delegation_chain_wrong_graph_fails() {
        use crate::delegation::DelegationChain;
        let cacao = make_signed_eddsa_cacao("graph-a", "datom:read", Some("2099-01-01T00:00:00Z"));
        let chain = DelegationChain::new(cacao);
        let result = chain.verify("graph-b", "datom:read");
        assert!(result.is_err(), "wrong graph CID must be rejected");
    }

    #[test]
    fn eddsa_cacao_delegation_chain_wrong_capability_fails() {
        use crate::delegation::DelegationChain;
        let cacao = make_signed_eddsa_cacao("g", "datom:read", Some("2099-01-01T00:00:00Z"));
        let chain = DelegationChain::new(cacao);
        let result = chain.verify("g", "datom:transact");
        assert!(result.is_err(), "wrong capability must be rejected");
    }
}
