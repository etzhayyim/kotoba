//! Passkey / WebAuthn authentication gate for kotoba.
//!
//! # Design principle
//!
//! Passkey is **not** a master private key — it is a root authenticator that
//! gates access to purpose-isolated keys.  Each key operation requires a fresh
//! `PasskeyAssertion` to be validated by `PasskeyGate`, which emits a
//! time-limited `Authorization`.  Actual key material (Signal identity key,
//! E2EE DEK, recovery key) lives in device-local secure storage or the Vault;
//! the gate never touches it.
//!
//! ```text
//! User
//!  └─ Passkey / WebAuthn  (authentication gate)
//!      ├─ WebLogin       → short-lived session token
//!      ├─ SiweSign       → Ethereum AA Smart Account op
//!      ├─ SignalKey       → Signal identity key unlock
//!      ├─ StorageKey      → E2EE DEK decrypt permit
//!      └─ Recovery        → guardian key access
//! ```

use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ── PasskeyAssertion ──────────────────────────────────────────────────────────

/// Result of a completed WebAuthn authentication ceremony (RP-verified).
///
/// In production this is constructed by the Relying Party after verifying
/// `AuthenticatorAssertionResponse`.  The RP MUST validate authenticatorData,
/// clientDataJSON, and the signature before building this struct.
#[derive(Debug, Clone)]
pub struct PasskeyAssertion {
    /// Opaque credential ID assigned by the RP at registration.
    pub credential_id: Vec<u8>,
    /// UP flag — user was physically present (device tap).
    pub user_present: bool,
    /// UV flag — user was verified (biometric / PIN).
    pub user_verified: bool,
    /// SHA-256(RP ID) — ensures assertion is bound to the correct origin.
    pub rp_id_hash: [u8; 32],
    /// Unix seconds when the assertion was produced by the authenticator.
    pub issued_at_secs: u64,
    /// Anti-replay nonce (copy of `clientDataJSON.challenge`).
    pub nonce: [u8; 16],
}

impl PasskeyAssertion {
    /// Returns `true` if the assertion is no older than `max_age_secs`.
    pub fn is_fresh(&self, max_age_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(self.issued_at_secs) <= max_age_secs
    }
}

// ── KeyOpKind ─────────────────────────────────────────────────────────────────

/// The key operation being authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyOpKind {
    /// Web login — produces a short-lived session token.
    WebLogin,
    /// SIWE / off-chain Ethereum message signature.
    SiweSign,
    /// Low-value Ethereum transaction (below spending limit).
    EthereumTxLow,
    /// High-value Ethereum transaction (at or above spending limit).
    EthereumTxHigh,
    /// Unlock Signal Protocol identity key on this device.
    SignalKeyUnlock,
    /// Decrypt E2EE storage data key (DEK).
    StorageKeyDecrypt,
    /// Add a new Passkey credential / device to this account.
    AddDevice,
    /// Access recovery / guardian key material.
    RecoveryKeyAccess,
}

// ── AuthLevel ─────────────────────────────────────────────────────────────────

/// Minimum authenticator assertion strength required for an operation.
///
/// Ordering: `UserPresence < UserVerified < UserVerifiedHighValue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthLevel {
    /// UP only — platform authenticator tap, no PIN / biometric required.
    UserPresence,
    /// UV required — biometric or PIN verified by the authenticator.
    UserVerified,
    /// UV + hardware security key (or equivalent high-assurance factor).
    /// In production the RP enforces this by restricting allowed authenticators
    /// to hardware-bound keys (e.g. YubiKey with PIN).
    UserVerifiedHighValue,
}

// ── KeyOpPolicy ───────────────────────────────────────────────────────────────

/// Policy mapping each `KeyOpKind` to the minimum `AuthLevel` and TTL.
///
/// Use `KeyOpPolicy::default()` for the standard configuration.
#[derive(Debug, Clone)]
pub struct KeyOpPolicy {
    entries: Vec<PolicyEntry>,
}

#[derive(Debug, Clone)]
struct PolicyEntry {
    op:           KeyOpKind,
    min_level:    AuthLevel,
    /// How long the resulting `Authorization` is valid (seconds).
    ttl_secs:     u64,
    /// Maximum age of the `PasskeyAssertion` itself (seconds).
    max_age_secs: u64,
}

impl Default for KeyOpPolicy {
    fn default() -> Self {
        Self {
            entries: vec![
                PolicyEntry { op: KeyOpKind::WebLogin,         min_level: AuthLevel::UserPresence,          ttl_secs: 3600, max_age_secs: 60 },
                PolicyEntry { op: KeyOpKind::SiweSign,         min_level: AuthLevel::UserVerified,          ttl_secs:  300, max_age_secs: 30 },
                PolicyEntry { op: KeyOpKind::EthereumTxLow,    min_level: AuthLevel::UserVerified,          ttl_secs:  300, max_age_secs: 30 },
                PolicyEntry { op: KeyOpKind::EthereumTxHigh,   min_level: AuthLevel::UserVerifiedHighValue, ttl_secs:   60, max_age_secs: 15 },
                PolicyEntry { op: KeyOpKind::SignalKeyUnlock,   min_level: AuthLevel::UserVerified,          ttl_secs:  600, max_age_secs: 30 },
                PolicyEntry { op: KeyOpKind::StorageKeyDecrypt, min_level: AuthLevel::UserPresence,          ttl_secs: 3600, max_age_secs: 60 },
                PolicyEntry { op: KeyOpKind::AddDevice,         min_level: AuthLevel::UserVerifiedHighValue, ttl_secs:  120, max_age_secs: 15 },
                PolicyEntry { op: KeyOpKind::RecoveryKeyAccess, min_level: AuthLevel::UserVerifiedHighValue, ttl_secs:  120, max_age_secs: 15 },
            ],
        }
    }
}

// ── PasskeyGateError ──────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PasskeyGateError {
    #[error("assertion is stale (max_age={0}s)")]
    StaleAssertion(u64),
    #[error("user presence (UP) flag not set")]
    UserNotPresent,
    #[error("user verification (UV) required but flag not set")]
    UserNotVerified,
    #[error("high-value operation requires hardware-bound authenticator")]
    HardwareKeyRequired,
    #[error("RP ID hash mismatch — assertion is for a different origin")]
    RpIdMismatch,
    #[error("no policy entry for op {0:?}")]
    NoPolicyEntry(KeyOpKind),
}

// ── Authorization ─────────────────────────────────────────────────────────────

/// Time-limited grant produced by `PasskeyGate::authorize`.
///
/// The caller MUST call `is_valid()` immediately before using the grant
/// to perform the key operation.
#[derive(Debug, Clone)]
pub struct Authorization {
    pub op:         KeyOpKind,
    /// Unix seconds after which this grant is invalid.
    pub expires_at: u64,
    /// Anti-replay nonce copied from the originating assertion.
    pub nonce:      [u8; 16],
}

impl Authorization {
    /// Returns `true` if the grant has not yet expired.
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now < self.expires_at
    }
}

// ── PasskeyGate ───────────────────────────────────────────────────────────────

/// Validates a `PasskeyAssertion` against `KeyOpPolicy` and issues an
/// `Authorization` grant.
///
/// The gate holds **no key material**.  It only determines whether the
/// authenticated human is permitted to perform the requested key operation
/// at this moment.
pub struct PasskeyGate {
    policy: KeyOpPolicy,
    /// RP ID hash the gate enforces.  `None` = skip check (testing only).
    expected_rp_id_hash: Option<[u8; 32]>,
}

impl PasskeyGate {
    pub fn new(policy: KeyOpPolicy) -> Self {
        Self { policy, expected_rp_id_hash: None }
    }

    /// Bind the gate to a specific RP ID hash (SHA-256 of the RP ID string).
    /// Should be set in production to prevent cross-origin replay.
    pub fn with_rp_id_hash(mut self, hash: [u8; 32]) -> Self {
        self.expected_rp_id_hash = Some(hash);
        self
    }

    /// Attempt to authorize `op` using the provided `assertion`.
    ///
    /// Returns an `Authorization` on success, or a `PasskeyGateError`
    /// describing which policy check failed.
    pub fn authorize(
        &self,
        op:        KeyOpKind,
        assertion: &PasskeyAssertion,
    ) -> Result<Authorization, PasskeyGateError> {
        let entry = self.policy.entries.iter()
            .find(|e| e.op == op)
            .ok_or(PasskeyGateError::NoPolicyEntry(op))?;

        // Freshness
        if !assertion.is_fresh(entry.max_age_secs) {
            return Err(PasskeyGateError::StaleAssertion(entry.max_age_secs));
        }

        // UP is always required
        if !assertion.user_present {
            return Err(PasskeyGateError::UserNotPresent);
        }

        // UV required at UserVerified or higher
        if entry.min_level >= AuthLevel::UserVerified && !assertion.user_verified {
            return Err(PasskeyGateError::UserNotVerified);
        }

        // UserVerifiedHighValue: same UV proxy check; production RP enforces
        // hardware authenticator restriction at the ceremony level.
        if entry.min_level == AuthLevel::UserVerifiedHighValue && !assertion.user_verified {
            return Err(PasskeyGateError::HardwareKeyRequired);
        }

        // RP ID hash (production enforcement)
        if let Some(expected) = self.expected_rp_id_hash {
            if assertion.rp_id_hash != expected {
                return Err(PasskeyGateError::RpIdMismatch);
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Authorization {
            op,
            expires_at: now + entry.ttl_secs,
            nonce: assertion.nonce,
        })
    }
}

// ── KeyHierarchy ──────────────────────────────────────────────────────────────

/// Per-user envelope of purpose-isolated key references.
///
/// No plaintext private key material is stored here.  Private keys live in
/// device-local secure storage (Secure Enclave / Android Keystore).
/// Symmetric keys (DEK, recovery) are stored as CID pointers into the Vault.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct KeyHierarchy {
    /// Ethereum smart account address (checksummed hex, 42 chars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eth_account: Option<String>,
    /// Signal Protocol identity public key (Ed25519, 32 bytes, base64url-no-pad).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_identity_pub: Option<String>,
    /// CID into the Vault for the KEK-wrapped E2EE data key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_dek_cid: Option<String>,
    /// CID into the Vault for the guardian recovery key blob.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_key_cid: Option<String>,
    /// Registered Passkey credential IDs (base64url-no-pad, RP-assigned).
    #[serde(default)]
    pub passkey_credential_ids: Vec<String>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_assertion(user_present: bool, user_verified: bool) -> PasskeyAssertion {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        PasskeyAssertion {
            credential_id:   vec![0x01, 0x02],
            user_present,
            user_verified,
            rp_id_hash:      [0u8; 32],
            issued_at_secs:  now,
            nonce:           [0xABu8; 16],
        }
    }

    fn gate() -> PasskeyGate {
        PasskeyGate::new(KeyOpPolicy::default())
    }

    // ── Basic grant paths ─────────────────────────────────────────────────────

    #[test]
    fn web_login_up_only_succeeds() {
        let a = fresh_assertion(true, false);
        let auth = gate().authorize(KeyOpKind::WebLogin, &a).unwrap();
        assert_eq!(auth.op, KeyOpKind::WebLogin);
        assert!(auth.is_valid());
    }

    #[test]
    fn siwe_uv_required_succeeds() {
        let a = fresh_assertion(true, true);
        let auth = gate().authorize(KeyOpKind::SiweSign, &a).unwrap();
        assert_eq!(auth.op, KeyOpKind::SiweSign);
        assert!(auth.is_valid());
    }

    #[test]
    fn signal_unlock_uv_required_succeeds() {
        let a = fresh_assertion(true, true);
        gate().authorize(KeyOpKind::SignalKeyUnlock, &a).unwrap();
    }

    #[test]
    fn storage_decrypt_up_only_succeeds() {
        let a = fresh_assertion(true, false);
        gate().authorize(KeyOpKind::StorageKeyDecrypt, &a).unwrap();
    }

    #[test]
    fn eth_high_value_uv_succeeds() {
        let a = fresh_assertion(true, true);
        gate().authorize(KeyOpKind::EthereumTxHigh, &a).unwrap();
    }

    #[test]
    fn add_device_uv_succeeds() {
        let a = fresh_assertion(true, true);
        gate().authorize(KeyOpKind::AddDevice, &a).unwrap();
    }

    // ── Rejection paths ───────────────────────────────────────────────────────

    #[test]
    fn siwe_up_only_rejected() {
        let a = fresh_assertion(true, false);
        let err = gate().authorize(KeyOpKind::SiweSign, &a).unwrap_err();
        assert!(matches!(err, PasskeyGateError::UserNotVerified));
    }

    #[test]
    fn user_not_present_rejected() {
        let a = fresh_assertion(false, false);
        let err = gate().authorize(KeyOpKind::WebLogin, &a).unwrap_err();
        assert!(matches!(err, PasskeyGateError::UserNotPresent));
    }

    #[test]
    fn stale_assertion_rejected() {
        let old_assertion = PasskeyAssertion {
            credential_id:  vec![0x01],
            user_present:   true,
            user_verified:  true,
            rp_id_hash:     [0u8; 32],
            issued_at_secs: 0,  // epoch — definitely stale
            nonce:          [0u8; 16],
        };
        let err = gate().authorize(KeyOpKind::WebLogin, &old_assertion).unwrap_err();
        assert!(matches!(err, PasskeyGateError::StaleAssertion(_)));
    }

    #[test]
    fn rp_id_mismatch_rejected() {
        let a = fresh_assertion(true, true);
        let expected = [0xFFu8; 32];
        let g = PasskeyGate::new(KeyOpPolicy::default()).with_rp_id_hash(expected);
        let err = g.authorize(KeyOpKind::WebLogin, &a).unwrap_err();
        assert!(matches!(err, PasskeyGateError::RpIdMismatch));
    }

    #[test]
    fn rp_id_match_succeeds() {
        let mut a = fresh_assertion(true, true);
        a.rp_id_hash = [0xFFu8; 32];
        let g = PasskeyGate::new(KeyOpPolicy::default()).with_rp_id_hash([0xFFu8; 32]);
        g.authorize(KeyOpKind::SiweSign, &a).unwrap();
    }

    // ── Authorization validity ────────────────────────────────────────────────

    #[test]
    fn authorization_is_valid_immediately() {
        let a = fresh_assertion(true, false);
        let auth = gate().authorize(KeyOpKind::WebLogin, &a).unwrap();
        assert!(auth.is_valid());
    }

    #[test]
    fn authorization_nonce_propagated() {
        let mut a = fresh_assertion(true, true);
        a.nonce = [0x42u8; 16];
        let auth = gate().authorize(KeyOpKind::SiweSign, &a).unwrap();
        assert_eq!(auth.nonce, [0x42u8; 16]);
    }

    // ── KeyHierarchy ──────────────────────────────────────────────────────────

    #[test]
    fn key_hierarchy_json_roundtrip() {
        let kh = KeyHierarchy {
            eth_account:           Some("0xDEAD".into()),
            signal_identity_pub:   Some("base64pubkey".into()),
            storage_dek_cid:       Some("bafydekref".into()),
            recovery_key_cid:      Some("bafyrecovery".into()),
            passkey_credential_ids: vec!["cred1".into(), "cred2".into()],
        };
        let json = serde_json::to_string(&kh).unwrap();
        let kh2: KeyHierarchy = serde_json::from_str(&json).unwrap();
        assert_eq!(kh.eth_account, kh2.eth_account);
        assert_eq!(kh.passkey_credential_ids, kh2.passkey_credential_ids);
    }

    #[test]
    fn key_hierarchy_empty_skips_optional_fields() {
        let kh = KeyHierarchy::default();
        let json = serde_json::to_string(&kh).unwrap();
        // Optional fields should not appear in JSON
        assert!(!json.contains("eth_account"));
        assert!(!json.contains("storage_dek_cid"));
    }
}
