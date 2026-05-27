//! `AgentIdentity` — Layer-1 identity keys for the Kotoba agent.
//!
//! Holds an Ed25519 signing keypair and a derived X25519 DH keypair.
//! In production these are loaded from K8s Secret / Keychain (env vars);
//! in dev/test an ephemeral keypair is generated at startup.
//!
//! ## Environment Variables
//! - `KOTOBA_AGENT_ED25519_HEX` — 64 hex chars (32-byte seed)
//! - `KOTOBA_AGENT_X25519_HEX`  — 64 hex chars (32-byte static secret)
//! - `KOTOBA_AGENT_DID`         — agent DID string (e.g. `did:plc:…`)
//!
//! If neither env var is set the agent runs in **ephemeral mode** (no
//! persistence across restarts).

use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Layer-1 identity keys for the Kotoba agent.
pub struct AgentIdentity {
    /// Ed25519 signing key (private key material — never logged).
    pub signing_key: SigningKey,
    /// X25519 static secret for ECIES key wrapping (never logged).
    pub dh_secret: StaticSecret,
    /// Agent DID string.
    pub did: String,
    /// Whether this identity is ephemeral (generated at startup, not persisted).
    pub ephemeral: bool,
}

impl AgentIdentity {
    /// Generate an ephemeral identity (dev/test).
    pub fn generate_ephemeral() -> Self {
        use rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        let dh_secret   = StaticSecret::random_from_rng(OsRng);
        let vk_bytes    = VerifyingKey::from(&signing_key).to_bytes();
        // Ephemeral DID uses hex-encoded verifying key bytes (dev only).
        let did         = format!("did:key:z{}", hex::encode(vk_bytes));

        Self { signing_key, dh_secret, did, ephemeral: true }
    }

    /// Load from environment variables, or fall back to ephemeral if not set.
    pub fn from_env() -> Self {
        let ed_hex  = std::env::var("KOTOBA_AGENT_ED25519_HEX").ok();
        let dh_hex  = std::env::var("KOTOBA_AGENT_X25519_HEX").ok();
        let did_env = std::env::var("KOTOBA_AGENT_DID").ok();

        match (ed_hex, dh_hex, did_env) {
            (Some(ed), Some(dh), Some(did)) => {
                let ed_bytes = match hex::decode(ed.trim()) {
                    Ok(b) if b.len() == 32 => b,
                    _ => {
                        tracing::warn!("KOTOBA_AGENT_ED25519_HEX invalid — falling back to ephemeral");
                        return Self::generate_ephemeral();
                    }
                };
                let dh_bytes: [u8; 32] = match hex::decode(dh.trim()) {
                    Ok(b) if b.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        arr
                    }
                    _ => {
                        tracing::warn!("KOTOBA_AGENT_X25519_HEX invalid — falling back to ephemeral");
                        return Self::generate_ephemeral();
                    }
                };

                let seed: [u8; 32] = {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&ed_bytes);
                    arr
                };
                let signing_key = SigningKey::from_bytes(&seed);
                let dh_secret   = StaticSecret::from(dh_bytes);

                tracing::info!(did = %did, "AgentIdentity loaded from env");
                Self { signing_key, dh_secret, did, ephemeral: false }
            }
            _ => {
                tracing::info!("KOTOBA_AGENT_* env not set — running ephemeral identity");
                Self::generate_ephemeral()
            }
        }
    }

    /// Return the X25519 public key for wrapping vault keys.
    pub fn x25519_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.dh_secret)
    }

    /// Return the Ed25519 verifying key (public).
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from(&self.signing_key)
    }

    /// Blake3-derived 8-char hex slug of the DID (stable identifier for storage paths).
    pub fn did_slug(&self) -> String {
        let hash = blake3::hash(self.did.as_bytes());
        hex::encode(&hash.as_bytes()[..4]) // 8 hex chars
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_identity_has_did() {
        let id = AgentIdentity::generate_ephemeral();
        assert!(!id.did.is_empty(), "DID should not be empty");
        assert!(id.ephemeral, "should be ephemeral");
    }

    #[test]
    fn did_slug_is_8_hex_chars() {
        let id = AgentIdentity::generate_ephemeral();
        let slug = id.did_slug();
        assert_eq!(slug.len(), 8, "slug={slug}");
        assert!(slug.chars().all(|c| c.is_ascii_hexdigit()), "slug={slug}");
    }

    #[test]
    fn x25519_public_key_matches_secret() {
        let id = AgentIdentity::generate_ephemeral();
        let pk = id.x25519_public_key();
        let expected = X25519PublicKey::from(&id.dh_secret);
        assert_eq!(pk.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn two_ephemeral_identities_differ() {
        let a = AgentIdentity::generate_ephemeral();
        let b = AgentIdentity::generate_ephemeral();
        assert_ne!(a.did, b.did);
    }

    #[test]
    fn verifying_key_matches_signing_key() {
        let id = AgentIdentity::generate_ephemeral();
        let vk = id.verifying_key();
        // The verifying key derived from signing_key must equal verifying_key()
        let expected = VerifyingKey::from(&id.signing_key);
        assert_eq!(vk.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn did_slug_is_stable_across_calls() {
        let id = AgentIdentity::generate_ephemeral();
        let slug1 = id.did_slug();
        let slug2 = id.did_slug();
        assert_eq!(slug1, slug2, "did_slug must be deterministic");
    }

    #[test]
    fn from_env_with_no_vars_is_ephemeral() {
        // Ensure env vars are not set (unset them for this test)
        std::env::remove_var("KOTOBA_AGENT_ED25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_X25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_DID");
        let id = AgentIdentity::from_env();
        assert!(id.ephemeral, "from_env with no vars should be ephemeral");
    }

    #[test]
    fn ephemeral_did_starts_with_did_key() {
        let id = AgentIdentity::generate_ephemeral();
        assert!(id.did.starts_with("did:key:z"), "ephemeral DID should start with did:key:z");
    }

    // ── New tests ─────────────────────────────────────────────────────────────

    #[test]
    fn did_slug_length_is_always_8() {
        // Even for DIDs of different lengths, the slug must always be 8 hex chars.
        for _ in 0..5 {
            let id = AgentIdentity::generate_ephemeral();
            assert_eq!(id.did_slug().len(), 8);
        }
    }

    #[test]
    fn different_dids_produce_different_slugs() {
        let a = AgentIdentity::generate_ephemeral();
        let b = AgentIdentity::generate_ephemeral();
        // With overwhelming probability two random DIDs hash to different slugs.
        assert_ne!(a.did_slug(), b.did_slug());
    }

    #[test]
    fn ephemeral_flag_is_true_for_generate_ephemeral() {
        let id = AgentIdentity::generate_ephemeral();
        assert!(id.ephemeral);
    }

    #[test]
    fn x25519_public_key_is_deterministic_from_secret() {
        let id = AgentIdentity::generate_ephemeral();
        let pk1 = id.x25519_public_key();
        let pk2 = id.x25519_public_key();
        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
    }

    #[test]
    fn verifying_key_bytes_are_32_bytes() {
        let id = AgentIdentity::generate_ephemeral();
        let vk = id.verifying_key();
        assert_eq!(vk.as_bytes().len(), 32);
    }

    #[test]
    fn x25519_public_key_bytes_are_32_bytes() {
        let id = AgentIdentity::generate_ephemeral();
        let pk = id.x25519_public_key();
        assert_eq!(pk.as_bytes().len(), 32);
    }

    #[test]
    fn ephemeral_did_contains_hex_encoded_verifying_key() {
        let id = AgentIdentity::generate_ephemeral();
        // DID format: "did:key:z{hex(vk_bytes)}"
        let vk_hex = hex::encode(id.verifying_key().as_bytes());
        let expected_suffix = format!("did:key:z{vk_hex}");
        assert_eq!(id.did, expected_suffix);
    }
}
