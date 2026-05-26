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
}
