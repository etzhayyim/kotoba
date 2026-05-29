use crate::identity::IdentityKeyPair;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::ZeroizeOnDrop;

pub type PreKeyId = u32;
pub type SignedPreKeyId = u32;

/// Ephemeral one-time pre-key (OPK).
#[derive(ZeroizeOnDrop)]
pub struct PreKey {
    pub id: PreKeyId,
    pub private: StaticSecret,
}

/// Signed semi-static pre-key (SPK).
#[derive(ZeroizeOnDrop)]
pub struct SignedPreKey {
    pub id: SignedPreKeyId,
    pub private: StaticSecret,
    /// Ed25519 signature over the public SPK bytes.
    pub signature: Vec<u8>,
}

/// Public pre-key bundle shared during X3DH.
/// Corresponds to `ai.gftd.signal.getPrekeyBundle` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    /// DID of the bundle owner.
    pub did: String,
    pub device_id: String,
    /// Identity key (serialised `IdentityKey`).
    pub identity_key: crate::identity::IdentityKey,
    /// Signed pre-key public bytes (32 bytes).
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_id: SignedPreKeyId,
    /// Ed25519 signature of `signed_prekey` by `identity_key.signing`.
    pub signed_prekey_sig: Vec<u8>,
    /// Optional one-time pre-key public bytes.
    pub one_time_prekey: Option<Vec<u8>>,
    pub one_time_prekey_id: Option<PreKeyId>,
}

impl PreKey {
    pub fn generate(id: PreKeyId) -> Self {
        Self {
            id,
            private: StaticSecret::random_from_rng(OsRng),
        }
    }
    pub fn public_bytes(&self) -> [u8; 32] {
        X25519Public::from(&self.private).to_bytes()
    }
    pub fn dh(&self, remote: &[u8; 32]) -> [u8; 32] {
        self.private
            .diffie_hellman(&X25519Public::from(*remote))
            .to_bytes()
    }
}

impl SignedPreKey {
    pub fn generate(id: SignedPreKeyId, identity_kp: &IdentityKeyPair) -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let pub_bytes = X25519Public::from(&private).to_bytes();
        let signature = identity_kp.sign(&pub_bytes);
        Self {
            id,
            private,
            signature,
        }
    }
    pub fn public_bytes(&self) -> [u8; 32] {
        X25519Public::from(&self.private).to_bytes()
    }
    pub fn dh(&self, remote: &[u8; 32]) -> [u8; 32] {
        self.private
            .diffie_hellman(&X25519Public::from(*remote))
            .to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;

    #[test]
    fn signed_prekey_signature_verifies() {
        let ik = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(1, &ik);
        let pub_bytes = spk.public_bytes();
        assert!(ik.public_key().verify(&pub_bytes, &spk.signature));
    }

    #[test]
    fn prekey_generate_has_correct_id() {
        let pk = PreKey::generate(42);
        assert_eq!(pk.id, 42);
    }

    #[test]
    fn prekey_public_bytes_is_32_bytes() {
        let pk = PreKey::generate(1);
        let pub_bytes = pk.public_bytes();
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn signed_prekey_has_correct_id() {
        let ik = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(99, &ik);
        assert_eq!(spk.id, 99);
    }

    #[test]
    fn signed_prekey_public_bytes_is_32_bytes() {
        let ik = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(1, &ik);
        let pub_bytes = spk.public_bytes();
        assert_eq!(pub_bytes.len(), 32);
    }

    #[test]
    fn signed_prekey_signature_is_non_empty() {
        let ik = IdentityKeyPair::generate();
        let spk = SignedPreKey::generate(1, &ik);
        assert!(!spk.signature.is_empty());
    }

    #[test]
    fn prekey_dh_produces_32_byte_secret() {
        let pk_a = PreKey::generate(1);
        let pk_b = PreKey::generate(2);
        let shared = pk_a.dh(&pk_b.public_bytes());
        assert_eq!(shared.len(), 32);
    }

    #[test]
    fn prekey_dh_is_symmetric() {
        let pk_a = PreKey::generate(1);
        let pk_b = PreKey::generate(2);
        let shared_ab = pk_a.dh(&pk_b.public_bytes());
        let shared_ba = pk_b.dh(&pk_a.public_bytes());
        assert_eq!(shared_ab, shared_ba, "Diffie-Hellman must be symmetric");
    }

    #[test]
    fn prekey_bundle_fields_round_trip() {
        let ik = IdentityKeyPair::generate();
        let bundle = PreKeyBundle {
            did: "did:test:abc".to_string(),
            device_id: "device-1".to_string(),
            identity_key: ik.public_key(),
            signed_prekey: vec![1u8; 32],
            signed_prekey_id: 5,
            signed_prekey_sig: vec![0u8; 64],
            one_time_prekey: None,
            one_time_prekey_id: None,
        };
        assert_eq!(bundle.did, "did:test:abc");
        assert_eq!(bundle.signed_prekey_id, 5);
        assert!(bundle.one_time_prekey.is_none());
    }
}
