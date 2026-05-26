//! X25519 ECIES key encapsulation (lightweight HPKE-like).
//!
//! Wire format: `ephemeral_pk(32) || nonce(12) || AES-256-GCM-ciphertext`
//!
//! Shared secret derivation:
//!   `ss = X25519(ephemeral_sk, recipient_pk)`
//!   `enc_key = HKDF-SHA256(ikm=ss, salt=ephemeral_pk||recipient_pk, info=b"kotoba/hpke/v1")`

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    aead::{seal, open, CryptoError},
    hkdf::derive_key_with_salt,
};

pub const EPHEMERAL_PK_LEN: usize = 32;

/// Seal `plaintext` to `recipient_pk`.
///
/// Returns `ephemeral_pk(32) || nonce(12) || AES-GCM-ciphertext`.
pub fn hpke_seal(recipient_pk: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Generate ephemeral X25519 keypair
    let eph_sk = EphemeralSecret::random_from_rng(rand_core::OsRng);
    let eph_pk = PublicKey::from(&eph_sk);

    // DH: shared_secret = X25519(eph_sk, recipient_pk)
    let ss = eph_sk.diffie_hellman(recipient_pk);
    let ss_bytes = Zeroizing::new(*ss.as_bytes());

    // Derive encryption key: HKDF(ikm=ss, salt=eph_pk||recipient_pk, info="kotoba/hpke/v1")
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pk.as_bytes());
    salt[32..].copy_from_slice(recipient_pk.as_bytes());
    let enc_key: [u8; 32] = derive_key_with_salt(ss_bytes.as_slice(), &salt, b"kotoba/hpke/v1");

    // AES-256-GCM seal → nonce(12) || ct
    let ct = seal(&enc_key, plaintext)?;

    // Wire: eph_pk(32) || nonce(12) || ciphertext
    let mut out = Vec::with_capacity(EPHEMERAL_PK_LEN + ct.len());
    out.extend_from_slice(eph_pk.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed blob produced by `hpke_seal`.
pub fn hpke_open(
    recipient_sk: &StaticSecret,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < EPHEMERAL_PK_LEN {
        return Err(CryptoError::TooShort(EPHEMERAL_PK_LEN));
    }

    let eph_pk_bytes: [u8; 32] = sealed[..EPHEMERAL_PK_LEN]
        .try_into()
        .map_err(|_| CryptoError::TooShort(EPHEMERAL_PK_LEN))?;
    let eph_pk = PublicKey::from(eph_pk_bytes);
    let ct = &sealed[EPHEMERAL_PK_LEN..];

    // DH: shared_secret = X25519(recipient_sk, eph_pk)
    let ss = recipient_sk.diffie_hellman(&eph_pk);
    let ss_bytes = Zeroizing::new(*ss.as_bytes());

    // Derive the same enc_key
    let recipient_pk = PublicKey::from(recipient_sk);
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pk.as_bytes());
    salt[32..].copy_from_slice(recipient_pk.as_bytes());
    let enc_key: [u8; 32] = derive_key_with_salt(ss_bytes.as_slice(), &salt, b"kotoba/hpke/v1");

    open(&enc_key, ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    fn random_keypair() -> (StaticSecret, PublicKey) {
        let sk = StaticSecret::random_from_rng(rand_core::OsRng);
        let pk = PublicKey::from(&sk);
        (sk, pk)
    }

    #[test]
    fn hpke_roundtrip() {
        let (sk, pk) = random_keypair();
        let msg = b"agent-sovereign secret vault key";
        let sealed = hpke_seal(&pk, msg).unwrap();
        let opened = hpke_open(&sk, &sealed).unwrap();
        assert_eq!(opened.as_slice(), msg);
    }

    #[test]
    fn hpke_wrong_key_fails() {
        let (_sk, pk) = random_keypair();
        let (wrong_sk, _) = random_keypair();
        let msg = b"secret";
        let sealed = hpke_seal(&pk, msg).unwrap();
        assert!(hpke_open(&wrong_sk, &sealed).is_err());
    }

    #[test]
    fn hpke_sealed_length() {
        let (_sk, pk) = random_keypair();
        let msg = b"hello";
        let sealed = hpke_seal(&pk, msg).unwrap();
        // eph_pk(32) + nonce(12) + plaintext(5) + tag(16) = 65
        assert_eq!(sealed.len(), 32 + 12 + msg.len() + 16);
    }

    #[test]
    fn hpke_each_seal_is_different() {
        let (_sk, pk) = random_keypair();
        let msg = b"same message";
        let s1 = hpke_seal(&pk, msg).unwrap();
        let s2 = hpke_seal(&pk, msg).unwrap();
        // Ephemeral key randomises each seal
        assert_ne!(s1, s2);
    }
}
