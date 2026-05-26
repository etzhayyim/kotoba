use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, AeadCore, OsRng}};
use thiserror::Error;
use zeroize::Zeroizing;

pub const KEY_LEN:   usize = 32;  // AES-256
pub const NONCE_LEN: usize = 12;  // GCM 96-bit nonce
pub const TAG_LEN:   usize = 16;  // GCM auth tag

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AEAD seal failed")]
    SealFailed,
    #[error("AEAD open failed: ciphertext tampered or wrong key")]
    OpenFailed,
    #[error("ciphertext too short (< {0} bytes)")]
    TooShort(usize),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
}

/// AES-256-GCM seal.
/// Returns `nonce || ciphertext_with_tag` (12 + plaintext.len() + 16 bytes).
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::SealFailed)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, plaintext).map_err(|_| CryptoError::SealFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM seal with explicit nonce (for deterministic tests only).
pub fn seal_with_nonce(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::SealFailed)?;
    let n = aes_gcm::Nonce::from(*nonce);
    let ct = cipher.encrypt(&n, plaintext).map_err(|_| CryptoError::SealFailed)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AES-256-GCM open.
/// Expects `nonce || ciphertext_with_tag` (as produced by `seal`).
pub fn open(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::TooShort(NONCE_LEN + TAG_LEN));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::OpenFailed)?;
    let nonce_arr: [u8; NONCE_LEN] = data[..NONCE_LEN].try_into()
        .map_err(|_| CryptoError::TooShort(NONCE_LEN))?;
    let nonce = aes_gcm::Nonce::from(nonce_arr);
    let pt = cipher.decrypt(&nonce, &data[NONCE_LEN..]).map_err(|_| CryptoError::OpenFailed)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
        k
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = random_key();
        let msg = b"hello kotoba-crypto";
        let ct = seal(&key, msg).unwrap();
        let pt = open(&key, &ct).unwrap();
        assert_eq!(pt.as_slice(), msg);
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let key = random_key();
        let ct = seal(&key, b"secret").unwrap();
        let wrong = random_key();
        assert!(open(&wrong, &ct).is_err());
    }

    #[test]
    fn open_with_tampered_data_fails() {
        let key = random_key();
        let mut ct = seal(&key, b"secret").unwrap();
        ct[NONCE_LEN] ^= 0xFF;
        assert!(open(&key, &ct).is_err());
    }

    #[test]
    fn ciphertext_is_longer_than_plaintext() {
        let key = random_key();
        let pt = b"short";
        let ct = seal(&key, pt).unwrap();
        assert!(ct.len() > pt.len());
        assert_eq!(ct.len(), NONCE_LEN + pt.len() + TAG_LEN);
    }
}
