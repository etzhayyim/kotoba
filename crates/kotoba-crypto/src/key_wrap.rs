/// AEAD-based key wrapping.
/// Wraps a key (or arbitrary secret bytes) under a wrapping key using AES-256-GCM.
/// `aad` = additional authenticated data (e.g. DID or device label).
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, AeadCore, OsRng}};
use zeroize::Zeroizing;
use crate::aead::CryptoError;

/// Wrap `plaintext_key` under `wrapping_key` with optional `aad`.
/// Returns `nonce || wrapped_bytes` (sealed with AES-256-GCM, aad as AAD).
pub fn wrap_key(
    wrapping_key: &[u8; 32],
    plaintext_key: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::aead::Payload;
    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| CryptoError::SealFailed)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let payload = Payload { msg: plaintext_key, aad };
    let ct = cipher.encrypt(&nonce, payload).map_err(|_| CryptoError::SealFailed)?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap a previously wrapped key.
/// `data` = `nonce || wrapped_bytes` as returned by `wrap_key`.
/// Returns `Zeroizing<Vec<u8>>` so the plaintext key material is wiped on drop.
pub fn unwrap_key(
    wrapping_key: &[u8; 32],
    data: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    use aes_gcm::aead::Payload;
    if data.len() < 12 {
        return Err(CryptoError::TooShort(12));
    }
    let cipher = Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| CryptoError::OpenFailed)?;
    let nonce = aes_gcm::Nonce::from_slice(&data[..12]);
    let payload = Payload { msg: &data[12..], aad };
    let pt = cipher.decrypt(nonce, payload).map_err(|_| CryptoError::OpenFailed)?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
        k
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let wk = random_key();
        let sk = random_key();
        let aad = b"did:plc:alice";
        let wrapped = wrap_key(&wk, &sk, aad).unwrap();
        let recovered = unwrap_key(&wk, &wrapped, aad).unwrap();
        assert_eq!(recovered.as_slice(), sk);
    }

    #[test]
    fn wrong_aad_fails() {
        let wk = random_key();
        let sk = random_key();
        let wrapped = wrap_key(&wk, &sk, b"alice").unwrap();
        assert!(unwrap_key(&wk, &wrapped, b"bob").is_err());
    }
}
