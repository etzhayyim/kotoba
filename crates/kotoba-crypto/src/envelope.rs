/// Wire format: `signal:v1:{base64url(nonce || ciphertext_with_tag)}`
/// Compatible with the TypeScript `@gftd/signal` `signal:v1:` prefix convention.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;
use crate::aead::CryptoError;

pub const SIGNAL_VAL_PREFIX: &str = "signal:v1:";

/// Encode `nonce || ciphertext` bytes as a `signal:v1:` envelope string.
pub fn encode_envelope(data: &[u8]) -> String {
    format!("{}{}", SIGNAL_VAL_PREFIX, URL_SAFE_NO_PAD.encode(data))
}

/// Decode a `signal:v1:{base64url}` envelope, returning the raw bytes.
pub fn decode_envelope(s: &str) -> Result<Vec<u8>, CryptoError> {
    let inner = s
        .strip_prefix(SIGNAL_VAL_PREFIX)
        .ok_or_else(|| CryptoError::InvalidEnvelope(format!("missing prefix: {s}")))?;
    let bytes = URL_SAFE_NO_PAD.decode(inner)?;
    Ok(bytes)
}

/// High-level: AES-256-GCM encrypt plaintext and return a `signal:v1:` string.
pub fn encrypt_field(key: &[u8; 32], plaintext: &[u8]) -> Result<String, CryptoError> {
    let ct = crate::aead::seal(key, plaintext)?;
    Ok(encode_envelope(&ct))
}

/// High-level: decode `signal:v1:` envelope and AES-256-GCM decrypt.
/// Returns `Zeroizing<Vec<u8>>` so plaintext is wiped from memory on drop.
pub fn decrypt_field(key: &[u8; 32], envelope: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let raw = decode_envelope(envelope)?;
    crate::aead::open(key, &raw)
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
    fn roundtrip_field_encryption() {
        let key = random_key();
        let msg = b"hello field encryption";
        let enc = encrypt_field(&key, msg).unwrap();
        assert!(enc.starts_with(SIGNAL_VAL_PREFIX));
        let dec = decrypt_field(&key, &enc).unwrap();
        assert_eq!(dec.as_slice(), msg);
    }

    #[test]
    fn decode_non_signal_prefix_fails() {
        let err = decode_envelope("not-a-signal-value");
        assert!(matches!(err, Err(CryptoError::InvalidEnvelope(_))));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let data = b"raw bytes go here";
        let enc = encode_envelope(data);
        let dec = decode_envelope(&enc).unwrap();
        assert_eq!(dec, data);
    }
}
