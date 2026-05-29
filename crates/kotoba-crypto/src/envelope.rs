use crate::aead::CryptoError;
/// Wire format: `signal:v1:{base64url(nonce || ciphertext_with_tag)}`
/// Compatible with the TypeScript `@gftd/signal` `signal:v1:` prefix convention.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

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

    #[test]
    fn signal_val_prefix_constant_value() {
        assert_eq!(SIGNAL_VAL_PREFIX, "signal:v1:");
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = random_key();
        let enc = encrypt_field(&key, b"").unwrap();
        assert!(enc.starts_with(SIGNAL_VAL_PREFIX));
        let dec = decrypt_field(&key, &enc).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn wrong_key_returns_decrypt_error() {
        let key1 = random_key();
        let key2 = random_key();
        // Ensure keys differ (astronomically likely)
        let enc = encrypt_field(&key1, b"secret").unwrap();
        let result = decrypt_field(&key2, &enc);
        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[test]
    fn same_plaintext_produces_different_ciphertexts() {
        let key = random_key();
        let msg = b"determinism check";
        let enc1 = encrypt_field(&key, msg).unwrap();
        let enc2 = encrypt_field(&key, msg).unwrap();
        // Due to random nonce, envelopes must differ
        assert_ne!(
            enc1, enc2,
            "nonces must be random — same plaintext must yield different envelopes"
        );
    }

    #[test]
    fn invalid_base64_after_prefix_returns_error() {
        let bad = format!("{}not!!valid==base64", SIGNAL_VAL_PREFIX);
        let result = decode_envelope(&bad);
        assert!(result.is_err(), "invalid base64 must be rejected");
    }

    #[test]
    fn truncated_payload_decrypt_fails() {
        let key = random_key();
        // A valid-looking envelope but with too few bytes after decoding (no nonce/tag)
        let truncated = format!("{}dG9vc2hvcnQ", SIGNAL_VAL_PREFIX); // "tooshort" base64url
        let result = decrypt_field(&key, &truncated);
        assert!(result.is_err(), "truncated ciphertext must fail to decrypt");
    }

    #[test]
    fn encode_envelope_produces_signal_prefix() {
        let data = vec![0u8, 1, 2, 255];
        let enc = encode_envelope(&data);
        assert!(enc.starts_with("signal:v1:"));
        // No padding characters in URL_SAFE_NO_PAD
        assert!(!enc.contains('='));
    }
}
