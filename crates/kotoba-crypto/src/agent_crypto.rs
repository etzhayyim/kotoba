//! `AgentCrypto` — opaque encryption engine trait.
//!
//! The agent can encrypt and decrypt data but never accesses raw key bytes.
//! Implementations hold vault key material in `Zeroizing<[u8;32]>` with no
//! public accessor.
//!
//! ## signal:v1: envelope
//! All encrypted text fields use the `signal:v1:<base64>` envelope so stored
//! ciphertext is identifiable and versioned.

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::{
    aead::{open, seal, CryptoError},
    envelope::{decode_envelope, encode_envelope},
    hkdf::derive_key_with_salt,
};

/// Opaque encryption-engine trait.
///
/// Implementors hold key material without exposing raw bytes.
/// All methods are `async` to allow future hardware-backed keys.
#[async_trait]
pub trait AgentCrypto: Send + Sync + 'static {
    /// Encrypt `plaintext` using a scope-derived key.
    ///
    /// `scope` is a domain label such as `"email/from"` used to derive a
    /// per-field subkey via HKDF.  The returned bytes are raw AES-GCM output
    /// (`nonce || ciphertext`) — NOT yet envelope-encoded.
    async fn encrypt(&self, scope: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt bytes produced by `encrypt`.
    async fn decrypt(
        &self,
        scope: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    /// Encrypt a UTF-8 text field and return a `signal:v1:<base64>` envelope.
    async fn seal_field(&self, scope: &[u8], text: &str) -> Result<String, CryptoError> {
        let ct = self.encrypt(scope, text.as_bytes()).await?;
        Ok(encode_envelope(&ct))
    }

    /// Decrypt a `signal:v1:<base64>` envelope and return the UTF-8 text.
    async fn open_field(&self, scope: &[u8], envelope: &str) -> Result<String, CryptoError> {
        let ct = decode_envelope(envelope)?;
        let mut pt = self.decrypt(scope, &ct).await?;
        // Move the inner Vec out without cloning to avoid an extra plaintext copy.
        // `pt` is left holding an empty Vec (zeroized on drop — no-op for empty).
        let inner = std::mem::take(&mut *pt);
        String::from_utf8(inner)
            .map_err(|e| CryptoError::InvalidEnvelope(format!("UTF-8 decode: {e}")))
    }

    /// Encrypt a blob directly (no envelope encoding — for vault blob storage).
    async fn encrypt_blob(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.encrypt(b"blob", plaintext).await
    }

    /// Decrypt a blob produced by `encrypt_blob`.
    async fn decrypt_blob(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.decrypt(b"blob", ciphertext).await
    }
}

/// A key-material-backed implementation of `AgentCrypto`.
///
/// The vault key is held in `Zeroizing<[u8;32]>` — no raw accessor is exposed.
/// Scope subkeys are derived with HKDF: `scope_key = HKDF(vault_key, salt=scope, info=b"kotoba/scope-key/v1")`.
pub struct VaultKeyedCrypto {
    vault_key: Zeroizing<[u8; 32]>,
}

impl VaultKeyedCrypto {
    /// Wrap an existing 32-byte vault key.  The caller must already hold the
    /// key in a `Zeroizing` allocation; this moves ownership in.
    pub fn new(vault_key: Zeroizing<[u8; 32]>) -> Self {
        Self { vault_key }
    }

    fn scope_key(&self, scope: &[u8]) -> [u8; 32] {
        derive_key_with_salt(self.vault_key.as_ref(), scope, b"kotoba/scope-key/v1")
    }
}

#[async_trait]
impl AgentCrypto for VaultKeyedCrypto {
    async fn encrypt(&self, scope: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sk = self.scope_key(scope);
        seal(&sk, plaintext)
    }

    async fn decrypt(
        &self,
        scope: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let sk = self.scope_key(scope);
        open(&sk, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_crypto() -> VaultKeyedCrypto {
        let key = Zeroizing::new([0x42u8; 32]);
        VaultKeyedCrypto::new(key)
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let c = test_crypto();
        let scope = b"email/body";
        let msg = b"Hello, world!";
        let ct = c.encrypt(scope, msg).await.unwrap();
        let pt = c.decrypt(scope, &ct).await.unwrap();
        assert_eq!(pt.as_slice(), msg);
    }

    #[tokio::test]
    async fn different_scopes_produce_different_ciphertext() {
        let c = test_crypto();
        let msg = b"same message";
        let ct1 = c.encrypt(b"scope-a", msg).await.unwrap();
        let ct2 = c.encrypt(b"scope-b", msg).await.unwrap();
        // Different scope keys → different nonces or key, so ct differs
        assert_ne!(ct1, ct2);
    }

    #[tokio::test]
    async fn wrong_scope_fails_decrypt() {
        let c = test_crypto();
        let ct = c.encrypt(b"scope-a", b"secret").await.unwrap();
        // Decrypting with different scope → wrong key → OpenFailed
        assert!(c.decrypt(b"scope-b", &ct).await.is_err());
    }

    #[tokio::test]
    async fn seal_open_field_roundtrip() {
        let c = test_crypto();
        let text = "test@example.com";
        let envelope = c.seal_field(b"email/from", text).await.unwrap();
        assert!(envelope.starts_with("signal:v1:"), "envelope={envelope}");
        let recovered = c.open_field(b"email/from", &envelope).await.unwrap();
        assert_eq!(recovered, text);
    }

    #[tokio::test]
    async fn blob_encrypt_decrypt() {
        let c = test_crypto();
        let data = b"binary blob data";
        let ct = c.encrypt_blob(data).await.unwrap();
        let pt = c.decrypt_blob(&ct).await.unwrap();
        assert_eq!(pt.as_slice(), data);
    }

    #[tokio::test]
    async fn encrypt_empty_plaintext_roundtrip() {
        let c = test_crypto();
        let ct = c.encrypt(b"scope", b"").await.unwrap();
        let pt = c.decrypt(b"scope", &ct).await.unwrap();
        assert!(pt.is_empty(), "empty plaintext must round-trip");
    }

    #[tokio::test]
    async fn seal_field_starts_with_signal_prefix() {
        let c = test_crypto();
        let env = c.seal_field(b"any-scope", "test value").await.unwrap();
        assert!(
            env.starts_with("signal:v1:"),
            "envelope must start with signal:v1:"
        );
    }

    #[tokio::test]
    async fn open_field_wrong_scope_returns_error() {
        let c = test_crypto();
        let env = c.seal_field(b"scope-correct", "hello").await.unwrap();
        let result = c.open_field(b"scope-wrong", &env).await;
        assert!(result.is_err(), "wrong scope must fail to open field");
    }

    #[tokio::test]
    async fn same_plaintext_different_scope_different_blob_ciphertext() {
        let c = test_crypto();
        let ct1 = c.encrypt_blob(b"same data").await.unwrap();
        let ct2 = c.encrypt_blob(b"same data").await.unwrap();
        // Nonces are random → ciphertexts differ even with same scope (b"blob")
        assert_ne!(ct1, ct2, "random nonces ensure ciphertexts differ");
    }

    #[tokio::test]
    async fn scope_key_derivation_produces_different_keys_per_scope() {
        let c = test_crypto();
        let msg = b"payload";
        let ct_a = c.encrypt(b"alpha", msg).await.unwrap();
        let ct_b = c.encrypt(b"beta", msg).await.unwrap();
        // Ciphertexts differ because scope keys differ (plus random nonces)
        assert_ne!(ct_a, ct_b);
    }

    #[tokio::test]
    async fn open_field_invalid_envelope_prefix_returns_error() {
        let c = test_crypto();
        let result = c.open_field(b"scope", "not-a-signal-value").await;
        assert!(result.is_err(), "must reject invalid envelope prefix");
    }
}
