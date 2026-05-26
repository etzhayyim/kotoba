/// SecureVault — AEAD-encrypted wrapper around `Vault`.
/// Plaintext bytes are AES-256-GCM sealed before being stored in the underlying Vault.
/// The `signal:v1:` envelope is used for the wire format.
///
/// This satisfies the Vault zero-knowledge invariant: the store only ever holds ciphertext.
///
/// `put_with_policy()` additionally returns a `DataPolicy::Encrypted` so that callers can
/// attach the policy directly to `ChainEntry` / `QuadObject::Encrypted` without having to
/// re-derive the CID.
use crate::vault::{Vault, BlobRef};
use kotoba_core::DataPolicy;
use bytes::Bytes;

/// AEAD-encrypted Vault.  Callers must supply the 32-byte vault key.
pub struct SecureVault {
    inner: Vault,
}

impl SecureVault {
    pub fn new() -> Self {
        Self { inner: Vault::new() }
    }

    pub fn with_vault(vault: Vault) -> Self {
        Self { inner: vault }
    }

    /// Encrypt `plaintext` with `key` and store the ciphertext.
    /// Returns a `BlobRef` keyed on the ciphertext CID (NOT the plaintext CID).
    pub async fn put(
        &self,
        key: &[u8; 32],
        plaintext: Bytes,
    ) -> Result<BlobRef, kotoba_crypto::aead::CryptoError> {
        let ct = kotoba_crypto::aead::seal(key, &plaintext)?;
        Ok(self.inner.put(Bytes::from(ct)).await)
    }

    /// Encrypt `plaintext`, store it, and return both the `BlobRef` and a
    /// `DataPolicy::Encrypted` that can be attached to a `ChainEntry` or
    /// `QuadObject::Encrypted`.
    ///
    /// `policy_cid`: CID of the PRE key-registry entry that controls who can
    /// decrypt (e.g. the CID returned by `PreKeyRegistry::grant()`).
    /// Pass `blob_ref.cid` as `policy_cid` for single-key blobs (no PRE delegation).
    pub async fn put_with_policy(
        &self,
        key: &[u8; 32],
        plaintext: Bytes,
        policy_cid: kotoba_core::cid::KotobaCid,
    ) -> Result<(BlobRef, DataPolicy), kotoba_crypto::aead::CryptoError> {
        let blob_ref = self.put(key, plaintext).await?;
        let policy = DataPolicy::Encrypted {
            ct_cid:     blob_ref.cid.clone(),
            policy_cid,
        };
        Ok((blob_ref, policy))
    }

    /// Retrieve ciphertext by CID and decrypt with `key`.
    pub async fn get(
        &self,
        key: &[u8; 32],
        blob_ref: &BlobRef,
    ) -> Result<Option<Bytes>, kotoba_crypto::aead::CryptoError> {
        let Some(ct) = self.inner.get(&blob_ref.cid).await else { return Ok(None) };
        let pt = kotoba_crypto::aead::open(key, &ct)?;
        Ok(Some(Bytes::from(pt.to_vec())))
    }

    pub async fn contains(&self, blob_ref: &BlobRef) -> bool {
        self.inner.contains(&blob_ref.cid).await
    }
}

impl Default for SecureVault {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
        k
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let sv  = SecureVault::new();
        let key = random_key();
        let data = Bytes::from_static(b"secret payload");
        let blob_ref = sv.put(&key, data.clone()).await.unwrap();
        let got = sv.get(&key, &blob_ref).await.unwrap().unwrap();
        assert_eq!(got, data);
    }

    #[tokio::test]
    async fn wrong_key_returns_error() {
        let sv  = SecureVault::new();
        let key = random_key();
        let wrong = random_key();
        let blob_ref = sv.put(&key, Bytes::from_static(b"top secret")).await.unwrap();
        assert!(sv.get(&wrong, &blob_ref).await.is_err());
    }

    #[tokio::test]
    async fn put_with_policy_returns_encrypted_data_policy() {
        use kotoba_core::{cid::KotobaCid, DataPolicy};
        let sv  = SecureVault::new();
        let key = random_key();
        let plaintext = Bytes::from_static(b"policy test");
        let policy_cid = KotobaCid::from_bytes(b"fake-pre-key-registry-entry");
        let (blob_ref, policy) = sv
            .put_with_policy(&key, plaintext.clone(), policy_cid.clone())
            .await
            .unwrap();
        match policy {
            DataPolicy::Encrypted { ct_cid, policy_cid: pcid } => {
                assert_eq!(ct_cid, blob_ref.cid);
                assert_eq!(pcid, policy_cid);
            }
            DataPolicy::Open => panic!("expected Encrypted policy"),
        }
        // Decrypt must still work via the existing get() path.
        let got = sv.get(&key, &blob_ref).await.unwrap().unwrap();
        assert_eq!(got, plaintext);
    }

    #[tokio::test]
    async fn raw_vault_holds_ciphertext_not_plaintext() {
        let sv  = SecureVault::new();
        let key = random_key();
        let plaintext = Bytes::from_static(b"must not be plaintext in store");
        let blob_ref = sv.put(&key, plaintext.clone()).await.unwrap();
        // Read raw bytes from the underlying vault — should differ from plaintext
        let raw = sv.inner.get(&blob_ref.cid).await.unwrap();
        assert_ne!(raw, plaintext);
    }
}
