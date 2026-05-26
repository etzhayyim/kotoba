/// PRE key registry — maps (owner_did, accessor_did) to a wrapped re-encryption key.
///
/// The re-key itself is AES-GCM wrapped with the owner's local `enc_key` before
/// storage so that even if the BlockStore is compromised the re-keys remain protected.
///
/// Flow (Hybrid PRE):
///   1. Owner encrypts datum with AES-256-GCM(`data_key`).
///   2. Owner encrypts `data_key` with HPKE to owner's own public key → `ct_key`.
///   3. Owner derives `re_key` such that AEAD_open(`re_key`, `ct_key`) → `data_key`.
///      (In practice: `re_key` = `data_key` wrapped under a per-accessor KDF output.)
///   4. `PreKeyRegistry::grant()` stores `wrap_key(owner_enc_key, re_key, aad)`.
///   5. On access: `get_rekey_authed()` verifies CACAO, unwraps, returns `re_key`.
///   6. Requester uses `re_key` + `ct_key` to recover `data_key`, then decrypts datum.
use kotoba_core::{cid::KotobaCid, store::BlockStore};
use kotoba_auth::delegation::{DelegationChain, DelegationError};
use kotoba_crypto::key_wrap::{wrap_key, unwrap_key};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum PreKeyError {
    #[error("no re-key registered for ({0}, {1})")]
    NotFound(String, String),
    #[error("access denied: {0}")]
    Access(#[from] DelegationError),
    #[error("crypto: {0}")]
    Crypto(#[from] kotoba_crypto::aead::CryptoError),
    #[error("store: {0}")]
    Store(String),
}

pub struct PreKeyRegistry {
    store: Arc<dyn BlockStore + Send + Sync>,
    /// (owner_did, accessor_did) → CID of the wrapped re-key block.
    index: Arc<RwLock<HashMap<(String, String), KotobaCid>>>,
}

impl PreKeyRegistry {
    pub fn new(store: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self { store, index: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Register a re-key granting `accessor_did` access to data owned by `owner_did`.
    ///
    /// `re_key`:        raw re-encryption key bytes (≤ 32 bytes for AES-256).
    /// `owner_enc_key`: local secret used to wrap `re_key` at rest.
    pub async fn grant(
        &self,
        owner_did: &str,
        accessor_did: &str,
        re_key: &[u8],
        owner_enc_key: &[u8; 32],
    ) -> Result<KotobaCid, PreKeyError> {
        let aad = Self::aad(owner_did, accessor_did);
        let wrapped = wrap_key(owner_enc_key, re_key, aad.as_bytes())?;
        let cid = KotobaCid::from_bytes(&wrapped);
        self.store.put(&cid, &wrapped)
            .map_err(|e| PreKeyError::Store(e.to_string()))?;
        self.index.write().await
            .insert((owner_did.to_string(), accessor_did.to_string()), cid.clone());
        Ok(cid)
    }

    /// Verify CACAO then return the raw re-key for the (owner, accessor) pair.
    ///
    /// `chain` must grant `"quad:read"` on `owner_did` to `accessor_did`.
    /// Returns `Zeroizing<Vec<u8>>` so the key material is wiped on drop.
    pub async fn get_rekey_authed(
        &self,
        chain: &DelegationChain,
        owner_did: &str,
        accessor_did: &str,
        owner_enc_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, PreKeyError> {
        chain.verify(owner_did, "quad:read")?;
        self.unwrap_rekey(owner_did, accessor_did, owner_enc_key).await
    }

    /// Revoke access immediately — deletes re-key from both index and block store.
    pub async fn revoke(&self, owner_did: &str, accessor_did: &str) {
        let k = (owner_did.to_string(), accessor_did.to_string());
        if let Some(cid) = self.index.write().await.remove(&k) {
            let _ = self.store.delete(&cid);
        }
    }

    /// All accessors currently holding a re-key for `owner_did`.
    pub async fn list_accessors(&self, owner_did: &str) -> Vec<String> {
        self.index.read().await.keys()
            .filter(|(o, _)| o == owner_did)
            .map(|(_, a)| a.clone())
            .collect()
    }

    fn aad(owner_did: &str, accessor_did: &str) -> String {
        format!("{owner_did}:{accessor_did}")
    }

    async fn unwrap_rekey(
        &self,
        owner_did: &str,
        accessor_did: &str,
        owner_enc_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, PreKeyError> {
        let cid = self.index.read().await
            .get(&(owner_did.to_string(), accessor_did.to_string()))
            .cloned()
            .ok_or_else(|| PreKeyError::NotFound(owner_did.to_string(), accessor_did.to_string()))?;

        let wrapped = self.store.get(&cid)
            .map_err(|e| PreKeyError::Store(e.to_string()))?
            .ok_or_else(|| PreKeyError::Store("re-key block missing from store".into()))?;

        let aad = Self::aad(owner_did, accessor_did);
        Ok(unwrap_key(owner_enc_key, &wrapped, aad.as_bytes())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_store::MemoryBlockStore;

    fn store() -> Arc<dyn BlockStore + Send + Sync> {
        Arc::new(MemoryBlockStore::default())
    }

    fn rand_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
        k
    }

    #[tokio::test]
    async fn grant_and_retrieve_roundtrip() {
        let reg = PreKeyRegistry::new(store());
        let enc_key = rand_key();
        let re_key  = rand_key();

        reg.grant("did:owner", "did:accessor", &re_key, &enc_key).await.unwrap();

        // Build a minimal DelegationChain that passes verify() for open-access tests.
        // (Real CACAO sig verification is exercised in kotoba-auth tests.)
        // Here we test only the storage layer — use the internal helper directly.
        let recovered = reg.unwrap_rekey("did:owner", "did:accessor", &enc_key).await.unwrap();
        assert_eq!(recovered.as_slice(), re_key);
    }

    #[tokio::test]
    async fn revoke_removes_entry() {
        let reg = PreKeyRegistry::new(store());
        let enc_key = rand_key();
        reg.grant("did:owner", "did:bob", &rand_key(), &enc_key).await.unwrap();
        reg.revoke("did:owner", "did:bob").await;
        let result = reg.unwrap_rekey("did:owner", "did:bob", &enc_key).await;
        assert!(matches!(result, Err(PreKeyError::NotFound(_, _))));
    }

    #[tokio::test]
    async fn list_accessors_after_grant() {
        let reg = PreKeyRegistry::new(store());
        let enc_key = rand_key();
        reg.grant("did:alice", "did:bob",   &rand_key(), &enc_key).await.unwrap();
        reg.grant("did:alice", "did:carol", &rand_key(), &enc_key).await.unwrap();
        let mut list = reg.list_accessors("did:alice").await;
        list.sort();
        assert_eq!(list, vec!["did:bob", "did:carol"]);
    }
}
