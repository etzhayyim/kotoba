//! `SovereignCrypto` — agent-sovereign key management (Layer 2).
//!
//! The vault key (`[u8; 32]`) is:
//!   1. Generated randomly at genesis,
//!   2. Wrapped (ECIES) with the agent's X25519 public key,
//!   3. Stored as a block in the `BlockStore`,
//!   4. A key-ref JSON `{ cid, version }` is written to `KseStore`.
//!
//! The agent can encrypt/decrypt but **never** exposes raw key bytes.
//!
//! ## Key Pointer Storage
//! ```text
//! KseStore key: "agent/crypto/{did_slug}/current.json"
//! KseStore key: "agent/crypto/{did_slug}/v{N}.json"
//! ```
//!
//! Each pointer JSON: `{ "cid": "<multibase>", "version": N }`
//!
//! ## Key Rotation
//! Generate a new random vault key, wrap it, store the block, update the
//! `current.json` pointer, and archive the old pointer as `v{N}.json`.
//! Old wrapped-key blocks are retained for historical decryption.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use kotoba_crypto::{AgentCrypto, CryptoError, VaultKeyedCrypto};
use kotoba_crypto::hpke::{hpke_seal, hpke_open};

use crate::agent_identity::AgentIdentity;
use crate::store::KseStore;

// ── Key pointer JSON ──────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
struct KeyRef {
    cid:     String,
    version: u64,
}

// ── SovereignCrypto ──────────────────────────────────────────────────────────

/// Agent-sovereign crypto engine.
///
/// Wraps a `VaultKeyedCrypto` and manages key lifecycle (genesis, load,
/// rotation) against a `BlockStore` + `KseStore`.
pub struct SovereignCrypto {
    inner: VaultKeyedCrypto,
}

impl SovereignCrypto {
    // ── Lifecycle ─────────────────────────────────────────────────────────

    /// Load the current vault key from storage, or generate a new one (genesis).
    ///
    /// Algorithm:
    ///   1. Check KseStore for `agent/crypto/{slug}/current.json`
    ///   2. If present: load wrapped blob from BlockStore, HPKE-unwrap with agent sk
    ///   3. If absent: generate random key, wrap, store, write pointer
    pub async fn load_or_genesis(
        identity:    &AgentIdentity,
        kse_store:   &KseStore,
        block_store: &Arc<dyn BlockStore + Send + Sync>,
    ) -> Result<Self> {
        let slug    = identity.did_slug();
        let cur_key = format!("agent/crypto/{slug}/current.json");

        if kse_store.exists(&cur_key).await {
            // Bootstrap: load existing key
            let data  = kse_store.get(&cur_key).await
                .context("read key-ref pointer")?;
            let key_ref: KeyRef = serde_json::from_slice(&data)
                .context("parse key-ref JSON")?;

            let cid = KotobaCid::from_multibase(&key_ref.cid)
                .ok_or_else(|| anyhow!("parse key ref CID: {}", key_ref.cid))?;

            let wrapped = block_store.get(&cid)
                .context("load wrapped key block")?
                .ok_or_else(|| anyhow!("wrapped key block not found: {}", key_ref.cid))?;

            let vault_key_bytes = hpke_open(&identity.dh_secret, &wrapped)
                .context("HPKE unwrap vault key")?;

            if vault_key_bytes.len() != 32 {
                return Err(anyhow!("vault key has wrong length: {}", vault_key_bytes.len()));
            }

            let mut arr = Zeroizing::new([0u8; 32]);
            arr.copy_from_slice(&vault_key_bytes);

            tracing::info!(
                did = %identity.did,
                version = key_ref.version,
                cid = %key_ref.cid,
                "SovereignCrypto: vault key loaded from store"
            );

            Ok(Self { inner: VaultKeyedCrypto::new(arr) })
        } else {
            // Genesis: generate and persist
            Self::genesis(identity, kse_store, block_store).await
        }
    }

    /// Genesis flow: generate a new random vault key, wrap it, persist.
    async fn genesis(
        identity:    &AgentIdentity,
        kse_store:   &KseStore,
        block_store: &Arc<dyn BlockStore + Send + Sync>,
    ) -> Result<Self> {
        // Generate 32-byte random vault key
        let mut raw_key = Zeroizing::new([0u8; 32]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, raw_key.as_mut());

        // HPKE-wrap with agent's X25519 public key
        let pk      = identity.x25519_public_key();
        let wrapped = hpke_seal(&pk, raw_key.as_ref())
            .context("HPKE wrap vault key")?;

        // Store wrapped blob; CID = blake3 of content
        let cid    = store_block(block_store, &wrapped)?;
        let cid_mb = cid.to_multibase();

        // Write key-ref pointer
        let key_ref = KeyRef { cid: cid_mb.clone(), version: 1 };
        let slug    = identity.did_slug();
        write_key_ref(kse_store, &slug, &key_ref).await?;

        tracing::info!(
            did      = %identity.did,
            cid      = %cid_mb,
            "SovereignCrypto: genesis — new vault key generated and wrapped"
        );

        Ok(Self { inner: VaultKeyedCrypto::new(raw_key) })
    }

    /// Rotate the vault key.
    ///
    /// Archives the current pointer as `v{N}.json`, generates a new vault key,
    /// wraps it, stores it, and updates `current.json`.
    pub async fn rotate(
        &self,
        identity:    &AgentIdentity,
        kse_store:   &KseStore,
        block_store: &Arc<dyn BlockStore + Send + Sync>,
    ) -> Result<Self> {
        let slug    = identity.did_slug();
        let cur_key = format!("agent/crypto/{slug}/current.json");

        // Read current pointer for archiving
        let current_version = if kse_store.exists(&cur_key).await {
            let data = kse_store.get(&cur_key).await.context("read current key-ref")?;
            let kr: KeyRef = serde_json::from_slice(&data).context("parse current key-ref")?;
            // Archive as v{N}
            let archive_key = format!("agent/crypto/{slug}/v{}.json", kr.version);
            kse_store.put(&archive_key, data)
                .await
                .context("archive key-ref")?;
            kr.version
        } else {
            0
        };

        // Generate new vault key
        let mut raw_key = Zeroizing::new([0u8; 32]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, raw_key.as_mut());

        // Wrap and store
        let pk      = identity.x25519_public_key();
        let wrapped = hpke_seal(&pk, raw_key.as_ref())
            .context("HPKE wrap rotated vault key")?;
        let cid    = store_block(block_store, &wrapped)?;
        let cid_mb = cid.to_multibase();

        let new_version = current_version + 1;
        let key_ref     = KeyRef { cid: cid_mb.clone(), version: new_version };
        write_key_ref(kse_store, &slug, &key_ref).await?;

        tracing::info!(
            did     = %identity.did,
            version = new_version,
            cid     = %cid_mb,
            "SovereignCrypto: vault key rotated"
        );

        Ok(Self { inner: VaultKeyedCrypto::new(raw_key) })
    }

    /// Re-encrypt a blob after key rotation.
    ///
    /// Decrypts `old_ciphertext` with `old_crypto` (the pre-rotation instance),
    /// then encrypts the result with `self` (the post-rotation instance).
    /// The intermediate plaintext is held in a `Zeroizing` buffer and wiped on drop.
    ///
    /// Typical call pattern:
    // let new_crypto = old_crypto.rotate(&id, &kse, &blk).await?;
    // let new_ct = new_crypto.reencrypt_blob(&old_crypto, b"blob", &old_ct).await?;
    pub async fn reencrypt_blob(
        &self,
        old_crypto: &SovereignCrypto,
        scope: &[u8],
        old_ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let plaintext = old_crypto.inner.decrypt(scope, old_ciphertext).await?;
        self.inner.encrypt(scope, &plaintext).await
    }
}

// ── AgentCrypto delegation ────────────────────────────────────────────────────

#[async_trait]
impl AgentCrypto for SovereignCrypto {
    async fn encrypt(&self, scope: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.inner.encrypt(scope, plaintext).await
    }

    async fn decrypt(&self, scope: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.inner.decrypt(scope, ciphertext).await
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Write a `KeyRef` as `current.json` (always overwrites).
async fn write_key_ref(kse_store: &KseStore, slug: &str, key_ref: &KeyRef) -> Result<()> {
    let json    = serde_json::to_vec(key_ref).context("serialize key-ref")?;
    let cur_key = format!("agent/crypto/{slug}/current.json");
    kse_store.put(&cur_key, Bytes::from(json))
        .await
        .context("write key-ref pointer")?;
    Ok(())
}

/// Store raw bytes in the BlockStore and return the CID.
fn store_block(
    block_store: &Arc<dyn BlockStore + Send + Sync>,
    data: &[u8],
) -> Result<KotobaCid> {
    // CID = blake3(data) as the content-address
    let hash = blake3::hash(data);
    let cid  = KotobaCid::from_bytes(hash.as_bytes());
    block_store.put(&cid, data)
        .context("write wrapped key block")?;
    Ok(cid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use object_store::local::LocalFileSystem;
    use kotoba_store::{BudgetedBlockStore, MemoryBlockStore};

    fn tmp_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("kotoba-sov-{}-{}", prefix, nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_stores(dir: &std::path::Path) -> (KseStore, Arc<dyn BlockStore + Send + Sync>) {
        let fs  = Arc::new(LocalFileSystem::new_with_prefix(dir).unwrap());
        let kse = KseStore::new(fs, "");
        let blk = Arc::new(BudgetedBlockStore::new(
            MemoryBlockStore::new(),
            64 * 1024 * 1024,
        )) as Arc<dyn BlockStore + Send + Sync>;
        (kse, blk)
    }

    #[tokio::test]
    async fn genesis_creates_key_and_pointer() {
        let dir = tmp_dir("genesis");
        let (kse, blk) = make_stores(&dir);
        let id  = AgentIdentity::generate_ephemeral();
        let crypto = SovereignCrypto::load_or_genesis(&id, &kse, &blk).await.unwrap();

        let slug    = id.did_slug();
        let cur_key = format!("agent/crypto/{slug}/current.json");
        assert!(kse.exists(&cur_key).await, "current.json should exist after genesis");

        // Can encrypt/decrypt
        let ct = crypto.encrypt(b"test", b"hello").await.unwrap();
        let pt = crypto.decrypt(b"test", &ct).await.unwrap();
        assert_eq!(pt.as_slice(), b"hello");
    }

    #[tokio::test]
    async fn load_or_genesis_is_idempotent() {
        let dir = tmp_dir("idempotent");
        let (kse, blk) = make_stores(&dir);
        let id = AgentIdentity::generate_ephemeral();

        let c1 = SovereignCrypto::load_or_genesis(&id, &kse, &blk).await.unwrap();
        // Second call should load the same key
        let c2 = SovereignCrypto::load_or_genesis(&id, &kse, &blk).await.unwrap();

        // Both should decrypt the same ciphertext
        let ct = c1.encrypt(b"scope", b"data").await.unwrap();
        let pt = c2.decrypt(b"scope", &ct).await.unwrap();
        assert_eq!(pt.as_slice(), b"data");
    }

    #[tokio::test]
    async fn rotate_produces_new_key() {
        let dir = tmp_dir("rotate");
        let (kse, blk) = make_stores(&dir);
        let id  = AgentIdentity::generate_ephemeral();

        let c1 = SovereignCrypto::load_or_genesis(&id, &kse, &blk).await.unwrap();
        // Encrypt with original key
        let ct_old = c1.encrypt(b"scope", b"original data").await.unwrap();

        let c2 = c1.rotate(&id, &kse, &blk).await.unwrap();

        // Old ciphertext cannot be decrypted by new key (different vault key)
        assert!(
            c2.decrypt(b"scope", &ct_old).await.is_err(),
            "rotated key should not decrypt old ciphertext"
        );

        // Archive file should exist
        let slug = id.did_slug();
        assert!(kse.exists(&format!("agent/crypto/{slug}/v1.json")).await);
        // Current pointer should be at version 2
        let data: KeyRef = serde_json::from_slice(
            &kse.get(&format!("agent/crypto/{slug}/current.json")).await.unwrap()
        ).unwrap();
        assert_eq!(data.version, 2);
    }

    #[tokio::test]
    async fn rotate_and_reencrypt_blob_is_accessible_with_new_key() {
        let dir = tmp_dir("reencrypt");
        let (kse, blk) = make_stores(&dir);
        let id = AgentIdentity::generate_ephemeral();

        let old_crypto = SovereignCrypto::load_or_genesis(&id, &kse, &blk).await.unwrap();

        // Encrypt with old key
        let plaintext = b"sensitive payload";
        let old_ct = old_crypto.encrypt(b"blob", plaintext).await.unwrap();

        // Rotate
        let new_crypto = old_crypto.rotate(&id, &kse, &blk).await.unwrap();

        // Old ciphertext not decryptable with new key
        assert!(new_crypto.decrypt(b"blob", &old_ct).await.is_err());

        // Re-encrypt produces ciphertext decryptable with new key
        let new_ct = new_crypto.reencrypt_blob(&old_crypto, b"blob", &old_ct).await.unwrap();
        let recovered = new_crypto.decrypt(b"blob", &new_ct).await.unwrap();
        assert_eq!(recovered.as_slice(), plaintext);

        // New ciphertext is NOT the same bytes as old (different key)
        assert_ne!(new_ct, old_ct);
    }
}
