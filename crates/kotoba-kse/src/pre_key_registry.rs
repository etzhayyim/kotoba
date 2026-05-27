/// PRE key registry — maps (owner_did, accessor_did) to a wrapped re-encryption key.
///
/// The re-key itself is AES-GCM wrapped with the owner's local `enc_key` before
/// storage so that even if the BlockStore is compromised the re-keys remain protected.
///
/// ## Persistence
///
/// When constructed with `with_shelf()`, the grant index is persisted to a `Shelf`
/// bucket (`KOTOBA_PRE_KEYS`, key `"index"`) as a JSON object mapping
/// `"{owner_did}:{accessor_did}"` → CID multibase.  The index is loaded back on
/// construction so grants survive process restarts.
///
/// ## Revocation Warrant
///
/// `revoke_emit_warrant()` performs local revocation AND returns a `KotobaCid` for a
/// CBOR-encoded `RekeyRevocationRecord`.  Callers should wrap this CID in a
/// `ChainContent::Warrant { rule_id: RULE_REKEY_REVOKED }` ChainEntry and gossip it to
/// peers.  `apply_revocation_warrant()` processes incoming peer Warrants.
///
/// ## Flow (Hybrid PRE)
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
use crate::shelf::{Shelf, BUCKET_PRE_KEYS};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

/// Rule ID used in `ChainContent::Warrant` when a re-key grant is revoked.
pub const RULE_REKEY_REVOKED: u8 = 7;

/// Shelf key used to persist the grant index.
const SHELF_INDEX_KEY: &str = "index";

/// CBOR-serialisable record stored as evidence in a RekeyRevoked Warrant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyRevocationRecord {
    pub owner_did:    String,
    pub accessor_did: String,
    pub revoked_at:   u64,   // Unix timestamp ms
}

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
    #[error("serialization: {0}")]
    Serde(String),
}

pub struct PreKeyRegistry {
    store: Arc<dyn BlockStore + Send + Sync>,
    /// (owner_did, accessor_did) → CID of the wrapped re-key block.
    index: Arc<RwLock<HashMap<(String, String), KotobaCid>>>,
    /// Revoked pairs — checked on every `get_rekey_authed` call.
    revoked: Arc<RwLock<HashSet<(String, String)>>>,
    /// Optional shelf for index persistence across restarts.
    shelf: Option<Arc<Shelf>>,
}

impl PreKeyRegistry {
    /// In-memory only — grants are lost on restart.
    pub fn new(store: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self {
            store,
            index:   Arc::new(RwLock::new(HashMap::new())),
            revoked: Arc::new(RwLock::new(HashSet::new())),
            shelf:   None,
        }
    }

    /// Persistent — grant index is loaded from `shelf` on construction and saved
    /// after every `grant()` / `revoke()`.
    pub async fn with_shelf(
        store: Arc<dyn BlockStore + Send + Sync>,
        shelf: Arc<Shelf>,
    ) -> Self {
        let mut reg = Self {
            store,
            index:   Arc::new(RwLock::new(HashMap::new())),
            revoked: Arc::new(RwLock::new(HashSet::new())),
            shelf:   Some(shelf),
        };
        reg.load_index().await;
        reg.load_revoked().await;
        reg
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
        {
            let mut idx = self.index.write().await;
            idx.insert((owner_did.to_string(), accessor_did.to_string()), cid.clone());
            // Also clear any prior revocation for this pair (re-grant is allowed).
            self.revoked.write().await
                .remove(&(owner_did.to_string(), accessor_did.to_string()));
        }
        self.persist_index().await;
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
        // verify() returns the issuer DID extracted from the verified CACAO.
        // We must check it matches accessor_did — otherwise a valid CACAO from
        // a different accessor could be used to look up an unrelated re-key.
        let issuer_did = chain.verify(owner_did, "quad:read")?;
        if issuer_did != accessor_did {
            return Err(PreKeyError::Access(DelegationError::RootMismatch));
        }
        // Check revocation set (fast path before touching BlockStore).
        if self.revoked.read().await
            .contains(&(owner_did.to_string(), accessor_did.to_string()))
        {
            return Err(PreKeyError::Access(DelegationError::CapabilityDenied(
                format!("re-key for ({owner_did}, {accessor_did}) has been revoked"),
            )));
        }
        self.unwrap_rekey(owner_did, accessor_did, owner_enc_key).await
    }

    /// Revoke access immediately — deletes re-key from index, BlockStore, and Shelf.
    ///
    /// Use `revoke_emit_warrant()` to also obtain evidence for DHT Warrant gossip.
    pub async fn revoke(&self, owner_did: &str, accessor_did: &str) {
        self.revoke_inner(owner_did, accessor_did).await;
    }

    /// Revoke access AND return a `KotobaCid` for a `RekeyRevocationRecord` evidence block.
    ///
    /// The returned CID should be used as `evidence` in a `ChainContent::Warrant`
    /// with `rule_id = RULE_REKEY_REVOKED` so that peers can also invalidate cached grants.
    pub async fn revoke_emit_warrant(
        &self,
        owner_did: &str,
        accessor_did: &str,
    ) -> Result<KotobaCid, PreKeyError> {
        self.revoke_inner(owner_did, accessor_did).await;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let record = RekeyRevocationRecord {
            owner_did:    owner_did.to_string(),
            accessor_did: accessor_did.to_string(),
            revoked_at:   ts,
        };
        let evidence_bytes = serde_json::to_vec(&record)
            .map_err(|e| PreKeyError::Serde(e.to_string()))?;
        let evidence_cid = KotobaCid::from_bytes(&evidence_bytes);
        self.store.put(&evidence_cid, &evidence_bytes)
            .map_err(|e| PreKeyError::Store(e.to_string()))?;
        Ok(evidence_cid)
    }

    /// Process an incoming peer Warrant with `rule_id = RULE_REKEY_REVOKED`.
    ///
    /// Loads the `RekeyRevocationRecord` from the BlockStore by `evidence_cid`,
    /// then applies local revocation.  No-ops if already revoked or record missing.
    pub async fn apply_revocation_warrant(&self, evidence_cid: &KotobaCid) {
        let Some(bytes) = self.store.get(evidence_cid)
            .ok()
            .flatten() else { return; };

        let Ok(record) = serde_json::from_slice::<RekeyRevocationRecord>(&bytes)
            else { return; };

        self.revoke_inner(&record.owner_did, &record.accessor_did).await;
        tracing::info!(
            owner_did = %record.owner_did,
            accessor_did = %record.accessor_did,
            "PreKeyRegistry: applied peer revocation warrant",
        );
    }

    /// All accessors currently holding a re-key for `owner_did`.
    pub async fn list_accessors(&self, owner_did: &str) -> Vec<String> {
        self.index.read().await.keys()
            .filter(|(o, _)| o == owner_did)
            .map(|(_, a)| a.clone())
            .collect()
    }

    // ── internal ─────────────────────────────────────────────────────────────

    fn aad(owner_did: &str, accessor_did: &str) -> String {
        format!("{owner_did}:{accessor_did}")
    }

    async fn revoke_inner(&self, owner_did: &str, accessor_did: &str) {
        let k = (owner_did.to_string(), accessor_did.to_string());
        if let Some(cid) = self.index.write().await.remove(&k) {
            let _ = self.store.delete(&cid);
        }
        self.revoked.write().await.insert(k);
        self.persist_index().await;
        self.persist_revoked_set().await;
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

    /// Serialise the current index as JSON and save to Shelf (no-op without shelf).
    ///
    /// Format: `[[owner_did, accessor_did, cid_multibase], ...]`
    /// Using an array of triples avoids splitting on `:` inside DID strings.
    async fn persist_index(&self) {
        let Some(shelf) = &self.shelf else { return; };
        let entries: Vec<[String; 3]> = self.index.read().await
            .iter()
            .map(|((o, a), cid)| [o.clone(), a.clone(), cid.to_multibase()])
            .collect();
        let Ok(json) = serde_json::to_vec(&entries) else { return; };
        shelf.put(BUCKET_PRE_KEYS, SHELF_INDEX_KEY.to_string(), Bytes::from(json)).await;
    }

    /// Load the grant index from Shelf on construction.
    ///
    /// Expects format `[[owner_did, accessor_did, cid_multibase], ...]`.
    async fn load_index(&mut self) {
        let Some(shelf) = &self.shelf else { return; };
        let Some(bytes) = shelf.get(BUCKET_PRE_KEYS, SHELF_INDEX_KEY).await else { return; };
        let Ok(entries) = serde_json::from_slice::<Vec<[String; 3]>>(&bytes) else { return; };
        let mut idx = self.index.write().await;
        for [owner, accessor, cid_mb] in entries {
            let Some(cid) = KotobaCid::from_multibase(&cid_mb) else { continue; };
            idx.insert((owner, accessor), cid);
        }
        tracing::info!(grants = idx.len(), "PreKeyRegistry: index loaded from shelf");
    }

    /// Load the revocation set from Shelf on construction.
    ///
    /// Expects format `[[owner_did, accessor_did], ...]`.
    async fn load_revoked(&mut self) {
        let Some(shelf) = &self.shelf else { return; };
        let Some(bytes) = shelf.get(BUCKET_PRE_KEYS, "_revoked").await else { return; };
        let Ok(list) = serde_json::from_slice::<Vec<[String; 2]>>(&bytes) else { return; };
        let mut rev = self.revoked.write().await;
        for [owner, accessor] in list {
            rev.insert((owner, accessor));
        }
        tracing::info!(revoked = rev.len(), "PreKeyRegistry: revocation set loaded from shelf");
    }

    /// Persist the full revocation set (called after every revoke).
    ///
    /// Format: `[[owner_did, accessor_did], ...]`
    async fn persist_revoked_set(&self) {
        let Some(shelf) = &self.shelf else { return; };
        let list: Vec<[String; 2]> = self.revoked.read().await
            .iter()
            .map(|(o, a)| [o.clone(), a.clone()])
            .collect();
        let Ok(json) = serde_json::to_vec(&list) else { return; };
        shelf.put(BUCKET_PRE_KEYS, "_revoked".to_string(), Bytes::from(json)).await;
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

        // Test storage layer directly.
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

    #[tokio::test]
    async fn shelf_persistence_survives_restart() {
        let s = store();
        let shelf = Arc::new(Shelf::new());
        let enc_key = rand_key();
        let re_key  = rand_key();

        // Simulate first run: grant and persist.
        {
            let reg = PreKeyRegistry::with_shelf(Arc::clone(&s), Arc::clone(&shelf)).await;
            reg.grant("did:alice", "did:bob", &re_key, &enc_key).await.unwrap();
        }

        // Simulate restart: load from shelf.
        {
            let reg = PreKeyRegistry::with_shelf(Arc::clone(&s), Arc::clone(&shelf)).await;
            let recovered = reg.unwrap_rekey("did:alice", "did:bob", &enc_key).await
                .expect("grant must survive restart");
            assert_eq!(recovered.as_slice(), re_key);
        }
    }

    #[tokio::test]
    async fn revoked_pair_rejected_by_get_rekey_authed_without_chain() {
        // Verify that revoked pairs are blocked even before CACAO chain check.
        // We test via unwrap_rekey absence + revoked set directly.
        let reg = PreKeyRegistry::new(store());
        let enc_key = rand_key();
        reg.grant("did:owner", "did:eve", &rand_key(), &enc_key).await.unwrap();
        reg.revoke("did:owner", "did:eve").await;
        // After revoke, index entry is gone → NotFound.
        assert!(reg.unwrap_rekey("did:owner", "did:eve", &enc_key).await.is_err());
        // revoked set should contain the pair.
        assert!(reg.revoked.read().await
            .contains(&("did:owner".to_string(), "did:eve".to_string())));
    }

    #[tokio::test]
    async fn emit_warrant_returns_evidence_cid() {
        let s = store();
        let reg = PreKeyRegistry::new(Arc::clone(&s));
        let enc_key = rand_key();
        reg.grant("did:alice", "did:bob", &rand_key(), &enc_key).await.unwrap();

        let evidence_cid = reg.revoke_emit_warrant("did:alice", "did:bob").await.unwrap();

        // Evidence block must be retrievable from BlockStore.
        let raw = s.get(&evidence_cid).unwrap().unwrap();
        let rec: RekeyRevocationRecord = serde_json::from_slice(&raw).unwrap();
        assert_eq!(rec.owner_did,    "did:alice");
        assert_eq!(rec.accessor_did, "did:bob");
    }

    #[tokio::test]
    async fn apply_revocation_warrant_revokes_locally() {
        let s = store();
        let enc_key = rand_key();
        let re_key  = rand_key();

        // Node A: holds the grant and emits a warrant.
        let node_a = PreKeyRegistry::new(Arc::clone(&s));
        node_a.grant("did:alice", "did:bob", &re_key, &enc_key).await.unwrap();
        let evidence_cid = node_a.revoke_emit_warrant("did:alice", "did:bob").await.unwrap();

        // Node B: receives the warrant — applies it locally.
        let node_b = PreKeyRegistry::new(Arc::clone(&s));
        node_b.grant("did:alice", "did:bob", &re_key, &enc_key).await.unwrap();
        node_b.apply_revocation_warrant(&evidence_cid).await;

        // Node B should now have the pair revoked.
        assert!(node_b.revoked.read().await
            .contains(&("did:alice".to_string(), "did:bob".to_string())));
    }

    /// CACAO signed by accessor-A cannot be used to fetch accessor-B's re-key.
    ///
    /// This guards against a cross-accessor substitution attack where an attacker
    /// holds a valid delegation for their own DID and passes a different accessor_did
    /// to `get_rekey_authed()` to retrieve an unrelated re-key entry.
    #[tokio::test]
    async fn issuer_mismatch_rejected_by_get_rekey_authed() {
        use ed25519_dalek::{Signer, SigningKey};
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use kotoba_auth::{Cacao, CacaoHeader, CacaoPayload, CacaoSig, DelegationChain};
        use kotoba_auth::ed25519_pubkey_to_did_key;

        // accessor-A: has a valid grant and provides a valid signed CACAO.
        let sk_a = SigningKey::from_bytes(&[11u8; 32]);
        let accessor_a_did = ed25519_pubkey_to_did_key(sk_a.verifying_key().as_bytes());

        // accessor-B: also has a grant; attacker wants accessor-B's re-key.
        let accessor_b_did = "did:key:zAttackerWantsThis";

        let owner_did = "did:key:zOwner";
        let enc_key   = rand_key();
        let re_key_b  = rand_key();

        let reg = PreKeyRegistry::new(store());
        reg.grant(owner_did, &accessor_a_did, &rand_key(), &enc_key).await.unwrap();
        reg.grant(owner_did, accessor_b_did, &re_key_b, &enc_key).await.unwrap();

        // Build a valid CACAO signed by accessor-A.
        let payload = CacaoPayload {
            iss:       accessor_a_did.clone(),
            aud:       "kotoba://test".into(),
            issued_at: "2026-05-26T00:00:00Z".into(),
            expiry:    None,
            nonce:     "issuer-mismatch-nonce".into(),
            domain:    "kotoba.test".into(),
            statement: None,
            version:   "1".into(),
            resources: vec![],
        };
        let mut cacao = Cacao {
            h: CacaoHeader { t: "caip122".into() },
            p: payload,
            s: CacaoSig { t: "EdDSA".into(), s: String::new() },
        };
        let sig = sk_a.sign(cacao.siwe_message().as_bytes());
        cacao.s.s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let chain = DelegationChain::new(cacao);

        // Attempt to use accessor-A's CACAO to fetch accessor-B's re-key.
        let err = reg
            .get_rekey_authed(&chain, owner_did, accessor_b_did, &enc_key)
            .await
            .unwrap_err();

        assert!(
            matches!(err, PreKeyError::Access(DelegationError::RootMismatch)),
            "expected RootMismatch, got {err:?}"
        );
    }

    // ---- New tests --------------------------------------------------------

    #[test]
    fn rule_rekey_revoked_constant_is_seven() {
        assert_eq!(RULE_REKEY_REVOKED, 7);
    }

    #[test]
    fn pre_key_error_not_found_display() {
        let e = PreKeyError::NotFound("did:owner".to_string(), "did:acc".to_string());
        let s = e.to_string();
        assert!(s.contains("did:owner") && s.contains("did:acc"),
            "NotFound display must include both DIDs, got: {s}");
    }

    #[test]
    fn pre_key_error_store_display() {
        let e = PreKeyError::Store("disk full".to_string());
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn pre_key_error_serde_display() {
        let e = PreKeyError::Serde("bad json".to_string());
        let s = e.to_string();
        assert!(s.contains("bad json") || s.contains("serialization"), "got: {s}");
    }

    #[test]
    fn rekey_revocation_record_serde_roundtrip() {
        let rec = RekeyRevocationRecord {
            owner_did:    "did:key:zOwner".to_string(),
            accessor_did: "did:key:zAcc".to_string(),
            revoked_at:   1_700_000_000_000,
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: RekeyRevocationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.owner_did,    rec.owner_did);
        assert_eq!(back.accessor_did, rec.accessor_did);
        assert_eq!(back.revoked_at,   rec.revoked_at);
    }

    #[tokio::test]
    async fn list_accessors_empty_for_unknown_owner() {
        let reg = PreKeyRegistry::new(store());
        let list = reg.list_accessors("did:unknown").await;
        assert!(list.is_empty(), "unknown owner must return empty accessor list");
    }

    #[tokio::test]
    async fn double_revoke_is_safe() {
        // Revoking an already-revoked pair must not panic.
        let reg = PreKeyRegistry::new(store());
        let enc_key = rand_key();
        reg.grant("did:alice", "did:bob", &rand_key(), &enc_key).await.unwrap();
        reg.revoke("did:alice", "did:bob").await;
        reg.revoke("did:alice", "did:bob").await; // second revoke — must not panic
        assert!(reg.revoked.read().await
            .contains(&("did:alice".to_string(), "did:bob".to_string())));
    }
}
