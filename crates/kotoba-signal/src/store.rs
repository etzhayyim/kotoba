/// SignalStore — unified in-memory store for identity, pre-keys, sessions, sender keys.
/// Acts as the local Signal Protocol state node (analogous to IndexedDB `gftd-signal-v1`).
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    identity::{DeviceId, IdentityKeyPair},
    prekey::{PreKey, PreKeyBundle, PreKeyId, SignedPreKey, SignedPreKeyId},
    group::InMemorySenderKeyStore,
    session::InMemorySessionStore,
    SignalError,
};

/// All Signal Protocol state for a local device.
pub struct SignalStore {
    pub local_did:     String,
    pub device_id:     DeviceId,
    pub identity:      IdentityKeyPair,
    prekeys:           Arc<RwLock<HashMap<PreKeyId, PreKey>>>,
    signed_prekeys:    Arc<RwLock<HashMap<SignedPreKeyId, SignedPreKey>>>,
    pub sessions:      InMemorySessionStore,
    pub sender_keys:   InMemorySenderKeyStore,
}

impl SignalStore {
    pub fn new(local_did: impl Into<String>, device_id: impl Into<String>) -> Self {
        Self {
            local_did:      local_did.into(),
            device_id:      device_id.into(),
            identity:       IdentityKeyPair::generate(),
            prekeys:        Arc::new(RwLock::new(HashMap::new())),
            signed_prekeys: Arc::new(RwLock::new(HashMap::new())),
            sessions:       InMemorySessionStore::new(),
            sender_keys:    InMemorySenderKeyStore::new(),
        }
    }

    // ── Pre-key management ─────────────────────────────────────────────────

    /// Generate `count` one-time pre-keys starting at `start_id`.
    pub async fn generate_prekeys(&self, start_id: PreKeyId, count: u32) {
        let mut map = self.prekeys.write().await;
        for i in 0..count {
            let id = start_id + i;
            map.insert(id, PreKey::generate(id));
        }
    }

    pub async fn consume_prekey(&self, id: PreKeyId) -> Option<PreKey> {
        self.prekeys.write().await.remove(&id)
    }

    pub async fn prekey_ids(&self) -> Vec<PreKeyId> {
        self.prekeys.read().await.keys().copied().collect()
    }

    /// Generate + store a signed pre-key.
    pub async fn rotate_signed_prekey(&self, id: SignedPreKeyId) {
        let spk = SignedPreKey::generate(id, &self.identity);
        self.signed_prekeys.write().await.insert(id, spk);
    }

    pub async fn get_signed_prekey(&self, id: SignedPreKeyId) -> Option<SignedPreKeyId> {
        if self.signed_prekeys.read().await.contains_key(&id) { Some(id) } else { None }
    }

    /// Build a PreKeyBundle for this device (for remote peers to fetch).
    pub async fn prekey_bundle(&self, signed_prekey_id: SignedPreKeyId) -> Result<PreKeyBundle, SignalError> {
        let spk_map = self.signed_prekeys.read().await;
        let spk = spk_map
            .get(&signed_prekey_id)
            .ok_or(SignalError::NoSignedPreKey(signed_prekey_id))?;

        let opk_entry = {
            let map = self.prekeys.read().await;
            map.iter().next().map(|(id, pk)| (*id, pk.public_bytes()))
        };

        Ok(PreKeyBundle {
            did:               self.local_did.clone(),
            device_id:         self.device_id.clone(),
            identity_key:      self.identity.public_key(),
            signed_prekey:     spk.public_bytes().to_vec(),
            signed_prekey_id:  spk.id,
            signed_prekey_sig: spk.signature.clone(),
            one_time_prekey:     opk_entry.map(|(_, pk)| pk.to_vec()),
            one_time_prekey_id:  opk_entry.map(|(id, _)| id),
        })
    }

    // ── Field-level encryption (convo-scoped) ─────────────────────────────────

    /// Derive a convo-scoped AES-256-GCM key.
    /// HKDF-SHA256(ikm = ik_dh_pub, info = "kotoba-field\x00{did}\x00{convo_id}")
    ///
    /// NUL is used as separator because DIDs and convo IDs must not contain NUL,
    /// preventing key-confusion between ("x", "y:z") and ("x:y", "z").
    ///
    /// # Panics
    /// Panics in debug builds if `peer_did` or `convo_id` contains a NUL byte,
    /// which would violate the separator invariant.
    pub fn derive_field_key(&self, peer_did: &str, convo_id: &str) -> [u8; 32] {
        debug_assert!(
            !peer_did.contains('\0'),
            "peer_did must not contain NUL bytes (got {peer_did:?})"
        );
        debug_assert!(
            !convo_id.contains('\0'),
            "convo_id must not contain NUL bytes (got {convo_id:?})"
        );
        let ik_dh_pub = x25519_dalek::PublicKey::from(&self.identity.dh).to_bytes();
        let mut info = b"kotoba-field\x00".to_vec();
        info.extend_from_slice(peer_did.as_bytes());
        info.push(0);
        info.extend_from_slice(convo_id.as_bytes());
        kotoba_crypto::hkdf::derive_key(&ik_dh_pub, &info)
    }

    /// Encrypt a field value → `signal:v1:{base64url}`.
    pub fn encrypt_field(
        &self,
        plaintext: &str,
        peer_did: &str,
        convo_id: &str,
    ) -> Result<String, SignalError> {
        let key = self.derive_field_key(peer_did, convo_id);
        kotoba_crypto::envelope::encrypt_field(&key, plaintext.as_bytes()).map_err(SignalError::Crypto)
    }

    /// Decrypt a `signal:v1:` field value.
    pub fn decrypt_field(
        &self,
        envelope: &str,
        peer_did: &str,
        convo_id: &str,
    ) -> Result<String, SignalError> {
        let key = self.derive_field_key(peer_did, convo_id);
        let mut bytes = kotoba_crypto::envelope::decrypt_field(&key, envelope).map_err(SignalError::Crypto)?;
        let inner = std::mem::take(&mut *bytes);
        String::from_utf8(inner).map_err(|e| SignalError::Store(e.to_string()))
    }
}

// ── InMemorySignalStore alias ──────────────────────────────────────────────────

/// Convenience alias — tests and server both use this.
pub type InMemorySignalStore = SignalStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn field_encrypt_decrypt_roundtrip() {
        let store = SignalStore::new("did:plc:alice", "dev-1");
        let enc = store.encrypt_field("secret value", "did:plc:bob", "convo-1").unwrap();
        assert!(enc.starts_with("signal:v1:"));
        let dec = store.decrypt_field(&enc, "did:plc:bob", "convo-1").unwrap();
        assert_eq!(dec, "secret value");
    }

    #[test]
    fn key_confusion_different_splits_produce_distinct_keys() {
        // "did:plc:a" + "b:c" must differ from "did:plc:a:b" + "c"
        let store = SignalStore::new("did:plc:owner", "dev-1");
        let k1 = store.derive_field_key("did:plc:a", "b:c");
        let k2 = store.derive_field_key("did:plc:a:b", "c");
        assert_ne!(k1, k2, "HKDF key-confusion: different splits must yield different keys");
    }

    #[test]
    fn derive_field_key_same_inputs_are_deterministic() {
        let store = SignalStore::new("did:plc:owner", "dev-1");
        let k1 = store.derive_field_key("did:plc:peer", "convo-abc");
        let k2 = store.derive_field_key("did:plc:peer", "convo-abc");
        assert_eq!(k1, k2, "same inputs must produce same key");
    }

    #[test]
    fn derive_field_key_different_convo_ids_produce_distinct_keys() {
        let store = SignalStore::new("did:plc:owner", "dev-1");
        let k1 = store.derive_field_key("did:plc:peer", "convo-1");
        let k2 = store.derive_field_key("did:plc:peer", "convo-2");
        assert_ne!(k1, k2, "different convo_id must yield different keys");
    }

    #[tokio::test]
    async fn prekey_bundle_roundtrip() {
        let store = SignalStore::new("did:plc:alice", "dev-1");
        store.generate_prekeys(1, 5).await;
        store.rotate_signed_prekey(1).await;
        let bundle = store.prekey_bundle(1).await.unwrap();
        assert_eq!(bundle.did, "did:plc:alice");
        assert!(bundle.one_time_prekey.is_some());
    }

    #[tokio::test]
    async fn generate_prekeys_creates_correct_count() {
        let store = SignalStore::new("did:plc:alice", "dev-1");
        store.generate_prekeys(1, 10).await;
        let ids = store.prekey_ids().await;
        assert_eq!(ids.len(), 10);
    }

    #[tokio::test]
    async fn consume_prekey_removes_entry() {
        let store = SignalStore::new("did:plc:alice", "dev-1");
        store.generate_prekeys(1, 3).await;
        let key = store.consume_prekey(1).await;
        assert!(key.is_some(), "prekey 1 should exist");
        let ids = store.prekey_ids().await;
        assert_eq!(ids.len(), 2, "consumed key should be removed");
        let again = store.consume_prekey(1).await;
        assert!(again.is_none(), "consuming the same key twice should return None");
    }

    #[tokio::test]
    async fn prekey_bundle_error_when_spk_missing() {
        let store = SignalStore::new("did:plc:alice", "dev-1");
        store.generate_prekeys(1, 1).await;
        // No signed prekey registered → should err with NoSignedPreKey
        let result = store.prekey_bundle(99).await;
        assert!(result.is_err(), "missing SPK should return error");
    }

    #[tokio::test]
    async fn prekey_bundle_no_opk_when_empty() {
        let store = SignalStore::new("did:plc:bob", "dev-2");
        store.rotate_signed_prekey(1).await;
        // No one-time prekeys → bundle.one_time_prekey should be None
        let bundle = store.prekey_bundle(1).await.unwrap();
        assert!(bundle.one_time_prekey.is_none());
        assert!(bundle.one_time_prekey_id.is_none());
    }

    #[test]
    fn derive_field_key_changes_with_peer_did() {
        let store = SignalStore::new("did:plc:owner", "dev-1");
        let k1 = store.derive_field_key("did:plc:alice", "convo-1");
        let k2 = store.derive_field_key("did:plc:bob",   "convo-1");
        assert_ne!(k1, k2, "different peer_did must yield different keys");
    }

    #[test]
    fn encrypt_field_same_plaintext_produces_different_ciphertexts() {
        let store = SignalStore::new("did:plc:owner", "dev-1");
        // AES-GCM uses a random nonce per call → same plaintext encrypts differently each time
        let c1 = store.encrypt_field("hello", "did:plc:bob", "convo-1").unwrap();
        let c2 = store.encrypt_field("hello", "did:plc:bob", "convo-1").unwrap();
        assert_ne!(c1, c2, "random nonce must produce distinct ciphertexts");
    }

    #[tokio::test]
    async fn get_signed_prekey_returns_none_for_unknown_id() {
        let store = SignalStore::new("did:plc:alice", "dev-1");
        assert!(store.get_signed_prekey(999).await.is_none());
    }
}
