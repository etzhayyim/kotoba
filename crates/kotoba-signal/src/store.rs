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

    // ── Field-level encryption (convo-scoped, compatible with @gftd/signal) ─

    /// Derive a convo-scoped AES-256-GCM key.
    /// HKDF-SHA256(ikm = ik_dh_pub, info = "kotoba-field:{did}:{convo_id}")
    pub fn derive_field_key(&self, peer_did: &str, convo_id: &str) -> [u8; 32] {
        let ik_dh_pub = x25519_dalek::PublicKey::from(&self.identity.dh).to_bytes();
        let info = format!("kotoba-field:{peer_did}:{convo_id}");
        kotoba_crypto::hkdf::derive_key(&ik_dh_pub, info.as_bytes())
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

    #[tokio::test]
    async fn prekey_bundle_roundtrip() {
        let store = SignalStore::new("did:plc:alice", "dev-1");
        store.generate_prekeys(1, 5).await;
        store.rotate_signed_prekey(1).await;
        let bundle = store.prekey_bundle(1).await.unwrap();
        assert_eq!(bundle.did, "did:plc:alice");
        assert!(bundle.one_time_prekey.is_some());
    }
}
