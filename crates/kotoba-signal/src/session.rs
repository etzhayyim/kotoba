/// Session = lifecycle wrapper around X3DH + Double Ratchet.
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use x25519_dalek::StaticSecret;
use serde::{Deserialize, Serialize};

use crate::{
    identity::IdentityKeyPair,
    prekey::{PreKey, PreKeyBundle, SignedPreKey},
    ratchet::{RatchetMessage, RatchetState},
    x3dh::{x3dh_init_receiver, x3dh_init_sender},
    SignalError,
};

/// An established 1:1 session between two peers.
pub struct Session {
    pub peer_did:   String,
    pub device_id:  String,
    pub ratchet:    RatchetState,
}

impl Session {
    /// Sender: establish a new session from a PreKeyBundle.
    pub fn initiate(
        local_ik:  &IdentityKeyPair,
        bundle:    &PreKeyBundle,
    ) -> Result<(Self, Vec<u8>), SignalError> {
        let out = x3dh_init_sender(local_ik, bundle)?;
        let ep = out.ephemeral_public.expect("sender always has ephemeral public");

        let spk_pub: [u8; 32] = bundle
            .signed_prekey
            .as_slice()
            .try_into()
            .map_err(|_| SignalError::BadSignature)?;

        let ratchet = RatchetState::init_sender(out.shared_secret, spk_pub);
        let session = Session {
            peer_did:  bundle.did.clone(),
            device_id: bundle.device_id.clone(),
            ratchet,
        };
        Ok((session, ep.to_vec()))
    }

    /// Receiver: establish a session from an incoming initial message.
    pub fn accept(
        local_ik:        &IdentityKeyPair,
        signed_prekey:   &SignedPreKey,
        one_time_prekey: Option<&PreKey>,
        sender_ik_pub:   &crate::identity::IdentityKey,
        ephemeral_pub:   &[u8; 32],
        sender_did:      &str,
        sender_device:   &str,
    ) -> Result<Self, SignalError> {
        let out = x3dh_init_receiver(
            local_ik,
            signed_prekey,
            one_time_prekey,
            sender_ik_pub,
            ephemeral_pub,
        )?;

        // Receiver uses SPK private as the initial ratchet key
        let spk_priv_bytes: [u8; 32] = signed_prekey.private.to_bytes();
        let spk_priv = StaticSecret::from(spk_priv_bytes);
        let ratchet = RatchetState::init_receiver(out.shared_secret, spk_priv);

        Ok(Session {
            peer_did:  sender_did.to_string(),
            device_id: sender_device.to_string(),
            ratchet,
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, SignalError> {
        self.ratchet.encrypt(plaintext)
    }

    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, SignalError> {
        self.ratchet.decrypt(msg)
    }
}

// ── Store trait ────────────────────────────────────────────────────────────────

pub trait SessionStore: Send + Sync {
    fn load_session(
        &self, peer_did: &str, device_id: &str,
    ) -> impl std::future::Future<Output = Option<SerializedSession>> + Send;

    fn store_session(
        &self, peer_did: &str, device_id: &str, session: SerializedSession,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// Serializable session snapshot (ratchet state is persisted as opaque bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedSession {
    pub peer_did:   String,
    pub device_id:  String,
    /// CBOR or JSON blob of ratchet state (implementation-defined).
    pub state_blob: Vec<u8>,
}

// ── In-memory store ────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct InMemorySessionStore {
    sessions: Arc<RwLock<HashMap<String, SerializedSession>>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self { Self::default() }

    fn session_key(peer_did: &str, device_id: &str) -> String {
        format!("{peer_did}:{device_id}")
    }
}

impl SessionStore for InMemorySessionStore {
    async fn load_session(&self, peer_did: &str, device_id: &str) -> Option<SerializedSession> {
        self.sessions
            .read()
            .await
            .get(&Self::session_key(peer_did, device_id))
            .cloned()
    }

    async fn store_session(&self, peer_did: &str, device_id: &str, session: SerializedSession) {
        self.sessions
            .write()
            .await
            .insert(Self::session_key(peer_did, device_id), session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(peer_did: &str, device_id: &str) -> SerializedSession {
        SerializedSession {
            peer_did:   peer_did.to_string(),
            device_id:  device_id.to_string(),
            state_blob: b"opaque-ratchet-state".to_vec(),
        }
    }

    #[tokio::test]
    async fn load_returns_none_when_empty() {
        let store = InMemorySessionStore::new();
        assert!(store.load_session("did:key:zA", "device-1").await.is_none());
    }

    #[tokio::test]
    async fn store_and_load_roundtrip() {
        let store   = InMemorySessionStore::new();
        let session = make_session("did:key:zA", "device-1");
        store.store_session("did:key:zA", "device-1", session.clone()).await;
        let loaded = store.load_session("did:key:zA", "device-1").await;
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.peer_did,   session.peer_did);
        assert_eq!(loaded.device_id,  session.device_id);
        assert_eq!(loaded.state_blob, session.state_blob);
    }

    #[tokio::test]
    async fn different_devices_are_isolated() {
        let store = InMemorySessionStore::new();
        store.store_session("did:key:zA", "device-1", make_session("did:key:zA", "device-1")).await;
        assert!(store.load_session("did:key:zA", "device-2").await.is_none());
    }

    #[tokio::test]
    async fn overwrite_session_updates_blob() {
        let store = InMemorySessionStore::new();
        let s1    = make_session("did:key:zA", "d1");
        let s2    = SerializedSession { state_blob: b"updated-blob".to_vec(), ..s1.clone() };
        store.store_session("did:key:zA", "d1", s1).await;
        store.store_session("did:key:zA", "d1", s2.clone()).await;
        let loaded = store.load_session("did:key:zA", "d1").await.unwrap();
        assert_eq!(loaded.state_blob, b"updated-blob");
    }

    #[test]
    fn serialized_session_json_roundtrip() {
        let s    = make_session("did:key:zA", "dev");
        let json = serde_json::to_string(&s).unwrap();
        let back: SerializedSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.peer_did,   s.peer_did);
        assert_eq!(back.state_blob, s.state_blob);
    }

    #[test]
    fn serialized_session_clone_is_independent() {
        let s = make_session("did:key:zB", "dev-2");
        let c = s.clone();
        assert_eq!(c.peer_did,  s.peer_did);
        assert_eq!(c.device_id, s.device_id);
        assert_eq!(c.state_blob, s.state_blob);
    }

    #[test]
    fn serialized_session_debug_contains_did() {
        let s = make_session("did:key:zDebug", "dev");
        let dbg = format!("{s:?}");
        assert!(dbg.contains("did:key:zDebug"));
    }

    #[tokio::test]
    async fn multiple_peers_stored_independently() {
        let store = InMemorySessionStore::new();
        let s1 = make_session("did:key:zA", "d1");
        let s2 = make_session("did:key:zB", "d1");
        store.store_session("did:key:zA", "d1", s1).await;
        store.store_session("did:key:zB", "d1", s2).await;

        let loaded_a = store.load_session("did:key:zA", "d1").await;
        let loaded_b = store.load_session("did:key:zB", "d1").await;
        assert!(loaded_a.is_some());
        assert!(loaded_b.is_some());
        assert_eq!(loaded_a.unwrap().peer_did, "did:key:zA");
        assert_eq!(loaded_b.unwrap().peer_did, "did:key:zB");
    }

    #[tokio::test]
    async fn store_clone_shares_state() {
        let store  = InMemorySessionStore::new();
        let cloned = store.clone();
        let s = make_session("did:key:zC", "dev-c");
        store.store_session("did:key:zC", "dev-c", s).await;
        // The clone wraps the same Arc<RwLock> so it must see the new entry
        let loaded = cloned.load_session("did:key:zC", "dev-c").await;
        assert!(loaded.is_some(), "clone should share the underlying map");
    }

    #[test]
    fn serialized_session_empty_blob() {
        let s = SerializedSession {
            peer_did:   "did:key:zA".to_string(),
            device_id:  "d1".to_string(),
            state_blob: vec![],
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: SerializedSession = serde_json::from_str(&json).unwrap();
        assert!(back.state_blob.is_empty());
    }

    #[tokio::test]
    async fn new_and_default_produce_equivalent_stores() {
        let s1 = InMemorySessionStore::new();
        let s2 = InMemorySessionStore::default();
        // Both should start empty
        assert!(s1.load_session("any", "any").await.is_none());
        assert!(s2.load_session("any", "any").await.is_none());
    }
}
