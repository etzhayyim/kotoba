use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
/// Sender Keys — group messaging (Signal specification).
///
/// Each group member distributes a SenderKeyState (chain_key + signing_key).
/// Group messages are encrypted with a symmetric ratchet derived from chain_key.
/// Other members verify + decrypt using the distributed sender key.
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zeroize::ZeroizeOnDrop;

use crate::SignalError;
use kotoba_crypto::aead::{open, seal};
use kotoba_crypto::hkdf::ratchet_chain;

/// Signal spec §5.2: reject messages that skip more than this many chain steps.
/// Prevents an attacker from forcing O(N) ratchet work and unbounded `skipped_keys` growth.
const MAX_SKIPPED_KEYS: usize = 1_000;

/// Per-member sender key state (private).
#[derive(ZeroizeOnDrop)]
pub struct SenderKeyState {
    pub group_id: String,
    pub member_did: String,
    pub chain_id: u32, // increments on each ratchet epoch
    pub chain_key: [u8; 32],
    pub chain_iter: u32,
    pub signing: SigningKey,
}

/// Public distribution record shared with group members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyDistribution {
    pub group_id: String,
    pub sender_did: String,
    pub chain_id: u32,
    pub chain_iter: u32,
    /// Current sender chain key (public representation: the chain_key itself, ONLY shared
    /// to group members already trusted — encrypted 1:1 per member via Double Ratchet).
    pub chain_key: Vec<u8>,
    /// Ed25519 verifying key (32 bytes).
    pub signing_key_pub: Vec<u8>,
}

/// An encrypted group message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyMessage {
    pub group_id: String,
    pub sender_did: String,
    pub chain_id: u32,
    pub n: u32,
    /// AES-256-GCM ciphertext (nonce || ct).
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature over `chain_id || n || ciphertext`.
    pub signature: Vec<u8>,
}

impl SenderKeyState {
    pub fn generate(group_id: impl Into<String>, member_did: impl Into<String>) -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let chain_key = {
            let mut k = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut k);
            k
        };
        Self {
            group_id: group_id.into(),
            member_did: member_did.into(),
            chain_id: 0,
            chain_key,
            chain_iter: 0,
            signing,
        }
    }

    /// Produce the public distribution record (to be encrypted 1:1 to each group member).
    pub fn distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            group_id: self.group_id.clone(),
            sender_did: self.member_did.clone(),
            chain_id: self.chain_id,
            chain_iter: self.chain_iter,
            chain_key: self.chain_key.to_vec(),
            signing_key_pub: self.signing.verifying_key().to_bytes().to_vec(),
        }
    }

    /// Encrypt `plaintext` as a group message and advance the chain.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<SenderKeyMessage, SignalError> {
        let (new_ck, mk) = ratchet_chain(&self.chain_key);
        self.chain_key = new_ck;
        let n = self.chain_iter;
        self.chain_iter += 1;

        let ciphertext = seal(&mk, plaintext).map_err(SignalError::Crypto)?;

        // Sign chain_id || n || ciphertext
        let mut sig_data = Vec::with_capacity(8 + ciphertext.len());
        sig_data.extend_from_slice(&self.chain_id.to_le_bytes());
        sig_data.extend_from_slice(&n.to_le_bytes());
        sig_data.extend_from_slice(&ciphertext);
        let signature = self.signing.sign(&sig_data).to_bytes().to_vec();

        Ok(SenderKeyMessage {
            group_id: self.group_id.clone(),
            sender_did: self.member_did.clone(),
            chain_id: self.chain_id,
            n,
            ciphertext,
            signature,
        })
    }
}

/// Per-member decryption state derived from a received SenderKeyDistribution.
pub struct GroupSession {
    pub group_id: String,
    pub sender_did: String,
    pub chain_id: u32,
    pub chain_key: [u8; 32],
    pub chain_iter: u32,
    pub signing_key_pub: VerifyingKey,
    /// Cached message keys for out-of-order delivery.
    skipped_keys: HashMap<(u32, u32), [u8; 32]>, // (chain_id, n) → mk
}

impl GroupSession {
    /// Create from a received `SenderKeyDistribution`.
    pub fn from_distribution(dist: &SenderKeyDistribution) -> Result<Self, SignalError> {
        let chain_key: [u8; 32] = dist
            .chain_key
            .as_slice()
            .try_into()
            .map_err(|_| SignalError::CounterMismatch)?;
        let vk_bytes: [u8; 32] = dist
            .signing_key_pub
            .as_slice()
            .try_into()
            .map_err(|_| SignalError::BadSignature)?;
        let signing_key_pub =
            VerifyingKey::from_bytes(&vk_bytes).map_err(|_| SignalError::BadSignature)?;
        Ok(Self {
            group_id: dist.group_id.clone(),
            sender_did: dist.sender_did.clone(),
            chain_id: dist.chain_id,
            chain_key,
            chain_iter: dist.chain_iter,
            signing_key_pub,
            skipped_keys: HashMap::new(),
        })
    }

    /// Verify + decrypt a `SenderKeyMessage`.
    pub fn decrypt(&mut self, msg: &SenderKeyMessage) -> Result<Vec<u8>, SignalError> {
        if msg.group_id != self.group_id || msg.sender_did != self.sender_did {
            return Err(SignalError::NoSession(msg.sender_did.clone()));
        }
        // Verify signature
        let mut sig_data = Vec::with_capacity(8 + msg.ciphertext.len());
        sig_data.extend_from_slice(&msg.chain_id.to_le_bytes());
        sig_data.extend_from_slice(&msg.n.to_le_bytes());
        sig_data.extend_from_slice(&msg.ciphertext);
        let sig = Signature::from_slice(&msg.signature).map_err(|_| SignalError::BadSignature)?;
        self.signing_key_pub
            .verify(&sig_data, &sig)
            .map_err(|_| SignalError::BadSignature)?;

        // Check skipped key cache
        let key = (msg.chain_id, msg.n);
        if let Some(mk) = self.skipped_keys.remove(&key) {
            let pt = open(&mk, &msg.ciphertext).map_err(SignalError::Crypto)?;
            return Ok(pt.to_vec());
        }

        // Advance chain to msg.n
        if msg.n < self.chain_iter {
            return Err(SignalError::CounterMismatch);
        }
        let skip_count = (msg.n - self.chain_iter) as usize;
        if self.skipped_keys.len() + skip_count > MAX_SKIPPED_KEYS {
            return Err(SignalError::TooManySkippedKeys);
        }
        while self.chain_iter < msg.n {
            let (new_ck, mk) = ratchet_chain(&self.chain_key);
            self.chain_key = new_ck;
            self.skipped_keys
                .insert((self.chain_id, self.chain_iter), mk);
            self.chain_iter += 1;
        }

        let (new_ck, mk) = ratchet_chain(&self.chain_key);
        self.chain_key = new_ck;
        self.chain_iter += 1;

        let pt = open(&mk, &msg.ciphertext).map_err(SignalError::Crypto)?;
        Ok(pt.to_vec())
    }
}

// ── In-memory sender key store ─────────────────────────────────────────────────

#[derive(Default, Clone)]
pub struct InMemorySenderKeyStore {
    states: Arc<RwLock<HashMap<String, SenderKeyDistribution>>>,
}

impl InMemorySenderKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn store(&self, dist: SenderKeyDistribution) {
        let k = format!("{}:{}", dist.group_id, dist.sender_did);
        self.states.write().await.insert(k, dist);
    }

    pub async fn load(&self, group_id: &str, sender_did: &str) -> Option<SenderKeyDistribution> {
        let k = format!("{group_id}:{sender_did}");
        self.states.read().await.get(&k).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_send_recv_roundtrip() {
        let mut sender = SenderKeyState::generate("group-1", "did:plc:alice");
        let dist = sender.distribution();
        let mut receiver = GroupSession::from_distribution(&dist).unwrap();

        let msg = sender.encrypt(b"hello group").unwrap();
        let pt = receiver.decrypt(&msg).unwrap();
        assert_eq!(pt, b"hello group");
    }

    #[test]
    fn group_multiple_messages_in_order() {
        let mut sender = SenderKeyState::generate("group-1", "did:plc:alice");
        let dist = sender.distribution();
        let mut receiver = GroupSession::from_distribution(&dist).unwrap();

        for i in 0u8..5 {
            let msg = sender.encrypt(&[i]).unwrap();
            let pt = receiver.decrypt(&msg).unwrap();
            assert_eq!(pt, &[i]);
        }
    }

    #[test]
    fn tampered_signature_rejected() {
        let mut sender = SenderKeyState::generate("group-1", "did:plc:alice");
        let dist = sender.distribution();
        let mut receiver = GroupSession::from_distribution(&dist).unwrap();

        let mut msg = sender.encrypt(b"secret").unwrap();
        msg.signature[0] ^= 0xFF;
        assert!(receiver.decrypt(&msg).is_err());
    }

    #[test]
    fn sender_key_distribution_json_roundtrip() {
        let sender = SenderKeyState::generate("group-rt", "did:plc:rt");
        let dist = sender.distribution();
        let json = serde_json::to_string(&dist).unwrap();
        let restored: SenderKeyDistribution = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.group_id, dist.group_id);
        assert_eq!(restored.sender_did, dist.sender_did);
        assert_eq!(restored.chain_key, dist.chain_key);
        assert_eq!(restored.signing_key_pub, dist.signing_key_pub);
    }

    #[test]
    fn sender_key_message_json_roundtrip() {
        let mut sender = SenderKeyState::generate("group-msg", "did:plc:msg");
        let msg = sender.encrypt(b"payload").unwrap();
        let json = serde_json::to_string(&msg).unwrap();
        let restored: SenderKeyMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.group_id, msg.group_id);
        assert_eq!(restored.sender_did, msg.sender_did);
        assert_eq!(restored.n, msg.n);
        assert_eq!(restored.ciphertext, msg.ciphertext);
        assert_eq!(restored.signature, msg.signature);
    }

    #[test]
    fn wrong_group_id_triggers_no_session() {
        let mut sender = SenderKeyState::generate("group-a", "did:plc:alice");
        let dist = sender.distribution();
        let mut receiver = GroupSession::from_distribution(&dist).unwrap();

        let mut msg = sender.encrypt(b"hello").unwrap();
        msg.group_id = "group-b".to_string(); // wrong group
        let result = receiver.decrypt(&msg);
        assert!(matches!(result, Err(crate::SignalError::NoSession(_))));
    }

    #[test]
    fn wrong_sender_did_triggers_no_session() {
        let mut sender = SenderKeyState::generate("group-x", "did:plc:alice");
        let dist = sender.distribution();
        let mut receiver = GroupSession::from_distribution(&dist).unwrap();

        let mut msg = sender.encrypt(b"hi").unwrap();
        msg.sender_did = "did:plc:eve".to_string(); // wrong sender
        let result = receiver.decrypt(&msg);
        assert!(matches!(result, Err(crate::SignalError::NoSession(_))));
    }

    #[test]
    fn chain_iter_increments_on_each_encrypt() {
        let mut sender = SenderKeyState::generate("grp", "did:plc:counter");
        assert_eq!(sender.chain_iter, 0);
        sender.encrypt(b"a").unwrap();
        assert_eq!(sender.chain_iter, 1);
        sender.encrypt(b"b").unwrap();
        assert_eq!(sender.chain_iter, 2);
    }

    #[test]
    fn distribution_reflects_initial_state() {
        let sender = SenderKeyState::generate("g", "did:plc:init");
        let dist = sender.distribution();
        assert_eq!(dist.group_id, "g");
        assert_eq!(dist.sender_did, "did:plc:init");
        assert_eq!(dist.chain_id, 0);
        assert_eq!(dist.chain_iter, 0);
        assert_eq!(dist.chain_key.len(), 32);
        assert_eq!(dist.signing_key_pub.len(), 32);
    }

    #[test]
    fn in_memory_store_store_and_load() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = InMemorySenderKeyStore::new();
            let sender = SenderKeyState::generate("grp-store", "did:plc:bob");
            let dist = sender.distribution();
            store.store(dist.clone()).await;

            let loaded = store.load("grp-store", "did:plc:bob").await;
            assert!(loaded.is_some());
            let d = loaded.unwrap();
            assert_eq!(d.group_id, dist.group_id);
            assert_eq!(d.sender_did, dist.sender_did);
        });
    }

    #[test]
    fn in_memory_store_missing_key_returns_none() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = InMemorySenderKeyStore::new();
            let result = store.load("nonexistent-group", "did:plc:nobody").await;
            assert!(result.is_none());
        });
    }

    #[test]
    fn max_skipped_keys_constant_is_positive_and_bounded() {
        assert!(
            MAX_SKIPPED_KEYS >= 100,
            "limit must allow normal out-of-order delivery"
        );
        assert!(
            MAX_SKIPPED_KEYS <= 5_000,
            "limit must cap memory to a sane ceiling"
        );
    }

    #[test]
    fn large_sequence_gap_is_rejected() {
        let mut sender = SenderKeyState::generate("group-gap", "did:plc:alice");
        let dist = sender.distribution();
        let mut receiver = GroupSession::from_distribution(&dist).unwrap();

        // Advance sender by MAX_SKIPPED_KEYS + 1 without receiver consuming
        for _ in 0..=(MAX_SKIPPED_KEYS) {
            sender.encrypt(b"skip me").unwrap();
        }
        // The next message has n = MAX_SKIPPED_KEYS + 1, which exceeds the cap
        let msg = sender.encrypt(b"too far ahead").unwrap();
        let result = receiver.decrypt(&msg);
        assert!(
            matches!(result, Err(crate::SignalError::TooManySkippedKeys)),
            "expected TooManySkippedKeys, got {:?}",
            result
        );
    }

    #[test]
    fn gap_just_at_limit_is_accepted() {
        let mut sender = SenderKeyState::generate("group-gap-ok", "did:plc:alice");
        let dist = sender.distribution();
        let mut receiver = GroupSession::from_distribution(&dist).unwrap();

        // Send and collect exactly MAX_SKIPPED_KEYS - 1 messages
        let mut msgs: Vec<SenderKeyMessage> = Vec::new();
        for _ in 0..(MAX_SKIPPED_KEYS - 1) {
            msgs.push(sender.encrypt(b"skip").unwrap());
        }
        // The next one lands exactly at the limit boundary
        let final_msg = sender.encrypt(b"at boundary").unwrap();
        // Receiver processes only the last one — skips MAX_SKIPPED_KEYS - 1 keys
        let result = receiver.decrypt(&final_msg);
        assert!(
            result.is_ok(),
            "gap at limit must be accepted, got {:?}",
            result
        );
        assert_eq!(result.unwrap(), b"at boundary");
    }

    #[test]
    fn out_of_order_delivery_works_within_limit() {
        let mut sender = SenderKeyState::generate("group-ooo", "did:plc:alice");
        let dist = sender.distribution();
        let mut receiver = GroupSession::from_distribution(&dist).unwrap();

        let msg0 = sender.encrypt(b"msg-0").unwrap();
        let msg1 = sender.encrypt(b"msg-1").unwrap();
        let msg2 = sender.encrypt(b"msg-2").unwrap();

        // Deliver out of order: 2, 0, 1
        let pt2 = receiver.decrypt(&msg2).unwrap();
        let pt0 = receiver.decrypt(&msg0).unwrap();
        let pt1 = receiver.decrypt(&msg1).unwrap();

        assert_eq!(pt0, b"msg-0");
        assert_eq!(pt1, b"msg-1");
        assert_eq!(pt2, b"msg-2");
    }
}
