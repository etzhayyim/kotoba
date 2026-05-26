/// Double Ratchet Algorithm (Signal specification).
///
/// State:
///   RK     — 32-byte root key
///   CK_s   — 32-byte sending chain key
///   CK_r   — 32-byte receiving chain key
///   DHs    — current sending ratchet key pair (X25519)
///   DHr    — remote ratchet public key (X25519)
///   Ns     — sending message counter
///   Nr     — receiving message counter
///   PN     — previous sending chain length (for skipped messages)
///   MKSKIPPED — cache of skipped message keys
use std::collections::HashMap;
use x25519_dalek::{StaticSecret, PublicKey as X25519Public};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;
use kotoba_crypto::{
    hkdf::{ratchet_root, ratchet_chain},
    aead::{seal, open},
};
use crate::SignalError;

const MAX_SKIP: u32 = 1000;

#[derive(ZeroizeOnDrop)]
pub struct RatchetState {
    pub root_key:         [u8; 32],
    pub send_chain_key:   Option<[u8; 32]>,
    pub recv_chain_key:   Option<[u8; 32]>,
    pub send_ratchet_priv: StaticSecret,
    pub recv_ratchet_pub:  Option<[u8; 32]>,
    pub send_counter:      u32,
    pub recv_counter:      u32,
    pub prev_send_counter: u32,
    #[zeroize(skip)]
    pub skipped_keys:      HashMap<(Vec<u8>, u32), [u8; 32]>,
}

/// Header sent with each Double Ratchet message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// Sender's current ratchet public key (32 bytes).
    pub dh_pub:    Vec<u8>,
    /// Previous sending chain length (PN).
    pub pn:        u32,
    /// Message counter within the current sending chain (N).
    pub n:         u32,
    /// AES-256-GCM ciphertext (nonce || ct, from `kotoba_crypto::aead::seal`).
    pub ciphertext: Vec<u8>,
}

impl RatchetState {
    /// Initialise as the session **initiator** (Alice / X3DH sender).
    /// `shared_secret` is the X3DH output.
    /// `remote_ratchet_pub` is the responder's signed pre-key public bytes.
    pub fn init_sender(shared_secret: [u8; 32], remote_ratchet_pub: [u8; 32]) -> Self {
        let send_ratchet_priv = StaticSecret::random_from_rng(OsRng);
        let dh_out = send_ratchet_priv
            .diffie_hellman(&X25519Public::from(remote_ratchet_pub))
            .to_bytes();
        let (root_key, send_chain_key) = ratchet_root(&shared_secret, &dh_out);

        Self {
            root_key,
            send_chain_key: Some(send_chain_key),
            recv_chain_key: None,
            send_ratchet_priv,
            recv_ratchet_pub: Some(remote_ratchet_pub),
            send_counter: 0,
            recv_counter: 0,
            prev_send_counter: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Initialise as the session **responder** (Bob / X3DH receiver).
    /// `shared_secret` is the X3DH output.
    /// `local_ratchet_priv` is Bob's signed pre-key private bytes (the SPK).
    pub fn init_receiver(shared_secret: [u8; 32], local_ratchet_priv: StaticSecret) -> Self {
        Self {
            root_key: shared_secret,
            send_chain_key: None,
            recv_chain_key: None,
            send_ratchet_priv: local_ratchet_priv,
            recv_ratchet_pub: None,
            send_counter: 0,
            recv_counter: 0,
            prev_send_counter: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt `plaintext` and advance the sending chain.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, SignalError> {
        let ck = self
            .send_chain_key
            .as_mut()
            .ok_or_else(|| SignalError::NoSession("send chain not initialised".into()))?;

        let (new_ck, mk) = ratchet_chain(ck);
        *ck = new_ck;

        let ct = seal(&mk, plaintext).map_err(SignalError::Crypto)?;
        let msg = RatchetMessage {
            dh_pub: X25519Public::from(&self.send_ratchet_priv).to_bytes().to_vec(),
            pn: self.prev_send_counter,
            n:  self.send_counter,
            ciphertext: ct,
        };
        self.send_counter += 1;
        Ok(msg)
    }

    /// Decrypt an incoming `RatchetMessage`.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, SignalError> {
        let dh_pub: [u8; 32] = msg
            .dh_pub
            .as_slice()
            .try_into()
            .map_err(|_| SignalError::CounterMismatch)?;

        // Try skipped message keys first
        let skip_key = (msg.dh_pub.clone(), msg.n);
        if let Some(mk) = self.skipped_keys.remove(&skip_key) {
            let pt = open(&mk, &msg.ciphertext).map_err(SignalError::Crypto)?;
            return Ok(pt.to_vec());
        }

        // DH ratchet step if dh_pub changed
        let needs_dh_ratchet = self
            .recv_ratchet_pub
            .map(|r| r != dh_pub)
            .unwrap_or(true);

        if needs_dh_ratchet {
            // Skip messages in old chain
            self.skip_message_keys(msg.pn)?;
            self.do_dh_ratchet(dh_pub)?;
        }

        // Skip messages in current receiving chain
        self.skip_message_keys(msg.n)?;

        let ck = self
            .recv_chain_key
            .as_mut()
            .ok_or_else(|| SignalError::NoSession("recv chain not initialised".into()))?;

        let (new_ck, mk) = ratchet_chain(ck);
        *ck = new_ck;
        self.recv_counter += 1;

        let pt = open(&mk, &msg.ciphertext).map_err(SignalError::Crypto)?;
        Ok(pt.to_vec())
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), SignalError> {
        if until.saturating_sub(self.recv_counter) > MAX_SKIP {
            return Err(SignalError::CounterMismatch);
        }
        while let Some(ck) = self.recv_chain_key.as_mut() {
            if self.recv_counter >= until {
                break;
            }
            let (new_ck, mk) = ratchet_chain(ck);
            *ck = new_ck;
            let dh_pub = self
                .recv_ratchet_pub
                .map(|k| k.to_vec())
                .unwrap_or_default();
            self.skipped_keys.insert((dh_pub, self.recv_counter), mk);
            self.recv_counter += 1;
        }
        Ok(())
    }

    fn do_dh_ratchet(&mut self, remote_pub: [u8; 32]) -> Result<(), SignalError> {
        self.prev_send_counter = self.send_counter;
        self.send_counter      = 0;
        self.recv_counter      = 0;

        // Receiving chain
        let dh_out = self
            .send_ratchet_priv
            .diffie_hellman(&X25519Public::from(remote_pub))
            .to_bytes();
        let (new_rk, recv_ck) = ratchet_root(&self.root_key, &dh_out);
        self.root_key       = new_rk;
        self.recv_chain_key = Some(recv_ck);

        // New sending ratchet key
        self.send_ratchet_priv = StaticSecret::random_from_rng(OsRng);
        let dh_out2 = self
            .send_ratchet_priv
            .diffie_hellman(&X25519Public::from(remote_pub))
            .to_bytes();
        let (new_rk2, send_ck) = ratchet_root(&self.root_key, &dh_out2);
        self.root_key       = new_rk2;
        self.send_chain_key = Some(send_ck);
        self.recv_ratchet_pub = Some(remote_pub);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pair() -> (RatchetState, RatchetState) {
        let shared = [0x42u8; 32];
        let bob_spk_priv = StaticSecret::random_from_rng(OsRng);
        let bob_spk_pub  = X25519Public::from(&bob_spk_priv).to_bytes();

        let alice = RatchetState::init_sender(shared, bob_spk_pub);
        let bob   = RatchetState::init_receiver(shared, bob_spk_priv);
        (alice, bob)
    }

    #[test]
    fn send_recv_single_message() {
        let (mut alice, mut bob) = make_pair();
        let msg = alice.encrypt(b"hello bob").unwrap();
        let pt  = bob.decrypt(&msg).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn send_multiple_messages_in_order() {
        let (mut alice, mut bob) = make_pair();
        for i in 0u8..5 {
            let msg = alice.encrypt(&[i]).unwrap();
            let pt  = bob.decrypt(&msg).unwrap();
            assert_eq!(pt, &[i]);
        }
    }

    #[test]
    fn bidirectional_exchange() {
        let (mut alice, mut bob) = make_pair();
        // Alice → Bob
        let m1 = alice.encrypt(b"ping").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"ping");
        // Bob → Alice (triggers DH ratchet on alice's side)
        let m2 = bob.encrypt(b"pong").unwrap();
        assert_eq!(alice.decrypt(&m2).unwrap(), b"pong");
    }

    #[test]
    fn ratchet_message_json_roundtrip() {
        let (mut alice, _bob) = make_pair();
        let msg = alice.encrypt(b"serialize me").unwrap();
        let json = serde_json::to_string(&msg).unwrap();
        let restored: RatchetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.dh_pub, msg.dh_pub);
        assert_eq!(restored.pn, msg.pn);
        assert_eq!(restored.n, msg.n);
        assert_eq!(restored.ciphertext, msg.ciphertext);
    }

    #[test]
    fn send_counter_increments_per_message() {
        let (mut alice, _bob) = make_pair();
        assert_eq!(alice.send_counter, 0);
        alice.encrypt(b"a").unwrap();
        assert_eq!(alice.send_counter, 1);
        alice.encrypt(b"b").unwrap();
        assert_eq!(alice.send_counter, 2);
    }

    #[test]
    fn receiver_init_send_chain_is_none() {
        let shared = [0x77u8; 32];
        let spk_priv = StaticSecret::random_from_rng(OsRng);
        let bob = RatchetState::init_receiver(shared, spk_priv);
        assert!(bob.send_chain_key.is_none());
    }

    #[test]
    fn sender_init_send_chain_is_some() {
        let (alice, _bob) = make_pair();
        assert!(alice.send_chain_key.is_some());
    }

    #[test]
    fn wrong_length_dh_pub_returns_counter_mismatch() {
        let (mut alice, mut bob) = make_pair();
        let mut msg = alice.encrypt(b"hello").unwrap();
        // Truncate dh_pub to 16 bytes — try_into::<[u8;32]> must fail
        msg.dh_pub = msg.dh_pub[..16].to_vec();
        let result = bob.decrypt(&msg);
        assert!(matches!(result, Err(crate::SignalError::CounterMismatch)));
    }

    #[test]
    fn encrypt_without_send_chain_returns_no_session() {
        let shared = [0x88u8; 32];
        let spk_priv = StaticSecret::random_from_rng(OsRng);
        let mut bob = RatchetState::init_receiver(shared, spk_priv);
        // Bob's send_chain_key is None at init_receiver — encrypt must fail
        let result = bob.encrypt(b"no chain");
        assert!(matches!(result, Err(crate::SignalError::NoSession(_))));
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut alice, mut bob) = make_pair();
        let m0 = alice.encrypt(b"first").unwrap();
        let m1 = alice.encrypt(b"second").unwrap();
        // Deliver second before first — skipped-keys path
        assert_eq!(bob.decrypt(&m1).unwrap(), b"second");
        assert_eq!(bob.decrypt(&m0).unwrap(), b"first");
    }
}
