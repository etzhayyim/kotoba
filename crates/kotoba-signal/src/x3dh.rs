//! X3DH Extended Triple Diffie-Hellman key agreement.
//!
//! Sender computes:
//!   DH1 = DH(IK_A,  SPK_B)
//!   DH2 = DH(EK_A,  IK_B)
//!   DH3 = DH(EK_A,  SPK_B)
//!   DH4 = DH(EK_A,  OPK_B)  (optional)
//!   SK  = HKDF(0xFF*32 || DH1 || DH2 || DH3 [|| DH4])
//!
//! Receiver computes the symmetric counterpart.
//!
//! Reference: Signal specification https://signal.org/docs/specifications/x3dh/

use crate::{
    identity::IdentityKeyPair,
    prekey::{PreKey, PreKeyBundle, SignedPreKey},
    SignalError,
};
use kotoba_crypto::hkdf::derive_key_with_salt;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

const X3DH_INFO: &[u8] = b"kotoba-x3dh-v1";
/// F-pad: 32 × 0xFF bytes prepended to DH output (per Signal spec)
const F_PAD: [u8; 32] = [0xFFu8; 32];

pub struct X3dhOutput {
    /// 32-byte shared secret — used as root key for Double Ratchet init.
    pub shared_secret: [u8; 32],
    /// Ephemeral public key (sender side only; sent in the initial message).
    pub ephemeral_public: Option<[u8; 32]>,
}

/// Sender side: initialise X3DH using the recipient's `bundle`.
/// Returns (shared_secret, ephemeral_public_key).
pub fn x3dh_init_sender(
    sender_ik: &IdentityKeyPair,
    bundle: &PreKeyBundle,
) -> Result<X3dhOutput, SignalError> {
    // Verify SPK signature
    let spk_pub: [u8; 32] = bundle
        .signed_prekey
        .as_slice()
        .try_into()
        .map_err(|_| SignalError::BadSignature)?;
    if !bundle
        .identity_key
        .verify(&spk_pub, &bundle.signed_prekey_sig)
    {
        return Err(SignalError::BadSignature);
    }

    let ik_b_dh: [u8; 32] = bundle
        .identity_key
        .dh
        .as_slice()
        .try_into()
        .map_err(|_| SignalError::BadSignature)?;

    // Ephemeral key
    let ek = StaticSecret::random_from_rng(OsRng);
    let ek_pub = X25519Public::from(&ek).to_bytes();

    let dh1 = sender_ik.dh(&spk_pub); // IK_A × SPK_B
    let dh2 = ek.diffie_hellman(&X25519Public::from(ik_b_dh)).to_bytes(); // EK_A × IK_B
    let dh3 = ek.diffie_hellman(&X25519Public::from(spk_pub)).to_bytes(); // EK_A × SPK_B

    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(&F_PAD);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    if let Some(opk_bytes) = &bundle.one_time_prekey {
        if let Ok(opk_arr) = <&[u8] as TryInto<[u8; 32]>>::try_into(opk_bytes.as_slice()) {
            let dh4 = ek.diffie_hellman(&X25519Public::from(opk_arr)).to_bytes();
            ikm.extend_from_slice(&dh4);
        }
    }

    let shared_secret = derive_key_with_salt(&ikm, &[], X3DH_INFO);

    Ok(X3dhOutput {
        shared_secret,
        ephemeral_public: Some(ek_pub),
    })
}

/// Receiver side: process an initial X3DH message.
/// `ephemeral_public` = EK_A bytes from the sender's initial message.
/// `used_opk_id`      = ID of the one-time pre-key consumed (if any).
pub fn x3dh_init_receiver(
    receiver_ik: &IdentityKeyPair,
    signed_prekey: &SignedPreKey,
    one_time_prekey: Option<&PreKey>,
    sender_ik_pub: &crate::identity::IdentityKey,
    ephemeral_public: &[u8; 32],
) -> Result<X3dhOutput, SignalError> {
    let ik_a_dh: [u8; 32] = sender_ik_pub
        .dh
        .as_slice()
        .try_into()
        .map_err(|_| SignalError::BadSignature)?;

    let dh1 = signed_prekey.dh(&ik_a_dh); // SPK_B × IK_A
    let dh2 = receiver_ik.dh(ephemeral_public); // IK_B  × EK_A
    let dh3 = signed_prekey.dh(ephemeral_public); // SPK_B × EK_A

    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(&F_PAD);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    if let Some(opk) = one_time_prekey {
        let dh4 = opk.dh(ephemeral_public);
        ikm.extend_from_slice(&dh4);
    }

    let shared_secret = derive_key_with_salt(&ikm, &[], X3DH_INFO);

    Ok(X3dhOutput {
        shared_secret,
        ephemeral_public: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::IdentityKeyPair,
        prekey::{PreKey, PreKeyBundle, SignedPreKey},
    };

    fn make_bundle(ik: &IdentityKeyPair, spk: &SignedPreKey, opk: Option<&PreKey>) -> PreKeyBundle {
        PreKeyBundle {
            did: "did:plc:bob".into(),
            device_id: "dev-1".into(),
            identity_key: ik.public_key(),
            signed_prekey: spk.public_bytes().to_vec(),
            signed_prekey_id: spk.id,
            signed_prekey_sig: spk.signature.clone(),
            one_time_prekey: opk.map(|k| k.public_bytes().to_vec()),
            one_time_prekey_id: opk.map(|k| k.id),
        }
    }

    #[test]
    fn x3dh_shared_secrets_match_without_opk() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_ik);

        let bundle = make_bundle(&bob_ik, &bob_spk, None);
        let sender_out = x3dh_init_sender(&alice_ik, &bundle).unwrap();
        let ep = sender_out.ephemeral_public.unwrap();

        let receiver_out =
            x3dh_init_receiver(&bob_ik, &bob_spk, None, &alice_ik.public_key(), &ep).unwrap();

        assert_eq!(sender_out.shared_secret, receiver_out.shared_secret);
    }

    #[test]
    fn x3dh_shared_secrets_match_with_opk() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_ik);
        let bob_opk = PreKey::generate(42);

        let bundle = make_bundle(&bob_ik, &bob_spk, Some(&bob_opk));
        let sender_out = x3dh_init_sender(&alice_ik, &bundle).unwrap();
        let ep = sender_out.ephemeral_public.unwrap();

        let receiver_out = x3dh_init_receiver(
            &bob_ik,
            &bob_spk,
            Some(&bob_opk),
            &alice_ik.public_key(),
            &ep,
        )
        .unwrap();

        assert_eq!(sender_out.shared_secret, receiver_out.shared_secret);
    }

    #[test]
    fn x3dh_bad_spk_signature_rejected() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_ik);
        let mut bundle = make_bundle(&bob_ik, &bob_spk, None);

        // Corrupt signature
        bundle.signed_prekey_sig[0] ^= 0xFF;
        assert!(x3dh_init_sender(&alice_ik, &bundle).is_err());
    }

    #[test]
    fn sender_ephemeral_public_is_some() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_ik);
        let bundle = make_bundle(&bob_ik, &bob_spk, None);
        let out = x3dh_init_sender(&alice_ik, &bundle).unwrap();
        assert!(out.ephemeral_public.is_some());
    }

    #[test]
    fn receiver_ephemeral_public_is_none() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_ik);
        let bundle = make_bundle(&bob_ik, &bob_spk, None);
        let sender_out = x3dh_init_sender(&alice_ik, &bundle).unwrap();
        let ep = sender_out.ephemeral_public.unwrap();
        let receiver_out =
            x3dh_init_receiver(&bob_ik, &bob_spk, None, &alice_ik.public_key(), &ep).unwrap();
        assert!(receiver_out.ephemeral_public.is_none());
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_ik);
        let bundle = make_bundle(&bob_ik, &bob_spk, None);
        let out = x3dh_init_sender(&alice_ik, &bundle).unwrap();
        assert_eq!(out.shared_secret.len(), 32);
    }

    #[test]
    fn short_signed_prekey_returns_bad_signature() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_ik);
        let mut bundle = make_bundle(&bob_ik, &bob_spk, None);
        // Replace signed_prekey with a 1-byte value — not 32 bytes
        bundle.signed_prekey = vec![0x01];
        let result = x3dh_init_sender(&alice_ik, &bundle);
        assert!(matches!(result, Err(crate::SignalError::BadSignature)));
    }

    #[test]
    fn different_initiators_produce_different_secrets() {
        let alice_ik = IdentityKeyPair::generate();
        let carol_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_ik);
        let bundle = make_bundle(&bob_ik, &bob_spk, None);

        let out_alice = x3dh_init_sender(&alice_ik, &bundle).unwrap();
        let out_carol = x3dh_init_sender(&carol_ik, &bundle).unwrap();
        assert_ne!(out_alice.shared_secret, out_carol.shared_secret);
    }

    #[test]
    fn ephemeral_public_is_32_bytes() {
        let alice_ik = IdentityKeyPair::generate();
        let bob_ik = IdentityKeyPair::generate();
        let bob_spk = SignedPreKey::generate(1, &bob_ik);
        let bundle = make_bundle(&bob_ik, &bob_spk, None);
        let out = x3dh_init_sender(&alice_ik, &bundle).unwrap();
        let ep = out.ephemeral_public.unwrap();
        assert_eq!(ep.len(), 32);
    }
}
