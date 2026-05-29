/// End-to-end integration test for the full Signal Protocol stack.
/// Covers: key generation → X3DH → Double Ratchet 1:1 → Sender Keys group → field encryption.
use kotoba_signal::{
    group::{GroupSession, SenderKeyState},
    identity::IdentityKeyPair,
    prekey::{PreKey, PreKeyBundle, SignedPreKey},
    ratchet::RatchetState,
    session::Session,
    store::SignalStore,
    x3dh::{x3dh_init_receiver, x3dh_init_sender},
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

// ── Helpers ────────────────────────────────────────────────────────────────────

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

// ── 1:1 Double Ratchet via Session ────────────────────────────────────────────

#[test]
fn full_session_initiate_and_decrypt() {
    let alice_ik = IdentityKeyPair::generate();
    let bob_ik = IdentityKeyPair::generate();
    let bob_spk = SignedPreKey::generate(1, &bob_ik);
    let bob_opk = PreKey::generate(100);

    let bundle = make_bundle(&bob_ik, &bob_spk, Some(&bob_opk));

    // Alice initiates
    let (mut alice_session, ep_bytes) = Session::initiate(&alice_ik, &bundle).unwrap();
    let ep: [u8; 32] = ep_bytes.try_into().unwrap();

    // Bob accepts
    let mut bob_session = Session::accept(
        &bob_ik,
        &bob_spk,
        Some(&bob_opk),
        &alice_ik.public_key(),
        &ep,
        "did:plc:alice",
        "dev-a",
    )
    .unwrap();

    // Alice → Bob
    let m1 = alice_session.encrypt(b"Hello Bob!").unwrap();
    assert_eq!(bob_session.decrypt(&m1).unwrap(), b"Hello Bob!");

    // Bob → Alice
    let m2 = bob_session.encrypt(b"Hi Alice!").unwrap();
    assert_eq!(alice_session.decrypt(&m2).unwrap(), b"Hi Alice!");

    // Multiple turns
    for i in 0u8..10 {
        let msg = alice_session.encrypt(&[i]).unwrap();
        assert_eq!(bob_session.decrypt(&msg).unwrap(), vec![i]);
        let reply = bob_session.encrypt(&[i + 100]).unwrap();
        assert_eq!(alice_session.decrypt(&reply).unwrap(), vec![i + 100]);
    }
}

// ── Group Sender Keys ─────────────────────────────────────────────────────────

#[test]
fn group_three_members_all_can_decrypt() {
    let group_id = "group:kotoba-test";

    // Alice creates a sender key
    let mut alice_sk = SenderKeyState::generate(group_id, "did:plc:alice");
    let alice_dist = alice_sk.distribution();

    // Bob and Carol receive the distribution
    let mut bob_session = GroupSession::from_distribution(&alice_dist).unwrap();
    let mut carol_session = GroupSession::from_distribution(&alice_dist).unwrap();

    // Alice sends 3 messages
    let m1 = alice_sk.encrypt(b"Hello group!").unwrap();
    let m2 = alice_sk.encrypt(b"Second message").unwrap();
    let m3 = alice_sk.encrypt(b"Third").unwrap();

    // Both can decrypt in order
    assert_eq!(bob_session.decrypt(&m1).unwrap(), b"Hello group!");
    assert_eq!(carol_session.decrypt(&m1).unwrap(), b"Hello group!");
    assert_eq!(bob_session.decrypt(&m2).unwrap(), b"Second message");
    assert_eq!(carol_session.decrypt(&m3).unwrap(), b"Third");
}

// ── Field-level encryption (signal:v1: envelope) ─────────────────────────────

#[tokio::test]
async fn signal_store_field_encryption_roundtrip() {
    let alice = SignalStore::new("did:plc:alice", "dev-1");

    let plain = "こんにちは、世界！";
    let enc = alice
        .encrypt_field(plain, "did:plc:bob", "convo-abc123")
        .unwrap();
    assert!(
        enc.starts_with("signal:v1:"),
        "envelope must have signal:v1: prefix"
    );

    let dec = alice
        .decrypt_field(&enc, "did:plc:bob", "convo-abc123")
        .unwrap();
    assert_eq!(dec, plain);
}

// ── SecureVault ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn secure_vault_roundtrip_via_store_key() {
    use bytes::Bytes;
    use kotoba_kse::SecureVault;

    let sv = SecureVault::new();
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut key);

    let secret = Bytes::from(b"vault top-secret blob".to_vec());
    let blob_ref = sv.put(&key, secret.clone()).await.unwrap();

    let recovered = sv.get(&key, &blob_ref).await.unwrap().unwrap();
    assert_eq!(recovered, secret);
}

// ── PreKey bundle management ──────────────────────────────────────────────────

#[tokio::test]
async fn store_prekey_bundle_and_retrieve() {
    let store = SignalStore::new("did:plc:alice", "dev-1");
    store.generate_prekeys(1, 10).await;
    store.rotate_signed_prekey(1).await;

    let bundle = store.prekey_bundle(1).await.unwrap();
    assert_eq!(bundle.did, "did:plc:alice");
    assert!(bundle.one_time_prekey.is_some());

    // Verify SPK signature
    assert!(
        bundle
            .identity_key
            .verify(&bundle.signed_prekey, &bundle.signed_prekey_sig),
        "SPK signature must be valid"
    );
}
