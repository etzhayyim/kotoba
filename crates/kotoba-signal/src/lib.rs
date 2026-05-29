//! Signal Protocol E2E for Kotoba.
//! SSoT replacing `@gftd/signal` (`10-protocol/signal/`).
//!
//! Wire format `signal:v1:{base64url}` is preserved for compatibility.

pub mod group;
pub mod identity;
pub mod message;
pub mod prekey;
pub mod ratchet;
pub mod session;
pub mod store;
pub mod x3dh;

pub use group::{GroupSession, InMemorySenderKeyStore, SenderKeyMessage, SenderKeyState};
pub use identity::{DeviceId, IdentityKey, IdentityKeyPair};
pub use message::{MessageType, Reaction, SignalMessage, ThreadMessage};
pub use prekey::{PreKey, PreKeyBundle, PreKeyId, SignedPreKey, SignedPreKeyId};
pub use ratchet::{RatchetMessage, RatchetState};
pub use session::{InMemorySessionStore, Session, SessionStore};
pub use store::{InMemorySignalStore, SignalStore};
pub use x3dh::{x3dh_init_receiver, x3dh_init_sender, X3dhOutput};

pub use kotoba_crypto::envelope::{decrypt_field, encrypt_field, SIGNAL_VAL_PREFIX};

#[derive(Debug, thiserror::Error)]
pub enum SignalError {
    #[error("crypto: {0}")]
    Crypto(#[from] kotoba_crypto::aead::CryptoError),
    #[error("no session for {0}")]
    NoSession(String),
    #[error("no pre-key {0}")]
    NoPreKey(u32),
    #[error("no signed pre-key {0}")]
    NoSignedPreKey(u32),
    #[error("signature verification failed")]
    BadSignature,
    #[error("message counter mismatch")]
    CounterMismatch,
    #[error("too many skipped message keys (gap exceeds limit)")]
    TooManySkippedKeys,
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("store error: {0}")]
    Store(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_session_display() {
        let e = SignalError::NoSession("did:key:zAlice".to_string());
        assert_eq!(e.to_string(), "no session for did:key:zAlice");
    }

    #[test]
    fn no_prekey_display() {
        let e = SignalError::NoPreKey(42);
        assert_eq!(e.to_string(), "no pre-key 42");
    }

    #[test]
    fn no_signed_prekey_display() {
        let e = SignalError::NoSignedPreKey(7);
        assert_eq!(e.to_string(), "no signed pre-key 7");
    }

    #[test]
    fn bad_signature_display() {
        let e = SignalError::BadSignature;
        assert_eq!(e.to_string(), "signature verification failed");
    }

    #[test]
    fn counter_mismatch_display() {
        let e = SignalError::CounterMismatch;
        assert_eq!(e.to_string(), "message counter mismatch");
    }

    #[test]
    fn store_error_display() {
        let e = SignalError::Store("disk full".to_string());
        assert_eq!(e.to_string(), "store error: disk full");
    }

    #[test]
    fn serde_error_from() {
        let json_err: serde_json::Error = serde_json::from_str::<i32>("bad").unwrap_err();
        let e = SignalError::from(json_err);
        assert!(e.to_string().starts_with("serialization: "));
    }

    // ---- New tests --------------------------------------------------------

    #[test]
    fn too_many_skipped_keys_display() {
        let e = SignalError::TooManySkippedKeys;
        assert_eq!(
            e.to_string(),
            "too many skipped message keys (gap exceeds limit)"
        );
    }

    #[test]
    fn no_prekey_zero_display() {
        let e = SignalError::NoPreKey(0);
        assert_eq!(e.to_string(), "no pre-key 0");
    }

    #[test]
    fn no_signed_prekey_zero_display() {
        let e = SignalError::NoSignedPreKey(0);
        assert_eq!(e.to_string(), "no signed pre-key 0");
    }

    #[test]
    fn store_error_empty_string() {
        let e = SignalError::Store(String::new());
        // message should be "store error: " followed by empty string
        assert!(e.to_string().starts_with("store error:"));
    }

    #[test]
    fn crypto_error_from_wraps_display() {
        use kotoba_crypto::aead::CryptoError;
        let inner = CryptoError::OpenFailed;
        let e = SignalError::from(inner);
        assert!(
            e.to_string().starts_with("crypto:"),
            "SignalError::Crypto must prefix with 'crypto:'"
        );
    }

    #[test]
    fn no_session_with_long_did() {
        let long_did = "did:key:".to_string() + &"z".repeat(100);
        let e = SignalError::NoSession(long_did.clone());
        assert!(e.to_string().contains(&long_did));
    }
}
