pub mod hkdf;
pub mod aead;
pub mod envelope;
pub mod key_wrap;
pub mod hpke;
pub mod agent_crypto;

pub use hkdf::{derive_key, derive_key_with_salt, HKDF_KEY_LEN};
pub use aead::{seal, open, CryptoError, KEY_LEN, NONCE_LEN, TAG_LEN};
pub use envelope::{encode_envelope, decode_envelope, SIGNAL_VAL_PREFIX};
pub use key_wrap::{wrap_key, unwrap_key};
pub use hpke::{hpke_seal, hpke_open};
pub use agent_crypto::{AgentCrypto, VaultKeyedCrypto};
