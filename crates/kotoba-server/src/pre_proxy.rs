/// PRE proxy — node-boundary re-encryption service.
///
/// Sits between the network (ciphertext world) and compute functions (plaintext world).
/// Inbound: the proxy HPKE-opens a sealed data_key using the node's secret key.
/// Outbound: after CACAO verification, the proxy fetches the data_key from the
/// PreKeyRegistry and HPKE-seals it to the requester's public key.
///
/// Compute functions are **never** aware of this layer — they always receive
/// plaintext `AuthMessage::payload` and return plaintext `AuthOutMessage::payload`.
use std::sync::Arc;

use kotoba_auth::delegation::DelegationChain;
use kotoba_crypto::aead::CryptoError;
use kotoba_crypto::hpke::hpke_seal;
use kotoba_kse::{PreKeyError, PreKeyRegistry};
use x25519_dalek::PublicKey;

#[derive(Debug, thiserror::Error)]
pub enum PreProxyError {
    #[error("pre-key registry: {0}")]
    PreKey(#[from] PreKeyError),
    #[error("hpke seal: {0}")]
    Hpke(#[from] CryptoError),
}

/// Node-boundary re-encryption service.
pub struct PreProxy {
    registry: Arc<PreKeyRegistry>,
}

impl PreProxy {
    pub fn new(registry: Arc<PreKeyRegistry>) -> Self {
        Self { registry }
    }

    /// Verify CACAO chain then deliver the data_key HPKE-sealed to the requester.
    ///
    /// Flow:
    ///   1. `chain` must grant `"quad:read"` on `owner_did`.
    ///   2. Fetch the wrapped re-key from the registry and unwrap with `owner_enc_key`.
    ///   3. HPKE-seal the raw data_key to `requester_pk` (X25519).
    ///   4. Return the sealed bytes — only the requester's secret key can open them.
    pub async fn reencrypt_for(
        &self,
        chain: &DelegationChain,
        owner_did: &str,
        accessor_did: &str,
        owner_enc_key: &[u8; 32],
        requester_pk: &[u8; 32],
    ) -> Result<Vec<u8>, PreProxyError> {
        // `data_key` is Zeroizing — wiped automatically when this scope exits.
        let data_key = self.registry
            .get_rekey_authed(chain, owner_did, accessor_did, owner_enc_key)
            .await?;

        let pk = PublicKey::from(*requester_pk);
        let sealed = hpke_seal(&pk, &data_key)?;
        Ok(sealed)
    }
}
