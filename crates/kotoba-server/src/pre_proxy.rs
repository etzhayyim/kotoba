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
use kotoba_auth::resolver::{DidDocumentResolver, DidResolverError};
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
    #[error("DID resolve: {0}")]
    DidResolve(#[from] DidResolverError),
    #[error("requester public key does not match accessor DID Document")]
    PkMismatch,
}

/// Node-boundary re-encryption service.
pub struct PreProxy {
    registry: Arc<PreKeyRegistry>,
    resolver: Arc<dyn DidDocumentResolver>,
}

impl PreProxy {
    pub fn new(registry: Arc<PreKeyRegistry>, resolver: Arc<dyn DidDocumentResolver>) -> Self {
        Self { registry, resolver }
    }

    /// Verify CACAO chain then deliver the data_key HPKE-sealed to the requester.
    ///
    /// Flow:
    ///   1. `chain` must grant `"quad:read"` on `owner_did`.
    ///   2. Resolve `accessor_did` DID Document and verify `requester_pk` matches
    ///      the registered X25519 key agreement key.  Hard error on mismatch — no
    ///      fallback, because a silent pass-through would allow key substitution.
    ///   3. Fetch the wrapped re-key from the registry and unwrap with `owner_enc_key`.
    ///   4. HPKE-seal the raw data_key to `requester_pk` (X25519).
    ///   5. Return the sealed bytes — only the requester's secret key can open them.
    pub async fn reencrypt_for(
        &self,
        chain: &DelegationChain,
        owner_did: &str,
        accessor_did: &str,
        owner_enc_key: &[u8; 32],
        requester_pk: &[u8; 32],
    ) -> Result<Vec<u8>, PreProxyError> {
        // Fix #4: validate requester_pk against accessor_did's DID Document.
        let registered_pk = self.resolver.x25519_key(accessor_did)?;
        if registered_pk != *requester_pk {
            return Err(PreProxyError::PkMismatch);
        }

        // `data_key` is Zeroizing — wiped automatically when this scope exits.
        let data_key = self.registry
            .get_rekey_authed(chain, owner_did, accessor_did, owner_enc_key)
            .await?;

        let pk = PublicKey::from(*requester_pk);
        let sealed = hpke_seal(&pk, &data_key)?;
        Ok(sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_auth::{
        DidDocument, VerificationMethod, ServiceEndpoint,
        did_document::ServiceEndpointValue,
        InMemoryDidResolver,
    };
    use kotoba_kse::PreKeyRegistry;
    use kotoba_store::MemoryBlockStore;

    fn make_doc_with_x25519(did: &str, key: [u8; 32]) -> DidDocument {
        let encoded = multibase::encode(multibase::Base::Base58Btc, &key);
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#key-x25519-1"),
                key_type: "X25519KeyAgreementKey2020".into(),
                controller: did.to_owned(),
                public_key_multibase: encoded,
            }],
            authentication: vec![],
            assertion_method: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![ServiceEndpoint {
                id: "#kotoba".into(),
                service_type: "KotobaNode".into(),
                endpoint: ServiceEndpointValue::Single("/ip4/127.0.0.1/tcp/4001".into()),
            }],
        }
    }

    fn make_proxy(accessor_did: &str, registered_pk: [u8; 32]) -> PreProxy {
        let store = Arc::new(MemoryBlockStore::new());
        let registry = Arc::new(PreKeyRegistry::new(store));
        let resolver = Arc::new(InMemoryDidResolver::new());
        resolver.insert(accessor_did, make_doc_with_x25519(accessor_did, registered_pk));
        PreProxy::new(registry, resolver)
    }

    #[tokio::test]
    async fn pk_mismatch_returns_error() {
        let accessor_did = "did:key:zAccessor";
        let registered_pk = [1u8; 32];
        let wrong_pk = [2u8; 32];

        let proxy = make_proxy(accessor_did, registered_pk);

        // Use a dummy chain — PkMismatch fires before registry lookup.
        use kotoba_auth::{Cacao, CacaoHeader, CacaoPayload, CacaoSig, DelegationChain};
        let chain = DelegationChain::new(Cacao {
            h: CacaoHeader { t: "caip122".into() },
            p: CacaoPayload {
                iss: accessor_did.into(),
                aud: "kotoba://test".into(),
                issued_at: "2026-05-26T00:00:00Z".into(),
                expiry: None,
                nonce: "n1".into(),
                domain: "kotoba.test".into(),
                statement: None,
                version: "1".into(),
                resources: vec![
                    "kotoba://can/quad:read".into(),
                    "kotoba://graph/bafytest".into(),
                ],
            },
            s: CacaoSig { t: "EdDSA".into(), s: "dummy".into() },
        });

        let err = proxy.reencrypt_for(
            &chain, "did:key:zOwner", accessor_did, &[0u8; 32], &wrong_pk,
        ).await.unwrap_err();

        assert!(matches!(err, PreProxyError::PkMismatch),
            "expected PkMismatch, got {err:?}");
    }

    #[tokio::test]
    async fn unknown_accessor_did_returns_did_resolve_error() {
        let accessor_did = "did:key:zUnknown";
        let store = Arc::new(MemoryBlockStore::new());
        let registry = Arc::new(PreKeyRegistry::new(store));
        let resolver = Arc::new(InMemoryDidResolver::new()); // empty
        let proxy = PreProxy::new(registry, resolver);

        use kotoba_auth::{Cacao, CacaoHeader, CacaoPayload, CacaoSig, DelegationChain};
        let chain = DelegationChain::new(Cacao {
            h: CacaoHeader { t: "caip122".into() },
            p: CacaoPayload {
                iss: accessor_did.into(),
                aud: "kotoba://test".into(),
                issued_at: "2026-05-26T00:00:00Z".into(),
                expiry: None,
                nonce: "n2".into(),
                domain: "kotoba.test".into(),
                statement: None,
                version: "1".into(),
                resources: vec![],
            },
            s: CacaoSig { t: "EdDSA".into(), s: "dummy".into() },
        });

        let err = proxy.reencrypt_for(
            &chain, "did:key:zOwner", accessor_did, &[0u8; 32], &[3u8; 32],
        ).await.unwrap_err();

        assert!(matches!(err, PreProxyError::DidResolve(_)),
            "expected DidResolve, got {err:?}");
    }
}
