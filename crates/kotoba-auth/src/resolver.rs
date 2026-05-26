use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::did_document::DidDocument;

#[derive(Debug, thiserror::Error)]
pub enum DidResolverError {
    #[error("DID not found: {0}")]
    NotFound(String),
    #[error("no X25519 key in DID Document for {0}")]
    NoX25519Key(String),
}

/// Resolve a DID to its DID Document.
///
/// Implementations are provided for in-memory test/dev use.
/// Production implementations fetch from a verifiable data registry
/// (e.g. PDS `com.atproto.identity.resolveHandle` → `did:plc` resolve).
pub trait DidDocumentResolver: Send + Sync {
    fn resolve(&self, did: &str) -> Result<DidDocument, DidResolverError>;

    /// Convenience: resolve and extract the X25519 public key.
    fn x25519_key(&self, did: &str) -> Result<[u8; 32], DidResolverError> {
        let doc = self.resolve(did)?;
        doc.x25519_public_key()
            .ok_or_else(|| DidResolverError::NoX25519Key(did.to_owned()))
    }
}

/// Thread-safe in-memory resolver — suitable for tests and single-node dev.
pub struct InMemoryDidResolver {
    docs: Arc<RwLock<HashMap<String, DidDocument>>>,
}

impl InMemoryDidResolver {
    pub fn new() -> Self {
        Self { docs: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub fn insert(&self, did: impl Into<String>, doc: DidDocument) {
        self.docs.write().unwrap().insert(did.into(), doc);
    }
}

impl Default for InMemoryDidResolver {
    fn default() -> Self { Self::new() }
}

impl DidDocumentResolver for InMemoryDidResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, DidResolverError> {
        self.docs
            .read()
            .unwrap()
            .get(did)
            .cloned()
            .ok_or_else(|| DidResolverError::NotFound(did.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did_document::{ServiceEndpoint, ServiceEndpointValue, VerificationMethod};

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

    #[test]
    fn inmemory_resolver_roundtrip() {
        let resolver = InMemoryDidResolver::new();
        let key = [7u8; 32];
        let did = "did:key:zAlice";
        resolver.insert(did, make_doc_with_x25519(did, key));

        let doc = resolver.resolve(did).expect("should resolve");
        assert_eq!(doc.id, did);
    }

    #[test]
    fn inmemory_resolver_not_found_returns_error() {
        let resolver = InMemoryDidResolver::new();
        let err = resolver.resolve("did:key:zNobody").unwrap_err();
        assert!(matches!(err, DidResolverError::NotFound(_)));
    }

    #[test]
    fn x25519_key_extracted_correctly() {
        let resolver = InMemoryDidResolver::new();
        let expected = [42u8; 32];
        let did = "did:key:zBob";
        resolver.insert(did, make_doc_with_x25519(did, expected));

        let got = resolver.x25519_key(did).expect("x25519 key present");
        assert_eq!(got, expected);
    }

    #[test]
    fn x25519_key_missing_returns_error() {
        let resolver = InMemoryDidResolver::new();
        let did = "did:key:zNoKey";
        resolver.insert(did, DidDocument {
            context: vec![],
            id: did.to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
        });
        let err = resolver.x25519_key(did).unwrap_err();
        assert!(matches!(err, DidResolverError::NoX25519Key(_)));
    }

    #[test]
    fn did_document_x25519_roundtrip() {
        let key = [99u8; 32];
        let did = "did:key:zCarol";
        let doc = make_doc_with_x25519(did, key);
        let extracted = doc.x25519_public_key().expect("should extract");
        assert_eq!(extracted, key);
    }
}
