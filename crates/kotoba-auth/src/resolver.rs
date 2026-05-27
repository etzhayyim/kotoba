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

    #[test]
    fn default_equals_new() {
        let r1 = InMemoryDidResolver::new();
        let r2 = InMemoryDidResolver::default();
        // Both should fail to resolve an unknown DID
        assert!(r1.resolve("did:key:zUnknown").is_err());
        assert!(r2.resolve("did:key:zUnknown").is_err());
    }

    #[test]
    fn insert_overwrites_existing_did() {
        let resolver = InMemoryDidResolver::new();
        let did = "did:key:zOverwrite";
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        resolver.insert(did, make_doc_with_x25519(did, key1));
        resolver.insert(did, make_doc_with_x25519(did, key2));

        // Second insert should overwrite the first
        let got = resolver.x25519_key(did).unwrap();
        assert_eq!(got, key2, "second insert should overwrite first");
    }

    #[test]
    fn multiple_dids_resolved_independently() {
        let resolver = InMemoryDidResolver::new();
        let dids = ["did:key:zA", "did:key:zB", "did:key:zC"];
        let keys = [[10u8; 32], [20u8; 32], [30u8; 32]];

        for (did, key) in dids.iter().zip(keys.iter()) {
            resolver.insert(*did, make_doc_with_x25519(did, *key));
        }

        for (did, expected_key) in dids.iter().zip(keys.iter()) {
            let got = resolver.x25519_key(did).unwrap();
            assert_eq!(&got, expected_key);
        }
    }

    #[test]
    fn error_display_messages() {
        let e1 = DidResolverError::NotFound("did:key:zFoo".to_string());
        assert!(e1.to_string().contains("DID not found"));
        assert!(e1.to_string().contains("did:key:zFoo"));

        let e2 = DidResolverError::NoX25519Key("did:key:zBar".to_string());
        assert!(e2.to_string().contains("X25519"));
        assert!(e2.to_string().contains("did:key:zBar"));
    }

    // ── New tests ─────────────────────────────────────────────────────────────

    #[test]
    fn x25519_key_for_unknown_did_returns_not_found() {
        // x25519_key calls resolve first; if resolve fails with NotFound, the
        // error should propagate as NotFound, NOT as NoX25519Key.
        let resolver = InMemoryDidResolver::new();
        let err = resolver.x25519_key("did:key:zNobodyX").unwrap_err();
        assert!(
            matches!(err, DidResolverError::NotFound(_)),
            "expected NotFound, got {err:?}"
        );
    }

    #[test]
    fn error_debug_contains_variant_name() {
        let e1 = DidResolverError::NotFound("did:key:zDebug".into());
        assert!(format!("{e1:?}").contains("NotFound"));

        let e2 = DidResolverError::NoX25519Key("did:key:zDebug2".into());
        assert!(format!("{e2:?}").contains("NoX25519Key"));
    }

    #[test]
    fn error_is_send_and_sync() {
        // Compile-time assertion that DidResolverError: Send + Sync.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DidResolverError>();
    }

    #[test]
    fn resolver_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryDidResolver>();
    }

    #[test]
    fn empty_resolver_has_no_documents() {
        let resolver = InMemoryDidResolver::new();
        // Resolving any DID on an empty resolver returns NotFound.
        assert!(matches!(
            resolver.resolve("did:key:zAny"),
            Err(DidResolverError::NotFound(_))
        ));
    }

    #[test]
    fn resolve_after_multiple_inserts_returns_correct_doc() {
        let resolver = InMemoryDidResolver::new();
        let dids = ["did:key:zA", "did:key:zB", "did:key:zC"];
        for (i, did) in dids.iter().enumerate() {
            let key = [(i as u8 + 1) * 10u8; 32];
            resolver.insert(*did, make_doc_with_x25519(did, key));
        }
        for did in &dids {
            let doc = resolver.resolve(did).unwrap();
            assert_eq!(&doc.id, did);
        }
    }
}
