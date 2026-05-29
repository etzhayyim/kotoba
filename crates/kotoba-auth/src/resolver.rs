use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::did_document::{
    DidDocument, VerificationMethod, ATPROTO_PDS_SERVICE, DIDCOMM_MESSAGING_SERVICE,
    DID_CONTEXT_V1, ED25519_KEY_TYPE_2020, KOTOBA_NODE_SERVICE,
};
use crate::did_key::parse_ed25519_did_key;

#[derive(Debug, thiserror::Error)]
pub enum DidResolverError {
    #[error("DID not found: {0}")]
    NotFound(String),
    #[error("no X25519 key in DID Document for {0}")]
    NoX25519Key(String),
    #[error("unsupported DID method: {0}")]
    UnsupportedMethod(String),
    #[error("invalid DID: {0}")]
    InvalidDid(String),
    #[error("DID document fetch failed for {url}: {message}")]
    Fetch { url: String, message: String },
    #[error("DID document parse failed: {0}")]
    Parse(String),
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

    /// Convenience: resolve a DID Document and check that one of its Ed25519
    /// verification methods contains the supplied multibase public key.
    fn ed25519_key_matches_multibase(
        &self,
        did: &str,
        public_key_multibase: &str,
    ) -> Result<bool, DidResolverError> {
        Ok(self
            .resolve(did)?
            .has_ed25519_public_key_multibase(public_key_multibase))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KotobaDidServiceConfig {
    pub didcomm_endpoint: String,
    pub atproto_pds_endpoint: String,
    pub kotoba_node_endpoint: String,
    pub graph_memberships: Vec<String>,
}

impl KotobaDidServiceConfig {
    pub fn new(
        didcomm_endpoint: impl Into<String>,
        atproto_pds_endpoint: impl Into<String>,
        kotoba_node_endpoint: impl Into<String>,
        graph_memberships: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            didcomm_endpoint: didcomm_endpoint.into(),
            atproto_pds_endpoint: atproto_pds_endpoint.into(),
            kotoba_node_endpoint: kotoba_node_endpoint.into(),
            graph_memberships: graph_memberships.into_iter().map(Into::into).collect(),
        }
    }

    pub fn apply_to(&self, doc: &mut DidDocument) {
        doc.ensure_single_service(
            "didcomm",
            DIDCOMM_MESSAGING_SERVICE,
            self.didcomm_endpoint.clone(),
        );
        doc.ensure_single_service(
            "atproto-pds",
            ATPROTO_PDS_SERVICE,
            self.atproto_pds_endpoint.clone(),
        );
        doc.ensure_single_service(
            "kotoba-node",
            KOTOBA_NODE_SERVICE,
            self.kotoba_node_endpoint.clone(),
        );
        doc.ensure_graph_membership_service(self.graph_memberships.clone());
    }
}

#[derive(Clone)]
pub struct ProtocolServiceDidResolver {
    inner: Arc<dyn DidDocumentResolver>,
    services: KotobaDidServiceConfig,
}

impl ProtocolServiceDidResolver {
    pub fn new(inner: Arc<dyn DidDocumentResolver>, services: KotobaDidServiceConfig) -> Self {
        Self { inner, services }
    }
}

impl DidDocumentResolver for ProtocolServiceDidResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, DidResolverError> {
        let mut doc = self.inner.resolve(did)?;
        self.services.apply_to(&mut doc);
        Ok(doc)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DidMethod {
    Key,
    Web,
    Plc,
    Other(String),
}

impl DidMethod {
    pub fn parse(did: &str) -> Result<Self, DidResolverError> {
        let mut parts = did.splitn(3, ':');
        if parts.next() != Some("did") {
            return Err(DidResolverError::InvalidDid(did.to_string()));
        }
        let Some(method) = parts.next() else {
            return Err(DidResolverError::InvalidDid(did.to_string()));
        };
        if parts.next().is_none() {
            return Err(DidResolverError::InvalidDid(did.to_string()));
        }
        Ok(match method {
            "key" => Self::Key,
            "web" => Self::Web,
            "plc" => Self::Plc,
            other => Self::Other(other.to_string()),
        })
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Key => "key",
            Self::Web => "web",
            Self::Plc => "plc",
            Self::Other(method) => method.as_str(),
        }
    }
}

pub trait DidMethodResolver: Send + Sync {
    fn method(&self) -> &'static str;
    fn resolve_method(&self, did: &str) -> Result<DidDocument, DidResolverError>;
}

#[derive(Default)]
pub struct CompositeDidResolver {
    resolvers: HashMap<&'static str, Box<dyn DidMethodResolver>>,
}

impl CompositeDidResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_default_methods(fetcher: Arc<dyn DidDocumentFetcher>) -> Self {
        Self::new()
            .with_method(DidKeyResolver)
            .with_method(DidWebResolver::new(Arc::clone(&fetcher)))
            .with_method(DidPlcResolver::new(fetcher))
    }

    pub fn with_method<R>(mut self, resolver: R) -> Self
    where
        R: DidMethodResolver + 'static,
    {
        self.resolvers.insert(resolver.method(), Box::new(resolver));
        self
    }
}

impl DidDocumentResolver for CompositeDidResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, DidResolverError> {
        let method = DidMethod::parse(did)?;
        self.resolvers
            .get(method.as_str())
            .ok_or_else(|| DidResolverError::UnsupportedMethod(method.as_str().to_string()))?
            .resolve_method(did)
    }
}

#[derive(Clone)]
pub struct LayeredDidResolver {
    resolvers: Vec<Arc<dyn DidDocumentResolver>>,
}

impl LayeredDidResolver {
    pub fn new(resolvers: Vec<Arc<dyn DidDocumentResolver>>) -> Self {
        Self { resolvers }
    }

    pub fn then(mut self, resolver: Arc<dyn DidDocumentResolver>) -> Self {
        self.resolvers.push(resolver);
        self
    }
}

impl DidDocumentResolver for LayeredDidResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, DidResolverError> {
        let mut last_err = None;
        for resolver in &self.resolvers {
            match resolver.resolve(did) {
                Ok(doc) => return Ok(doc),
                Err(e @ DidResolverError::NotFound(_))
                | Err(e @ DidResolverError::UnsupportedMethod(_)) => last_err = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| DidResolverError::NotFound(did.to_owned())))
    }
}

pub struct DidKeyResolver;

impl DidMethodResolver for DidKeyResolver {
    fn method(&self) -> &'static str {
        "key"
    }

    fn resolve_method(&self, did: &str) -> Result<DidDocument, DidResolverError> {
        let pubkey =
            parse_ed25519_did_key(did).map_err(|e| DidResolverError::InvalidDid(e.to_string()))?;
        let key_id = format!("{did}#{}", did.trim_start_matches("did:key:"));
        Ok(DidDocument {
            context: vec![DID_CONTEXT_V1.to_string()],
            id: did.to_string(),
            verification_method: vec![VerificationMethod {
                id: key_id.clone(),
                key_type: ED25519_KEY_TYPE_2020.to_string(),
                controller: did.to_string(),
                public_key_multibase: multibase::encode(multibase::Base::Base58Btc, pubkey),
            }],
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id.clone()],
            capability_invocation: vec![key_id.clone()],
            capability_delegation: vec![key_id],
            service: vec![],
        })
    }
}

pub trait DidDocumentFetcher: Send + Sync {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, DidResolverError>;
}

#[derive(Default)]
pub struct InMemoryDidDocumentFetcher {
    docs: RwLock<HashMap<String, Vec<u8>>>,
}

impl InMemoryDidDocumentFetcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_json(&self, url: impl Into<String>, json: impl Into<Vec<u8>>) {
        self.docs.write().unwrap().insert(url.into(), json.into());
    }
}

impl DidDocumentFetcher for InMemoryDidDocumentFetcher {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, DidResolverError> {
        self.docs
            .read()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| DidResolverError::Fetch {
                url: url.to_string(),
                message: "not found".to_string(),
            })
    }
}

pub struct DidWebResolver {
    fetcher: Arc<dyn DidDocumentFetcher>,
}

impl DidWebResolver {
    pub fn new(fetcher: Arc<dyn DidDocumentFetcher>) -> Self {
        Self { fetcher }
    }
}

impl DidMethodResolver for DidWebResolver {
    fn method(&self) -> &'static str {
        "web"
    }

    fn resolve_method(&self, did: &str) -> Result<DidDocument, DidResolverError> {
        let url = did_web_url(did)?;
        parse_fetched_did_document(did, &self.fetcher.fetch(&url)?)
    }
}

pub struct DidPlcResolver {
    fetcher: Arc<dyn DidDocumentFetcher>,
    directory: String,
}

impl DidPlcResolver {
    pub fn new(fetcher: Arc<dyn DidDocumentFetcher>) -> Self {
        Self {
            fetcher,
            directory: "https://plc.directory".to_string(),
        }
    }

    pub fn with_directory(
        fetcher: Arc<dyn DidDocumentFetcher>,
        directory: impl Into<String>,
    ) -> Self {
        Self {
            fetcher,
            directory: directory.into().trim_end_matches('/').to_string(),
        }
    }

    pub fn url_for(&self, did: &str) -> Result<String, DidResolverError> {
        if !matches!(DidMethod::parse(did)?, DidMethod::Plc) {
            return Err(DidResolverError::InvalidDid(did.to_string()));
        }
        Ok(format!("{}/{}", self.directory, did))
    }
}

impl DidMethodResolver for DidPlcResolver {
    fn method(&self) -> &'static str {
        "plc"
    }

    fn resolve_method(&self, did: &str) -> Result<DidDocument, DidResolverError> {
        let url = self.url_for(did)?;
        parse_fetched_did_document(did, &self.fetcher.fetch(&url)?)
    }
}

pub fn did_web_url(did: &str) -> Result<String, DidResolverError> {
    if !matches!(DidMethod::parse(did)?, DidMethod::Web) {
        return Err(DidResolverError::InvalidDid(did.to_string()));
    }
    let suffix = did
        .strip_prefix("did:web:")
        .ok_or_else(|| DidResolverError::InvalidDid(did.to_string()))?;
    if suffix.is_empty() {
        return Err(DidResolverError::InvalidDid(did.to_string()));
    }
    Ok(if suffix.contains(':') {
        format!("https://{}/did.json", suffix.replace(':', "/"))
    } else {
        format!("https://{suffix}/.well-known/did.json")
    })
}

fn parse_fetched_did_document(did: &str, bytes: &[u8]) -> Result<DidDocument, DidResolverError> {
    let doc: DidDocument =
        serde_json::from_slice(bytes).map_err(|e| DidResolverError::Parse(e.to_string()))?;
    if doc.id != did {
        return Err(DidResolverError::InvalidDid(format!(
            "document id {} does not match {did}",
            doc.id
        )));
    }
    Ok(doc)
}

/// Thread-safe in-memory resolver — suitable for tests and single-node dev.
pub struct InMemoryDidResolver {
    docs: Arc<RwLock<HashMap<String, DidDocument>>>,
}

impl InMemoryDidResolver {
    pub fn new() -> Self {
        Self {
            docs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert(&self, did: impl Into<String>, doc: DidDocument) {
        self.docs.write().unwrap().insert(did.into(), doc);
    }
}

impl Default for InMemoryDidResolver {
    fn default() -> Self {
        Self::new()
    }
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

#[derive(Debug, Clone)]
pub struct DatomDidResolver {
    datoms: Arc<Vec<kotoba_datomic::Datom>>,
}

impl DatomDidResolver {
    pub fn new(datoms: Vec<kotoba_datomic::Datom>) -> Self {
        Self {
            datoms: Arc::new(datoms),
        }
    }
}

impl DidDocumentResolver for DatomDidResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, DidResolverError> {
        DidDocument::from_datoms(did, &self.datoms)
            .ok_or_else(|| DidResolverError::NotFound(did.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did_document::{
        ServiceEndpoint, ServiceEndpointValue, VerificationMethod, ATPROTO_PDS_SERVICE,
        DIDCOMM_MESSAGING_SERVICE, KOTOBA_GRAPH_MEMBERSHIP_SERVICE, KOTOBA_NODE_SERVICE,
    };

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

    fn make_json_doc(did: &str) -> Vec<u8> {
        serde_json::to_vec(&DidDocument::empty(did)).unwrap()
    }

    fn make_protocol_service_json_doc(did: &str) -> Vec<u8> {
        let mut doc = DidDocument::empty(did);
        doc.push_single_service(
            "didcomm",
            DIDCOMM_MESSAGING_SERVICE,
            "didcomm://agent/inbox",
        );
        doc.push_single_service(
            "atproto-pds",
            ATPROTO_PDS_SERVICE,
            "https://pds.example.com",
        );
        doc.push_single_service(
            "kotoba-node",
            KOTOBA_NODE_SERVICE,
            "/ip4/127.0.0.1/tcp/4001",
        );
        doc.push_graph_membership_service(["kotoba://graph/bafygraph"]);
        serde_json::to_vec(&doc).unwrap()
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
    fn resolver_matches_ed25519_public_key_multibase() {
        let resolver = InMemoryDidResolver::new();
        let did = "did:key:zEd25519";
        let key = [7u8; 32];
        let encoded = multibase::encode(multibase::Base::Base58Btc, key);
        let mut doc = DidDocument::empty(did);
        doc.verification_method.push(VerificationMethod {
            id: format!("{did}#agent-ed25519"),
            key_type: ED25519_KEY_TYPE_2020.to_string(),
            controller: did.to_string(),
            public_key_multibase: encoded.clone(),
        });
        resolver.insert(did, doc);

        assert!(resolver
            .ed25519_key_matches_multibase(did, &encoded)
            .unwrap());
        assert!(!resolver
            .ed25519_key_matches_multibase(
                did,
                &multibase::encode(multibase::Base::Base58Btc, [9u8; 32]),
            )
            .unwrap());
    }

    #[test]
    fn x25519_key_missing_returns_error() {
        let resolver = InMemoryDidResolver::new();
        let did = "did:key:zNoKey";
        resolver.insert(
            did,
            DidDocument {
                context: vec![],
                id: did.to_owned(),
                verification_method: vec![],
                authentication: vec![],
                assertion_method: vec![],
                capability_invocation: vec![],
                capability_delegation: vec![],
                service: vec![],
            },
        );
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

    #[test]
    fn did_method_parse_recognizes_key_web_and_plc() {
        assert_eq!(DidMethod::parse("did:key:z6Mkabc").unwrap(), DidMethod::Key);
        assert_eq!(
            DidMethod::parse("did:web:example.com").unwrap(),
            DidMethod::Web
        );
        assert_eq!(DidMethod::parse("did:plc:abc").unwrap(), DidMethod::Plc);
        assert_eq!(
            DidMethod::parse("did:example:123").unwrap(),
            DidMethod::Other("example".into())
        );
    }

    #[test]
    fn did_key_resolver_builds_w3c_did_document() {
        let pubkey = [9u8; 32];
        let did = crate::did_key::ed25519_pubkey_to_did_key(&pubkey);
        let doc = DidKeyResolver.resolve_method(&did).unwrap();
        assert_eq!(doc.id, did);
        assert_eq!(doc.context, vec![crate::DID_CONTEXT_V1]);
        assert_eq!(doc.ed25519_public_key().unwrap(), pubkey);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.capability_invocation, doc.authentication);
    }

    #[test]
    fn did_web_url_follows_well_known_and_path_rules() {
        assert_eq!(
            did_web_url("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            did_web_url("did:web:example.com:users:alice").unwrap(),
            "https://example.com/users/alice/did.json"
        );
    }

    #[test]
    fn composite_resolver_dispatches_key_web_and_plc() {
        let fetcher = Arc::new(InMemoryDidDocumentFetcher::new());
        fetcher.insert_json(
            "https://example.com/.well-known/did.json",
            make_json_doc("did:web:example.com"),
        );
        fetcher.insert_json(
            "https://plc.directory/did:plc:alice",
            make_json_doc("did:plc:alice"),
        );
        let resolver = CompositeDidResolver::with_default_methods(fetcher);
        let did_key = crate::did_key::ed25519_pubkey_to_did_key(&[3u8; 32]);

        assert_eq!(resolver.resolve(&did_key).unwrap().id, did_key);
        assert_eq!(
            resolver.resolve("did:web:example.com").unwrap().id,
            "did:web:example.com"
        );
        assert_eq!(
            resolver.resolve("did:plc:alice").unwrap().id,
            "did:plc:alice"
        );
    }

    #[test]
    fn composite_resolver_preserves_kotoba_protocol_services_for_web_and_plc() {
        let fetcher = Arc::new(InMemoryDidDocumentFetcher::new());
        fetcher.insert_json(
            "https://agent.example/.well-known/did.json",
            make_protocol_service_json_doc("did:web:agent.example"),
        );
        fetcher.insert_json(
            "https://plc.directory/did:plc:kotobaagent",
            make_protocol_service_json_doc("did:plc:kotobaagent"),
        );
        let resolver = CompositeDidResolver::with_default_methods(fetcher);

        for did in ["did:web:agent.example", "did:plc:kotobaagent"] {
            let doc = resolver.resolve(did).unwrap();
            assert_eq!(doc.didcomm_endpoint(), Some("didcomm://agent/inbox"));
            assert_eq!(doc.atproto_pds_endpoint(), Some("https://pds.example.com"));
            assert_eq!(doc.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4001"));
            assert_eq!(doc.graph_memberships(), vec!["kotoba://graph/bafygraph"]);
            assert!(doc.service_by_type(DIDCOMM_MESSAGING_SERVICE).is_some());
            assert!(doc.service_by_type(ATPROTO_PDS_SERVICE).is_some());
            assert!(doc.service_by_type(KOTOBA_NODE_SERVICE).is_some());
            assert!(doc
                .service_by_type(KOTOBA_GRAPH_MEMBERSHIP_SERVICE)
                .is_some());
        }
    }

    #[test]
    fn protocol_service_resolver_augments_did_key_web_and_plc_documents() {
        let fetcher = Arc::new(InMemoryDidDocumentFetcher::new());
        fetcher.insert_json(
            "https://agent.example/.well-known/did.json",
            make_json_doc("did:web:agent.example"),
        );
        fetcher.insert_json(
            "https://plc.directory/did:plc:kotobaagent",
            make_json_doc("did:plc:kotobaagent"),
        );
        let inner = Arc::new(CompositeDidResolver::with_default_methods(fetcher));
        let resolver = ProtocolServiceDidResolver::new(
            inner,
            KotobaDidServiceConfig::new(
                "didcomm://mediator/default",
                "https://pds.example.com",
                "/ip4/127.0.0.1/tcp/4001",
                ["kotoba://graph/default"],
            ),
        );
        let did_key = crate::did_key::ed25519_pubkey_to_did_key(&[4u8; 32]);

        for did in [
            did_key.as_str(),
            "did:web:agent.example",
            "did:plc:kotobaagent",
        ] {
            let doc = resolver.resolve(did).unwrap();
            assert_eq!(doc.didcomm_endpoint(), Some("didcomm://mediator/default"));
            assert_eq!(doc.atproto_pds_endpoint(), Some("https://pds.example.com"));
            assert_eq!(doc.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4001"));
            assert_eq!(doc.graph_memberships(), vec!["kotoba://graph/default"]);
            assert!(doc.service_by_type(DIDCOMM_MESSAGING_SERVICE).is_some());
            assert!(doc.service_by_type(ATPROTO_PDS_SERVICE).is_some());
            assert!(doc.service_by_type(KOTOBA_NODE_SERVICE).is_some());
            assert!(doc
                .service_by_type(KOTOBA_GRAPH_MEMBERSHIP_SERVICE)
                .is_some());
        }
    }

    #[test]
    fn protocol_service_resolver_augmented_did_key_web_and_plc_documents_roundtrip_as_datoms() {
        use crate::did_document::{
            ATTR_DID_CORE_SERVICE, ATTR_DID_CORE_SERVICE_ENDPOINT, ATTR_RDF_TYPE,
        };

        let fetcher = Arc::new(InMemoryDidDocumentFetcher::new());
        fetcher.insert_json(
            "https://agent.example/.well-known/did.json",
            make_json_doc("did:web:agent.example"),
        );
        fetcher.insert_json(
            "https://plc.directory/did:plc:kotobaagent",
            make_json_doc("did:plc:kotobaagent"),
        );
        let resolver = ProtocolServiceDidResolver::new(
            Arc::new(CompositeDidResolver::with_default_methods(fetcher)),
            KotobaDidServiceConfig::new(
                "didcomm://mediator/default",
                "https://pds.example.com",
                "/ip4/127.0.0.1/tcp/4001",
                ["kotoba://graph/default"],
            ),
        );
        let did_key = crate::did_key::ed25519_pubkey_to_did_key(&[4u8; 32]);

        for did in [
            did_key.as_str(),
            "did:web:agent.example",
            "did:plc:kotobaagent",
        ] {
            let doc = resolver.resolve(did).unwrap();
            let datoms = doc.to_datoms(kotoba_core::cid::KotobaCid::from_bytes(
                format!("{did}/did-doc-tx").as_bytes(),
            ));
            let datom_resolver = DatomDidResolver::new(datoms.clone());
            let restored = datom_resolver.resolve(did).unwrap();

            assert_eq!(restored.didcomm_endpoint(), doc.didcomm_endpoint());
            assert_eq!(restored.atproto_pds_endpoint(), doc.atproto_pds_endpoint());
            assert_eq!(restored.kotoba_endpoint(), doc.kotoba_endpoint());
            assert_eq!(restored.graph_memberships(), doc.graph_memberships());
            for service_type in [
                DIDCOMM_MESSAGING_SERVICE,
                ATPROTO_PDS_SERVICE,
                KOTOBA_NODE_SERVICE,
                KOTOBA_GRAPH_MEMBERSHIP_SERVICE,
            ] {
                assert!(
                    datoms.iter().any(|datom| datom.a == ATTR_RDF_TYPE
                        && datom.v == kotoba_datomic::Value::string(service_type)),
                    "{did} missing RDF service type {service_type}"
                );
            }
            assert!(
                datoms.iter().any(|datom| datom.a == ATTR_DID_CORE_SERVICE),
                "{did} missing W3C DID Core service edge"
            );
            assert!(
                datoms
                    .iter()
                    .any(|datom| datom.a == ATTR_DID_CORE_SERVICE_ENDPOINT),
                "{did} missing W3C DID Core serviceEndpoint projection"
            );
        }
    }

    #[test]
    fn protocol_service_resolver_preserves_existing_service_endpoints() {
        let did = "did:plc:kotobaagent";
        let mut doc = DidDocument::empty(did);
        doc.push_single_service("didcomm", DIDCOMM_MESSAGING_SERVICE, "didcomm://custom");
        let registry = InMemoryDidResolver::new();
        registry.insert(did, doc);
        let resolver = ProtocolServiceDidResolver::new(
            Arc::new(registry),
            KotobaDidServiceConfig::new(
                "didcomm://default",
                "https://pds.example.com",
                "/ip4/127.0.0.1/tcp/4001",
                ["kotoba://graph/default"],
            ),
        );

        let resolved = resolver.resolve(did).unwrap();

        assert_eq!(resolved.didcomm_endpoint(), Some("didcomm://custom"));
        assert_eq!(
            resolved.atproto_pds_endpoint(),
            Some("https://pds.example.com")
        );
        assert_eq!(resolved.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4001"));
        assert_eq!(resolved.graph_memberships(), vec!["kotoba://graph/default"]);
    }

    #[test]
    fn datom_resolver_resolves_published_protocol_services() {
        let mut doc = DidDocument::empty("did:plc:kotobaagent");
        doc.push_single_service(
            "didcomm",
            DIDCOMM_MESSAGING_SERVICE,
            "didcomm://mediator/kotobaagent",
        );
        doc.push_single_service(
            "atproto-pds",
            ATPROTO_PDS_SERVICE,
            "https://pds.example.com",
        );
        doc.push_single_service(
            "kotoba-node",
            KOTOBA_NODE_SERVICE,
            "/ip4/127.0.0.1/tcp/4001",
        );
        doc.push_graph_membership_service(["kotoba://graph/a", "kotoba://graph/b"]);
        let resolver = DatomDidResolver::new(
            doc.to_datoms(kotoba_core::cid::KotobaCid::from_bytes(b"did-doc-tx")),
        );

        let resolved = resolver.resolve("did:plc:kotobaagent").unwrap();

        assert_eq!(
            resolved.didcomm_endpoint(),
            Some("didcomm://mediator/kotobaagent")
        );
        assert_eq!(
            resolved.atproto_pds_endpoint(),
            Some("https://pds.example.com")
        );
        assert_eq!(resolved.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4001"));
        assert_eq!(
            resolved.graph_memberships(),
            vec!["kotoba://graph/a", "kotoba://graph/b"]
        );
    }

    #[test]
    fn datom_resolver_resolves_w3c_did_core_iri_service_projection() {
        use crate::did_document::{
            ATTR_DID_CORE_ID, ATTR_DID_CORE_SERVICE, ATTR_DID_CORE_SERVICE_ENDPOINT, ATTR_RDF_TYPE,
        };

        let did = "did:plc:w3cserviceagent";
        let doc_entity = kotoba_core::cid::KotobaCid::from_bytes(did.as_bytes());
        let tx = kotoba_core::cid::KotobaCid::from_bytes(b"w3c-did-core-service-tx");
        let didcomm_service_id = format!("{did}#didcomm");
        let pds_service_id = format!("{did}#atproto-pds");
        let graph_service_id = format!("{did}#kotoba-graphs");
        let service_datoms = [
            (
                &didcomm_service_id,
                DIDCOMM_MESSAGING_SERVICE,
                "didcomm://agent/inbox",
            ),
            (
                &pds_service_id,
                ATPROTO_PDS_SERVICE,
                "https://pds.example.com",
            ),
            (
                &graph_service_id,
                KOTOBA_GRAPH_MEMBERSHIP_SERVICE,
                "kotoba://graph/bafygraph",
            ),
        ];
        let mut datoms = vec![kotoba_datomic::Datom::assert(
            doc_entity.clone(),
            ATTR_DID_CORE_ID.to_string(),
            kotoba_datomic::Value::string(did),
            tx.clone(),
        )];
        for (service_id, service_type, endpoint) in service_datoms {
            let service_entity = kotoba_core::cid::KotobaCid::from_bytes(service_id.as_bytes());
            datoms.push(kotoba_datomic::Datom::assert(
                doc_entity.clone(),
                ATTR_DID_CORE_SERVICE.to_string(),
                kotoba_datomic::Value::string(service_id),
                tx.clone(),
            ));
            datoms.push(kotoba_datomic::Datom::assert(
                service_entity.clone(),
                ATTR_DID_CORE_ID.to_string(),
                kotoba_datomic::Value::string(service_id),
                tx.clone(),
            ));
            datoms.push(kotoba_datomic::Datom::assert(
                service_entity.clone(),
                ATTR_RDF_TYPE.to_string(),
                kotoba_datomic::Value::string(service_type),
                tx.clone(),
            ));
            datoms.push(kotoba_datomic::Datom::assert(
                service_entity,
                ATTR_DID_CORE_SERVICE_ENDPOINT.to_string(),
                kotoba_datomic::Value::string(endpoint),
                tx.clone(),
            ));
        }

        let resolver = DatomDidResolver::new(datoms);
        let resolved = resolver.resolve(did).unwrap();

        assert_eq!(resolved.didcomm_endpoint(), Some("didcomm://agent/inbox"));
        assert_eq!(
            resolved.atproto_pds_endpoint(),
            Some("https://pds.example.com")
        );
        assert_eq!(
            resolved.graph_memberships(),
            vec!["kotoba://graph/bafygraph"]
        );
    }

    #[test]
    fn layered_resolver_falls_back_after_missing_datom_document() {
        let fallback = InMemoryDidResolver::new();
        fallback.insert(
            "did:plc:fallback".to_string(),
            DidDocument::empty("did:plc:fallback"),
        );
        let resolver = LayeredDidResolver::new(vec![
            Arc::new(DatomDidResolver::new(vec![])),
            Arc::new(fallback),
        ]);

        let resolved = resolver.resolve("did:plc:fallback").unwrap();

        assert_eq!(resolved.id, "did:plc:fallback");
    }

    #[test]
    fn layered_resolver_prefers_distributed_datom_registry_over_method_resolver() {
        let did = "did:plc:kotobaagent";
        let mut registry_doc = DidDocument::empty(did);
        registry_doc.push_single_service(
            "kotoba-node",
            KOTOBA_NODE_SERVICE,
            "/ip4/127.0.0.1/tcp/4001",
        );
        registry_doc.push_single_service(
            "didcomm",
            DIDCOMM_MESSAGING_SERVICE,
            "didcomm://registry/kotobaagent",
        );

        let fetcher = Arc::new(InMemoryDidDocumentFetcher::new());
        fetcher.insert_json(
            "https://plc.directory/did:plc:kotobaagent",
            make_protocol_service_json_doc(did),
        );
        let resolver = LayeredDidResolver::new(vec![
            Arc::new(DatomDidResolver::new(registry_doc.to_datoms(
                kotoba_core::cid::KotobaCid::from_bytes(b"registry-did-doc-tx"),
            ))),
            Arc::new(CompositeDidResolver::with_default_methods(fetcher)),
        ]);

        let resolved = resolver.resolve(did).unwrap();

        assert_eq!(
            resolved.didcomm_endpoint(),
            Some("didcomm://registry/kotobaagent")
        );
        assert_eq!(resolved.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4001"));
        assert_eq!(resolved.atproto_pds_endpoint(), None);
    }

    #[test]
    fn fetched_document_id_must_match_requested_did() {
        let fetcher = Arc::new(InMemoryDidDocumentFetcher::new());
        fetcher.insert_json(
            "https://example.com/.well-known/did.json",
            make_json_doc("did:web:other.example"),
        );
        let resolver = CompositeDidResolver::with_default_methods(fetcher);
        let err = resolver.resolve("did:web:example.com").unwrap_err();
        assert!(matches!(err, DidResolverError::InvalidDid(_)));
    }
}
