//! IPNS head records for Kotoba database / graph identities.
//!
//! This module is the mutable-name boundary for the distributed Datomic target:
//! an IPNS name resolves to the latest commit CID for a graph/database.  The
//! in-memory registry is deliberately small; production publishing can replace
//! it with Kubo `/api/v0/name/*` or an embedded IPFS DHT implementation while
//! preserving the same record semantics.

use crate::cid::{dag_cbor_block, parse_cid};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ipld_core::cid::Cid as IpldCid;
use multibase::Base;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpnsName(pub String);

impl IpnsName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A Kotoba IPNS record.
///
/// `value` is the CID string of the latest DAG-CBOR commit block.  `sequence`
/// is monotonically increasing per name; stale records are rejected by
/// [`InMemoryIpnsRegistry`].  `valid_until` uses strict UTC text so the record
/// is stable in DAG-CBOR and JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpnsRecord {
    pub name: IpnsName,
    pub value: String,
    pub sequence: u64,
    pub valid_until: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_multibase: Option<String>,
}

impl IpnsRecord {
    pub fn new(
        name: impl Into<String>,
        value: &IpldCid,
        sequence: u64,
        valid_until: impl Into<String>,
    ) -> Self {
        Self {
            name: IpnsName::new(name),
            value: value.to_string(),
            sequence,
            valid_until: valid_until.into(),
            ttl_secs: None,
            controller_did: None,
            public_key_multibase: None,
            signature_multibase: None,
        }
    }

    pub fn value_cid(&self) -> Result<IpldCid, IpnsRegistryError> {
        parse_cid(&self.value).map_err(|e| IpnsRegistryError::InvalidCid(e.to_string()))
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>, IpnsRegistryError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            name: &'a IpnsName,
            value: &'a str,
            sequence: u64,
            valid_until: &'a str,
            ttl_secs: Option<u64>,
            controller_did: Option<&'a str>,
            public_key_multibase: Option<&'a str>,
        }

        let payload = Payload {
            name: &self.name,
            value: &self.value,
            sequence: self.sequence,
            valid_until: &self.valid_until,
            ttl_secs: self.ttl_secs,
            controller_did: self.controller_did.as_deref(),
            public_key_multibase: self.public_key_multibase.as_deref(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&payload, &mut bytes)
            .map_err(|e| IpnsRegistryError::Signature(e.to_string()))?;
        Ok(bytes)
    }

    pub fn sign_ed25519(&mut self, signing_key: &SigningKey) -> Result<(), IpnsRegistryError> {
        self.public_key_multibase = Some(multibase::encode(
            Base::Base58Btc,
            signing_key.verifying_key().as_bytes(),
        ));
        let payload = self.signing_payload()?;
        let signature = signing_key.sign(&payload);
        self.signature_multibase = Some(multibase::encode(Base::Base58Btc, signature.to_bytes()));
        Ok(())
    }

    pub fn verify_ed25519_signature(&self) -> Result<(), IpnsRegistryError> {
        let public_key_multibase = self
            .public_key_multibase
            .as_deref()
            .ok_or(IpnsRegistryError::MissingPublicKey)?;
        let signature_multibase = self
            .signature_multibase
            .as_deref()
            .ok_or(IpnsRegistryError::MissingSignature)?;
        let (_, public_key_bytes) = multibase::decode(public_key_multibase)
            .map_err(|e| IpnsRegistryError::InvalidSignature(e.to_string()))?;
        let verifying_key = VerifyingKey::from_bytes(
            public_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| IpnsRegistryError::InvalidPublicKey(public_key_bytes.len()))?,
        )
        .map_err(|e| IpnsRegistryError::InvalidSignature(e.to_string()))?;
        let (_, signature_bytes) = multibase::decode(signature_multibase)
            .map_err(|e| IpnsRegistryError::InvalidSignature(e.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|e| IpnsRegistryError::InvalidSignature(e.to_string()))?;
        verifying_key
            .verify_strict(&self.signing_payload()?, &signature)
            .map_err(|e| IpnsRegistryError::InvalidSignature(e.to_string()))
    }

    pub fn signature_verified(&self) -> bool {
        self.verify_ed25519_signature().is_ok()
    }

    pub fn verify_signature_if_present(&self) -> Result<(), IpnsRegistryError> {
        match (&self.public_key_multibase, &self.signature_multibase) {
            (None, None) => Ok(()),
            _ => self.verify_ed25519_signature(),
        }
    }

    pub fn require_verified_signature(&self) -> Result<(), IpnsRegistryError> {
        self.verify_ed25519_signature()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IpnsRegistryError {
    #[error("IPNS name not found: {0}")]
    NotFound(String),
    #[error("stale IPNS record for {name}: current sequence {current}, incoming {incoming}")]
    StaleRecord {
        name: String,
        current: u64,
        incoming: u64,
    },
    #[error("invalid CID in IPNS value: {0}")]
    InvalidCid(String),
    #[error("missing IPNS public key")]
    MissingPublicKey,
    #[error("invalid IPNS public key length: {0}")]
    InvalidPublicKey(usize),
    #[error("missing IPNS signature")]
    MissingSignature,
    #[error("invalid IPNS signature: {0}")]
    InvalidSignature(String),
    #[error("IPNS signature payload: {0}")]
    Signature(String),
    #[error("kubo IPNS HTTP: {0}")]
    Kubo(String),
    #[error("registry lock poisoned")]
    LockPoisoned,
}

pub trait IpnsRegistry: Send + Sync {
    fn publish(&self, record: IpnsRecord) -> Result<(), IpnsRegistryError>;
    fn resolve(&self, name: &IpnsName) -> Result<IpnsRecord, IpnsRegistryError>;
}

#[derive(Clone)]
pub struct SignedIpnsRegistry {
    inner: Arc<dyn IpnsRegistry>,
}

impl SignedIpnsRegistry {
    pub fn new(inner: Arc<dyn IpnsRegistry>) -> Self {
        Self { inner }
    }
}

impl IpnsRegistry for SignedIpnsRegistry {
    fn publish(&self, record: IpnsRecord) -> Result<(), IpnsRegistryError> {
        record.require_verified_signature()?;
        self.inner.publish(record)
    }

    fn resolve(&self, name: &IpnsName) -> Result<IpnsRecord, IpnsRegistryError> {
        let record = self.inner.resolve(name)?;
        record.require_verified_signature()?;
        Ok(record)
    }
}

#[derive(Clone, Default)]
pub struct InMemoryIpnsRegistry {
    records: Arc<RwLock<HashMap<IpnsName, IpnsRecord>>>,
}

impl InMemoryIpnsRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

impl IpnsRegistry for InMemoryIpnsRegistry {
    fn publish(&self, record: IpnsRecord) -> Result<(), IpnsRegistryError> {
        record.value_cid()?;
        record.verify_signature_if_present()?;
        let mut records = self
            .records
            .write()
            .map_err(|_| IpnsRegistryError::LockPoisoned)?;
        if let Some(current) = records.get(&record.name) {
            if record.sequence <= current.sequence {
                return Err(IpnsRegistryError::StaleRecord {
                    name: record.name.0,
                    current: current.sequence,
                    incoming: record.sequence,
                });
            }
        }
        records.insert(record.name.clone(), record);
        Ok(())
    }

    fn resolve(&self, name: &IpnsName) -> Result<IpnsRecord, IpnsRegistryError> {
        self.records
            .read()
            .map_err(|_| IpnsRegistryError::LockPoisoned)?
            .get(name)
            .cloned()
            .ok_or_else(|| IpnsRegistryError::NotFound(name.0.clone()))
    }
}

/// Kubo-backed IPNS registry using `/api/v0/name/publish` and
/// `/api/v0/name/resolve`.
///
/// The registry keeps a local monotonic-sequence cache to preserve Kotoba's
/// stale-write guard, then publishes the same head to Kubo.  `IpnsName` is
/// passed as the Kubo key alias on publish; operators must create matching keys
/// with `ipfs key gen <ipns-name>` for durable public IPNS names.  Resolve first
/// checks the local cache, then falls back to Kubo for already-published names.
#[derive(Clone)]
pub struct KuboIpnsRegistry {
    client: reqwest::blocking::Client,
    endpoint: String,
    token: Option<String>,
    local: InMemoryIpnsRegistry,
}

#[derive(Debug, Deserialize)]
struct KuboNamePublishResp {
    #[serde(rename = "Name")]
    _name: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Debug, Deserialize)]
struct KuboNameResolveResp {
    #[serde(rename = "Path")]
    path: String,
}

#[derive(Debug, Deserialize)]
struct KuboBlockPutResp {
    #[serde(rename = "Key")]
    key: String,
}

impl KuboIpnsRegistry {
    pub fn new(endpoint: impl Into<String>) -> Self {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            client,
            endpoint: endpoint.into(),
            token: None,
            local: InMemoryIpnsRegistry::new(),
        }
    }

    pub fn from_env() -> Self {
        let endpoint = std::env::var("KOTOBA_IPFS_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:5001".into());
        let token = std::env::var("KOTOBA_IPFS_TOKEN").ok();
        Self {
            token,
            ..Self::new(endpoint)
        }
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    fn api_url(&self, method: &str) -> String {
        format!("{}/api/v0/{method}", self.endpoint.trim_end_matches('/'))
    }

    fn authed(&self, rb: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        match &self.token {
            Some(token) => rb.bearer_auth(token),
            None => rb,
        }
    }

    fn signed_record_block(record: &IpnsRecord) -> Result<(IpldCid, Vec<u8>), IpnsRegistryError> {
        dag_cbor_block(record).map_err(|e| IpnsRegistryError::Kubo(format!("record cbor: {e}")))
    }

    fn put_record_block_kubo(&self, record: &IpnsRecord) -> Result<IpldCid, IpnsRegistryError> {
        let (cid, data) = Self::signed_record_block(record)?;
        let url = format!(
            "{}?cid-codec=dag-cbor&mhtype=sha2-256",
            self.api_url("block/put")
        );
        let part = reqwest::blocking::multipart::Part::bytes(data).file_name("ipns-record.cbor");
        let form = reqwest::blocking::multipart::Form::new().part("data", part);
        let resp = self
            .authed(self.client.post(url).multipart(form))
            .send()
            .map_err(|e| IpnsRegistryError::Kubo(format!("block/put send: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            return Err(IpnsRegistryError::Kubo(format!(
                "block/put {status}: {text}"
            )));
        }
        let parsed: KuboBlockPutResp = resp
            .json()
            .map_err(|e| IpnsRegistryError::Kubo(format!("block/put parse: {e}")))?;
        if parsed.key != cid.to_string() {
            return Err(IpnsRegistryError::Kubo(format!(
                "block/put returned CID {}, expected {}",
                parsed.key, cid
            )));
        }
        Ok(cid)
    }

    fn get_record_block_kubo(
        &self,
        name: &IpnsName,
        record_cid: &str,
    ) -> Result<Option<IpnsRecord>, IpnsRegistryError> {
        let url = format!("{}?arg={record_cid}", self.api_url("block/get"));
        let resp = self
            .authed(self.client.post(url))
            .send()
            .map_err(|e| IpnsRegistryError::Kubo(format!("block/get send: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            if text.contains("block not found") || text.contains("not found") {
                return Ok(None);
            }
            return Err(IpnsRegistryError::Kubo(format!(
                "block/get {status}: {text}"
            )));
        }
        let bytes = resp
            .bytes()
            .map_err(|e| IpnsRegistryError::Kubo(format!("block/get body: {e}")))?;
        let record: IpnsRecord = match ciborium::from_reader(bytes.as_ref()) {
            Ok(record) => record,
            Err(_) => return Ok(None),
        };
        if &record.name != name {
            return Err(IpnsRegistryError::Kubo(format!(
                "IPNS record block name {}, expected {}",
                record.name.as_str(),
                name.as_str()
            )));
        }
        record.value_cid()?;
        record.verify_signature_if_present()?;
        Ok(Some(record))
    }

    fn publish_kubo(&self, record: &IpnsRecord) -> Result<(), IpnsRegistryError> {
        let record_cid = self.put_record_block_kubo(record)?;
        let ttl = record
            .ttl_secs
            .map(|secs| format!("{secs}s"))
            .unwrap_or_else(|| "60s".to_string());
        let url = format!(
            "{}?arg=/ipfs/{}&key={}&resolve=false&allow-offline=true&ttl={}",
            self.api_url("name/publish"),
            record_cid,
            record.name.as_str(),
            ttl,
        );
        let resp = self
            .authed(self.client.post(url))
            .send()
            .map_err(|e| IpnsRegistryError::Kubo(format!("name/publish send: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            return Err(IpnsRegistryError::Kubo(format!(
                "name/publish {status}: {text}"
            )));
        }
        let parsed: KuboNamePublishResp = resp
            .json()
            .map_err(|e| IpnsRegistryError::Kubo(format!("name/publish parse: {e}")))?;
        let published = parsed.value.strip_prefix("/ipfs/").unwrap_or(&parsed.value);
        if published != record_cid.to_string() {
            return Err(IpnsRegistryError::Kubo(format!(
                "name/publish returned value {published}, expected {record_cid}"
            )));
        }
        Ok(())
    }

    fn resolve_kubo(&self, name: &IpnsName) -> Result<IpnsRecord, IpnsRegistryError> {
        let url = format!(
            "{}?arg={}&recursive=true&nocache=false",
            self.api_url("name/resolve"),
            name.as_str()
        );
        let resp = self
            .authed(self.client.post(url))
            .send()
            .map_err(|e| IpnsRegistryError::Kubo(format!("name/resolve send: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(IpnsRegistryError::NotFound(name.0.clone()));
        }
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            if text.contains("not found") || text.contains("could not resolve") {
                return Err(IpnsRegistryError::NotFound(name.0.clone()));
            }
            return Err(IpnsRegistryError::Kubo(format!(
                "name/resolve {status}: {text}"
            )));
        }
        let parsed: KuboNameResolveResp = resp
            .json()
            .map_err(|e| IpnsRegistryError::Kubo(format!("name/resolve parse: {e}")))?;
        let value = parsed
            .path
            .strip_prefix("/ipfs/")
            .unwrap_or(&parsed.path)
            .to_string();
        parse_cid(&value).map_err(|e| IpnsRegistryError::InvalidCid(e.to_string()))?;
        if let Some(record) = self.get_record_block_kubo(name, &value)? {
            return Ok(record);
        }
        Ok(IpnsRecord {
            name: name.clone(),
            value,
            sequence: 0,
            valid_until: String::new(),
            ttl_secs: None,
            controller_did: None,
            public_key_multibase: None,
            signature_multibase: None,
        })
    }
}

impl IpnsRegistry for KuboIpnsRegistry {
    fn publish(&self, record: IpnsRecord) -> Result<(), IpnsRegistryError> {
        self.local.publish(record.clone())?;
        self.publish_kubo(&record)
    }

    fn resolve(&self, name: &IpnsName) -> Result<IpnsRecord, IpnsRegistryError> {
        match self.local.resolve(name) {
            Ok(record) => Ok(record),
            Err(IpnsRegistryError::NotFound(_)) => self.resolve_kubo(name),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw_cid;

    #[test]
    fn publish_and_resolve_roundtrip() {
        let registry = InMemoryIpnsRegistry::new();
        let cid = raw_cid(b"commit");
        let record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2026-05-29T00:00:00Z");
        registry.publish(record.clone()).unwrap();
        assert_eq!(registry.resolve(&record.name).unwrap(), record);
    }

    #[test]
    fn stale_sequence_is_rejected() {
        let registry = InMemoryIpnsRegistry::new();
        let cid = raw_cid(b"commit");
        let name = "k51-kotoba-test";
        registry
            .publish(IpnsRecord::new(name, &cid, 2, "2026-05-29T00:00:00Z"))
            .unwrap();
        let err = registry
            .publish(IpnsRecord::new(name, &cid, 1, "2026-05-29T00:00:00Z"))
            .unwrap_err();
        assert!(matches!(err, IpnsRegistryError::StaleRecord { .. }));
    }

    #[test]
    fn ipns_record_signs_and_verifies_ed25519() {
        let cid = raw_cid(b"commit");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2026-05-29T00:00:00Z");
        record.ttl_secs = Some(60);

        record.sign_ed25519(&signing_key).unwrap();

        assert!(record.public_key_multibase.is_some());
        assert!(record.signature_multibase.is_some());
        assert!(record.signature_verified());
    }

    #[test]
    fn ipns_record_signature_rejects_tampering() {
        let cid = raw_cid(b"commit");
        let other = raw_cid(b"other-commit");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2026-05-29T00:00:00Z");
        record.sign_ed25519(&signing_key).unwrap();
        record.value = other.to_string();

        assert!(matches!(
            record.verify_ed25519_signature(),
            Err(IpnsRegistryError::InvalidSignature(_))
        ));
    }

    #[test]
    fn publish_rejects_tampered_signed_record() {
        let registry = InMemoryIpnsRegistry::new();
        let cid = raw_cid(b"commit");
        let other = raw_cid(b"other-commit");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2026-05-29T00:00:00Z");
        record.sign_ed25519(&signing_key).unwrap();
        record.value = other.to_string();

        assert!(matches!(
            registry.publish(record),
            Err(IpnsRegistryError::InvalidSignature(_))
        ));
    }

    #[test]
    fn publish_rejects_partial_signature_metadata() {
        let registry = InMemoryIpnsRegistry::new();
        let cid = raw_cid(b"commit");
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2026-05-29T00:00:00Z");
        record.public_key_multibase = Some(multibase::encode(Base::Base58Btc, [7; 32]));

        assert!(matches!(
            registry.publish(record),
            Err(IpnsRegistryError::MissingSignature)
        ));
    }

    #[test]
    fn signed_registry_requires_verified_signature_on_publish() {
        let registry = SignedIpnsRegistry::new(Arc::new(InMemoryIpnsRegistry::new()));
        let cid = raw_cid(b"commit");
        let record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2026-05-29T00:00:00Z");

        assert!(matches!(
            registry.publish(record),
            Err(IpnsRegistryError::MissingPublicKey)
        ));
    }

    #[test]
    fn signed_registry_resolves_signed_records() {
        let inner = Arc::new(InMemoryIpnsRegistry::new());
        let registry = SignedIpnsRegistry::new(inner);
        let cid = raw_cid(b"commit");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2026-05-29T00:00:00Z");
        record.sign_ed25519(&signing_key).unwrap();

        registry.publish(record.clone()).unwrap();

        assert_eq!(registry.resolve(&record.name).unwrap(), record);
    }

    #[test]
    fn kubo_signed_record_block_roundtrips_as_dag_cbor() {
        let cid = raw_cid(b"commit");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2026-05-29T00:00:00Z");
        record.ttl_secs = Some(60);
        record.sign_ed25519(&signing_key).unwrap();

        let (record_cid, bytes) = KuboIpnsRegistry::signed_record_block(&record).unwrap();
        let decoded: IpnsRecord = ciborium::from_reader(bytes.as_slice()).unwrap();

        assert_eq!(decoded, record);
        assert_eq!(
            record_cid,
            crate::cid::cid_for_bytes(crate::cid::CODEC_DAG_CBOR, &bytes)
        );
        assert!(decoded.signature_verified());
    }

    #[test]
    fn ipns_record_signature_requires_signature() {
        let cid = raw_cid(b"commit");
        let record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2026-05-29T00:00:00Z");

        assert!(matches!(
            record.verify_ed25519_signature(),
            Err(IpnsRegistryError::MissingPublicKey)
        ));
    }
}
