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

const KUBO_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const KUBO_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const KUBO_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KUBO_POOL_MAX_IDLE_PER_HOST: usize = 8;

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
    client: reqwest::Client,
    endpoint: String,
    token: Option<String>,
    local: InMemoryIpnsRegistry,
    /// Cache of alias → kubo-issued IPNS id (the actual peer-id-style hash
    /// `name/resolve` requires).  Populated lazily on `key/gen` and on
    /// startup via `bootstrap_aliases_from_kubo` (which scans `key/list`).
    /// Without this mapping, every name/resolve hits an unresolvable alias
    /// string and returns 500 "cannot resolve" — datomic.* read endpoints
    /// then 404 even though the data is durably stored.
    alias_id: Arc<RwLock<HashMap<String, String>>>,
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

#[derive(Debug, Deserialize)]
struct KuboIdResp {
    #[serde(rename = "ID")]
    id: String,
}

#[derive(Debug, Deserialize)]
pub struct KuboKeyGenResp {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Id")]
    pub id: String,
}

#[derive(Debug, Deserialize)]
struct KuboKeyListResp {
    #[serde(rename = "Keys")]
    keys: Vec<KuboKeyGenResp>,
}

impl KuboIpnsRegistry {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            client: kubo_http_client(),
            endpoint: endpoint.into(),
            token: None,
            local: InMemoryIpnsRegistry::new(),
            alias_id: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn from_env() -> Self {
        let endpoint = std::env::var("KOTOBA_IPFS_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:5001".into());
        let token = std::env::var("KOTOBA_IPFS_TOKEN").ok();
        let registry = Self {
            token,
            ..Self::new(endpoint)
        };
        // Best-effort hydrate of alias → kubo id from the daemon's keystore so
        // restart-without-prior-publish still resolves names that previous
        // runs created.  A failure here is non-fatal (kubo may be down at
        // boot); resolve_kubo will still work for aliases that get re-published
        // in this process lifetime.
        if let Err(e) = registry.bootstrap_aliases_from_kubo() {
            tracing::warn!(
                err = %e,
                "KuboIpnsRegistry: alias bootstrap failed at boot (kubo likely not ready); retrying in background"
            );
            // The embedded Kubo sidecar is frequently not reachable at process
            // start (observed ~30s warm-up). A single best-effort call therefore
            // leaves the alias→id map empty, so names published by previous runs
            // stay unresolvable (datomic.* reads 404). Retry in the background —
            // `KuboIpnsRegistry` is `Clone` and shares the `alias_id` Arc, so the
            // live registry sees the hydrated map once kubo comes up.
            let probe = registry.clone();
            std::thread::spawn(move || {
                for attempt in 1..=30u32 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    match probe.bootstrap_aliases_from_kubo() {
                        Ok(()) => {
                            tracing::info!(
                                attempt,
                                "KuboIpnsRegistry: alias bootstrap succeeded on background retry"
                            );
                            break;
                        }
                        Err(_) => continue,
                    }
                }
            });
        }
        registry
    }

    /// Populate the alias→id cache by listing all keys in Kubo's keystore.
    /// Called from `from_env` on startup; safe to call again at any time.
    pub fn bootstrap_aliases_from_kubo(&self) -> Result<(), IpnsRegistryError> {
        let url = format!("{}?ipns-base=base36", self.api_url("key/list"));
        let resp = Self::wait(
            "key/list send",
            self.authed(self.client.post(url)).send(),
        )?;
        let status = resp.status();
        if !status.is_success() {
            let text = Self::wait("key/list body", resp.text()).unwrap_or_default();
            return Err(IpnsRegistryError::Kubo(format!("key/list {status}: {text}")));
        }
        let parsed: KuboKeyListResp = Self::wait("key/list parse", resp.json())?;
        let mut map = self
            .alias_id
            .write()
            .map_err(|_| IpnsRegistryError::LockPoisoned)?;
        let mut hydrated = 0usize;
        for k in parsed.keys {
            if k.name.starts_with("k51-kotoba-") {
                map.insert(k.name, k.id);
                hydrated += 1;
            }
        }
        if hydrated > 0 {
            tracing::info!(
                hydrated,
                "KuboIpnsRegistry: alias→id cache populated from key/list"
            );
        }
        Ok(())
    }

    fn record_alias(&self, alias: &str, id: &str) {
        if let Ok(mut m) = self.alias_id.write() {
            m.insert(alias.to_string(), id.to_string());
        }
    }

    /// Resolve a kotoba alias to the Kubo-issued IPNS id (peer-id-style hash).
    /// Falls back to the alias itself when no mapping is known so the caller
    /// can still attempt a Kubo lookup (and trigger NotFound the normal way).
    fn alias_to_resolve_arg(&self, alias: &str) -> String {
        if let Ok(m) = self.alias_id.read() {
            if let Some(id) = m.get(alias) {
                return id.clone();
            }
        }
        alias.to_string()
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    pub fn self_id(&self) -> Result<String, IpnsRegistryError> {
        let resp = Self::wait(
            "id send",
            self.authed(self.client.post(self.api_url("id"))).send(),
        )?;
        let status = resp.status();
        if !status.is_success() {
            let text = Self::wait("id body", resp.text()).unwrap_or_default();
            return Err(IpnsRegistryError::Kubo(format!("id {status}: {text}")));
        }
        let parsed: KuboIdResp = Self::wait("id parse", resp.json())?;
        Ok(parsed.id)
    }

    pub fn generate_ed25519_key(&self, name: &str) -> Result<KuboKeyGenResp, IpnsRegistryError> {
        let url = format!(
            "{}?arg={name}&type=ed25519&ipns-base=base36",
            self.api_url("key/gen")
        );
        let resp = Self::wait("key/gen send", self.authed(self.client.post(url)).send())?;
        let status = resp.status();
        if !status.is_success() {
            let text = Self::wait("key/gen body", resp.text()).unwrap_or_default();
            return Err(IpnsRegistryError::Kubo(format!("key/gen {status}: {text}")));
        }
        Self::wait("key/gen parse", resp.json())
    }

    fn api_url(&self, method: &str) -> String {
        format!("{}/api/v0/{method}", self.endpoint.trim_end_matches('/'))
    }

    fn authed(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(token) => rb.bearer_auth(token),
            None => rb,
        }
    }

    fn wait<T, E: std::fmt::Display>(
        context: &str,
        fut: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, IpnsRegistryError> {
        let result = match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| IpnsRegistryError::Kubo(format!("runtime build: {e}")))?
                .block_on(fut),
        };
        result.map_err(|e| IpnsRegistryError::Kubo(format!("{context}: {e}")))
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
        let part = reqwest::multipart::Part::bytes(data).file_name("ipns-record.cbor");
        let form = reqwest::multipart::Form::new().part("data", part);
        let resp = Self::wait(
            "block/put send",
            self.authed(self.client.post(url).multipart(form)).send(),
        )?;
        let status = resp.status();
        if !status.is_success() {
            let text = Self::wait("block/put body", resp.text()).unwrap_or_default();
            return Err(IpnsRegistryError::Kubo(format!(
                "block/put {status}: {text}"
            )));
        }
        let parsed: KuboBlockPutResp = Self::wait("block/put parse", resp.json())?;
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
        let resp = Self::wait("block/get send", self.authed(self.client.post(url)).send())?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let text = Self::wait("block/get body", resp.text()).unwrap_or_default();
            if text.contains("block not found") || text.contains("not found") {
                return Ok(None);
            }
            return Err(IpnsRegistryError::Kubo(format!(
                "block/get {status}: {text}"
            )));
        }
        let bytes = Self::wait("block/get body", resp.bytes())?;
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
        // Kubo refuses `name/publish` if the key alias does not already exist
        // in its keystore (returns 500 "no key by the given name was found").
        // We auto-create the key here so first-write to a graph just works
        // without out-of-band `ipfs key gen` ceremony.
        match self.try_publish_kubo(record) {
            Ok(()) => Ok(()),
            Err(IpnsRegistryError::Kubo(msg))
                if msg.contains("no key by the given name was found")
                    || msg.contains("not found in keystore") =>
            {
                tracing::info!(
                    name = %record.name.as_str(),
                    "ipns: kubo key not in keystore, generating it"
                );
                let gen = self.generate_ed25519_key(record.name.as_str())?;
                // Remember the alias → kubo IPNS id binding so future
                // resolve_kubo calls can target the actual peer-id-style
                // hash that Kubo will recognise.
                self.record_alias(&gen.name, &gen.id);
                self.try_publish_kubo(record)
            }
            Err(e) => Err(e),
        }
    }

    fn try_publish_kubo(&self, record: &IpnsRecord) -> Result<(), IpnsRegistryError> {
        let record_cid = self.put_record_block_kubo(record)?;
        let ttl = record
            .ttl_secs
            .map(|secs| format!("{secs}s"))
            .unwrap_or_else(|| "60s".to_string());
        // `offline=true` made publish skip the Kubo datastore write on 0.34.1,
        // so records vanished the moment the kubo sidecar restarted (and
        // therefore on every pod restart, since kotoba+kubo share a lifecycle).
        // Dropping the flag lets Kubo persist the IPNS entry to the local
        // repo (PVC) AND announce on the DHT — durable across restarts.
        let url = format!(
            "{}?arg=/ipfs/{}&key={}&resolve=false&ttl={}",
            self.api_url("name/publish"),
            record_cid,
            record.name.as_str(),
            ttl,
        );
        let resp = Self::wait(
            "name/publish send",
            self.authed(self.client.post(url)).send(),
        )?;
        let status = resp.status();
        if !status.is_success() {
            let text = Self::wait("name/publish body", resp.text()).unwrap_or_default();
            return Err(IpnsRegistryError::Kubo(format!(
                "name/publish {status}: {text}"
            )));
        }
        let parsed: KuboNamePublishResp = Self::wait("name/publish parse", resp.json())?;
        let published = parsed.value.strip_prefix("/ipfs/").unwrap_or(&parsed.value);
        if published != record_cid.to_string() {
            return Err(IpnsRegistryError::Kubo(format!(
                "name/publish returned value {published}, expected {record_cid}"
            )));
        }
        Ok(())
    }

    fn resolve_kubo(&self, name: &IpnsName) -> Result<IpnsRecord, IpnsRegistryError> {
        // name/resolve needs the Kubo-issued peer-id hash, not our alias
        // string.  Look up the mapping (populated by publish_kubo's auto
        // key/gen + bootstrap_aliases_from_kubo).  Falls back to the alias
        // itself when unknown so the request still gets sent — Kubo's
        // 500 "cannot resolve" path then maps to NotFound below.
        let resolve_arg = self.alias_to_resolve_arg(name.as_str());
        let url = format!(
            "{}?arg={}&recursive=true&nocache=false",
            self.api_url("name/resolve"),
            resolve_arg
        );
        let resp = Self::wait(
            "name/resolve send",
            self.authed(self.client.post(url)).send(),
        )?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(IpnsRegistryError::NotFound(name.0.clone()));
        }
        if !status.is_success() {
            let text = Self::wait("name/resolve body", resp.text()).unwrap_or_default();
            // Kubo returns 500 with body variants like "cannot resolve",
            // "could not resolve", or "name not found" depending on version
            // and whether the name was ever published.  Treat all of them
            // as NotFound so the caller can fall back to a fresh head
            // instead of bubbling up a hard 500 (which currently kills
            // datomic.transact and datomic.q at startup before any name has
            // been published).
            if text.contains("not found")
                || text.contains("could not resolve")
                || text.contains("cannot resolve")
            {
                return Err(IpnsRegistryError::NotFound(name.0.clone()));
            }
            return Err(IpnsRegistryError::Kubo(format!(
                "name/resolve {status}: {text}"
            )));
        }
        let parsed: KuboNameResolveResp = Self::wait("name/resolve parse", resp.json())?;
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

fn kubo_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(KUBO_CONNECT_TIMEOUT)
        .timeout(KUBO_REQUEST_TIMEOUT)
        .pool_idle_timeout(KUBO_POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(KUBO_POOL_MAX_IDLE_PER_HOST)
        .build()
        .unwrap_or_default()
}

impl IpnsRegistry for KuboIpnsRegistry {
    fn publish(&self, record: IpnsRecord) -> Result<(), IpnsRegistryError> {
        // Persist to the in-memory cache synchronously so subsequent
        // resolve() calls on the same node see the new head immediately.
        self.local.publish(record.clone())?;
        // Kubo's name/publish blocks for DHT propagation (~20 s on Kubo
        // 0.34.1).  When the caller can be served from the local resolve
        // cache (single-pod deploys, immediate read-after-write within the
        // same process), the DHT confirmation does not need to be on the
        // user's critical path.  Spawn it so transact returns as soon as
        // the block puts complete; the IPNS update propagates asynchronously
        // and shows up via Kubo's IPFS resolve to other peers.
        let me = self.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = tokio::task::spawn_blocking(move || me.publish_kubo(&record))
                    .await
                    .unwrap_or_else(|join| Err(IpnsRegistryError::Kubo(format!("join: {join}"))))
                {
                    tracing::warn!(error = %e, "ipns: kubo publish failed (async)");
                }
            });
        } else {
            // No tokio runtime — fall back to sync publish (tests, CLI).
            self.publish_kubo(&record)?;
        }
        Ok(())
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
        let record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2030-01-01T00:00:00Z");
        registry.publish(record.clone()).unwrap();
        assert_eq!(registry.resolve(&record.name).unwrap(), record);
    }

    #[test]
    fn stale_sequence_is_rejected() {
        let registry = InMemoryIpnsRegistry::new();
        let cid = raw_cid(b"commit");
        let name = "k51-kotoba-test";
        registry
            .publish(IpnsRecord::new(name, &cid, 2, "2030-01-01T00:00:00Z"))
            .unwrap();
        let err = registry
            .publish(IpnsRecord::new(name, &cid, 1, "2030-01-01T00:00:00Z"))
            .unwrap_err();
        assert!(matches!(err, IpnsRegistryError::StaleRecord { .. }));
    }

    #[test]
    fn kubo_ipns_client_uses_bounded_sidecar_timeouts() {
        assert_eq!(KUBO_CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(KUBO_REQUEST_TIMEOUT, Duration::from_secs(30));
        assert_eq!(KUBO_POOL_IDLE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(KUBO_POOL_MAX_IDLE_PER_HOST, 8);
    }

    #[test]
    fn ipns_record_signs_and_verifies_ed25519() {
        let cid = raw_cid(b"commit");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2030-01-01T00:00:00Z");
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
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2030-01-01T00:00:00Z");
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
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2030-01-01T00:00:00Z");
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
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2030-01-01T00:00:00Z");
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
        let record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2030-01-01T00:00:00Z");

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
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2030-01-01T00:00:00Z");
        record.sign_ed25519(&signing_key).unwrap();

        registry.publish(record.clone()).unwrap();

        assert_eq!(registry.resolve(&record.name).unwrap(), record);
    }

    #[test]
    fn kubo_signed_record_block_roundtrips_as_dag_cbor() {
        let cid = raw_cid(b"commit");
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2030-01-01T00:00:00Z");
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
        let record = IpnsRecord::new("k51-kotoba-test", &cid, 1, "2030-01-01T00:00:00Z");

        assert!(matches!(
            record.verify_ed25519_signature(),
            Err(IpnsRegistryError::MissingPublicKey)
        ));
    }
}
