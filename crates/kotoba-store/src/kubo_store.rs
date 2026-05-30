use anyhow::{anyhow, Result};
use bytes::Bytes;
use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use serde::Deserialize;
/// KuboBlockStore — IPFS cold block store backed by a Kubo HTTP node.
///
/// Uses KotobaCid (sha2-256 CIDv1 dag-cbor) directly as the IPFS block CID.
/// No secondary index or CID translation is needed: the same IPFS CID that
/// kotoba uses internally is stored verbatim in Kubo.  Any node that holds a
/// KotobaCid multibase string can retrieve the block from the IPFS network via
/// Kubo's bitswap/DHT without any additional mapping.
///
/// Kubo HTTP API used:
///   POST /api/v0/block/put?cid-codec=dag-cbor&mhtype=sha2-256 — store raw bytes
///   POST /api/v0/block/get?arg={cid}                          — retrieve raw bytes
///   POST /api/v0/block/stat?arg={cid}                         — check existence
///   POST /api/v0/block/rm?arg={cid}&force=true                — delete
///
/// Env vars:
///   KOTOBA_IPFS_ENDPOINT  — base URL (default: http://localhost:5001)
///   KOTOBA_IPFS_TOKEN     — optional Bearer JWT
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const KUBO_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const KUBO_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const KUBO_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KUBO_POOL_MAX_IDLE_PER_HOST: usize = 8;
/// After a connect failure, wait this long before letting the next op
/// re-probe Kubo. Avoids a permanently-stuck `available=false` state where
/// every block silently drops while Kubo has already recovered.
const KUBO_FAILURE_COOLDOWN_SECS: u64 = 5;

#[derive(Deserialize)]
struct BlockPutResponse {
    #[serde(rename = "Key")]
    key: String,
}

pub struct KuboBlockStore {
    client: reqwest::Client,
    endpoint: String,
    token: Option<String>,
    pinned: Arc<RwLock<HashSet<[u8; 36]>>>,
    /// Unix-seconds timestamp of the most recent connect failure.
    /// `is_available()` returns false only while we're within
    /// `KUBO_FAILURE_COOLDOWN_SECS` of that timestamp.  This lets a stuck
    /// store recover automatically: when Kubo comes back, the next op after
    /// the cooldown probes it and resumes normal operation.  `0` means
    /// "never failed".
    failed_at_unix: Arc<AtomicU64>,
}

impl KuboBlockStore {
    pub fn new(endpoint: impl Into<String>) -> Self {
        // 5 s connect timeout absorbs sidecar startup race; pool reuse + capped
        // idle keep the Kubo handler from leaking CLOSE_WAIT under burst commits
        // (observed 318 CLOSE_WAIT + 287 FIN_WAIT2 on Kubo 0.34.1 with the prior
        // 500 ms / unbounded pool config).
        let client = kubo_http_client();
        Self {
            client,
            endpoint: endpoint.into(),
            token: None,
            pinned: Arc::new(RwLock::new(HashSet::new())),
            failed_at_unix: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Probe the Kubo daemon's `/api/v0/version` endpoint.
    ///
    /// Returns `Ok((version, commit))` on a 200 response so operators can log
    /// the running daemon version at startup.  Falls back to `Err` if the
    /// daemon is unreachable, returns a non-2xx, or the JSON is malformed.
    pub async fn probe_version(&self) -> anyhow::Result<(String, String)> {
        let url = format!("{}/api/v0/version", self.endpoint.trim_end_matches('/'));
        let mut req = self.client.post(&url);
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("connect: {e}"))?;
        if !resp.status().is_success() {
            anyhow::bail!("HTTP {}", resp.status());
        }
        // Extract just Version/Commit fields from the JSON body without pulling
        // serde_json into the crate's deps — we only need two string lookups.
        let body = resp
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("read: {e}"))?;
        let version = extract_json_string_field(&body, "Version").unwrap_or_default();
        let commit = extract_json_string_field(&body, "Commit").unwrap_or_default();
        Ok((version, commit))
    }

    pub fn from_env() -> Self {
        let endpoint = std::env::var("KOTOBA_IPFS_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:5001".into());
        let token = std::env::var("KOTOBA_IPFS_TOKEN").ok();
        let client = kubo_http_client();
        Self {
            client,
            endpoint,
            token,
            pinned: Arc::new(RwLock::new(HashSet::new())),
            failed_at_unix: Arc::new(AtomicU64::new(0)),
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!("{}/api/v0/{method}", self.endpoint.trim_end_matches('/'))
    }

    fn mark_unavailable(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.failed_at_unix.store(now, Ordering::Relaxed);
    }
    fn mark_available(&self) {
        self.failed_at_unix.store(0, Ordering::Relaxed);
    }
    pub fn is_available(&self) -> bool {
        let failed_at = self.failed_at_unix.load(Ordering::Relaxed);
        if failed_at == 0 {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(failed_at) >= KUBO_FAILURE_COOLDOWN_SECS
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

impl Clone for KuboBlockStore {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            endpoint: self.endpoint.clone(),
            token: self.token.clone(),
            pinned: Arc::clone(&self.pinned),
            failed_at_unix: Arc::clone(&self.failed_at_unix),
        }
    }
}

impl BlockStore for KuboBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> Result<()> {
        if !self.is_available() {
            return Ok(());
        }

        let url = format!(
            "{}?cid-codec=dag-cbor&mhtype=sha2-256",
            self.api_url("block/put")
        );
        let body = data.to_vec();
        let client = self.client.clone();
        let token = self.token.clone();
        let cid_mb = cid.to_multibase();

        let resp_key = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let part = reqwest::multipart::Part::bytes(body).file_name("blob");
                let form = reqwest::multipart::Form::new().part("data", part);
                let rb = client.post(&url).multipart(form);
                let rb = match &token {
                    Some(t) => rb.bearer_auth(t),
                    None => rb,
                };
                let resp = rb
                    .send()
                    .await
                    .map_err(|e| anyhow!("kubo block/put: {e}"))?;
                if !resp.status().is_success() {
                    let st = resp.status();
                    let tx = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("kubo block/put {st}: {tx}"));
                }
                let parsed: BlockPutResponse = resp
                    .json()
                    .await
                    .map_err(|e| anyhow!("kubo block/put parse: {e}"))?;
                Ok::<String, anyhow::Error>(parsed.key)
            })
        });

        match resp_key {
            Err(e) => {
                if e.to_string().contains("connect") {
                    self.mark_unavailable();
                }
                Err(e)
            }
            Ok(key) => {
                self.mark_available();
                tracing::debug!(cid = %cid_mb, kubo_key = %key, "kubo block stored");
                Ok(())
            }
        }
    }

    fn get(&self, cid: &KotobaCid) -> Result<Option<Bytes>> {
        if !self.is_available() {
            return Ok(None);
        }

        let url = format!("{}?arg={}", self.api_url("block/get"), cid.to_multibase());
        let client = self.client.clone();
        let token = self.token.clone();

        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let rb = client.post(&url);
                let rb = match &token {
                    Some(t) => rb.bearer_auth(t),
                    None => rb,
                };
                let resp = rb
                    .send()
                    .await
                    .map_err(|e| anyhow!("kubo block/get: {e}"))?;
                let status = resp.status();
                if status == reqwest::StatusCode::NOT_FOUND || status.as_u16() == 500 {
                    let text = resp.text().await.unwrap_or_default();
                    if text.contains("block not found") || text.contains("not found") {
                        return Ok::<Option<Bytes>, anyhow::Error>(None);
                    }
                    return Err(anyhow!("kubo block/get error: {text}"));
                }
                if !status.is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("kubo block/get {status}: {text}"));
                }
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| anyhow!("kubo block/get body: {e}"))?;
                Ok(Some(bytes))
            })
        });

        match result {
            Err(e) => {
                if e.to_string().contains("connect") {
                    self.mark_unavailable();
                }
                Err(e)
            }
            Ok(bytes) => {
                self.mark_available();
                Ok(bytes)
            }
        }
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        if !self.is_available() {
            return false;
        }

        let url = format!("{}?arg={}", self.api_url("block/stat"), cid.to_multibase());
        let client = self.client.clone();
        let token = self.token.clone();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let rb = client.post(&url);
                let rb = match &token {
                    Some(t) => rb.bearer_auth(t),
                    None => rb,
                };
                match rb.send().await {
                    Ok(resp) => resp.status().is_success(),
                    Err(_) => false,
                }
            })
        })
    }

    fn delete(&self, cid: &KotobaCid) -> Result<()> {
        if !self.is_available() {
            return Ok(());
        }

        let url = format!(
            "{}?arg={}&force=true",
            self.api_url("block/rm"),
            cid.to_multibase()
        );
        let client = self.client.clone();
        let token = self.token.clone();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let rb = client.post(&url);
                let rb = match &token {
                    Some(t) => rb.bearer_auth(t),
                    None => rb,
                };
                let resp = rb.send().await.map_err(|e| anyhow!("kubo block/rm: {e}"))?;
                if !resp.status().is_success() {
                    let st = resp.status();
                    let text = resp.text().await.unwrap_or_default();
                    if !text.contains("not found") {
                        return Err(anyhow!("kubo block/rm {st}: {text}"));
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
        })
    }

    fn pin(&self, cid: &KotobaCid) {
        self.pinned.write().unwrap().insert(cid.0);
    }

    fn unpin(&self, cid: &KotobaCid) {
        self.pinned.write().unwrap().remove(&cid.0);
    }

    fn is_pinned(&self, cid: &KotobaCid) -> bool {
        self.pinned.read().unwrap().contains(&cid.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha2_cid_roundtrip() {
        let data = b"hello kotoba single-cid";
        let cid = KotobaCid::from_bytes(data);
        let mb = cid.to_multibase();
        // CIDv1 dag-cbor sha2-256 multibase starts with 'b' (base32lower)
        assert!(mb.starts_with('b'), "multibase prefix must be 'b'");
        let cid2 = KotobaCid::from_multibase(&mb).expect("round-trip");
        assert_eq!(cid, cid2);
    }

    #[test]
    fn kubo_http_client_uses_bounded_sidecar_timeouts() {
        assert_eq!(KUBO_CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(KUBO_REQUEST_TIMEOUT, Duration::from_secs(30));
        assert_eq!(KUBO_POOL_IDLE_TIMEOUT, Duration::from_secs(30));
        assert_eq!(KUBO_POOL_MAX_IDLE_PER_HOST, 8);
        assert_eq!(KUBO_FAILURE_COOLDOWN_SECS, 5);
    }

    #[test]
    fn different_data_different_cid() {
        let c1 = KotobaCid::from_bytes(b"block a");
        let c2 = KotobaCid::from_bytes(b"block b");
        assert_ne!(c1.to_multibase(), c2.to_multibase());
    }

    #[test]
    fn unavailable_get_returns_none() {
        let store = KuboBlockStore::new("http://localhost:5001");
        store.mark_unavailable();
        let cid = KotobaCid::from_bytes(b"any");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let res = rt.block_on(async {
            tokio::task::spawn_blocking(move || store.get(&cid))
                .await
                .unwrap()
        });
        assert!(res.unwrap().is_none(), "unavailable store must return None");
    }

    #[test]
    fn unavailable_has_returns_false() {
        let store = KuboBlockStore::new("http://localhost:5001");
        store.mark_unavailable();
        let cid = KotobaCid::from_bytes(b"any");
        assert!(!store.has(&cid));
    }

    #[test]
    fn kubo_store_retries_after_failure_cooldown() {
        let store = KuboBlockStore::new("http://localhost:5001");
        store.mark_unavailable();
        assert!(!store.is_available());

        let stale_failure = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(KUBO_FAILURE_COOLDOWN_SECS + 1);
        store.failed_at_unix.store(stale_failure, Ordering::Relaxed);

        assert!(store.is_available());
        store.mark_available();
        assert_eq!(store.failed_at_unix.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn pin_unpin_roundtrip() {
        let store = KuboBlockStore::new("http://localhost:5001");
        let cid = KotobaCid::from_bytes(b"pin-test");
        assert!(!store.is_pinned(&cid));
        store.pin(&cid);
        assert!(store.is_pinned(&cid));
        store.unpin(&cid);
        assert!(!store.is_pinned(&cid));
    }

    #[test]
    fn extract_json_string_field_basic() {
        let body = r#"{"Version":"0.27.0","Commit":"abc123","Other":42}"#;
        assert_eq!(
            extract_json_string_field(body, "Version"),
            Some("0.27.0".into())
        );
        assert_eq!(
            extract_json_string_field(body, "Commit"),
            Some("abc123".into())
        );
        assert_eq!(extract_json_string_field(body, "Missing"), None);
    }
}

/// Minimal JSON string-field extractor (avoids a serde_json dep).
/// Looks for `"<key>":"<value>"` and returns the unescaped value.
fn extract_json_string_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let i = body.find(&needle)?;
    let rest = &body[i + needle.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let val = &after_colon[1..];
    let end = val.find('"')?;
    Some(val[..end].to_string())
}
