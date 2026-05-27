/// KuboBlockStore — Dual-CID cold block store backed by a Kubo/IPFS HTTP node.
///
/// Internal KotobaCid (blake3-256 CIDv1) is used as the primary key throughout
/// the system.  At the storage boundary this crate computes a SHA2-256 CIDv1
/// (the IPFS standard) and maintains a lightweight in-memory index:
///
///   blake3 KotobaCid → SHA2-256 CIDv1 multibase string (base32lower, "bafkrei…")
///
/// This means the rest of kotoba (Journal, Vault, QuadStore, VM, wire format)
/// never sees or handles SHA2-256 CIDs.  The translation is local to this file.
///
/// Kubo HTTP API used:
///   POST /api/v0/block/put?cid-codec=raw&mhtype=sha2-256  — store raw bytes
///   POST /api/v0/block/get?arg={sha256_cid}               — retrieve raw bytes
///   POST /api/v0/block/stat?arg={sha256_cid}              — check existence
///   POST /api/v0/block/rm?arg={sha256_cid}&force=true     — delete
///
/// Env vars:
///   KOTOBA_IPFS_ENDPOINT  — base URL (default: http://localhost:5001)
///   KOTOBA_IPFS_TOKEN     — optional Bearer JWT
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use bytes::Bytes;
use anyhow::{anyhow, Result};
use sha2::{Sha256, Digest};
use serde::Deserialize; // for BlockPutResponse
use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;

// ── SHA2-256 CIDv1 encoding ──────────────────────────────────────────────────

const MULTIBASE_BASE32LOWER: u8 = b'b';

/// Encode raw bytes as a SHA2-256 CIDv1 in base32lower multibase.
///
/// Wire layout: [0x01 version, 0x55 raw codec, 0x12 sha2-256, 0x20 hash-len, hash[32]]
fn sha256_cid(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    let mut cid_bytes = [0u8; 36];
    cid_bytes[0] = 0x01; // CIDv1
    cid_bytes[1] = 0x55; // codec: raw
    cid_bytes[2] = 0x12; // multihash: sha2-256
    cid_bytes[3] = 0x20; // hash length: 32
    cid_bytes[4..36].copy_from_slice(&hash);
    let encoded = data_encoding::BASE32_NOPAD.encode(&cid_bytes).to_ascii_lowercase();
    format!("{}{}", MULTIBASE_BASE32LOWER as char, encoded)
}

// ── Kubo API response shapes ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct BlockPutResponse {
    #[serde(rename = "Key")]
    key: String,
}

// ── KuboBlockStore ───────────────────────────────────────────────────────────

pub struct KuboBlockStore {
    client:   reqwest::Client,
    endpoint: String,
    token:    Option<String>,
    /// blake3 CID bytes ([u8;36]) → SHA2-256 CIDv1 multibase string.
    index:    Arc<RwLock<HashMap<[u8; 36], String>>>,
    pinned:   Arc<RwLock<HashSet<[u8; 36]>>>,
}

impl KuboBlockStore {
    /// Create a store pointing at `endpoint` (e.g. `"http://127.0.0.1:5001"`).
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            client:   reqwest::Client::new(),
            endpoint: endpoint.into(),
            token:    None,
            index:    Arc::new(RwLock::new(HashMap::new())),
            pinned:   Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Read endpoint + optional bearer token from env vars.
    ///   KOTOBA_IPFS_ENDPOINT (default: http://localhost:5001)
    ///   KOTOBA_IPFS_TOKEN
    pub fn from_env() -> Self {
        let endpoint = std::env::var("KOTOBA_IPFS_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:5001".into());
        let token = std::env::var("KOTOBA_IPFS_TOKEN").ok();
        Self {
            client:   reqwest::Client::new(),
            endpoint,
            token,
            index:    Arc::new(RwLock::new(HashMap::new())),
            pinned:   Arc::new(RwLock::new(HashSet::new())),
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!("{}/api/v0/{method}", self.endpoint.trim_end_matches('/'))
    }

    /// Look up the SHA2-256 CID for a given blake3 `KotobaCid` in the index.
    fn sha256_from_index(&self, cid: &KotobaCid) -> Option<String> {
        self.index.read().unwrap().get(&cid.0).cloned()
    }

    /// Store a blake3 → sha256 mapping in the index.
    fn index_insert(&self, cid: &KotobaCid, sha256: String) {
        self.index.write().unwrap().insert(cid.0, sha256);
    }

    /// Remove a blake3 → sha256 mapping from the index.
    fn index_remove(&self, cid: &KotobaCid) {
        self.index.write().unwrap().remove(&cid.0);
    }
}

impl Clone for KuboBlockStore {
    fn clone(&self) -> Self {
        Self {
            client:   self.client.clone(),
            endpoint: self.endpoint.clone(),
            token:    self.token.clone(),
            index:    Arc::clone(&self.index),
            pinned:   Arc::clone(&self.pinned),
        }
    }
}

impl BlockStore for KuboBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> Result<()> {
        // Compute SHA2-256 CIDv1 at the storage boundary.
        let sha256 = sha256_cid(data);

        // Upload to Kubo: POST /api/v0/block/put?cid-codec=raw&mhtype=sha2-256
        let url = format!(
            "{}?cid-codec=raw&mhtype=sha2-256",
            self.api_url("block/put")
        );
        let body = data.to_vec();
        let client   = self.client.clone();
        let token    = self.token.clone();
        let sha256_c = sha256.clone();

        let resp_key = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let part = reqwest::multipart::Part::bytes(body)
                    .file_name("blob");
                let form = reqwest::multipart::Form::new().part("data", part);
                let rb = client.post(&url).multipart(form);
                let rb = match &token {
                    Some(t) => rb.bearer_auth(t),
                    None    => rb,
                };
                let resp = rb.send().await
                    .map_err(|e| anyhow!("kubo block/put request: {e}"))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let text   = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("kubo block/put {status}: {text}"));
                }
                let parsed: BlockPutResponse = resp.json().await
                    .map_err(|e| anyhow!("kubo block/put parse: {e}"))?;
                Ok::<String, anyhow::Error>(parsed.key)
            })
        })?;

        tracing::debug!(blake3 = %cid, sha256 = %resp_key, "kubo block stored");
        // Canonicalise: use the CID that Kubo returned (may differ in encoding).
        self.index_insert(cid, resp_key.is_empty().then(|| sha256_c).unwrap_or(resp_key));
        Ok(())
    }

    fn get(&self, cid: &KotobaCid) -> Result<Option<Bytes>> {
        let sha256 = match self.sha256_from_index(cid) {
            Some(s) => s,
            None    => return Ok(None), // unknown CID — not in this store
        };

        let url    = format!("{}?arg={sha256}", self.api_url("block/get"));
        let client = self.client.clone();
        let token  = self.token.clone();

        let bytes = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let rb = client.post(&url);
                let rb = match &token {
                    Some(t) => rb.bearer_auth(t),
                    None    => rb,
                };
                let resp = rb.send().await
                    .map_err(|e| anyhow!("kubo block/get request: {e}"))?;
                if resp.status() == reqwest::StatusCode::NOT_FOUND
                    || resp.status().as_u16() == 500
                {
                    // Kubo returns 500 with "blockstore: block not found" body
                    let text = resp.text().await.unwrap_or_default();
                    if text.contains("block not found") || text.contains("not found") {
                        return Ok::<Option<Bytes>, anyhow::Error>(None);
                    }
                    return Err(anyhow!("kubo block/get error: {text}"));
                }
                if !resp.status().is_success() {
                    let status = resp.status();
                    let text   = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("kubo block/get {status}: {text}"));
                }
                let bytes = resp.bytes().await
                    .map_err(|e| anyhow!("kubo block/get read body: {e}"))?;
                Ok(Some(bytes))
            })
        })?;

        Ok(bytes)
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        let sha256 = match self.sha256_from_index(cid) {
            Some(s) => s,
            None    => return false,
        };

        let url    = format!("{}?arg={sha256}", self.api_url("block/stat"));
        let client = self.client.clone();
        let token  = self.token.clone();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let rb = client.post(&url);
                let rb = match &token {
                    Some(t) => rb.bearer_auth(t),
                    None    => rb,
                };
                match rb.send().await {
                    Ok(resp) => resp.status().is_success(),
                    Err(_)   => false,
                }
            })
        })
    }

    fn delete(&self, cid: &KotobaCid) -> Result<()> {
        let sha256 = match self.sha256_from_index(cid) {
            Some(s) => s,
            None    => return Ok(()), // not in this store
        };

        let url    = format!("{}?arg={sha256}&force=true", self.api_url("block/rm"));
        let client = self.client.clone();
        let token  = self.token.clone();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let rb = client.post(&url);
                let rb = match &token {
                    Some(t) => rb.bearer_auth(t),
                    None    => rb,
                };
                let resp = rb.send().await
                    .map_err(|e| anyhow!("kubo block/rm request: {e}"))?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let text   = resp.text().await.unwrap_or_default();
                    // "not found" is not an error for delete
                    if !text.contains("not found") {
                        return Err(anyhow!("kubo block/rm {status}: {text}"));
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
        })?;

        self.index_remove(cid);
        Ok(())
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
    fn sha256_cid_deterministic() {
        let data = b"hello kotoba dual-cid";
        let cid1 = sha256_cid(data);
        let cid2 = sha256_cid(data);
        assert_eq!(cid1, cid2, "SHA2-256 CID must be deterministic");
        assert!(cid1.starts_with('b'), "multibase prefix must be 'b' (base32lower)");
    }

    #[test]
    fn sha256_cid_different_data() {
        let cid1 = sha256_cid(b"block a");
        let cid2 = sha256_cid(b"block b");
        assert_ne!(cid1, cid2, "different data must produce different CIDs");
    }

    #[test]
    fn index_insert_and_lookup() {
        let store = KuboBlockStore::new("http://localhost:5001");
        let cid   = KotobaCid::from_bytes(b"test-block");
        let sha   = "bafkreitest".to_string();
        store.index_insert(&cid, sha.clone());
        assert_eq!(store.sha256_from_index(&cid), Some(sha));
    }

    #[test]
    fn index_remove() {
        let store = KuboBlockStore::new("http://localhost:5001");
        let cid   = KotobaCid::from_bytes(b"test-remove");
        store.index_insert(&cid, "bafkrei1".to_string());
        store.index_remove(&cid);
        assert_eq!(store.sha256_from_index(&cid), None);
    }

    #[test]
    fn has_returns_false_for_unknown_cid() {
        let store = KuboBlockStore::new("http://localhost:5001");
        let cid   = KotobaCid::from_bytes(b"not-inserted");
        // No index entry → has() returns false without any HTTP call
        assert!(!store.has(&cid));
    }

    #[test]
    fn get_returns_none_for_unknown_cid() {
        let store = KuboBlockStore::new("http://localhost:5001");
        let cid   = KotobaCid::from_bytes(b"not-inserted");
        // Wrap in a minimal tokio runtime for the sync bridge
        let rt    = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            tokio::task::spawn_blocking(move || store.get(&cid)).await.unwrap()
        });
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn pin_unpin_roundtrip() {
        let store = KuboBlockStore::new("http://localhost:5001");
        let cid   = KotobaCid::from_bytes(b"pin-test");
        assert!(!store.is_pinned(&cid));
        store.pin(&cid);
        assert!(store.is_pinned(&cid));
        store.unpin(&cid);
        assert!(!store.is_pinned(&cid));
    }
}
