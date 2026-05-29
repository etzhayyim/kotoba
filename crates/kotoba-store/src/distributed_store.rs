#[cfg(test)]
use crate::MemoryBlockStore;
use anyhow::Result;
use bytes::Bytes;
use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
/// DistributedBlockStore — multi-peer block fetch with local-first caching.
///
/// Implements the distributed read path for IPFS-backed ProllyTree queries:
///   1. Check local store (hot cache hit → µs)
///   2. On miss: try each peer's Kubo HTTP `/api/v0/block/get?arg={cid}` in order
///   3. On success: promote block to local store; subsequent reads are cache hits
///
/// Write path: writes go to local store only.  Background replication (bitswap
/// announce to peers) is handled out-of-band by the Kubo daemon or KotobaSwarm.
///
/// # Env-driven peer list
///
/// `KOTOBA_PEERS` — space-separated Kubo HTTP base URLs, e.g.:
/// ```text
/// KOTOBA_PEERS="http://peer1:5001 http://peer2:5001"
/// ```
///
/// # Usage with TieredBlockStore
///
/// Compose a full IPFS-distributed read path:
/// ```text
/// TieredBlockStore
///   hot = BudgetedBlockStore<MemoryBlockStore>   (LRU hot cache)
///   cold = DistributedBlockStore                  (local Kubo + peer fallback)
/// ```
use std::sync::Arc;

/// A block store that reads from `local` first, then fans out to `peers` on miss.
///
/// On peer hit the block is promoted to `local` so the next access is a cache hit.
pub struct DistributedBlockStore {
    local: Arc<dyn BlockStore + Send + Sync>,
    peers: Vec<String>, // Kubo HTTP base URLs
    client: reqwest::Client,
}

impl DistributedBlockStore {
    pub fn new(local: Arc<dyn BlockStore + Send + Sync>, peers: Vec<String>) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(500))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self {
            local,
            peers,
            client,
        }
    }

    /// Create from `KOTOBA_PEERS` env var (space-separated URLs).
    /// Falls back to `local`-only if the var is absent.
    pub fn from_env(local: Arc<dyn BlockStore + Send + Sync>) -> Self {
        let s = std::env::var("KOTOBA_PEERS").unwrap_or_default();
        Self::from_peers_str(&s, local)
    }

    /// Create from a space-separated peer URL string (useful in tests).
    pub fn from_peers_str(peers_str: &str, local: Arc<dyn BlockStore + Send + Sync>) -> Self {
        let peers = peers_str
            .split_whitespace()
            .map(|s| s.trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self::new(local, peers)
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    fn kubo_get_url(base: &str, cid_mb: &str) -> String {
        format!("{base}/api/v0/block/get?arg={cid_mb}")
    }

    /// Fetch from a single peer Kubo node.  Returns `None` if not available.
    fn fetch_from_peer(&self, peer: &str, cid_mb: &str) -> Option<Bytes> {
        let url = Self::kubo_get_url(peer, cid_mb);
        let client = self.client.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                let resp = client.post(&url).send().await.ok()?;
                if !resp.status().is_success() {
                    return None;
                }
                let b = resp.bytes().await.ok()?;
                if b.is_empty() {
                    None
                } else {
                    Some(b)
                }
            })
        })
    }
}

impl BlockStore for DistributedBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> Result<()> {
        self.local.put(cid, data)
    }

    fn get(&self, cid: &KotobaCid) -> Result<Option<Bytes>> {
        // 1. Local hit
        if let Some(b) = self.local.get(cid)? {
            return Ok(Some(b));
        }
        // 2. Fan out to peers
        let cid_mb = cid.to_multibase();
        for peer in &self.peers {
            if let Some(b) = self.fetch_from_peer(peer, &cid_mb) {
                // Promote to local cache (ignore write error — best-effort)
                let _ = self.local.put(cid, &b);
                tracing::debug!(peer = %peer, cid = %cid_mb, "distributed block fetch hit");
                return Ok(Some(b));
            }
        }
        Ok(None)
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        if self.local.has(cid) {
            return true;
        }
        // Lightweight: try a stat/head on each peer (not full block fetch)
        let cid_mb = cid.to_multibase();
        for peer in &self.peers {
            let url = format!("{peer}/api/v0/block/stat?arg={cid_mb}");
            let client = self.client.clone();
            let found = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async move {
                    client
                        .post(&url)
                        .send()
                        .await
                        .map(|r| r.status().is_success())
                        .unwrap_or(false)
                })
            });
            if found {
                return true;
            }
        }
        false
    }

    fn delete(&self, cid: &KotobaCid) -> Result<()> {
        self.local.delete(cid)
    }

    fn pin(&self, cid: &KotobaCid) {
        self.local.pin(cid)
    }
    fn unpin(&self, cid: &KotobaCid) {
        self.local.unpin(cid)
    }
    fn is_pinned(&self, cid: &KotobaCid) -> bool {
        self.local.is_pinned(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_local() -> Arc<dyn BlockStore + Send + Sync> {
        Arc::new(MemoryBlockStore::new())
    }

    #[test]
    fn distributed_store_local_hit_no_peers() {
        let local = make_local();
        let cid = KotobaCid::from_bytes(b"dist-test-cid-1");
        local.put(&cid, b"hello-block").unwrap();
        let dist = DistributedBlockStore::new(local, vec![]);
        let result = dist.get(&cid).unwrap();
        assert_eq!(result.as_deref(), Some(b"hello-block" as &[u8]));
    }

    #[test]
    fn distributed_store_miss_no_peers_returns_none() {
        let local = make_local();
        let cid = KotobaCid::from_bytes(b"dist-test-cid-2");
        let dist = DistributedBlockStore::new(local, vec![]);
        assert!(dist.get(&cid).unwrap().is_none());
    }

    #[test]
    fn distributed_store_has_checks_local() {
        let local = make_local();
        let cid = KotobaCid::from_bytes(b"dist-test-cid-3");
        local.put(&cid, b"data").unwrap();
        let dist = DistributedBlockStore::new(local, vec![]);
        assert!(dist.has(&cid));
    }

    #[test]
    fn distributed_store_has_returns_false_when_absent() {
        let local = make_local();
        let cid = KotobaCid::from_bytes(b"dist-test-cid-4");
        let dist = DistributedBlockStore::new(local, vec![]);
        assert!(!dist.has(&cid));
    }

    #[test]
    fn distributed_store_peer_count() {
        let local = make_local();
        let dist = DistributedBlockStore::new(
            local,
            vec!["http://p1:5001".into(), "http://p2:5001".into()],
        );
        assert_eq!(dist.peer_count(), 2);
    }

    #[test]
    fn distributed_store_put_writes_to_local() {
        let local = make_local();
        let cid = KotobaCid::from_bytes(b"dist-test-cid-5");
        let dist = DistributedBlockStore::new(Arc::clone(&local), vec![]);
        dist.put(&cid, b"written").unwrap();
        // Verify block is in the underlying local store
        let direct = local.get(&cid).unwrap();
        assert_eq!(direct.as_deref(), Some(b"written" as &[u8]));
    }

    #[test]
    fn distributed_store_from_peers_str_empty() {
        // Test from_peers_str directly (no env var mutation needed)
        let dist = DistributedBlockStore::from_peers_str("", make_local());
        assert_eq!(dist.peer_count(), 0);
    }

    #[test]
    fn distributed_store_from_peers_str_parses_space_separated() {
        let dist = DistributedBlockStore::from_peers_str(
            "http://a:5001 http://b:5001 http://c:5001",
            make_local(),
        );
        assert_eq!(dist.peer_count(), 3);
    }
}
