use std::sync::Arc;
use std::collections::HashMap;

use bytes::Bytes;
use kotoba_dht::{
    neighborhood::Neighborhood,
    node_id::NodeId,
};
use kotoba_kse::{sync_window::SyncWindow, Journal, KseStore, Shelf, Topic, Vault};
use kotoba_kqe::quad::Quad;
use kotoba_graph::QuadStore;
use kotoba_kse::SecureVault;
use kotoba_store::IpfsPinClient;
use kotoba_runtime::{host::InferenceFn, UdfExecutor, WasmExecutor};
use kotoba_ingest::embed_client::{EmbedClient, HttpEmbedClient};
use kotoba_vm::{distributed::DistributedPregelRunner, InvokeRouter};
use kotoba_core::store::BlockStore;
use kotoba_crypto::AgentCrypto;

/// Shared server state — Arc-wrapped and injected into every axum handler.
pub struct KotobaState {
    pub version:       &'static str,
    // ── KSE ──────────────────────────────────────────────────────────────
    pub journal:       Arc<Journal>,
    pub shelf:         Arc<Shelf>,
    /// Content-addressed private blob vault (no GossipSub, no CACAO required).
    pub vault:         Arc<Vault>,
    // ── KDHT ─────────────────────────────────────────────────────────────
    pub neighborhood:  Arc<tokio::sync::RwLock<Neighborhood>>,
    pub local_node_id: NodeId,
    // ── KVM / Runtime ────────────────────────────────────────────────────
    pub executor:      Arc<WasmExecutor>,
    pub udf:           Arc<UdfExecutor>,
    pub router:        Arc<InvokeRouter>,
    // ── P2P / Gossip ─────────────────────────────────────────────────────
    /// GossipSub outbound channel — `Some(tx)` when the swarm actor is running.
    pub gossip_tx:        Option<tokio::sync::mpsc::Sender<(String, Vec<u8>)>>,
    // ── Distributed Pregel ───────────────────────────────────────────────
    /// Pregel runner — `Some` after swarm is attached.
    /// Lock to inject messages or trigger a superstep from XRPC handlers.
    pub pregel_runner:    Option<Arc<tokio::sync::Mutex<DistributedPregelRunner>>>,
    // ── Inference ────────────────────────────────────────────────────────
    /// Gemma 4 E2B inference engine, loaded at startup when `KOTOBA_LOAD_GEMMA` is set.
    pub inference_engine: Option<InferenceFn>,
    // ── BlockStore ───────────────────────────────────────────────────────
    /// Content-addressed block store (BudgetedBlockStore<MemoryBlockStore> hot + optional B2 cold).
    pub block_store: Arc<dyn BlockStore + Send + Sync>,
    // ── QuadStore ────────────────────────────────────────────────────────────
    /// Quad write/read with ProllyTree commit + 3-index Journal publish.
    pub quad_store:  Arc<QuadStore>,
    // ── IPFS Pinning ─────────────────────────────────────────────────────────
    /// Optional IPFS Pinning Service client (Pinata/web3.storage/Filebase).
    pub ipfs_pin: Option<Arc<IpfsPinClient>>,
    // ── Email E2E Storage ────────────────────────────────────────────────────
    /// AES-256-GCM encrypted vault for email body blobs (legacy; kept for compat).
    pub secure_vault: Arc<SecureVault>,
    // ── Agent-Sovereign Crypto ───────────────────────────────────────────────
    /// Opaque crypto engine — encrypts/decrypts without exposing raw key bytes.
    /// Initialised via `init_crypto()` after construction; starts as `None`.
    pub crypto: Option<Arc<dyn AgentCrypto>>,
    // ── KSE Key-Ref Store ────────────────────────────────────────────────────
    /// KseStore for agent key-ref pointer persistence (backed by LocalFileSystem or B2).
    pub kse_store: Option<KseStore>,
    // ── Agent Sessions ───────────────────────────────────────────────────────
    /// Active SyncWindow sessions keyed by session_id.
    pub agent_sessions: Arc<tokio::sync::RwLock<HashMap<String, SyncWindow>>>,
    // ── CC Vector Search ─────────────────────────────────────────────────────
    /// Optional embed client for CC vector search (KOTOBA_EMBED_URL).
    pub cc_embed_client: Option<Arc<dyn EmbedClient>>,
}

impl KotobaState {
    pub fn new(inference_engine: Option<InferenceFn>) -> anyhow::Result<Self> {
        // Hot block cache — BudgetedBlockStore<MemoryBlockStore>.
        // Capacity: KOTOBA_HOT_CACHE_BYTES (default 256 MiB) or
        //           KOTOBA_STORAGE_BUDGET_BYTES (legacy alias, same meaning).
        // Persistence: B2/S3 cold tier (LayeredBlockStore) if KOTOBA_B2_* env vars are set.
        // All KSE components (Journal, Vault, SecureVault) share the same store.
        let store_path: Option<String> = std::env::var("KOTOBA_STORE_PATH").ok();

        const DEFAULT_HOT_BYTES: usize = 256 * 1024 * 1024; // 256 MiB
        let hot_cache_bytes: usize = std::env::var("KOTOBA_HOT_CACHE_BYTES")
            .ok()
            .or_else(|| std::env::var("KOTOBA_STORAGE_BUDGET_BYTES").ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_HOT_BYTES);

        let block_store: Arc<dyn BlockStore + Send + Sync> = {
            let hot = kotoba_store::BudgetedBlockStore::new(
                kotoba_store::MemoryBlockStore::new(),
                hot_cache_bytes,
            );
            tracing::info!(
                hot_cache_mib = hot_cache_bytes / (1024 * 1024),
                "BlockStore: BudgetedBlockStore<MemoryBlockStore> hot cache"
            );
            Arc::new(hot)
        };

        // Journal — Merkle WAL backed by block_store; head pointer in a sibling JSON file.
        let journal = Arc::new(match &store_path {
            Some(path) => {
                let head_path = format!("{path}.journal-head.json");
                tracing::info!("KSE Journal: block-store persistence enabled");
                Journal::with_block_store(Arc::clone(&block_store), head_path)
            }
            None => {
                tracing::info!("KSE Journal: in-memory only (set KOTOBA_STORE_PATH for persistence)");
                Journal::new()
            }
        });
        let shelf = Arc::new(Shelf::new());

        // KDHT — generate ephemeral NodeId (dev mode; prod uses persisted Ed25519 key)
        let local_node_id = {
            let seed: [u8; 32] = rand_seed();
            NodeId(seed)
        };
        let neighborhood = Arc::new(tokio::sync::RwLock::new(
            Neighborhood::new(local_node_id.clone()),
        ));

        // Runtime — wire the inference engine into InvokeRouter / WasmExecutor
        let gateway_url = std::env::var("KOTOBA_GATEWAY_URL")
            .unwrap_or_else(|_| "http://localhost:9000".into());

        let (executor, router) = match &inference_engine {
            Some(engine) => (
                Arc::new(WasmExecutor::with_inference(10_000_000, engine.clone())?),
                Arc::new(InvokeRouter::with_inference(10_000_000, &gateway_url, engine.clone())?),
            ),
            None => (
                Arc::new(WasmExecutor::new(10_000_000)?),
                Arc::new(InvokeRouter::new(10_000_000, gateway_url)?),
            ),
        };
        let udf = Arc::new(UdfExecutor::new()?);

        // IPFS Pinning Service client (E) — optional, no daemon required
        let ipfs_pin = IpfsPinClient::from_env();
        if ipfs_pin.is_some() {
            tracing::info!("IPFS pinning enabled (KOTOBA_IPFS_PIN_ENDPOINT)");
        }

        // QuadStore — wraps Journal + BlockStore; provides ProllyTree commit path
        let quad_store = Arc::new(QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store)));

        // Vault — content-addressed private blob store; backed by block_store.
        let vault = Arc::new(if store_path.is_some() {
            tracing::info!("Vault: block-store persistence enabled");
            Vault::with_block_store(Arc::clone(&block_store))
        } else {
            tracing::info!("Vault: in-memory only");
            Vault::new()
        });

        // SecureVault — E2E encrypted blob store for email bodies; shares block_store.
        let secure_vault = Arc::new(if store_path.is_some() {
            tracing::info!("SecureVault: block-store persistence enabled");
            SecureVault::with_vault(Vault::with_block_store(Arc::clone(&block_store)))
        } else {
            SecureVault::new()
        });

        // KseStore — for agent key-ref pointer storage; backed by LocalFileSystem if
        // KOTOBA_STORE_PATH is set, otherwise None (crypto will be ephemeral).
        let kse_store: Option<KseStore> = store_path.as_ref().and_then(|path| {
            let dir = std::path::Path::new(path.as_str()).parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            std::fs::create_dir_all(&dir).ok()?;
            let fs = object_store::local::LocalFileSystem::new_with_prefix(&dir).ok()?;
            tracing::info!(?dir, "KseStore: LocalFileSystem key-ref store enabled");
            Some(KseStore::new(Arc::new(fs), "kse/"))
        });

        // CC embed client — optional; enables vector search over Common Crawl data
        let cc_embed_client: Option<Arc<dyn EmbedClient>> =
            HttpEmbedClient::from_env().ok().map(|c| Arc::new(c) as Arc<dyn EmbedClient>);
        if cc_embed_client.is_some() {
            tracing::info!("CC embed client enabled (KOTOBA_EMBED_URL)");
        }

        Ok(Self {
            version: env!("CARGO_PKG_VERSION"),
            journal,
            shelf,
            vault,
            neighborhood,
            local_node_id,
            executor,
            udf,
            router,
            gossip_tx:      None,
            pregel_runner:  None,
            inference_engine,
            block_store,
            quad_store,
            ipfs_pin,
            secure_vault,
            crypto:          None,
            kse_store,
            agent_sessions:  Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            cc_embed_client,
        })
    }

    /// Initialise the agent-sovereign crypto engine.
    ///
    /// Must be called once from the async context (e.g. `main.rs`) after
    /// `KotobaState::new()`. Loads or generates the vault key via HPKE.
    pub async fn init_crypto(mut self) -> anyhow::Result<Self> {
        use kotoba_kse::{AgentIdentity, SovereignCrypto};

        let identity = AgentIdentity::from_env();
        tracing::info!(did = %identity.did, ephemeral = identity.ephemeral, "agent identity initialised");

        // Build a temporary in-memory KseStore if no persistent one is available
        let sc: SovereignCrypto = if let Some(ref ks) = self.kse_store {
            SovereignCrypto::load_or_genesis(&identity, ks, &self.block_store).await?
        } else {
            // No persistent KseStore — generate ephemeral key in a temp KseStore
            let fs = object_store::memory::InMemory::new();
            let tmp_ks = KseStore::new(Arc::new(fs), "kse/");
            SovereignCrypto::load_or_genesis(&identity, &tmp_ks, &self.block_store).await?
        };

        self.crypto = Some(Arc::new(sc));
        tracing::info!("agent-sovereign crypto initialised");
        Ok(self)
    }

    /// Returns a reference to the crypto engine, or errors if not initialised.
    pub fn crypto_required(&self) -> anyhow::Result<Arc<dyn AgentCrypto>> {
        self.crypto.clone()
            .ok_or_else(|| anyhow::anyhow!("crypto not initialised — call init_crypto() first"))
    }

    /// Replay Journal WAL into the in-memory QuadStore Arrangement.
    ///
    /// Must be called once after `KotobaState::new()` and before serving
    /// requests.  When the Journal is backed by B2 this recovers all quads
    /// written in previous runs; with in-memory-only Journal it is a no-op.
    pub async fn replay_wal(&self) {
        self.quad_store.replay_from_journal().await;
    }

    /// Attach a GossipSub outbound channel after construction.
    pub fn attach_gossip(mut self, tx: tokio::sync::mpsc::Sender<(String, Vec<u8>)>) -> Self {
        self.gossip_tx = Some(tx);
        self
    }

    /// Attach the distributed Pregel runner after swarm setup.
    pub fn attach_pregel(mut self, runner: DistributedPregelRunner) -> Self {
        self.pregel_runner = Some(Arc::new(tokio::sync::Mutex::new(runner)));
        self
    }

    /// Publish a Quad assert to the KSE Journal (fine SPO topic) and,
    /// if the swarm is active, also propagate via GossipSub on the coarse
    /// `"quad/assert"` topic so peers can ingest without subscribing to
    /// every specific SPO address.
    ///
    /// Returns the JournalEntry CID string.
    pub async fn journal_assert(&self, quad: &Quad) -> String {
        let object_str = format!("{:?}", quad.object);
        let topic = Topic::quad_spo(
            &quad.graph.to_multibase(),
            &quad.subject.to_multibase(),
            &quad.predicate,
            &object_str,
        );
        let payload = serde_json::to_vec(quad).unwrap_or_default();

        // Gossip on a coarse topic so peers can subscribe once and receive all asserts.
        // Channel carries raw KSE names (no "kotoba/" prefix); KotobaSwarm::publish adds it.
        if let Some(tx) = &self.gossip_tx {
            tx.try_send(("quad/assert".to_string(), payload.clone())).ok();
        }

        let entry = self.journal.publish(topic, Bytes::from(payload)).await;
        entry.cid.to_multibase()
    }

    /// Publish a Quad retract to the KSE Journal.
    pub async fn journal_retract(&self, quad: &Quad) -> String {
        let topic   = Topic(format!("kotoba/retract/{}/{}/{}", quad.graph, quad.subject, quad.predicate));
        let payload = serde_json::to_vec(quad).unwrap_or_default();

        // Gossip retract events on a coarse topic as well.
        if let Some(tx) = &self.gossip_tx {
            tx.try_send(("quad/retract".to_string(), payload.clone())).ok();
        }

        let entry = self.journal.publish(topic, Bytes::from(payload)).await;
        entry.cid.to_multibase()
    }
}


/// Generate a deterministic-ish seed for the ephemeral dev NodeId.
/// Production: load from persisted Ed25519 key in Shelf/Keychain.
fn rand_seed() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let hash = blake3::hash(&ts.to_le_bytes());
    *hash.as_bytes()
}
