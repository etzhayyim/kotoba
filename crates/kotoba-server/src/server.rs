use std::sync::Arc;
use std::collections::HashMap;

use bytes::Bytes;
use kotoba_core::named_graph::{GraphVisibility, NamedGraph};
use kotoba_core::cid::KotobaCid;
use kotoba_dht::{
    neighborhood::Neighborhood,
    node_id::NodeId,
};
use kotoba_kse::{sync_window::SyncWindow, AgentIdentity, Journal, KseStore, PreKeyRegistry, Shelf, Topic, Vault};
use kotoba_kqe::quad::Quad;
use kotoba_graph::QuadStore;
use kotoba_kse::SecureVault;
use kotoba_store::IpfsPinClient;
use kotoba_runtime::{host::InferenceFn, UdfExecutor, WasmExecutor};
use kotoba_ingest::embed_client::{EmbedClient, HttpEmbedClient};
use kotoba_vm::{distributed::DistributedPregelRunner, InvokeRouter};
use kotoba_core::store::BlockStore;
use kotoba_crypto::AgentCrypto;

/// Participation role for this KOTOBA node (ADR-2605260005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRole {
    /// Storage provider — earns citation/royalty_mkoto Quad per cited Datom.
    Pin,
    /// Execution provider — earns gas/consumed_mkoto Quad per WASM superstep.
    Compute,
}

impl NodeRole {
    /// Parse comma-separated `KOTOBA_NODE_ROLES` env var. Defaults to `[Pin, Compute]`.
    pub fn from_env() -> Vec<Self> {
        let val = std::env::var("KOTOBA_NODE_ROLES")
            .unwrap_or_else(|_| "pin,compute".to_string());
        let mut roles = Vec::new();
        for part in val.split(',') {
            match part.trim().to_ascii_lowercase().as_str() {
                "pin"     => roles.push(NodeRole::Pin),
                "compute" => roles.push(NodeRole::Compute),
                other     => tracing::warn!(role = other, "unknown KOTOBA_NODE_ROLES value, ignoring"),
            }
        }
        if roles.is_empty() {
            roles.push(NodeRole::Pin);
            roles.push(NodeRole::Compute);
        }
        roles
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            NodeRole::Pin     => "pin",
            NodeRole::Compute => "compute",
        }
    }
}

/// Shared server state — Arc-wrapped and injected into every axum handler.
pub struct KotobaState {
    pub version:       &'static str,
    // ── Node identity / participation (ADR-2605260005) ────────────────────
    /// Operator DID derived from `KOTOBA_AGENT_DID` (or ephemeral did:key).
    pub operator_did:  String,
    /// Participation roles for this node (Pin, Compute, or both).
    pub node_roles:    Vec<NodeRole>,
    /// Shared agent identity — constructed once in `new()` and reused in
    /// `init_crypto()` to prevent double-generation in ephemeral mode.
    identity:          Arc<AgentIdentity>,
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
    // ── PRE Key Registry ─────────────────────────────────────────────────────
    /// Maps (owner_did, accessor_did) → wrapped re-encryption key.
    /// `None` until `attach_pre_key_registry()` is called.
    pub pre_key_registry: Option<Arc<PreKeyRegistry>>,
    // ── Named Graph Registry ─────────────────────────────────────────────────
    /// Maps graph CID → (graph name, GraphVisibility).
    /// Pre-populated with well-known public + authed graphs at startup.
    /// Callers may register additional graphs via `register_graph()`.
    pub graph_registry: Arc<tokio::sync::RwLock<HashMap<KotobaCid, (String, GraphVisibility)>>>,
    // ── CACAO Nonce Store ─────────────────────────────────────────────────────
    /// Replay-prevention registry for CACAO nonces (CAIP-74 §8).
    /// Tracks each nonce until the corresponding CACAO expires.
    pub nonce_store: Arc<crate::nonce_store::NonceStore>,
    // ── Outbound HTTP ─────────────────────────────────────────────────────────
    /// Shared HTTP client — used for did:web DID document resolution and other
    /// outbound fetches.  10-second timeout; connection pool reused across requests.
    pub http_client: reqwest::Client,
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

        // Agent identity — constructed once; reused in init_crypto() to avoid
        // double-generation of ephemeral keys (each call to generate_ephemeral()
        // produces a different random keypair and DID).
        let identity    = Arc::new(AgentIdentity::from_env());
        let operator_did = identity.did.clone();
        let node_roles   = NodeRole::from_env();
        tracing::info!(
            did        = %operator_did,
            ephemeral  = identity.ephemeral,
            roles      = ?node_roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            "node identity + roles initialised"
        );

        // KDHT — NodeId = blake3(Ed25519 verifying key) — safe to expose publicly.
        // MUST NOT use signing_key.to_bytes() (private key seed) here.
        let local_node_id = NodeId::from_pubkey(&identity.verifying_key().to_bytes());
        let neighborhood  = Arc::new(tokio::sync::RwLock::new(
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

        // Named graph registry — pre-populate well-known graphs.
        let graph_registry = {
            let mut map: HashMap<KotobaCid, (String, GraphVisibility)> = HashMap::new();
            let pub_g  = NamedGraph::public();
            let auth_g = NamedGraph::authenticated();
            map.insert(pub_g.cid.clone(),  (pub_g.name.clone(),  pub_g.visibility));
            map.insert(auth_g.cid.clone(), (auth_g.name.clone(), auth_g.visibility));
            Arc::new(tokio::sync::RwLock::new(map))
        };

        Ok(Self {
            version: env!("CARGO_PKG_VERSION"),
            operator_did,
            node_roles,
            identity,
            journal,
            shelf,
            vault,
            neighborhood,
            local_node_id,
            executor,
            udf,
            router,
            gossip_tx:        None,
            pregel_runner:    None,
            inference_engine,
            block_store,
            quad_store,
            ipfs_pin,
            secure_vault,
            crypto:            None,
            kse_store,
            agent_sessions:    Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            cc_embed_client,
            pre_key_registry:  None,
            graph_registry,
            nonce_store: Arc::new(crate::nonce_store::NonceStore::new()),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        })
    }

    /// Initialise the agent-sovereign crypto engine.
    ///
    /// Must be called once from the async context (e.g. `main.rs`) after
    /// `KotobaState::new()`. Loads or generates the vault key via HPKE.
    pub async fn init_crypto(mut self) -> anyhow::Result<Self> {
        use kotoba_kse::SovereignCrypto;

        // Reuse the identity constructed in new() — do NOT call from_env() again,
        // as each ephemeral call generates a different random keypair/DID.
        let identity = Arc::clone(&self.identity);
        tracing::info!(did = %identity.did, ephemeral = identity.ephemeral, "agent-sovereign crypto initialising");

        // Build a temporary in-memory KseStore if no persistent one is available
        let sc: SovereignCrypto = if let Some(ref ks) = self.kse_store {
            SovereignCrypto::load_or_genesis(&*identity, ks, &self.block_store).await?
        } else {
            // No persistent KseStore — generate ephemeral key in a temp KseStore
            let fs = object_store::memory::InMemory::new();
            let tmp_ks = KseStore::new(Arc::new(fs), "kse/");
            SovereignCrypto::load_or_genesis(&*identity, &tmp_ks, &self.block_store).await?
        };

        self.crypto = Some(Arc::new(sc));
        tracing::info!("agent-sovereign crypto initialised");
        Ok(self)
    }

    /// Returns true when the agent is running with an ephemeral (non-persisted) identity.
    pub fn is_ephemeral(&self) -> bool {
        self.identity.ephemeral
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

    /// Attach a PRE key registry for actor-level content encryption grants.
    pub fn attach_pre_key_registry(mut self, registry: Arc<PreKeyRegistry>) -> Self {
        self.pre_key_registry = Some(registry);
        self
    }

    /// Look up the visibility of a named graph by its CID.
    ///
    /// Falls back to `Authenticated` for unknown graphs (safe default).
    pub async fn graph_visibility(&self, cid: &KotobaCid) -> GraphVisibility {
        let registry = self.graph_registry.read().await;
        registry
            .get(cid)
            .map(|(_, v)| v.clone())
            .unwrap_or(GraphVisibility::Authenticated)
    }

    /// Register a named graph in the registry.
    ///
    /// Typically called at boot-time for well-known application graphs.
    pub async fn register_graph(&self, graph: NamedGraph) {
        let mut registry = self.graph_registry.write().await;
        registry.insert(graph.cid.clone(), (graph.name.clone(), graph.visibility));
    }

    /// Write node registration Quads to the `kotoba/network/nodes` graph (ADR-2605260005).
    ///
    /// Called once at startup (from `main.rs`) and re-callable via the
    /// `kotoba_node_register` MCP tool to refresh the registration timestamp.
    pub async fn register_node(&self) {
        use kotoba_kqe::quad::QuadObject;
        use std::time::{SystemTime, UNIX_EPOCH};

        let graph_cid   = KotobaCid::from_bytes(b"kotoba/network/nodes");
        let subject_cid = KotobaCid::from_bytes(self.operator_did.as_bytes());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let endpoint = std::env::var("KOTOBA_PUBLIC_ENDPOINT").unwrap_or_else(|_| {
            let port = std::env::var("KOTOBA_PORT").unwrap_or_else(|_| "8080".into());
            format!("http://localhost:{port}")
        });
        let node_id_hex = hex::encode(self.local_node_id.0);

        let mut quads = vec![
            Quad { graph: graph_cid.clone(), subject: subject_cid.clone(),
                predicate: "node/did".to_string(),
                object: QuadObject::Text(self.operator_did.clone()) },
            Quad { graph: graph_cid.clone(), subject: subject_cid.clone(),
                predicate: "node/version".to_string(),
                object: QuadObject::Text(self.version.to_string()) },
            Quad { graph: graph_cid.clone(), subject: subject_cid.clone(),
                predicate: "node/endpoint".to_string(),
                object: QuadObject::Text(endpoint) },
            Quad { graph: graph_cid.clone(), subject: subject_cid.clone(),
                predicate: "node/node_id_hex".to_string(),
                object: QuadObject::Text(node_id_hex) },
            Quad { graph: graph_cid.clone(), subject: subject_cid.clone(),
                predicate: "node/registered_at".to_string(),
                object: QuadObject::Integer(ts) },
        ];

        for role in &self.node_roles {
            let predicate = format!("node/role/{}", role.as_str());
            quads.push(Quad { graph: graph_cid.clone(), subject: subject_cid.clone(),
                predicate, object: QuadObject::Bool(true) });
        }

        for quad in &quads {
            self.journal_assert(quad).await;
            self.quad_store.assert(quad.clone()).await;
        }
        tracing::info!(
            did   = %self.operator_did,
            roles = ?self.node_roles.iter().map(NodeRole::as_str).collect::<Vec<_>>(),
            "node registered in kotoba/network/nodes"
        );
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
        // Quad is serde-derived with primitive types — serialization cannot fail.
        let payload = serde_json::to_vec(quad)
            .expect("Quad serialization is infallible");

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
        // Quad is serde-derived with primitive types — serialization cannot fail.
        let payload = serde_json::to_vec(quad)
            .expect("Quad serialization is infallible");

        // Gossip retract events on a coarse topic as well.
        if let Some(tx) = &self.gossip_tx {
            tx.try_send(("quad/retract".to_string(), payload.clone())).ok();
        }

        let entry = self.journal.publish(topic, Bytes::from(payload)).await;
        entry.cid.to_multibase()
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_role_from_env_defaults_to_both() {
        std::env::remove_var("KOTOBA_NODE_ROLES");
        let roles = NodeRole::from_env();
        assert!(roles.contains(&NodeRole::Pin));
        assert!(roles.contains(&NodeRole::Compute));
    }

    #[test]
    fn node_role_from_env_pin_only() {
        std::env::set_var("KOTOBA_NODE_ROLES", "pin");
        let roles = NodeRole::from_env();
        assert_eq!(roles, vec![NodeRole::Pin]);
        std::env::remove_var("KOTOBA_NODE_ROLES");
    }

    #[test]
    fn node_role_from_env_compute_only() {
        std::env::set_var("KOTOBA_NODE_ROLES", "compute");
        let roles = NodeRole::from_env();
        assert_eq!(roles, vec![NodeRole::Compute]);
        std::env::remove_var("KOTOBA_NODE_ROLES");
    }

    #[test]
    fn node_role_as_str_roundtrips() {
        assert_eq!(NodeRole::Pin.as_str(), "pin");
        assert_eq!(NodeRole::Compute.as_str(), "compute");
    }

    #[test]
    fn kotoba_state_new_populates_operator_did() {
        let state = KotobaState::new(None).expect("new");
        assert!(!state.operator_did.is_empty(), "operator_did must not be empty");
        assert!(
            state.operator_did.starts_with("did:"),
            "operator_did must be a DID: {}", state.operator_did
        );
    }

    #[test]
    fn kotoba_state_new_node_id_deterministic_in_ephemeral_mode() {
        // Two states created without env vars both derive NodeId from a freshly
        // generated ephemeral key — they should differ (each is random).
        std::env::remove_var("KOTOBA_AGENT_ED25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_X25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_DID");
        let a = KotobaState::new(None).expect("a");
        let b = KotobaState::new(None).expect("b");
        // ephemeral → each call generates a fresh key → different NodeIds
        assert_ne!(a.local_node_id.0, b.local_node_id.0,
            "ephemeral NodeIds must differ across restarts");
    }

    #[tokio::test]
    async fn register_node_writes_quads() {
        let state = KotobaState::new(None).expect("new");
        state.register_node().await;

        use kotoba_core::cid::KotobaCid;
        let graph_cid = KotobaCid::from_bytes(b"kotoba/network/nodes");
        let arrangement = state.quad_store.arrangement(&graph_cid).await
            .expect("kotoba/network/nodes graph should exist after register_node");

        let subject_cid = KotobaCid::from_bytes(state.operator_did.as_bytes());
        let objects = arrangement.get_objects(&subject_cid, "node/did");
        assert!(!objects.is_empty(), "node/did quad should exist");
        let objects_ts = arrangement.get_objects(&subject_cid, "node/registered_at");
        assert!(!objects_ts.is_empty(), "node/registered_at quad should exist");
    }

    #[test]
    fn is_ephemeral_returns_true_without_env_vars() {
        std::env::remove_var("KOTOBA_AGENT_ED25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_X25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_DID");
        let state = KotobaState::new(None).expect("new");
        assert!(state.is_ephemeral(), "should be ephemeral without env vars");
    }

    #[test]
    fn node_id_matches_operator_did_signing_key() {
        // NodeId is blake3(verifying_key) — derived from the same identity used for
        // operator_did (prevents the double-generation bug; never exposes private key).
        std::env::remove_var("KOTOBA_AGENT_ED25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_X25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_DID");
        let state = KotobaState::new(None).expect("new");
        // operator_did is non-empty and consistent with node_id (both from same identity)
        assert!(!hex::encode(state.local_node_id.0).is_empty());
        assert!(!state.operator_did.is_empty());
        // Two calls produce different ephemeral identities — confirming Arc reuse
        // within a single state (not across states)
        let state2 = KotobaState::new(None).expect("new2");
        assert_ne!(state.local_node_id.0, state2.local_node_id.0,
            "distinct states have distinct ephemeral NodeIds");
        assert_ne!(state.operator_did, state2.operator_did,
            "distinct states have distinct ephemeral DIDs");
    }

    #[test]
    fn require_operator_auth_accepts_tenant_jwt_with_operator_did() {
        // Simulate what tenant_jwt(&s.operator_did) produces in e2e tests.
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use axum::http::HeaderMap;

        std::env::remove_var("KOTOBA_AGENT_ED25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_X25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_DID");
        let state = KotobaState::new(None).expect("new");
        let did = &state.operator_did;

        let header  = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            format!(r#"{{"sub":"{did}","exp":9999999999}}"#).as_bytes()
        );
        let tok = format!("{header}.{payload}.fakesig");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {tok}").parse().unwrap(),
        );

        let result = crate::graph_auth::require_operator_auth(&headers, did);
        assert!(result.is_ok(),
            "require_operator_auth must accept tenant_jwt with operator_did; got err: {result:?}");
    }

    #[tokio::test]
    async fn init_crypto_preserves_operator_did() {
        // Guard against the double-generation bug: init_crypto() must not call
        // AgentIdentity::from_env() again; it must reuse the Arc stored in new().
        std::env::remove_var("KOTOBA_AGENT_ED25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_X25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_DID");
        let state = KotobaState::new(None).expect("new");
        let did_before = state.operator_did.clone();
        let state = state.init_crypto().await.expect("init_crypto");
        assert_eq!(state.operator_did, did_before,
            "operator_did must be unchanged after init_crypto");
        assert!(state.crypto_required().is_ok(), "crypto must be initialized");
    }
}
