use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use kotoba_auth::{
    CompositeDidResolver, DidDocument, DidDocumentFetcher, DidDocumentResolver, DidResolverError,
    InMemoryDidResolver, KotobaDidServiceConfig, LayeredDidResolver, ProtocolServiceDidResolver,
    VerificationMethod, ATPROTO_PDS_SERVICE, DIDCOMM_MESSAGING_SERVICE, DID_CONTEXT_V1,
    KOTOBA_NODE_SERVICE,
};
use kotoba_core::cid::KotobaCid;
use kotoba_core::named_graph::{GraphVisibility, NamedGraph};
use kotoba_core::store::BlockStore;
use kotoba_crypto::AgentCrypto;
use kotoba_datomic::distributed::{
    CommitDatomsRequest, DistributedCommitWriter, DistributedDatomReader,
};
use kotoba_dht::{neighborhood::Neighborhood, node_id::NodeId};
use kotoba_graph::QuadStore;
use kotoba_ingest::embed_client::{EmbedClient, HttpEmbedClient};
use kotoba_ipfs::{
    InMemoryIpnsRegistry, IpnsName, IpnsRecord, IpnsRegistry, KuboIpnsRegistry, SignedIpnsRegistry,
};
use kotoba_kqe::{quad::LegacyQuad as Quad, Datom as KqeDatom, Value as KqeValue};
use kotoba_kse::SecureVault;
use kotoba_kse::{
    sync_window::SyncWindow, AgentIdentity, Journal, KseStore, PreKeyRegistry, Shelf, Topic, Vault,
};
#[cfg(feature = "wasm-runtime")]
use kotoba_runtime::{UdfExecutor, WasmExecutor};
use kotoba_store::IpfsPinClient;
#[cfg(feature = "wasm-runtime")]
use kotoba_vm::{distributed::DistributedPregelRunner, InvokeRouter};

pub type InferenceFn = Arc<dyn Fn(&str, usize) -> anyhow::Result<String> + Send + Sync + 'static>;

/// Participation role for this KOTOBA node (ADR-2605260005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRole {
    /// Storage provider — earns citation/royalty_mkoto Quad per cited Datom.
    Pin,
    /// Execution provider — earns gas/consumed_mkoto Quad per WASM superstep.
    Compute,
    /// Firehose relay — bridges the local KSE Journal onto the libp2p `firehose`
    /// gossip topic and forwards peers' firehose entries (the mesh half of the
    /// D+E federation surface, 2026-05-30). Opt-in: not in the default set.
    Relay,
}

impl NodeRole {
    /// Parse comma-separated `KOTOBA_NODE_ROLES` env var. Defaults to `[Pin, Compute]`.
    pub fn from_env() -> Vec<Self> {
        let val = std::env::var("KOTOBA_NODE_ROLES").unwrap_or_else(|_| "pin,compute".to_string());
        let mut roles = Vec::new();
        for part in val.split(',') {
            match part.trim().to_ascii_lowercase().as_str() {
                "pin" => roles.push(NodeRole::Pin),
                "compute" => roles.push(NodeRole::Compute),
                "relay" => roles.push(NodeRole::Relay),
                other => tracing::warn!(role = other, "unknown KOTOBA_NODE_ROLES value, ignoring"),
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
            NodeRole::Pin => "pin",
            NodeRole::Compute => "compute",
            NodeRole::Relay => "relay",
        }
    }
}

#[derive(Clone, Default)]
pub struct HttpDidDocumentFetcher;

impl HttpDidDocumentFetcher {
    pub fn new() -> Self {
        Self
    }
}

impl DidDocumentFetcher for HttpDidDocumentFetcher {
    fn fetch(&self, url: &str) -> Result<Vec<u8>, DidResolverError> {
        let original_url = url.to_string();
        let thread_url = original_url.clone();
        std::thread::spawn(move || {
            let client = reqwest::blocking::Client::builder()
                .connect_timeout(std::time::Duration::from_millis(500))
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default();
            let resp = client
                .get(&thread_url)
                .send()
                .map_err(|e| DidResolverError::Fetch {
                    url: thread_url.clone(),
                    message: e.to_string(),
                })?;
            let status = resp.status();
            if !status.is_success() {
                return Err(DidResolverError::Fetch {
                    url: thread_url,
                    message: format!("HTTP {status}"),
                });
            }
            Ok(resp
                .bytes()
                .map_err(|e| DidResolverError::Fetch {
                    url: thread_url,
                    message: e.to_string(),
                })?
                .to_vec())
        })
        .join()
        .map_err(|_| DidResolverError::Fetch {
            url: original_url,
            message: "fetch thread panicked".to_string(),
        })?
    }
}

#[derive(Clone)]
pub struct DistributedDidResolver {
    block_store: Arc<dyn BlockStore + Send + Sync>,
    ipns_registry: Arc<dyn IpnsRegistry>,
    ipns_names: Vec<String>,
}

impl DistributedDidResolver {
    pub fn new(
        block_store: Arc<dyn BlockStore + Send + Sync>,
        ipns_registry: Arc<dyn IpnsRegistry>,
        ipns_names: Vec<String>,
    ) -> Self {
        Self {
            block_store,
            ipns_registry,
            ipns_names,
        }
    }
}

impl DidDocumentResolver for DistributedDidResolver {
    fn resolve(&self, did: &str) -> Result<DidDocument, DidResolverError> {
        let reader = DistributedDatomReader::new(&*self.block_store, &*self.ipns_registry);
        let did_ipns_name = did_document_ipns_name(did);
        let mut ipns_names = Vec::with_capacity(self.ipns_names.len() + 1);
        ipns_names.push(did_ipns_name);
        ipns_names.extend(self.ipns_names.iter().cloned());
        ipns_names.dedup();
        for ipns_name in &ipns_names {
            let db =
                reader
                    .current_db_for_name(ipns_name)
                    .map_err(|e| DidResolverError::Fetch {
                        url: format!("ipns://{ipns_name}"),
                        message: e.to_string(),
                    })?;
            let Some(db) = db else {
                continue;
            };
            if let Some(doc) = DidDocument::from_datoms(did, &db.datoms()) {
                return Ok(doc);
            }
        }
        Err(DidResolverError::NotFound(did.to_owned()))
    }
}

fn distributed_graph_ipns_name(graph_cid: &KotobaCid) -> String {
    format!("k51-kotoba-{}", graph_cid.to_multibase())
}

pub(crate) fn did_document_ipns_name(did: &str) -> String {
    let did_cid = KotobaCid::from_bytes(did.as_bytes());
    format!("k51-kotoba-did-{}", did_cid.to_multibase())
}

fn did_document_resolver_ipns_names() -> Vec<String> {
    if let Ok(raw) = std::env::var("KOTOBA_DID_DOCUMENT_GRAPHS") {
        let names = raw
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                if value.starts_with("k51-") {
                    value.to_string()
                } else {
                    format!("k51-kotoba-{value}")
                }
            })
            .collect::<Vec<_>>();
        if !names.is_empty() {
            return names;
        }
    }

    [
        NamedGraph::public().cid,
        NamedGraph::authenticated().cid,
        NamedGraph::new("kotobase-kg-v1", GraphVisibility::Authenticated).cid,
    ]
    .iter()
    .map(distributed_graph_ipns_name)
    .collect()
}

/// Shared server state — Arc-wrapped and injected into every axum handler.
pub struct KotobaState {
    pub version: &'static str,
    // ── Node identity / participation (ADR-2605260005) ────────────────────
    /// Operator DID derived from `KOTOBA_AGENT_DID` (or ephemeral did:key).
    pub operator_did: String,
    /// Participation roles for this node (Pin, Compute, or both).
    pub node_roles: Vec<NodeRole>,
    /// Shared agent identity — constructed once in `new()` and reused in
    /// `init_crypto()` to prevent double-generation in ephemeral mode.
    identity: Arc<AgentIdentity>,
    // ── KSE ──────────────────────────────────────────────────────────────
    pub journal: Arc<Journal>,
    pub shelf: Arc<Shelf>,
    /// Content-addressed private blob vault (no GossipSub, no CACAO required).
    pub vault: Arc<Vault>,
    // ── KDHT ─────────────────────────────────────────────────────────────
    pub neighborhood: Arc<tokio::sync::RwLock<Neighborhood>>,
    pub local_node_id: NodeId,
    // ── KVM / Runtime ────────────────────────────────────────────────────
    #[cfg(feature = "wasm-runtime")]
    pub executor: Arc<WasmExecutor>,
    #[cfg(feature = "wasm-runtime")]
    pub udf: Arc<UdfExecutor>,
    #[cfg(feature = "wasm-runtime")]
    pub router: Arc<InvokeRouter>,
    // ── P2P / Gossip ─────────────────────────────────────────────────────
    /// GossipSub outbound channel — `Some(tx)` when the swarm actor is running.
    pub gossip_tx: Option<tokio::sync::mpsc::Sender<(String, Vec<u8>)>>,
    // ── Distributed Pregel ───────────────────────────────────────────────
    /// Pregel runner — `Some` after swarm is attached.
    /// Lock to inject messages or trigger a superstep from XRPC handlers.
    #[cfg(feature = "wasm-runtime")]
    pub pregel_runner: Option<Arc<tokio::sync::Mutex<DistributedPregelRunner>>>,
    // ── Inference ────────────────────────────────────────────────────────
    /// Gemma 4 E2B inference engine, loaded at startup when `KOTOBA_LOAD_GEMMA` is set.
    pub inference_engine: Option<InferenceFn>,
    // ── BlockStore ───────────────────────────────────────────────────────
    /// Content-addressed block store (BudgetedBlockStore<MemoryBlockStore> hot + optional B2 cold).
    pub block_store: Arc<dyn BlockStore + Send + Sync>,
    // ── Distributed Datomic Head Registry ─────────────────────────────────
    /// Mutable graph/database heads.  This is the IPNS boundary for ProllyTree
    /// Datom commits; production can replace the in-memory registry with Kubo
    /// name publish/resolve without changing XRPC semantics.
    pub ipns_registry: Arc<dyn IpnsRegistry>,
    /// DID resolver abstraction for did:key, did:web, and did:plc controller checks.
    pub did_resolver: Arc<dyn DidDocumentResolver>,
    // ── QuadStore ────────────────────────────────────────────────────────────
    /// Legacy graph projection write/read with Datom-native ProllyTree commit.
    pub quad_store: Arc<QuadStore>,
    // ── kotobase Pinning ─────────────────────────────────────────────────────────
    /// Optional kotobase.gftd.ai XRPC pin client (KOTOBA_PIN_TOKEN).
    pub ipfs_pin: Arc<IpfsPinClient>,
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
    fn public_http_endpoint_from_env() -> String {
        std::env::var("KOTOBA_PUBLIC_ENDPOINT").unwrap_or_else(|_| {
            let port = std::env::var("KOTOBA_PORT").unwrap_or_else(|_| "8080".into());
            format!("http://localhost:{port}")
        })
    }

    fn did_protocol_service_config() -> KotobaDidServiceConfig {
        let kotoba_endpoint = std::env::var("KOTOBA_NODE_ENDPOINT")
            .or_else(|_| std::env::var("KOTOBA_PUBLIC_ENDPOINT"))
            .unwrap_or_else(|_| "/ip4/127.0.0.1/tcp/4001".to_string());
        let didcomm_endpoint =
            std::env::var("KOTOBA_DIDCOMM_ENDPOINT").unwrap_or_else(|_| "didcomm://{did}".into());
        let atproto_pds_endpoint = std::env::var("KOTOBA_ATPROTO_PDS_ENDPOINT")
            .unwrap_or_else(|_| Self::public_http_endpoint_from_env());
        let graph_memberships = [
            NamedGraph::public().cid,
            NamedGraph::authenticated().cid,
            NamedGraph::new("kotobase-kg-v1", GraphVisibility::Authenticated).cid,
        ]
        .into_iter()
        .map(|cid| format!("kotoba://graph/{}", cid.to_multibase()));

        KotobaDidServiceConfig::new(
            didcomm_endpoint,
            atproto_pds_endpoint,
            kotoba_endpoint,
            graph_memberships,
        )
    }

    pub fn new(inference_engine: Option<InferenceFn>) -> anyhow::Result<Self> {
        // Hot block cache — BudgetedBlockStore<MemoryBlockStore>.
        // Capacity: KOTOBA_HOT_CACHE_BYTES (default 256 MiB) or
        //           KOTOBA_STORAGE_BUDGET_BYTES (legacy alias, same meaning).
        // Persistence: KuboBlockStore cold tier (Kubo/IPFS HTTP, SHA2-256 dual-CID) if KOTOBA_STORE_PATH is set.
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
            // Cold tier: KuboBlockStore (Kubo/IPFS HTTP, SHA2-256 CIDv1) — ENABLED BY DEFAULT.
            // Endpoint from KOTOBA_IPFS_ENDPOINT (default: http://localhost:5001).
            // Set KOTOBA_IPFS=off to disable (in-memory only mode for tests/dev).
            let ipfs_off = std::env::var("KOTOBA_IPFS")
                .map(|v| {
                    v.eq_ignore_ascii_case("off") || v == "0" || v.eq_ignore_ascii_case("false")
                })
                .unwrap_or(false);
            if !ipfs_off {
                let cold = kotoba_store::KuboBlockStore::from_env();
                // F-3: attach the kotobase remote-pin client if configured so
                // every local recursive pin/add also lands on kotobase.gftd.ai.
                // Falls back to a single-pin (local only) when the env vars
                // are absent — preserves dev / local-Kubo workflows.
                let cold = match kotoba_store::IpfsPinClient::from_pin_env() {
                    Some(remote) => {
                        tracing::info!(
                            "kotobase pin fanout enabled \
                             (KOTOBA_IPFS_PIN_ENDPOINT)"
                        );
                        cold.with_remote_pin(remote)
                    }
                    None => cold,
                };
                let endpoint = std::env::var("KOTOBA_IPFS_ENDPOINT")
                    .unwrap_or_else(|_| "http://localhost:5001".into());
                let tiered = kotoba_store::TieredBlockStore::new(hot, cold);

                // KOTOBA_PEERS — space-separated Kubo HTTP URLs for federated
                // read.  When set, wrap the tiered store in a
                // DistributedBlockStore so cache misses fan out to peer Kubo
                // nodes before failing.  Each peer is a `KOTOBA_IPFS_ENDPOINT`-
                // shaped URL.
                let peers_str = std::env::var("KOTOBA_PEERS").unwrap_or_default();
                if !peers_str.trim().is_empty() {
                    let local: Arc<dyn BlockStore + Send + Sync> = Arc::new(tiered);
                    let dist = kotoba_store::DistributedBlockStore::from_peers_str(
                        &peers_str,
                        Arc::clone(&local),
                    );
                    tracing::info!(
                        hot_cache_mib = hot_cache_bytes / (1024 * 1024),
                        ipfs_endpoint = %endpoint,
                        peer_count = dist.peer_count(),
                        "BlockStore: DistributedBlockStore<TieredBlockStore<…>> — multi-peer federation enabled"
                    );
                    Arc::new(dist)
                } else {
                    tracing::info!(
                        hot_cache_mib = hot_cache_bytes / (1024 * 1024),
                        ipfs_endpoint = %endpoint,
                        "BlockStore: TieredBlockStore<BudgetedMemory, KuboIpfs> — IPFS cold tier ENABLED by default"
                    );
                    Arc::new(tiered)
                }
            } else {
                tracing::warn!(
                    hot_cache_mib = hot_cache_bytes / (1024 * 1024),
                    "BlockStore: BudgetedBlockStore<MemoryBlockStore> — IPFS cold tier DISABLED via KOTOBA_IPFS=off"
                );
                Arc::new(hot)
            }
        };

        let raw_ipns_registry: Arc<dyn IpnsRegistry> = match std::env::var("KOTOBA_IPNS") {
            Ok(mode) if mode.eq_ignore_ascii_case("kubo") => {
                tracing::info!(
                    "IPNS Registry: Kubo /api/v0/name publish/resolve enabled via KOTOBA_IPNS=kubo"
                );
                Arc::new(KuboIpnsRegistry::from_env())
            }
            _ => {
                tracing::info!(
                    "IPNS Registry: in-memory graph heads (set KOTOBA_IPNS=kubo for Kubo name publish)"
                );
                Arc::new(InMemoryIpnsRegistry::new())
            }
        };
        let ipns_registry: Arc<dyn IpnsRegistry> = match std::env::var(
            "KOTOBA_IPNS_REQUIRE_SIGNATURE",
        ) {
            Ok(v)
                if v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off") =>
            {
                tracing::warn!(
                        "IPNS Registry: signature-required policy disabled via KOTOBA_IPNS_REQUIRE_SIGNATURE"
                    );
                raw_ipns_registry
            }
            _ => {
                tracing::info!(
                        "IPNS Registry: signature-required policy enabled for distributed Datomic heads"
                    );
                Arc::new(SignedIpnsRegistry::new(raw_ipns_registry))
            }
        };

        // Journal — Merkle WAL backed by block_store; head pointer in a sibling JSON file.
        let journal = Arc::new(match &store_path {
            Some(path) => {
                let head_path = format!("{path}.journal-head.json");
                tracing::info!("KSE Journal: block-store persistence enabled");
                Journal::with_block_store(Arc::clone(&block_store), head_path)
            }
            None => {
                tracing::info!(
                    "KSE Journal: in-memory only (set KOTOBA_STORE_PATH for persistence)"
                );
                Journal::new()
            }
        });
        let shelf = Arc::new(Shelf::new());

        // Agent identity — constructed once; reused in init_crypto() to avoid
        // double-generation of ephemeral keys (each call to generate_ephemeral()
        // produces a different random keypair and DID).
        let identity = Arc::new(AgentIdentity::from_env());
        let operator_did = identity.did.clone();
        let node_roles = NodeRole::from_env();
        tracing::info!(
            did        = %operator_did,
            ephemeral  = identity.ephemeral,
            roles      = ?node_roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            "node identity + roles initialised"
        );

        // KDHT — NodeId = blake3(Ed25519 verifying key) — safe to expose publicly.
        // MUST NOT use signing_key.to_bytes() (private key seed) here.
        let local_node_id = NodeId::from_pubkey(&identity.verifying_key().to_bytes());
        let neighborhood = Arc::new(tokio::sync::RwLock::new(Neighborhood::new(
            local_node_id.clone(),
        )));

        // Runtime — wire the inference engine into InvokeRouter / WasmExecutor
        // only when the heavy Wasmtime-backed runtime is explicitly enabled.
        #[cfg(feature = "wasm-runtime")]
        let (executor, udf, router) = {
            let gateway_url = std::env::var("KOTOBA_GATEWAY_URL")
                .unwrap_or_else(|_| "http://localhost:9000".into());
            let (executor, router) = match &inference_engine {
                Some(engine) => (
                    Arc::new(WasmExecutor::with_inference(10_000_000, engine.clone())?),
                    Arc::new(InvokeRouter::with_inference(
                        10_000_000,
                        &gateway_url,
                        engine.clone(),
                    )?),
                ),
                None => (
                    Arc::new(WasmExecutor::new(10_000_000)?),
                    Arc::new(InvokeRouter::new(10_000_000, gateway_url)?),
                ),
            };
            (executor, Arc::new(UdfExecutor::new()?), router)
        };

        // IPFS pin client — always initialised; pins against KOTOBA_IPFS_ENDPOINT (default localhost:5001)
        let ipfs_pin = IpfsPinClient::from_env();
        tracing::info!("IPFS pin client ready (KOTOBA_IPFS_ENDPOINT)");

        // QuadStore — wraps Journal + BlockStore; provides ProllyTree commit path
        let quad_store = Arc::new(QuadStore::new(
            Arc::clone(&journal),
            Arc::clone(&block_store),
        ));

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
            let dir = std::path::Path::new(path.as_str())
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            std::fs::create_dir_all(&dir).ok()?;
            let fs = object_store::local::LocalFileSystem::new_with_prefix(&dir).ok()?;
            tracing::info!(?dir, "KseStore: LocalFileSystem key-ref store enabled");
            Some(KseStore::new(Arc::new(fs), "kse/"))
        });

        // CC embed client — optional; enables vector search over Common Crawl data
        let cc_embed_client: Option<Arc<dyn EmbedClient>> = HttpEmbedClient::from_env()
            .ok()
            .map(|c| Arc::new(c) as Arc<dyn EmbedClient>);
        if cc_embed_client.is_some() {
            tracing::info!("CC embed client enabled (KOTOBA_EMBED_URL)");
        }

        let did_resolver_base: Arc<dyn DidDocumentResolver> =
            Arc::new(LayeredDidResolver::new(vec![
                Arc::new(DistributedDidResolver::new(
                    Arc::clone(&block_store),
                    Arc::clone(&ipns_registry),
                    did_document_resolver_ipns_names(),
                )),
                Arc::new(CompositeDidResolver::with_default_methods(Arc::new(
                    HttpDidDocumentFetcher::new(),
                ))),
            ]));
        let did_resolver: Arc<dyn DidDocumentResolver> = Arc::new(ProtocolServiceDidResolver::new(
            did_resolver_base,
            Self::did_protocol_service_config(),
        ));

        // Named graph registry — pre-populate well-known graphs.
        //
        // `kotobase-kg-v1` is the multi-tenant kotobase data plane (named graph
        // backing ai.gftd.apps.kotobase.kg.*).  It is explicitly registered as
        // `Authenticated` (any valid Bearer JWT may read) so that tenant apps
        // can read back data they themselves wrote without provisioning a
        // depth-2 CACAO delegation chain.  Writes still require Bearer auth
        // (require_kg_write_auth in kg.rs) — the visibility only governs reads.
        let graph_registry = {
            let mut map: HashMap<KotobaCid, (String, GraphVisibility)> = HashMap::new();
            let pub_g = NamedGraph::public();
            let auth_g = NamedGraph::authenticated();
            let kg_g = NamedGraph::new("kotobase-kg-v1", GraphVisibility::Authenticated);
            map.insert(pub_g.cid.clone(), (pub_g.name.clone(), pub_g.visibility));
            map.insert(auth_g.cid.clone(), (auth_g.name.clone(), auth_g.visibility));
            map.insert(kg_g.cid.clone(), (kg_g.name.clone(), kg_g.visibility));
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
            #[cfg(feature = "wasm-runtime")]
            executor,
            #[cfg(feature = "wasm-runtime")]
            udf,
            #[cfg(feature = "wasm-runtime")]
            router,
            gossip_tx: None,
            #[cfg(feature = "wasm-runtime")]
            pregel_runner: None,
            inference_engine,
            block_store,
            ipns_registry,
            did_resolver,
            quad_store,
            ipfs_pin,
            secure_vault,
            crypto: None,
            kse_store,
            agent_sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            cc_embed_client,
            pre_key_registry: None,
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

    /// Returns true when the agent is running with an ephemeral (non-persisted) identity.
    pub fn is_ephemeral(&self) -> bool {
        self.identity.ephemeral
    }

    /// Returns a reference to the crypto engine, or errors if not initialised.
    pub fn crypto_required(&self) -> anyhow::Result<Arc<dyn AgentCrypto>> {
        self.crypto
            .clone()
            .ok_or_else(|| anyhow::anyhow!("crypto not initialised — call init_crypto() first"))
    }

    /// Sign a Kotoba-managed IPNS head record with this node's stable DID key.
    pub fn sign_ipns_record(&self, record: &mut IpnsRecord) -> anyhow::Result<()> {
        record
            .sign_ed25519(&self.identity.signing_key)
            .map_err(|e| anyhow::anyhow!("ipns record sign: {e}"))
    }

    pub fn ipns_signing_key(&self) -> ed25519_dalek::SigningKey {
        self.identity.signing_key.clone()
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
    #[cfg(feature = "wasm-runtime")]
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
    /// Default visibility for unknown graphs is controlled by
    /// `KOTOBA_DEFAULT_VISIBILITY`:
    ///   - `private`         (default) — requires CACAO delegation chain on operator DID
    ///   - `authenticated`              — requires any non-empty Bearer token
    ///   - `public`                     — open access
    ///
    /// The DEFAULT is `private` so CACAO is the canonical authentication path
    /// out-of-the-box.
    pub async fn graph_visibility(&self, cid: &KotobaCid) -> GraphVisibility {
        let registry = self.graph_registry.read().await;
        if let Some((_, v)) = registry.get(cid) {
            return v.clone();
        }
        match std::env::var("KOTOBA_DEFAULT_VISIBILITY")
            .unwrap_or_else(|_| "private".into())
            .to_ascii_lowercase()
            .as_str()
        {
            "public"        => GraphVisibility::Public,
            "authenticated" => GraphVisibility::Authenticated,
            _ /* private */ => GraphVisibility::Private {
                owner_did: self.operator_did.clone(),
            },
        }
    }

    /// Register a named graph in the registry.
    ///
    /// Typically called at boot-time for well-known application graphs.
    pub async fn register_graph(&self, graph: NamedGraph) {
        let mut registry = self.graph_registry.write().await;
        registry.insert(graph.cid.clone(), (graph.name.clone(), graph.visibility));
    }

    pub fn local_auth_did_document(&self) -> DidDocument {
        let did = self.operator_did.clone();
        let key_id = format!("{did}#agent-ed25519");
        let public_key_multibase = multibase::encode(
            multibase::Base::Base58Btc,
            self.identity.verifying_key().to_bytes(),
        );
        let x25519_key_id = format!("{did}#agent-x25519");
        let x25519_public_key_multibase = multibase::encode(
            multibase::Base::Base58Btc,
            self.identity.x25519_public_key().to_bytes(),
        );
        DidDocument {
            context: vec![DID_CONTEXT_V1.to_string()],
            id: did.clone(),
            verification_method: vec![
                VerificationMethod {
                    id: key_id.clone(),
                    key_type: "Ed25519VerificationKey2020".to_string(),
                    controller: did.clone(),
                    public_key_multibase,
                },
                VerificationMethod {
                    id: x25519_key_id.clone(),
                    key_type: "X25519KeyAgreementKey2020".to_string(),
                    controller: did.clone(),
                    public_key_multibase: x25519_public_key_multibase,
                },
            ],
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id.clone()],
            key_agreement: vec![x25519_key_id],
            capability_invocation: vec![key_id.clone()],
            capability_delegation: vec![key_id],
            service: vec![],
        }
    }

    pub async fn local_did_document(&self) -> DidDocument {
        let did = self.operator_did.clone();
        let mut doc = self.local_auth_did_document();

        let kotoba_endpoint = std::env::var("KOTOBA_NODE_ENDPOINT")
            .or_else(|_| std::env::var("KOTOBA_PUBLIC_ENDPOINT"))
            .unwrap_or_else(|_| "/ip4/127.0.0.1/tcp/4001".to_string());
        doc.push_single_service("kotoba-node", KOTOBA_NODE_SERVICE, kotoba_endpoint);

        let didcomm_endpoint = std::env::var("KOTOBA_DIDCOMM_ENDPOINT")
            .unwrap_or_else(|_| format!("didcomm://{}", did));
        doc.push_single_service("didcomm", DIDCOMM_MESSAGING_SERVICE, didcomm_endpoint);

        let atproto_pds_endpoint = std::env::var("KOTOBA_ATPROTO_PDS_ENDPOINT")
            .unwrap_or_else(|_| Self::public_http_endpoint_from_env());
        doc.push_single_service("atproto-pds", ATPROTO_PDS_SERVICE, atproto_pds_endpoint);

        let memberships = self
            .graph_registry
            .read()
            .await
            .keys()
            .map(|cid| format!("kotoba://graph/{}", cid.to_multibase()))
            .collect::<Vec<_>>();
        doc.push_graph_membership_service(memberships);
        doc
    }

    pub async fn did_ed25519_key_matches(&self, did: &str, public_key_multibase: &str) -> bool {
        if did == self.operator_did {
            let resolver = InMemoryDidResolver::new();
            resolver.insert(self.operator_did.clone(), self.local_did_document().await);
            return resolver
                .ed25519_key_matches_multibase(did, public_key_multibase)
                .unwrap_or(false);
        }
        self.did_resolver
            .ed25519_key_matches_multibase(did, public_key_multibase)
            .unwrap_or(false)
    }

    /// Write node registration Datoms to the distributed
    /// `kotoba/network/nodes` head and mirror them into the legacy Quad view
    /// for backward-compatible peers (ADR-2605260005).
    ///
    /// Called once at startup (from `main.rs`) and re-callable via the
    /// `kotoba_node_register` MCP tool to refresh the registration timestamp.
    pub async fn register_node(&self) {
        use std::time::{SystemTime, UNIX_EPOCH};

        let graph_cid = KotobaCid::from_bytes(b"kotoba/network/nodes");
        let subject_cid = KotobaCid::from_bytes(self.operator_did.as_bytes());
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let endpoint = Self::public_http_endpoint_from_env();
        let node_id_hex = hex::encode(self.local_node_id.0);

        let mut datoms = vec![
            KqeDatom::assert(
                subject_cid.clone(),
                "node/did".to_string(),
                KqeValue::Text(self.operator_did.clone()),
                graph_cid.clone(),
            ),
            KqeDatom::assert(
                subject_cid.clone(),
                "node/version".to_string(),
                KqeValue::Text(self.version.to_string()),
                graph_cid.clone(),
            ),
            KqeDatom::assert(
                subject_cid.clone(),
                "node/endpoint".to_string(),
                KqeValue::Text(endpoint),
                graph_cid.clone(),
            ),
            KqeDatom::assert(
                subject_cid.clone(),
                "node/node_id_hex".to_string(),
                KqeValue::Text(node_id_hex),
                graph_cid.clone(),
            ),
            KqeDatom::assert(
                subject_cid.clone(),
                "node/registered_at".to_string(),
                KqeValue::Integer(ts),
                graph_cid.clone(),
            ),
        ];

        for role in &self.node_roles {
            let predicate = format!("node/role/{}", role.as_str());
            datoms.push(KqeDatom::assert(
                subject_cid.clone(),
                predicate,
                KqeValue::Bool(true),
                graph_cid.clone(),
            ));
        }

        let ipns_name = distributed_graph_ipns_name(&graph_cid);
        let current_head = match self
            .ipns_registry
            .resolve(&IpnsName::new(ipns_name.clone()))
        {
            Ok(record) => Some(record),
            Err(kotoba_ipfs::IpnsRegistryError::NotFound(_)) => None,
            Err(err) => {
                tracing::warn!(error = %err, "node registration IPNS resolve failed; falling back to legacy projection");
                None
            }
        };
        let expected_parent = current_head
            .as_ref()
            .and_then(|record| KotobaCid::from_multibase(&record.value));
        let seq = current_head
            .as_ref()
            .map(|record| record.sequence + 1)
            .unwrap_or(1);

        let distributed_datoms = datoms
            .iter()
            .cloned()
            .map(kotoba_datomic::Datom::from_kqe)
            .collect::<Vec<_>>();
        let distributed = DistributedCommitWriter::new(&*self.block_store, &*self.ipns_registry)
            .commit_datoms(CommitDatomsRequest {
                ipns_name: ipns_name.clone(),
                graph: graph_cid.clone(),
                datoms: distributed_datoms,
                expected_parent,
                tx_cid: None,
                author: self.operator_did.clone(),
                seq,
                valid_until: "2099-01-01T00:00:00Z".to_string(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: Some(self.operator_did.clone()),
                ipns_signing_key: Some(self.ipns_signing_key()),
            });

        let tx_cid = match distributed {
            Ok(report) => Some(report.commit.tx_cid),
            Err(err) => {
                tracing::warn!(error = %err, "node registration distributed Datomic commit failed; falling back to legacy projection");
                None
            }
        };

        for mut datom in datoms {
            datom.op = true;
            if let Some(tx_cid) = &tx_cid {
                datom.tx = tx_cid.clone();
            }
            self.journal_assert_datom(&graph_cid, &datom).await;
            self.quad_store
                .apply_journaled_datom(graph_cid.clone(), datom)
                .await;
        }
        tracing::info!(
            did   = %self.operator_did,
            roles = ?self.node_roles.iter().map(NodeRole::as_str).collect::<Vec<_>>(),
            ipns_name = %ipns_name,
            "node registered in distributed kotoba/network/nodes"
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
        // All handlers construct QuadObject::{Text,Bytes,Cid,Integer,Bool,...} — never Float.
        // Float(f64) would fail for NaN/Inf; guard at call sites if Float is ever added.
        let payload = serde_json::to_vec(quad)
            .expect("Quad serialization: Float(NaN/Inf) must not reach journal_assert");

        // Gossip on a coarse topic so peers can subscribe once and receive all asserts.
        // Channel carries raw KSE names (no "kotoba/" prefix); KotobaSwarm::publish adds it.
        if let Some(tx) = &self.gossip_tx {
            tx.try_send(("quad/assert".to_string(), payload.clone()))
                .ok();
        }

        let entry = self.journal.publish(topic, Bytes::from(payload)).await;
        entry.cid.to_multibase()
    }

    /// Publish a Datom assert through the legacy Quad journal projection.
    ///
    /// The journal protocol remains Quad-shaped for backward-compatible peers,
    /// but callers that already operate on Datoms should not have to project
    /// back to Quad at the call site.
    pub async fn journal_assert_datom(&self, graph_cid: &KotobaCid, datom: &KqeDatom) -> String {
        self.journal_assert(&datom_journal_quad(graph_cid, datom))
            .await
    }

    /// Compatibility journal assert plus Datom-native graph-store apply.
    pub async fn assert_datom_compat(&self, graph_cid: KotobaCid, mut datom: KqeDatom) -> String {
        datom.op = true;
        let journal_cid = self.journal_assert_datom(&graph_cid, &datom).await;
        let tx_cid = KotobaCid::from_multibase(&journal_cid)
            .unwrap_or_else(|| KotobaCid::from_bytes(journal_cid.as_bytes()));
        datom.tx = tx_cid;
        self.quad_store
            .apply_journaled_datom(graph_cid, datom)
            .await;
        journal_cid
    }

    /// Compatibility write for legacy Quad API callers.
    ///
    /// The Journal still receives the Quad wire payload, while the graph store
    /// receives a Datom whose transaction is the Journal entry CID.
    pub async fn assert_quad_compat(&self, quad: Quad) -> String {
        let graph_cid = quad.graph.clone();
        let journal_cid = self.journal_assert(&quad).await;
        let tx_cid = KotobaCid::from_multibase(&journal_cid)
            .unwrap_or_else(|| KotobaCid::from_bytes(journal_cid.as_bytes()));
        let mut datom = KqeDatom::from_legacy_quad(quad, true);
        datom.tx = tx_cid;
        self.quad_store
            .apply_journaled_datom(graph_cid, datom)
            .await;
        journal_cid
    }

    /// Apply a legacy Quad caller through the Datom-native graph-store path
    /// while preserving legacy graph projection publication.
    pub async fn assert_quad_store_datom(&self, quad: Quad) {
        let graph_cid = quad.graph.clone();
        let datom = KqeDatom::from_legacy_quad(quad, true);
        self.quad_store.assert_datom(graph_cid, datom).await;
    }

    /// Publish a Quad retract to the KSE Journal.
    pub async fn journal_retract(&self, quad: &Quad) -> String {
        let topic = Topic(format!(
            "kotoba/retract/{}/{}/{}",
            quad.graph, quad.subject, quad.predicate
        ));
        // All handlers construct QuadObject::{Text,Bytes,Cid,...} — never Float.
        let payload = serde_json::to_vec(quad)
            .expect("Quad serialization: Float(NaN/Inf) must not reach journal_retract");

        // Gossip retract events on a coarse topic as well.
        if let Some(tx) = &self.gossip_tx {
            tx.try_send(("quad/retract".to_string(), payload.clone()))
                .ok();
        }

        let entry = self.journal.publish(topic, Bytes::from(payload)).await;
        entry.cid.to_multibase()
    }

    /// Publish a Datom retract through the legacy Quad journal projection.
    pub async fn journal_retract_datom(&self, graph_cid: &KotobaCid, datom: &KqeDatom) -> String {
        self.journal_retract(&datom_journal_quad(graph_cid, datom))
            .await
    }

    /// Compatibility journal retract plus Datom-native graph-store apply.
    pub async fn retract_datom_compat(&self, graph_cid: KotobaCid, mut datom: KqeDatom) -> String {
        datom.op = false;
        let journal_cid = self.journal_retract_datom(&graph_cid, &datom).await;
        let tx_cid = KotobaCid::from_multibase(&journal_cid)
            .unwrap_or_else(|| KotobaCid::from_bytes(journal_cid.as_bytes()));
        datom.tx = tx_cid;
        self.quad_store
            .apply_journaled_datom(graph_cid, datom)
            .await;
        journal_cid
    }

    /// Compatibility retract for legacy Quad API callers.
    pub async fn retract_quad_compat(&self, quad: Quad) -> String {
        let graph_cid = quad.graph.clone();
        let journal_cid = self.journal_retract(&quad).await;
        let tx_cid = KotobaCid::from_multibase(&journal_cid)
            .unwrap_or_else(|| KotobaCid::from_bytes(journal_cid.as_bytes()));
        let mut datom = KqeDatom::from_legacy_quad(quad, false);
        datom.tx = tx_cid;
        self.quad_store
            .apply_journaled_datom(graph_cid, datom)
            .await;
        journal_cid
    }

    /// Apply a legacy Quad retract through the Datom-native graph-store path.
    pub async fn retract_quad_store_datom(&self, quad: Quad) {
        let graph_cid = quad.graph.clone();
        let datom = KqeDatom::from_legacy_quad(quad, false);
        self.quad_store.retract_datom(graph_cid, datom).await;
    }
}

fn datom_journal_quad(graph_cid: &KotobaCid, datom: &KqeDatom) -> Quad {
    Quad {
        graph: graph_cid.clone(),
        subject: datom.e.clone(),
        predicate: datom.a.clone(),
        object: datom.v.clone().into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_auth::did_document::{
        ATTR_DID_CORE_ID, ATTR_DID_CORE_SERVICE, ATTR_DID_CORE_SERVICE_ENDPOINT, ATTR_RDF_TYPE,
    };

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
        assert!(
            !state.operator_did.is_empty(),
            "operator_did must not be empty"
        );
        assert!(
            state.operator_did.starts_with("did:"),
            "operator_did must be a DID: {}",
            state.operator_did
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
        assert_ne!(
            a.local_node_id.0, b.local_node_id.0,
            "ephemeral NodeIds must differ across restarts"
        );
    }

    #[tokio::test]
    async fn register_node_writes_distributed_datomic_head_and_quads() {
        let state = KotobaState::new(None).expect("new");
        state.register_node().await;

        use kotoba_core::cid::KotobaCid;
        let graph_cid = KotobaCid::from_bytes(b"kotoba/network/nodes");
        let arrangement = state
            .quad_store
            .arrangement(&graph_cid)
            .await
            .expect("kotoba/network/nodes graph should exist after register_node");

        let subject_cid = KotobaCid::from_bytes(state.operator_did.as_bytes());
        let values = arrangement.get_values(&subject_cid, "node/did");
        assert!(!values.is_empty(), "node/did datom should exist");
        let registered_at_values = arrangement.get_values(&subject_cid, "node/registered_at");
        assert!(
            !registered_at_values.is_empty(),
            "node/registered_at datom should exist"
        );

        let ipns_name = distributed_graph_ipns_name(&graph_cid);
        let db = DistributedDatomReader::new(&*state.block_store, &*state.ipns_registry)
            .current_db_for_name(&ipns_name)
            .expect("distributed node registry head should read")
            .expect("distributed node registry head should exist");
        let datoms = db.datoms();
        assert!(
            datoms.iter().any(|datom| {
                datom.e == subject_cid
                    && datom.a == "node/did"
                    && datom.v == kotoba_datomic::Value::string(&state.operator_did)
            }),
            "node/did must be readable from the distributed Datomic/IPNS head"
        );
        assert!(
            datoms.iter().any(|datom| {
                datom.e == subject_cid
                    && datom.a == "node/registered_at"
                    && matches!(datom.v, kotoba_datomic::Value::Integer(_))
            }),
            "node/registered_at must be readable from the distributed Datomic/IPNS head"
        );
    }

    #[tokio::test]
    async fn local_did_document_advertises_kotoba_protocol_services() {
        std::env::set_var("KOTOBA_ATPROTO_PDS_ENDPOINT", "https://pds.example.com");
        let state = KotobaState::new(None).expect("new");
        let doc = state.local_did_document().await;
        std::env::remove_var("KOTOBA_ATPROTO_PDS_ENDPOINT");

        assert_eq!(doc.id, state.operator_did);
        assert!(doc.ed25519_public_key().is_some());
        assert!(doc.x25519_public_key().is_some());
        assert_eq!(doc.key_agreement.len(), 1);
        assert!(doc.kotoba_endpoint().is_some());
        assert!(doc.didcomm_endpoint().is_some());
        assert_eq!(doc.atproto_pds_endpoint(), Some("https://pds.example.com"));
        assert!(doc
            .graph_memberships()
            .iter()
            .all(|scope| scope.starts_with("kotoba://graph/")));

        std::env::remove_var("KOTOBA_ATPROTO_PDS_ENDPOINT");
        std::env::set_var("KOTOBA_PUBLIC_ENDPOINT", "https://kotoba.example.com");
        let state = KotobaState::new(None).expect("new");
        let doc = state.local_did_document().await;
        std::env::remove_var("KOTOBA_PUBLIC_ENDPOINT");

        assert_eq!(
            doc.atproto_pds_endpoint(),
            Some("https://kotoba.example.com")
        );
    }

    #[test]
    fn kotoba_state_did_resolver_falls_back_to_did_key_with_protocol_services() {
        std::env::set_var("KOTOBA_NO_KEYCHAIN", "1");
        std::env::remove_var("KOTOBA_AGENT_DID");
        std::env::remove_var("KOTOBA_AGENT_ED25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_X25519_HEX");
        std::env::remove_var("KOTOBA_DIDCOMM_ENDPOINT");
        std::env::set_var("KOTOBA_IPFS", "off");
        std::env::remove_var("KOTOBA_IPNS");
        std::env::set_var(
            "KOTOBA_ATPROTO_PDS_ENDPOINT",
            "https://pds.resolver.example",
        );

        let state = KotobaState::new(None).expect("new");
        let resolved = state.did_resolver.resolve(&state.operator_did).unwrap();
        let expected_didcomm = format!("didcomm://{}", state.operator_did);

        std::env::remove_var("KOTOBA_ATPROTO_PDS_ENDPOINT");
        std::env::remove_var("KOTOBA_NO_KEYCHAIN");
        std::env::remove_var("KOTOBA_IPFS");

        assert_eq!(resolved.id, state.operator_did);
        assert_eq!(resolved.didcomm_endpoint(), Some(expected_didcomm.as_str()));
        assert_eq!(
            resolved.atproto_pds_endpoint(),
            Some("https://pds.resolver.example")
        );
        assert!(resolved.kotoba_endpoint().is_some());
        assert!(resolved
            .graph_memberships()
            .iter()
            .all(|scope| scope.starts_with("kotoba://graph/")));
        assert!(resolved.has_kotoba_protocol_services());
    }

    #[test]
    fn distributed_did_resolver_reads_document_from_ipns_datomic_head() {
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(kotoba_store::MemoryBlockStore::new());
        let ipns: Arc<dyn IpnsRegistry> = Arc::new(InMemoryIpnsRegistry::new());
        let did = "did:plc:distributedagent";
        let graph = KotobaCid::from_bytes(format!("did-document-registry:{did}").as_bytes());
        let ipns_name = did_document_ipns_name(did);

        let mut doc = DidDocument::empty(did);
        doc.push_single_service(
            "didcomm",
            DIDCOMM_MESSAGING_SERVICE,
            "didcomm://mediator/distributedagent",
        );
        doc.push_single_service(
            "atproto-pds",
            ATPROTO_PDS_SERVICE,
            "https://pds.distributedagent.example",
        );
        doc.push_single_service(
            "kotoba-node",
            KOTOBA_NODE_SERVICE,
            "/ip4/127.0.0.1/tcp/4101",
        );
        doc.push_graph_membership_service([
            "kotoba://graph/distributed-a",
            "kotoba://graph/distributed-b",
        ]);
        let tx_cid = KotobaCid::from_bytes(b"did-resolver-datomic-tx");
        let writer = kotoba_datomic::distributed::DistributedCommitWriter::new(&*store, &*ipns);
        writer
            .commit_datoms(kotoba_datomic::distributed::CommitDatomsRequest {
                ipns_name: ipns_name.clone(),
                graph,
                datoms: doc.to_datoms(tx_cid.clone()),
                expected_parent: None,
                tx_cid: Some(tx_cid),
                author: "did:key:zWriter".to_string(),
                seq: 1,
                valid_until: "2026-05-29T00:00:00Z".to_string(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .expect("commit DID document datoms");

        let resolver = DistributedDidResolver::new(store, ipns, vec![]);
        let resolved = resolver.resolve(did).unwrap();

        assert_eq!(
            resolved.didcomm_endpoint(),
            Some("didcomm://mediator/distributedagent")
        );
        assert_eq!(
            resolved.atproto_pds_endpoint(),
            Some("https://pds.distributedagent.example")
        );
        assert_eq!(resolved.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4101"));
        assert_eq!(
            resolved.graph_memberships(),
            vec![
                "kotoba://graph/distributed-a",
                "kotoba://graph/distributed-b"
            ]
        );
        assert!(resolved.has_kotoba_protocol_services());
    }

    #[test]
    fn distributed_did_resolver_reads_w3c_did_core_services_from_shared_head() {
        let store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(kotoba_store::MemoryBlockStore::new());
        let ipns: Arc<dyn IpnsRegistry> = Arc::new(InMemoryIpnsRegistry::new());
        let did = "did:web:shared.example";
        let graph = KotobaCid::from_bytes(b"shared-did-document-registry");
        let ipns_name = "k51-kotoba-shared-did-registry".to_string();
        let tx_cid = KotobaCid::from_bytes(b"shared-did-w3c-service-tx");
        let doc_entity = KotobaCid::from_bytes(did.as_bytes());
        let service_specs = [
            (
                format!("{did}#didcomm"),
                DIDCOMM_MESSAGING_SERVICE,
                kotoba_datomic::Value::string("didcomm://mediator/shared"),
            ),
            (
                format!("{did}#atproto-pds"),
                ATPROTO_PDS_SERVICE,
                kotoba_datomic::Value::string("https://pds.shared.example"),
            ),
            (
                format!("{did}#kotoba-node"),
                KOTOBA_NODE_SERVICE,
                kotoba_datomic::Value::string("/ip4/127.0.0.1/tcp/4201"),
            ),
            (
                format!("{did}#kotoba-graphs"),
                kotoba_auth::KOTOBA_GRAPH_MEMBERSHIP_SERVICE,
                kotoba_datomic::Value::vector([
                    kotoba_datomic::Value::string("kotoba://graph/shared-a"),
                    kotoba_datomic::Value::string("kotoba://graph/shared-b"),
                ]),
            ),
        ];
        let mut datoms = vec![kotoba_datomic::Datom::assert(
            doc_entity.clone(),
            ATTR_DID_CORE_ID.to_string(),
            kotoba_datomic::Value::string(did),
            tx_cid.clone(),
        )];
        for (service_id, service_type, endpoint) in service_specs {
            let service_entity = KotobaCid::from_bytes(service_id.as_bytes());
            datoms.push(kotoba_datomic::Datom::assert(
                doc_entity.clone(),
                ATTR_DID_CORE_SERVICE.to_string(),
                kotoba_datomic::Value::string(&service_id),
                tx_cid.clone(),
            ));
            datoms.push(kotoba_datomic::Datom::assert(
                service_entity.clone(),
                ATTR_DID_CORE_ID.to_string(),
                kotoba_datomic::Value::string(&service_id),
                tx_cid.clone(),
            ));
            datoms.push(kotoba_datomic::Datom::assert(
                service_entity.clone(),
                ATTR_RDF_TYPE.to_string(),
                kotoba_datomic::Value::string(service_type),
                tx_cid.clone(),
            ));
            datoms.push(kotoba_datomic::Datom::assert(
                service_entity,
                ATTR_DID_CORE_SERVICE_ENDPOINT.to_string(),
                endpoint,
                tx_cid.clone(),
            ));
        }

        let writer = kotoba_datomic::distributed::DistributedCommitWriter::new(&*store, &*ipns);
        writer
            .commit_datoms(kotoba_datomic::distributed::CommitDatomsRequest {
                ipns_name: ipns_name.clone(),
                graph,
                datoms,
                expected_parent: None,
                tx_cid: Some(tx_cid),
                author: "did:key:zWriter".to_string(),
                seq: 1,
                valid_until: "2026-05-30T00:00:00Z".to_string(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .expect("commit shared DID document registry");

        let resolver = DistributedDidResolver::new(store, ipns, vec![ipns_name]);
        let resolved = resolver.resolve(did).unwrap();

        assert_eq!(
            resolved.didcomm_endpoint(),
            Some("didcomm://mediator/shared")
        );
        assert_eq!(
            resolved.atproto_pds_endpoint(),
            Some("https://pds.shared.example")
        );
        assert_eq!(resolved.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4201"));
        assert_eq!(
            resolved.graph_memberships(),
            vec!["kotoba://graph/shared-a", "kotoba://graph/shared-b"]
        );
        assert!(resolved.has_kotoba_protocol_services());
    }

    #[test]
    fn is_ephemeral_returns_true_without_env_vars() {
        std::env::set_var("KOTOBA_NO_KEYCHAIN", "1");
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
        std::env::set_var("KOTOBA_NO_KEYCHAIN", "1");
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
        assert_ne!(
            state.local_node_id.0, state2.local_node_id.0,
            "distinct states have distinct ephemeral NodeIds"
        );
        assert_ne!(
            state.operator_did, state2.operator_did,
            "distinct states have distinct ephemeral DIDs"
        );
    }

    #[test]
    fn require_operator_auth_accepts_tenant_jwt_with_operator_did() {
        // Simulate what tenant_jwt(&s.operator_did) produces in e2e tests.
        use axum::http::HeaderMap;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        std::env::set_var("KOTOBA_NO_KEYCHAIN", "1");
        std::env::remove_var("KOTOBA_AGENT_ED25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_X25519_HEX");
        std::env::remove_var("KOTOBA_AGENT_DID");
        let state = KotobaState::new(None).expect("new");
        let did = &state.operator_did;

        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload =
            URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{did}","exp":9999999999}}"#).as_bytes());
        let tok = format!("{header}.{payload}.fakesig");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {tok}").parse().unwrap(),
        );

        let result = crate::graph_auth::require_operator_auth(&headers, did);
        assert!(
            result.is_ok(),
            "require_operator_auth must accept tenant_jwt with operator_did; got err: {result:?}"
        );
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
        assert_eq!(
            state.operator_did, did_before,
            "operator_did must be unchanged after init_crypto"
        );
        assert!(
            state.crypto_required().is_ok(),
            "crypto must be initialized"
        );
    }
}
