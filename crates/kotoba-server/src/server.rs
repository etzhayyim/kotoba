use std::sync::Arc;

use bytes::Bytes;
use kotoba_dht::{
    neighborhood::Neighborhood,
    node_id::NodeId,
};
use kotoba_kse::{store::KseStore, Journal, Shelf, Topic};
use kotoba_kqe::quad::Quad;
use kotoba_runtime::{host::InferenceFn, UdfExecutor, WasmExecutor};
use kotoba_vm::{distributed::DistributedPregelRunner, InvokeRouter};

/// Shared server state — Arc-wrapped and injected into every axum handler.
pub struct KotobaState {
    pub version:       &'static str,
    // ── KSE ──────────────────────────────────────────────────────────────
    pub journal:       Arc<Journal>,
    pub shelf:         Arc<Shelf>,
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
}

impl KotobaState {
    pub fn new(inference_engine: Option<InferenceFn>) -> anyhow::Result<Self> {
        // KSE — wire B2 persistence when env vars are present
        let journal = Arc::new(match build_kse_store("kotoba/journal/") {
            Some(store) => {
                tracing::info!("KSE Journal: B2 persistence enabled");
                Journal::with_store(store)
            }
            None => {
                tracing::info!("KSE Journal: in-memory only (set KOTOBA_B2_* for persistence)");
                Journal::new()
            }
        });
        let shelf   = Arc::new(Shelf::new());

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

        Ok(Self {
            version: env!("CARGO_PKG_VERSION"),
            journal,
            shelf,
            neighborhood,
            local_node_id,
            executor,
            udf,
            router,
            gossip_tx:     None,
            pregel_runner: None,
            inference_engine,
        })
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

/// Build a `KseStore` backed by Backblaze B2 (S3-compatible) when the
/// required env vars are present.
///
/// Required: `KOTOBA_B2_BUCKET`, `KOTOBA_B2_KEY_ID`, `KOTOBA_B2_APP_KEY`
/// Optional: `KOTOBA_B2_ENDPOINT` (default: `https://s3.us-west-001.backblazeb2.com`)
fn build_kse_store(prefix: &str) -> Option<Arc<KseStore>> {
    let bucket   = std::env::var("KOTOBA_B2_BUCKET").ok()?;
    let key_id   = std::env::var("KOTOBA_B2_KEY_ID").ok()?;
    let app_key  = std::env::var("KOTOBA_B2_APP_KEY").ok()?;
    let endpoint = std::env::var("KOTOBA_B2_ENDPOINT")
        .unwrap_or_else(|_| "https://s3.us-west-001.backblazeb2.com".into());

    use object_store::aws::AmazonS3Builder;
    let s3 = AmazonS3Builder::new()
        .with_bucket_name(&bucket)
        .with_access_key_id(&key_id)
        .with_secret_access_key(&app_key)
        .with_endpoint(&endpoint)
        .build()
        .map_err(|e| tracing::warn!("B2 store build failed: {e}"))
        .ok()?;

    Some(Arc::new(KseStore::new(Arc::new(s3), prefix)))
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
