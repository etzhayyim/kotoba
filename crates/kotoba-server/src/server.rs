use std::sync::Arc;

use bytes::Bytes;
use kotoba_dht::{
    neighborhood::Neighborhood,
    node_id::NodeId,
};
use kotoba_kse::{Journal, Shelf, Topic};
use kotoba_kqe::quad::Quad;
use kotoba_runtime::{UdfExecutor, WasmExecutor};
use kotoba_vm::InvokeRouter;

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
}

impl KotobaState {
    pub fn new() -> anyhow::Result<Self> {
        // KSE
        let journal = Arc::new(Journal::new());
        let shelf   = Arc::new(Shelf::new());

        // KDHT — generate ephemeral NodeId (dev mode; prod uses persisted Ed25519 key)
        let local_node_id = {
            let seed: [u8; 32] = rand_seed();
            NodeId(seed)
        };
        let neighborhood = Arc::new(tokio::sync::RwLock::new(
            Neighborhood::new(local_node_id.clone()),
        ));

        // Runtime
        let gateway_url = std::env::var("KOTOBA_GATEWAY_URL")
            .unwrap_or_else(|_| "http://localhost:9000".into());
        let executor = Arc::new(WasmExecutor::new(10_000_000)?);
        let udf      = Arc::new(UdfExecutor::new()?);
        let router   = Arc::new(InvokeRouter::new(10_000_000, gateway_url)?);

        Ok(Self {
            version: env!("CARGO_PKG_VERSION"),
            journal,
            shelf,
            neighborhood,
            local_node_id,
            executor,
            udf,
            router,
        })
    }

    /// Publish a Quad assert to the KSE Journal (SPO topic).
    /// Returns the JournalEntry CID string.
    pub async fn journal_assert(&self, quad: &Quad) -> String {
        let object_str = format!("{:?}", quad.object);
        let topic  = Topic::quad_spo(
            &quad.graph.to_multibase(),
            &quad.subject.to_multibase(),
            &quad.predicate,
            &object_str,
        );
        let payload = serde_json::to_vec(quad).unwrap_or_default();
        let entry  = self.journal.publish(topic, Bytes::from(payload)).await;
        entry.cid.to_multibase()
    }

    /// Publish a Quad retract to the KSE Journal.
    pub async fn journal_retract(&self, quad: &Quad) -> String {
        let topic   = Topic(format!("kotoba/retract/{}/{}/{}", quad.graph, quad.subject, quad.predicate));
        let payload = serde_json::to_vec(quad).unwrap_or_default();
        let entry   = self.journal.publish(topic, Bytes::from(payload)).await;
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
