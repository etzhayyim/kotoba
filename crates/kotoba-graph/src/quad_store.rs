use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::Quad;
use kotoba_kqe::delta::Delta;
use kotoba_kqe::arrangement::Arrangement;
use kotoba_kse::journal::Journal;
use kotoba_kse::topic::Topic;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// QuadStore — Quad write/read API with 3-index Journal publish
pub struct QuadStore {
    journal:      Arc<Journal>,
    arrangements: Arc<RwLock<HashMap<String, Arrangement>>>, // graph_cid → Arrangement
}

impl QuadStore {
    pub fn new(journal: Arc<Journal>) -> Self {
        Self {
            journal,
            arrangements: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Write quad: publish to SPO/POS/OSP Topics + update Arrangement
    pub async fn assert(&self, quad: Quad) -> Delta {
        let g = quad.graph.to_multibase();
        let s = quad.subject.to_multibase();
        let p = &quad.predicate.clone();
        let o = "o"; // object hash placeholder

        // 3-index publish (EAVT → SPO/POS/OSP)
        let payload = serde_json::to_vec(&quad).unwrap_or_default().into();
        self.journal.publish(Topic::quad_spo(&g, &s, p, o), bytes::Bytes::clone(&payload)).await;
        self.journal.publish(Topic::quad_pos(&g, p, o, &s), bytes::Bytes::clone(&payload)).await;
        self.journal.publish(Topic::quad_osp(&g, o, &s, p), payload).await;

        let delta = Delta::assert(quad.clone());
        let mut arrs = self.arrangements.write().await;
        arrs.entry(g).or_insert_with(Arrangement::new).insert(&quad);
        delta
    }

    pub async fn retract(&self, quad: Quad) -> Delta {
        let g = quad.graph.to_multibase();
        let mut arrs = self.arrangements.write().await;
        arrs.entry(g).or_insert_with(Arrangement::new).remove(&quad);
        Delta::retract(quad)
    }

    pub async fn arrangement(&self, graph_cid: &KotobaCid) -> Option<Arrangement> {
        self.arrangements.read().await.get(&graph_cid.to_multibase()).cloned()
    }
}
