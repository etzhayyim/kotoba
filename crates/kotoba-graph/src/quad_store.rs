use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use kotoba_core::prolly::ProllyTree;
use kotoba_kqe::quad::Quad;
use kotoba_kqe::delta::Delta;
use kotoba_kqe::arrangement::Arrangement;
use kotoba_kse::journal::Journal;
use kotoba_kse::topic::Topic;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::commit::{Commit, CommitDag};

/// QuadStore — Quad write/read API with 3-index Journal publish + ProllyTree commit
pub struct QuadStore {
    journal:      Arc<Journal>,
    block_store:  Arc<dyn BlockStore + Send + Sync>,
    arrangements: Arc<RwLock<HashMap<String, Arrangement>>>, // graph_cid → Arrangement
    commit_dag:   Arc<RwLock<CommitDag>>,
}

impl QuadStore {
    pub fn new(journal: Arc<Journal>, block_store: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self {
            journal,
            block_store,
            arrangements: Arc::new(RwLock::new(HashMap::new())),
            commit_dag:   Arc::new(RwLock::new(CommitDag::new())),
        }
    }

    /// Write quad: publish to SPO/POS/OSP Topics + update in-memory Arrangement
    pub async fn assert(&self, quad: Quad) -> Delta {
        let g = quad.graph.to_multibase();
        let s = quad.subject.to_multibase();
        let p = &quad.predicate.clone();
        let o = {
            let obj_bytes = serde_json::to_vec(&quad.object).unwrap_or_default();
            kotoba_core::cid::KotobaCid::from_bytes(&obj_bytes).to_multibase()
        };

        let payload = serde_json::to_vec(&quad).unwrap_or_default().into();
        self.journal.publish(Topic::quad_spo(&g, &s, p, &o), bytes::Bytes::clone(&payload)).await;
        self.journal.publish(Topic::quad_pos(&g, p, &o, &s), bytes::Bytes::clone(&payload)).await;
        self.journal.publish(Topic::quad_osp(&g, &o, &s, p), payload).await;

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

    /// Return the head Commit for `graph_cid` (if any).
    pub async fn head_commit(&self, graph_cid: &KotobaCid) -> Option<Commit> {
        self.commit_dag.read().await.head(graph_cid).cloned()
    }

    /// Return all head commit CIDs as a map from graph multibase → commit multibase.
    /// Used by `kqe.get-head` host function.
    pub async fn head_commit_map(&self) -> std::collections::HashMap<String, String> {
        self.commit_dag.read().await.heads_as_map()
    }

    /// Flush the current Arrangement for `graph_cid` into a ProllyTree Leaf node,
    /// persist it in the BlockStore, create a Commit, and update the CommitDag.
    ///
    /// Returns the new commit CID.
    pub async fn commit(
        &self,
        author:    &str,
        graph_cid: KotobaCid,
        seq:       u64,
    ) -> anyhow::Result<KotobaCid> {
        // Build sorted (key, value) entries from the Arrangement
        let entries: Vec<(Vec<u8>, Vec<u8>)> = {
            let arrs = self.arrangements.read().await;
            match arrs.get(&graph_cid.to_multibase()) {
                None => vec![],
                Some(arr) => arr.quads(&graph_cid).into_iter()
                    .map(|quad| {
                        // key  = CBOR(graph || subject || predicate)
                        // value = CBOR(object)
                        let key = {
                            let mut k = Vec::new();
                            k.extend_from_slice(&quad.graph.0);
                            k.extend_from_slice(&quad.subject.0);
                            k.extend_from_slice(quad.predicate.as_bytes());
                            k
                        };
                        let val = serde_json::to_vec(&quad.object).unwrap_or_default();
                        (key, val)
                    })
                    .collect(),
            }
        };

        // Build a full ProllyTree (chunked Leaf + Internal levels) and flush to BlockStore
        let root_cid = ProllyTree::build_tree(entries, &*self.block_store)?;

        // Get previous head CID for the DAG chain
        let prev = self.commit_dag.read().await
            .head(&graph_cid)
            .map(|c| c.cid.clone());

        // Seal + persist Commit
        let commit = Commit::seal(graph_cid.clone(), root_cid, prev, author.to_string(), seq);
        let cid    = commit.persist(&*self.block_store)?;

        // Update in-memory CommitDag
        self.commit_dag.write().await.add(commit);

        tracing::info!(%cid, author, seq, "QuadStore committed");
        Ok(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_kqe::quad::QuadObject;
    use kotoba_kse::Journal;
    use kotoba_store::MemoryBlockStore;

    fn make_quad(g: &str, s: &str, p: &str, o: &str) -> Quad {
        Quad {
            graph:     KotobaCid::from_bytes(g.as_bytes()),
            subject:   KotobaCid::from_bytes(s.as_bytes()),
            predicate: p.to_string(),
            object:    QuadObject::Text(o.to_string()),
        }
    }

    #[tokio::test]
    async fn commit_creates_persistent_block() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);

        let graph = KotobaCid::from_bytes(b"test-graph");
        qs.assert(make_quad("test-graph", "alice", "knows", "bob")).await;
        qs.assert(make_quad("test-graph", "alice", "name",  "Alice")).await;

        let cid = qs.commit("did:test", graph.clone(), 1).await.unwrap();

        // Block store must contain the commit block
        assert!(block_store.has(&cid));

        // CommitDag head must point to the new commit
        let head = qs.head_commit(&graph).await.unwrap();
        assert_eq!(head.cid, cid);
        assert_eq!(head.seq, 1);
    }

    #[tokio::test]
    async fn commit_chain_links_prev() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);

        let graph = KotobaCid::from_bytes(b"graph-chain");
        qs.assert(make_quad("graph-chain", "a", "p", "1")).await;
        let cid1 = qs.commit("did:test", graph.clone(), 1).await.unwrap();

        qs.assert(make_quad("graph-chain", "b", "p", "2")).await;
        let cid2 = qs.commit("did:test", graph.clone(), 2).await.unwrap();

        let head = qs.head_commit(&graph).await.unwrap();
        assert_eq!(head.prev, Some(cid1));
        assert_eq!(head.cid, cid2);
    }
}
