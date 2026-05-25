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

    /// Assert without publishing to Journal — used during WAL replay on startup.
    pub async fn assert_silent(&self, quad: Quad) {
        let g = quad.graph.to_multibase();
        let mut arrs = self.arrangements.write().await;
        arrs.entry(g).or_insert_with(Arrangement::new).insert(&quad);
    }

    /// Retract without publishing to Journal — used during WAL replay on startup.
    pub async fn retract_silent(&self, quad: Quad) {
        let g = quad.graph.to_multibase();
        let mut arrs = self.arrangements.write().await;
        arrs.entry(g).or_insert_with(Arrangement::new).remove(&quad);
    }

    /// Replay the Journal WAL into the in-memory Arrangement.
    ///
    /// Reads all entries from seq=1, filters SPO-assert and retract topics,
    /// deduplicates by entry CID (same payload bytes → same CID), and applies
    /// them in seq order.  Called once at startup before serving requests.
    pub async fn replay_from_journal(&self) {
        let entries = self.journal.read_since(1).await;
        if entries.is_empty() { return; }

        let mut seen = std::collections::HashSet::<KotobaCid>::new();
        // (seq, is_assert, quad)
        let mut ordered: Vec<(u64, bool, Quad)> = Vec::new();

        for entry in &entries {
            let t = entry.topic.as_str();
            // SPO assert topics: "/kotoba/quad/{graph}/..."
            let is_assert  = t.starts_with("/kotoba/quad/");
            // Retract topics: "kotoba/retract/..."
            let is_retract = t.starts_with("kotoba/retract/");

            if (is_assert || is_retract) && seen.insert(entry.cid.clone()) {
                if let Ok(quad) = serde_json::from_slice::<Quad>(&entry.payload) {
                    ordered.push((entry.seq, is_assert, quad));
                }
            }
        }

        ordered.sort_unstable_by_key(|(seq, _, _)| *seq);
        let total = ordered.len();

        for (_, is_assert, quad) in ordered {
            if is_assert {
                self.assert_silent(quad).await;
            } else {
                self.retract_silent(quad).await;
            }
        }

        tracing::info!(entries = total, "QuadStore WAL replay complete");
    }

    pub async fn arrangement(&self, graph_cid: &KotobaCid) -> Option<Arrangement> {
        self.arrangements.read().await.get(&graph_cid.to_multibase()).cloned()
    }

    /// Return all Quads whose subject matches `subject`, optionally restricted to `graph_cid`.
    /// When `graph_cid` is None, scans every named graph in memory.
    pub async fn get_entity_quads(
        &self,
        graph_cid: Option<&KotobaCid>,
        subject: &KotobaCid,
    ) -> Vec<Quad> {
        let arrs = self.arrangements.read().await;
        if let Some(gcid) = graph_cid {
            return arrs.get(&gcid.to_multibase())
                .map(|arr| arr.get_subject_quads(gcid, subject))
                .unwrap_or_default();
        }
        let mut out = vec![];
        for (g_mb, arr) in arrs.iter() {
            let gcid = KotobaCid::from_multibase(g_mb)
                .unwrap_or_else(|| KotobaCid::from_bytes(g_mb.as_bytes()));
            out.extend(arr.get_subject_quads(&gcid, subject));
        }
        out
    }

    /// Quads whose predicate starts with `prefix`, optionally within a named graph.
    pub async fn quads_by_predicate_prefix(
        &self,
        graph_cid: Option<&KotobaCid>,
        prefix: &str,
    ) -> Vec<Quad> {
        let arrs = self.arrangements.read().await;
        if let Some(gcid) = graph_cid {
            return arrs.get(&gcid.to_multibase())
                .map(|arr| arr.quads_with_predicate_prefix(gcid, prefix))
                .unwrap_or_default();
        }
        let mut out = vec![];
        for (g_mb, arr) in arrs.iter() {
            let gcid = KotobaCid::from_multibase(g_mb)
                .unwrap_or_else(|| KotobaCid::from_bytes(g_mb.as_bytes()));
            out.extend(arr.quads_with_predicate_prefix(&gcid, prefix));
        }
        out
    }

    /// Snapshot all quads in the named graph as Assert Deltas (Datalog seed).
    pub async fn snapshot_deltas(&self, graph_cid: &KotobaCid) -> Vec<Delta> {
        self.arrangements.read().await
            .get(&graph_cid.to_multibase())
            .map(|arr| arr.to_deltas(graph_cid))
            .unwrap_or_default()
    }

    /// Count quads whose predicate starts with `prefix` within the named graph.
    pub async fn count_by_predicate_prefix(&self, graph_cid: &KotobaCid, prefix: &str) -> usize {
        self.arrangements.read().await
            .get(&graph_cid.to_multibase())
            .map(|arr| arr.count_by_predicate_prefix(prefix))
            .unwrap_or(0)
    }

    /// Find subject CIDs where predicate = `predicate` and object_key = `object_key`,
    /// optionally within a named graph.
    pub async fn lookup_subject_by_po(
        &self,
        graph_cid: Option<&KotobaCid>,
        predicate: &str,
        object_key: &str,
    ) -> Vec<KotobaCid> {
        let arrs = self.arrangements.read().await;
        if let Some(gcid) = graph_cid {
            return arrs.get(&gcid.to_multibase())
                .map(|arr| arr.get_subjects_by_predicate_object(predicate, object_key))
                .unwrap_or_default();
        }
        let mut out = vec![];
        for arr in arrs.values() {
            out.extend(arr.get_subjects_by_predicate_object(predicate, object_key));
        }
        out
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

    /// Return the ordered list of commits between `since_head` (exclusive) and the
    /// current head (inclusive), oldest-first.
    ///
    /// Used by a syncing agent to fetch only the delta it is missing:
    /// ```ignore
    /// let delta = quad_store.commits_since(&graph, window.head_cid.as_ref()).await;
    /// ```
    ///
    /// Returns an empty `Vec` if `since_head` is already the current head, or if
    /// `graph_cid` has no commits yet.
    pub async fn commits_since(
        &self,
        graph_cid: &KotobaCid,
        since_head: Option<&KotobaCid>,
    ) -> Vec<Commit> {
        let dag = self.commit_dag.read().await;
        let mut chain: Vec<Commit> = Vec::new();
        let mut cursor = dag.head(graph_cid).cloned();

        while let Some(commit) = cursor {
            // Stop if we've reached the caller's known head (exclusive)
            if let Some(stop) = since_head {
                if &commit.cid == stop {
                    break;
                }
            }
            let prev = commit.prev.clone();
            chain.push(commit);
            cursor = prev.and_then(|p| dag.get(&p).cloned());
        }

        chain.reverse(); // oldest first
        chain
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
    async fn commits_since_returns_full_chain_for_fresh_agent() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        let graph = KotobaCid::from_bytes(b"graph-since");

        qs.assert(make_quad("graph-since", "a", "p", "1")).await;
        let c1 = qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.assert(make_quad("graph-since", "b", "p", "2")).await;
        let c2 = qs.commit("did:test", graph.clone(), 2).await.unwrap();
        qs.assert(make_quad("graph-since", "c", "p", "3")).await;
        let c3 = qs.commit("did:test", graph.clone(), 3).await.unwrap();

        // Fresh agent (no prior head) should see all three commits oldest-first
        let delta = qs.commits_since(&graph, None).await;
        assert_eq!(delta.len(), 3);
        assert_eq!(delta[0].cid, c1);
        assert_eq!(delta[1].cid, c2);
        assert_eq!(delta[2].cid, c3);
    }

    #[tokio::test]
    async fn commits_since_returns_only_new_commits() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        let graph = KotobaCid::from_bytes(b"graph-partial");

        qs.assert(make_quad("graph-partial", "a", "p", "1")).await;
        let c1 = qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.assert(make_quad("graph-partial", "b", "p", "2")).await;
        let c2 = qs.commit("did:test", graph.clone(), 2).await.unwrap();
        qs.assert(make_quad("graph-partial", "c", "p", "3")).await;
        let c3 = qs.commit("did:test", graph.clone(), 3).await.unwrap();

        // Agent already has c1, only wants c2 and c3
        let delta = qs.commits_since(&graph, Some(&c1)).await;
        assert_eq!(delta.len(), 2);
        assert_eq!(delta[0].cid, c2);
        assert_eq!(delta[1].cid, c3);
    }

    #[tokio::test]
    async fn commits_since_returns_empty_when_up_to_date() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        let graph = KotobaCid::from_bytes(b"graph-uptodate");

        qs.assert(make_quad("graph-uptodate", "a", "p", "1")).await;
        let head = qs.commit("did:test", graph.clone(), 1).await.unwrap();

        let delta = qs.commits_since(&graph, Some(&head)).await;
        assert!(delta.is_empty(), "already at head — nothing to sync");
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
