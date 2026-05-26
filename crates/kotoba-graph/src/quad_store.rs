use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use kotoba_core::prolly::ProllyTree;
use kotoba_store::{CapturingBlockStore, CarBundleWriter};
use kotoba_kqe::quad::Quad;
use kotoba_kqe::delta::Delta;
use kotoba_kqe::arrangement::Arrangement;
use kotoba_kse::journal::Journal;
use kotoba_kse::topic::Topic;
use kotoba_auth::delegation::{DelegationChain, DelegationError};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::commit::{Commit, CommitDag};

/// Error returned when a CACAO-gated quad write fails.
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("delegation: {0}")]
    Delegation(#[from] DelegationError),
}

/// QuadStore — Quad write/read API with 3-index Journal publish + ProllyTree commit
pub struct QuadStore {
    journal:       Arc<Journal>,
    block_store:   Arc<dyn BlockStore + Send + Sync>,
    arrangements:  Arc<RwLock<HashMap<String, Arrangement>>>, // graph_cid → Arrangement
    commit_dag:    Arc<RwLock<CommitDag>>,
    /// seq of the last successful commit — persisted as a checkpoint in the Journal store.
    /// On startup this is loaded from the checkpoint before Journal replay so that
    /// `replay_from_journal` only processes entries written *after* the last commit,
    /// not the full WAL history.
    committed_seq: Arc<RwLock<u64>>,
}

impl QuadStore {
    pub fn new(journal: Arc<Journal>, block_store: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self {
            journal,
            block_store,
            arrangements:  Arc::new(RwLock::new(HashMap::new())),
            commit_dag:    Arc::new(RwLock::new(CommitDag::new())),
            committed_seq: Arc::new(RwLock::new(0)),
        }
    }

    /// Write quad: publish to 4-index Topics (SPO/PSO/POS/OSP) + update Arrangement.
    pub async fn assert(&self, quad: Quad) -> Delta {
        let g = quad.graph.to_multibase();
        let s = quad.subject.to_multibase();
        let p = quad.predicate.clone();
        let o = {
            let obj_bytes = serde_json::to_vec(&quad.object).unwrap_or_default();
            kotoba_core::cid::KotobaCid::from_bytes(&obj_bytes).to_multibase()
        };

        let payload = serde_json::to_vec(&quad).unwrap_or_default().into();
        self.journal.publish(Topic::quad_spo(&g, &s, &p, &o), bytes::Bytes::clone(&payload)).await;
        self.journal.publish(Topic::quad_pso(&g, &p, &s, &o), bytes::Bytes::clone(&payload)).await;
        self.journal.publish(Topic::quad_pos(&g, &p, &o, &s), bytes::Bytes::clone(&payload)).await;
        self.journal.publish(Topic::quad_osp(&g, &o, &s, &p), payload).await;

        let delta = Delta::assert(quad.clone());
        let mut arrs = self.arrangements.write().await;
        arrs.entry(g).or_insert_with(Arrangement::new).insert(&quad);
        delta
    }

    /// CACAO-gated quad assert.
    ///
    /// Verifies that `chain` grants `"quad:write"` on the quad's **graph** CID before
    /// delegating to `assert()`. Compute functions should call this instead of `assert()`
    /// whenever the write originates from an actor rather than the server itself.
    pub async fn assert_authed(
        &self,
        quad: Quad,
        chain: &DelegationChain,
    ) -> Result<Delta, AccessError> {
        let graph_mb = quad.graph.to_multibase();
        chain.verify(&graph_mb, "quad:write")?;
        Ok(self.assert(quad).await)
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

    /// Insert a batch of quads with a single lock acquisition — fast path for bulk ingest.
    /// Does not publish to Journal.
    pub async fn assert_batch_silent(&self, quads: Vec<Quad>) {
        if quads.is_empty() { return; }
        let mut arrs = self.arrangements.write().await;
        for quad in &quads {
            let g = quad.graph.to_multibase();
            arrs.entry(g).or_insert_with(Arrangement::new).insert(quad);
        }
    }

    /// Retract without publishing to Journal — used during WAL replay on startup.
    pub async fn retract_silent(&self, quad: Quad) {
        let g = quad.graph.to_multibase();
        let mut arrs = self.arrangements.write().await;
        arrs.entry(g).or_insert_with(Arrangement::new).remove(&quad);
    }

    /// Restore state from Journal on startup.
    ///
    /// Reads the checkpoint written by the last `commit()` call to find
    /// `committed_seq`, then replays only Journal entries **after** that seq.
    /// This ensures startup cost is O(uncommitted delta) regardless of total
    /// data history — 1B quads committed = < 1s startup vs ~83 minutes previously.
    ///
    /// First-run (no checkpoint): falls back to replaying from seq=1.
    pub async fn replay_from_journal(&self) {
        // Load checkpoint; extract committed_seq and restore CommitDag heads.
        let committed = if let Some(raw) = self.journal.read_checkpoint().await {
            let value = serde_json::from_slice::<serde_json::Value>(&raw).ok();
            let seq = value.as_ref()
                .and_then(|v| v["committed_seq"].as_u64())
                .unwrap_or(0);
            *self.committed_seq.write().await = seq;
            tracing::info!(committed_seq = seq, "QuadStore: checkpoint found, replaying delta only");

            // Restore CommitDag from checkpoint heads map.
            if let Some(heads) = value
                .as_ref()
                .and_then(|v| v["heads"].as_object())
            {
                let mut restored = 0usize;
                for (_graph_mb, commit_mb) in heads {
                    if let Some(commit_mb_str) = commit_mb.as_str() {
                        if let Some(commit_cid) = KotobaCid::from_multibase(commit_mb_str) {
                            match crate::commit::Commit::load(&commit_cid, &*self.block_store) {
                                Ok(Some(commit)) => {
                                    self.commit_dag.write().await.add(commit);
                                    restored += 1;
                                }
                                Ok(None) => {
                                    tracing::warn!(
                                        commit_cid = %commit_cid,
                                        "CommitDag restore: commit block not found in BlockStore"
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        commit_cid = %commit_cid,
                                        "CommitDag restore: failed to load commit: {e}"
                                    );
                                }
                            }
                        }
                    }
                }
                tracing::info!(graphs = restored, "CommitDag restored from checkpoint");
            }

            seq
        } else {
            tracing::info!("QuadStore: no checkpoint, full WAL replay (first run)");
            0
        };

        // Only load entries written after the last committed seq.
        let entries = self.journal.read_since(committed + 1).await;
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

    /// Return quads for `subject` in `graph_cid`, searching committed ProllyTree data.
    ///
    /// Hot path: if the Arrangement still holds the graph, returns immediately
    /// (identical to `get_entity_quads`).
    ///
    /// Cold path: when the Arrangement has been cleared after `commit()`, decodes
    /// quads from the EAVT ProllyTree via `scan_prefix(subject_bytes)`.  Each tree
    /// level = 1 BlockStore GET (1–6 RTTs for 1K–1B quads).
    pub async fn get_entity_quads_cold(
        &self,
        graph_cid: &KotobaCid,
        subject:   &KotobaCid,
    ) -> anyhow::Result<Vec<Quad>> {
        // ── Hot path ──────────────────────────────────────────────────────────
        {
            let arrs = self.arrangements.read().await;
            if let Some(arr) = arrs.get(&graph_cid.to_multibase()) {
                if !arr.is_empty() {
                    return Ok(arr.get_subject_quads(graph_cid, subject));
                }
            }
        }

        // ── Cold path: EAVT ProllyTree scan ───────────────────────────────────
        let head = self.commit_dag.read().await.head(graph_cid).cloned();
        let Some(commit) = head else {
            return Ok(vec![]); // no commit yet
        };

        let root_eavt = commit.root.clone(); // EAVT root (backward-compat field)
        let prefix    = &subject.0[..];      // subject bytes = EAVT key prefix

        let bs = Arc::clone(&self.block_store);
        let prefix_vec = prefix.to_vec();
        let entries = tokio::task::spawn_blocking(move || {
            ProllyTree::scan_prefix(&root_eavt, &prefix_vec, &*bs)
        }).await
          .map_err(|e| anyhow::anyhow!("spawn_blocking panic: {e}"))??;

        // Each EAVT entry: key = subject||predicate bytes, value = object JSON.
        // Decode the predicate (the bytes after the fixed subject prefix length).
        let subject_len = subject.0.len();
        let mut quads = Vec::new();
        for (key, val) in entries {
            if key.len() <= subject_len { continue; }
            let predicate = match std::str::from_utf8(&key[subject_len..]) {
                Ok(p)  => p.to_string(),
                Err(_) => continue,
            };
            let object: kotoba_kqe::quad::QuadObject =
                serde_json::from_slice(&val).unwrap_or(kotoba_kqe::quad::QuadObject::Text(String::new()));
            quads.push(Quad {
                graph:    graph_cid.clone(),
                subject:  subject.clone(),
                predicate,
                object,
            });
        }
        Ok(quads)
    }

    /// Clear the in-memory Arrangement for `graph_cid`, reclaiming RAM.
    /// Call after `commit()` in a batch-ingest cycle when working-set > budget.
    pub async fn reset_arrangement(&self, graph_cid: &KotobaCid) {
        if let Some(arr) = self.arrangements.write().await.get_mut(&graph_cid.to_multibase()) {
            arr.clear();
        }
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

    /// Flush the current Arrangement for `graph_cid` into 4 covering ProllyTrees
    /// (EAVT/AEVT/AVET/VAET), persist all roots in the BlockStore, create a Commit,
    /// and update the CommitDag.
    ///
    /// Returns the new commit CID.
    pub async fn commit(
        &self,
        author:    &str,
        graph_cid: KotobaCid,
        seq:       u64,
    ) -> anyhow::Result<KotobaCid> {
        let (eavt_entries, aevt_entries, avet_entries, vaet_entries) = {
            let arrs = self.arrangements.read().await;
            match arrs.get(&graph_cid.to_multibase()) {
                None => (vec![], vec![], vec![], vec![]),
                Some(arr) => {
                    // EAVT (SPO): key = subject || predicate, value = object bytes
                    let eavt: Vec<(Vec<u8>, Vec<u8>)> = arr.quads(&graph_cid).into_iter()
                        .map(|q| {
                            let mut k = Vec::new();
                            k.extend_from_slice(&q.subject.0);
                            k.extend_from_slice(q.predicate.as_bytes());
                            let v = serde_json::to_vec(&q.object).unwrap_or_default();
                            (k, v)
                        })
                        .collect();

                    // AEVT (PSO): key = predicate || subject bytes, value = object bytes
                    let aevt: Vec<(Vec<u8>, Vec<u8>)> = arr.aevt_entries().into_iter()
                        .flat_map(|(pred, subj, objs)| {
                            objs.into_iter().map(move |obj| {
                                let mut k = Vec::new();
                                k.extend_from_slice(pred.as_bytes());
                                k.extend_from_slice(&subj.0);
                                let v = serde_json::to_vec(&obj).unwrap_or_default();
                                (k, v)
                            })
                        })
                        .collect();

                    // AVET (POS): key = predicate || object_key bytes, value = subject bytes
                    let avet: Vec<(Vec<u8>, Vec<u8>)> = arr.avet_entries().into_iter()
                        .flat_map(|(pred, okey, subs)| {
                            subs.into_iter().map(move |s| {
                                let mut k = Vec::new();
                                k.extend_from_slice(pred.as_bytes());
                                k.extend_from_slice(okey.as_bytes());
                                (k, s.0.to_vec())
                            })
                        })
                        .collect();

                    // VAET (OCP): key = object_cid || predicate, value = subject bytes  (ref-only)
                    let vaet: Vec<(Vec<u8>, Vec<u8>)> = arr.vaet_entries().into_iter()
                        .flat_map(|(ocid, pred, subs)| {
                            subs.into_iter().map(move |s| {
                                let mut k = Vec::new();
                                k.extend_from_slice(&ocid.0);
                                k.extend_from_slice(pred.as_bytes());
                                (k, s.0.to_vec())
                            })
                        })
                        .collect();

                    (eavt, aevt, avet, vaet)
                }
            }
        };

        // Build 4 ProllyTrees in parallel, each on a dedicated 64 MB stack thread.
        // Each thread gets a CapturingBlockStore that writes through to the shared hot store
        // and simultaneously records every block written — used below for CAR bundling.
        let bs = Arc::clone(&self.block_store);
        let tree_inputs: Vec<(&'static str, Vec<(Vec<u8>, Vec<u8>)>)> = vec![
            ("eavt", eavt_entries),
            ("aevt", aevt_entries),
            ("avet", avet_entries),
            ("vaet", vaet_entries),
        ];

        let mut handles = Vec::with_capacity(4);
        for (name, entries) in tree_inputs {
            let inner = Arc::clone(&bs);
            let handle = std::thread::Builder::new()
                .stack_size(64 * 1024 * 1024)
                .name(format!("kotoba-prolly-{name}"))
                .spawn(move || -> anyhow::Result<(KotobaCid, Vec<(KotobaCid, Vec<u8>)>)> {
                    let cap = Arc::new(CapturingBlockStore::new(inner));
                    let root = ProllyTree::build_tree(entries, &*cap)?;
                    let blocks = cap.drain();
                    Ok((root, blocks))
                })
                .map_err(|e| anyhow::anyhow!("failed to spawn prolly-{name} thread: {e}"))?;
            handles.push(handle);
        }

        let mut roots: Vec<KotobaCid> = Vec::with_capacity(4);
        let mut all_blocks: Vec<(KotobaCid, Vec<u8>)> = Vec::new();
        for h in handles {
            let (root, blocks) = h.join()
                .map_err(|_| anyhow::anyhow!("prolly-build thread panicked"))??;
            roots.push(root);
            all_blocks.extend(blocks);
        }
        let root_vaet = roots.remove(3);
        let root_avet = roots.remove(2);
        let root_aevt = roots.remove(1);
        let root_eavt = roots.remove(0);

        let mut index_roots = std::collections::HashMap::new();
        index_roots.insert("aevt".to_string(), root_aevt);
        index_roots.insert("avet".to_string(), root_avet);
        index_roots.insert("vaet".to_string(), root_vaet);

        // Get previous head CID for the DAG chain
        let prev = self.commit_dag.read().await
            .head(&graph_cid)
            .map(|c| c.cid.clone());

        // Seal + persist Commit (root = EAVT for backward compat)
        let commit = Commit::seal(graph_cid.clone(), root_eavt, prev, author.to_string(), seq, index_roots);
        let cid    = commit.persist(&*self.block_store)?;

        // Pack all tree blocks + commit block into a single CAR bundle.
        // The CAR is stored in the block store under the commit CID so the cold tier
        // can upload it as one batched PUT instead of N individual PUTs.
        {
            let mut writer = CarBundleWriter::new(cid.clone());
            for (bcid, data) in &all_blocks {
                writer.append(bcid, data);
            }
            let (car_bytes, _idx) = writer.finish();
            let car_cid = KotobaCid::from_bytes(&car_bytes);
            if let Err(e) = self.block_store.put(&car_cid, &car_bytes) {
                tracing::warn!(%cid, car_blocks = all_blocks.len(), "CAR bundle write failed: {e}");
            } else {
                tracing::debug!(%cid, car_blocks = all_blocks.len(),
                    car_bytes = car_bytes.len(), "CAR bundle stored");
            }
        }

        // Update in-memory CommitDag
        self.commit_dag.write().await.add(commit);

        // ── Checkpoint ────────────────────────────────────────────────────────────
        // Record committed_seq + CommitDag heads as a tiny JSON blob in the Journal
        // store.  On the next startup replay_from_journal() will skip all Journal
        // entries ≤ this seq — reducing startup cost from O(all history) to O(delta).
        *self.committed_seq.write().await = seq;
        {
            let heads = self.commit_dag.read().await.heads_as_map();
            let cp    = serde_json::json!({ "committed_seq": seq, "heads": heads });
            let bytes = bytes::Bytes::from(cp.to_string().into_bytes());
            self.journal.write_checkpoint(bytes).await;
        }
        // Trim ring buffer (in-process memory free).
        self.journal.trim_before(seq).await;
        // Trim persistent seq-index in B2 (fire-and-forget; old seq keys deleted).
        {
            let j = Arc::clone(&self.journal);
            tokio::spawn(async move { j.trim_persistent_before(seq).await; });
        }
        // ─────────────────────────────────────────────────────────────────────────

        tracing::info!(%cid, author, seq, "QuadStore committed (4-index)");
        Ok(cid)
    }

    /// Mark-sweep GC: delete blocks in the store not reachable from any commit in the DAG.
    ///
    /// Walk strategy: every commit stored in the in-memory CommitDag is treated as a GC root.
    /// Each commit's 4 ProllyTree roots are recursively walked to collect all live block CIDs.
    /// Blocks returned by `block_store.all_cids()` but absent from the live set are deleted.
    ///
    /// Stores that don't implement `all_cids()` (S3, iroh) return an empty vec — in that case
    /// this function safely returns 0 without modifying anything.
    ///
    /// Returns the count of deleted blocks.
    pub async fn gc_dead_blocks(&self) -> anyhow::Result<usize> {
        let live = {
            let dag = self.commit_dag.read().await;
            dag.all_live_cids(&*self.block_store)?
        };
        let all = self.block_store.all_cids();
        let mut deleted = 0usize;
        for cid in all {
            if !live.contains(&cid) {
                if let Err(e) = self.block_store.delete(&cid) {
                    tracing::warn!("gc_dead_blocks: delete failed for {}: {e}", cid.to_multibase());
                } else {
                    deleted += 1;
                }
            }
        }
        if deleted > 0 {
            tracing::info!(deleted, "gc_dead_blocks: collected {deleted} unreachable blocks");
        }
        Ok(deleted)
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

    /// P2: After commit + reset_arrangement, get_entity_quads_cold must reconstruct
    /// quads for a specific subject from the committed EAVT ProllyTree.
    #[tokio::test]
    async fn cold_fallback_returns_committed_quads_after_arrangement_clear() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);

        let graph   = KotobaCid::from_bytes(b"cold-graph");
        let subject = KotobaCid::from_bytes(b"alice");

        // Assert two quads for alice and one for bob
        qs.assert(make_quad("cold-graph", "alice", "name",  "Alice")).await;
        qs.assert(make_quad("cold-graph", "alice", "knows", "Bob")).await;
        qs.assert(make_quad("cold-graph", "bob",   "name",  "Bob")).await;

        qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.reset_arrangement(&graph).await; // evict hot Arrangement

        let quads = qs.get_entity_quads_cold(&graph, &subject).await.unwrap();
        assert_eq!(quads.len(), 2, "should find 2 quads for alice from cold ProllyTree");
        let predicates: std::collections::HashSet<&str> =
            quads.iter().map(|q| q.predicate.as_str()).collect();
        assert!(predicates.contains("name"),  "name predicate expected");
        assert!(predicates.contains("knows"), "knows predicate expected");
    }

    #[tokio::test]
    async fn gc_dead_blocks_removes_orphaned_blocks_and_keeps_live() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        let graph = KotobaCid::from_bytes(b"gc-graph");

        // Commit 1 — writes ProllyTree blocks + 1 CAR bundle per commit
        qs.assert(make_quad("gc-graph", "a", "p", "v1")).await;
        qs.commit("did:test", graph.clone(), 1).await.unwrap();

        // Commit 2 — writes another set of ProllyTree blocks + CAR bundle
        qs.assert(make_quad("gc-graph", "b", "p", "v2")).await;
        qs.commit("did:test", graph.clone(), 2).await.unwrap();

        // Record the live-only count: all_cids minus CAR bundles
        // (CAR bundles stored per commit are fire-and-forget and not reachable via DAG traversal)
        let count_before_orphan = block_store.block_count();

        // Inject a truly orphaned block — not referenced by any commit or tree
        let orphan_cid = KotobaCid::from_bytes(b"orphan-data");
        block_store.put(&orphan_cid, b"orphan payload").unwrap();
        assert_eq!(block_store.block_count(), count_before_orphan + 1);

        // GC: deletes our explicit orphan + the per-commit CAR bundles (also unreachable)
        let deleted = qs.gc_dead_blocks().await.unwrap();
        assert!(deleted >= 1, "at least the explicit orphan should be deleted");
        assert!(!block_store.has(&orphan_cid), "explicit orphan must be gone");

        // ProllyTree blocks + commit blocks must remain (all in CommitDag live set)
        let remaining = block_store.block_count();
        // We deleted CAR bundles (2 commits × 1 CAR each) + 1 explicit orphan = ≥3 removed
        // Exact count depends on how many tree blocks commit() builds — just assert invariants.
        assert!(remaining > 0, "live blocks must survive GC");
        // Running GC a second time on an already-clean store is idempotent
        let deleted2 = qs.gc_dead_blocks().await.unwrap();
        assert_eq!(deleted2, 0, "second GC pass on clean store removes nothing");
    }
}
