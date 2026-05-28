use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;

/// `(label, kv-pairs)` input for one ProllyTree build thread.
type TreeInput = (&'static str, Vec<(Vec<u8>, Vec<u8>)>);
/// Result from one ProllyTree build thread: `(root_cid, captured_blocks)`.
type TreeResult = anyhow::Result<(KotobaCid, Vec<(KotobaCid, Vec<u8>)>)>;
use kotoba_core::prolly::ProllyTree;
use kotoba_store::{CapturingBlockStore, CarBundleWriter};
use kotoba_kqe::quad::Quad;
use kotoba_kqe::delta::Delta;
use kotoba_kqe::arrangement::Arrangement;
use kotoba_kqe::datalog::DatalogProgram;
use kotoba_kse::journal::Journal;
use kotoba_kse::topic::Topic;
use kotoba_auth::delegation::{DelegationChain, DelegationError};
use std::sync::Arc;
use tokio::sync::RwLock;
use dashmap::DashMap;

use crate::commit::{Commit, CommitDag};

/// Error returned when a CACAO-gated quad operation fails.
#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error("delegation: {0}")]
    Delegation(#[from] DelegationError),
    #[error("internal: {0}")]
    Internal(String),
}

/// QuadStore — Quad write/read API with 3-index Journal publish + ProllyTree commit
pub struct QuadStore {
    journal:       Arc<Journal>,
    block_store:   Arc<dyn BlockStore + Send + Sync>,
    arrangements:  Arc<DashMap<String, Arrangement>>, // graph_cid → Arrangement
    commit_dag:    Arc<RwLock<CommitDag>>,
    /// seq of the last successful commit — persisted as a checkpoint in the Journal store.
    /// On startup this is loaded from the checkpoint before Journal replay so that
    /// `replay_from_journal` only processes entries written *after* the last commit,
    /// not the full WAL history.
    committed_seq: Arc<RwLock<u64>>,
    /// Per-graph flag: `true` iff the hot arrangement is a SUPERSET of the committed
    /// cold ProllyTree (or there is no committed state).  In that case, query paths
    /// may short-circuit and return from hot alone.  Set to `false` after WAL replay
    /// of post-checkpoint entries — replay only restores uncommitted quads into hot,
    /// so the committed cold state is no longer fully reflected in hot.
    hot_covers_all: Arc<DashMap<String, bool>>,
}

impl QuadStore {
    pub fn new(journal: Arc<Journal>, block_store: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self {
            journal,
            block_store,
            arrangements:  Arc::new(DashMap::new()),
            commit_dag:    Arc::new(RwLock::new(CommitDag::new())),
            committed_seq: Arc::new(RwLock::new(0)),
            hot_covers_all: Arc::new(DashMap::new()),
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
        self.arrangements.entry(g.clone()).or_insert_with(Arrangement::new).insert(&quad);
        // Normal write: hot remains a superset of (committed ∪ pending uncommitted).
        self.hot_covers_all.entry(g).or_insert(true);
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

    /// CACAO-gated batch insert.
    ///
    /// Verifies that `chain` grants `"quad:write"` on every **unique graph** CID present
    /// in `quads` before delegating to `assert_batch_silent`.  All quads across all named
    /// graphs in the batch are checked up front — the batch is rejected atomically if any
    /// graph scope fails.
    ///
    /// Typical use: actor writes a cluster of related quads (e.g. all attributes of one
    /// entity) in a single CACAO-authorized call without per-quad overhead.
    pub async fn assert_batch_authed(
        &self,
        quads: Vec<Quad>,
        chain: &DelegationChain,
    ) -> Result<usize, AccessError> {
        // Collect unique graph CIDs and verify authorization for each.
        let mut seen = std::collections::HashSet::new();
        for q in &quads {
            let g = q.graph.to_multibase();
            if seen.insert(g.clone()) {
                chain.verify(&g, "quad:write")?;
            }
        }
        let n = quads.len();
        self.assert_batch_silent(quads).await;
        Ok(n)
    }

    pub async fn retract(&self, quad: Quad) -> Delta {
        let g = quad.graph.to_multibase();
        self.arrangements.entry(g).or_insert_with(Arrangement::new).remove(&quad);
        Delta::retract(quad)
    }

    /// Assert without publishing to Journal — used during WAL replay on startup.
    ///
    /// Marks the graph's `hot_covers_all` flag as `false` because replay only
    /// loads post-checkpoint (uncommitted) quads into the arrangement; the
    /// committed cold ProllyTree state is NOT reflected in hot any more.
    pub async fn assert_silent(&self, quad: Quad) {
        let g = quad.graph.to_multibase();
        self.arrangements.entry(g.clone()).or_insert_with(Arrangement::new).insert(&quad);
        // Hot is now a strict subset of (committed ∪ uncommitted) — cold must also be consulted.
        self.hot_covers_all.insert(g, false);
    }

    /// Insert a batch of quads — fast path for bulk ingest.
    /// Does not publish to Journal.
    pub async fn assert_batch_silent(&self, quads: Vec<Quad>) {
        if quads.is_empty() { return; }
        for quad in &quads {
            let g = quad.graph.to_multibase();
            self.arrangements.entry(g).or_insert_with(Arrangement::new).insert(quad);
        }
    }

    /// Retract without publishing to Journal — used during WAL replay on startup.
    pub async fn retract_silent(&self, quad: Quad) {
        let g = quad.graph.to_multibase();
        self.arrangements.entry(g).or_insert_with(Arrangement::new).remove(&quad);
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
        self.arrangements.get(&graph_cid.to_multibase()).map(|r| r.clone())
    }

    /// Return all known graph CIDs — union of committed (CommitDag) and in-memory (Arrangements).
    pub async fn all_graph_cids(&self) -> Vec<KotobaCid> {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut cids: Vec<KotobaCid> = Vec::new();
        for r in self.arrangements.iter() {
            if seen.insert(r.key().clone()) {
                if let Some(cid) = KotobaCid::from_multibase(r.key()) {
                    cids.push(cid);
                }
            }
        }
        for c in self.commit_dag.read().await.graph_cids() {
            let mb = c.to_multibase();
            if seen.insert(mb) {
                cids.push(c);
            }
        }
        cids
    }

    /// Return all Quads whose subject matches `subject`, optionally restricted to `graph_cid`.
    /// When `graph_cid` is None, scans every named graph in memory.
    pub async fn get_entity_quads(
        &self,
        graph_cid: Option<&KotobaCid>,
        subject: &KotobaCid,
    ) -> Vec<Quad> {
        if let Some(gcid) = graph_cid {
            return self.arrangements.get(&gcid.to_multibase())
                .map(|arr| arr.get_subject_quads(gcid, subject))
                .unwrap_or_default();
        }
        let mut out = vec![];
        for entry in self.arrangements.iter() {
            let g_mb = entry.key();
            let arr = entry.value();
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
        if let Some(gcid) = graph_cid {
            return self.arrangements.get(&gcid.to_multibase())
                .map(|arr| arr.quads_with_predicate_prefix(gcid, prefix))
                .unwrap_or_default();
        }
        let mut out = vec![];
        for entry in self.arrangements.iter() {
            let g_mb = entry.key();
            let arr = entry.value();
            let gcid = KotobaCid::from_multibase(g_mb)
                .unwrap_or_else(|| KotobaCid::from_bytes(g_mb.as_bytes()));
            out.extend(arr.quads_with_predicate_prefix(&gcid, prefix));
        }
        out
    }

    /// Snapshot all quads in the named graph as Assert Deltas (Datalog seed).
    pub async fn snapshot_deltas(&self, graph_cid: &KotobaCid) -> Vec<Delta> {
        self.arrangements.get(&graph_cid.to_multibase())
            .map(|arr| arr.to_deltas(graph_cid))
            .unwrap_or_default()
    }

    /// Count quads whose predicate starts with `prefix` within the named graph.
    pub async fn count_by_predicate_prefix(&self, graph_cid: &KotobaCid, prefix: &str) -> usize {
        self.arrangements.get(&graph_cid.to_multibase())
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
        if let Some(gcid) = graph_cid {
            return self.arrangements.get(&gcid.to_multibase())
                .map(|arr| arr.get_subjects_by_predicate_object(predicate, object_key))
                .unwrap_or_default();
        }
        let mut out = vec![];
        for entry in self.arrangements.iter() {
            out.extend(entry.value().get_subjects_by_predicate_object(predicate, object_key));
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
        // ── Hot path (only when hot is known to cover all committed state) ────
        {
            let key = graph_cid.to_multibase();
            if let Some(arr) = self.arrangements.get(&key) {
                let covers_all = self.hot_covers_all.get(&key)
                    .map(|v| *v).unwrap_or(true);
                if !arr.is_empty() && covers_all {
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

        // ── Union with hot (when hot is a partial view, e.g. post-replay) ────
        // If hot has uncommitted writes for this subject, merge them in.  Use
        // (predicate, object) as the dedupe key — committed and hot can
        // describe the same fact through different write paths.
        if let Some(arr) = self.arrangements.get(&graph_cid.to_multibase()) {
            if !arr.is_empty() {
                let hot_quads = arr.get_subject_quads(graph_cid, subject);
                let mut seen: std::collections::HashSet<(String, Vec<u8>)> = quads.iter()
                    .map(|q| (q.predicate.clone(), serde_json::to_vec(&q.object).unwrap_or_default()))
                    .collect();
                for hq in hot_quads {
                    let key = (hq.predicate.clone(), serde_json::to_vec(&hq.object).unwrap_or_default());
                    if seen.insert(key) {
                        quads.push(hq);
                    }
                }
            }
        }
        Ok(quads)
    }

    /// Cold-path AEVT scan: fetch quads by predicate prefix from the committed ProllyTree.
    pub async fn quads_by_predicate_prefix_cold(
        &self,
        graph_cid:        &KotobaCid,
        predicate_prefix: &str,
    ) -> anyhow::Result<Vec<Quad>> {
        // ── Hot path (only when hot is known to cover all committed state) ────
        {
            let key = graph_cid.to_multibase();
            if let Some(arr) = self.arrangements.get(&key) {
                let covers_all = self.hot_covers_all.get(&key).map(|v| *v).unwrap_or(true);
                if !arr.is_empty() && covers_all {
                    return Ok(arr.quads_with_predicate_prefix(graph_cid, predicate_prefix));
                }
            }
        }

        // ── Cold path: AEVT ProllyTree scan ───────────────────────────────────
        let head = self.commit_dag.read().await.head(graph_cid).cloned();
        let Some(commit) = head else { return Ok(vec![]); };

        let root_aevt = match commit.index_roots.get("aevt") {
            Some(r) => r.clone(),
            None    => return Ok(vec![]), // pre-index-roots commit
        };

        let bs         = Arc::clone(&self.block_store);
        let prefix_vec = predicate_prefix.as_bytes().to_vec();
        let entries    = tokio::task::spawn_blocking(move || {
            ProllyTree::scan_prefix(&root_aevt, &prefix_vec, &*bs)
        }).await
          .map_err(|e| anyhow::anyhow!("spawn_blocking panic: {e}"))??;

        // AEVT key = predicate_bytes || subject_bytes[36]; val = object JSON
        const CID_LEN: usize = 36;
        let mut quads = Vec::new();
        for (key, val) in entries {
            if key.len() <= CID_LEN { continue; }
            let predicate = match std::str::from_utf8(&key[..key.len() - CID_LEN]) {
                Ok(p)  => p.to_string(),
                Err(_) => continue,
            };
            let subj_arr: [u8; 36] = match key[key.len() - CID_LEN..].try_into() {
                Ok(b)  => b,
                Err(_) => continue,
            };
            let object: kotoba_kqe::quad::QuadObject =
                serde_json::from_slice(&val).unwrap_or(kotoba_kqe::quad::QuadObject::Text(String::new()));
            quads.push(Quad {
                graph:    graph_cid.clone(),
                subject:  KotobaCid(subj_arr),
                predicate,
                object,
            });
        }

        // Union with hot (when hot is a partial post-replay view)
        if let Some(arr) = self.arrangements.get(&graph_cid.to_multibase()) {
            if !arr.is_empty() {
                let hot = arr.quads_with_predicate_prefix(graph_cid, predicate_prefix);
                let mut seen: std::collections::HashSet<(KotobaCid, String, Vec<u8>)> = quads.iter()
                    .map(|q| (q.subject.clone(), q.predicate.clone(),
                        serde_json::to_vec(&q.object).unwrap_or_default()))
                    .collect();
                for hq in hot {
                    let k = (hq.subject.clone(), hq.predicate.clone(),
                        serde_json::to_vec(&hq.object).unwrap_or_default());
                    if seen.insert(k) { quads.push(hq); }
                }
            }
        }
        Ok(quads)
    }

    /// Cold-path AVET scan: resolve subjects by predicate + object_key from the committed ProllyTree.
    pub async fn lookup_subject_by_po_cold(
        &self,
        graph_cid:  &KotobaCid,
        predicate:  &str,
        object_key: &str,
    ) -> anyhow::Result<Vec<KotobaCid>> {
        // ── Hot path (only when hot covers all committed state) ───────────────
        {
            let key = graph_cid.to_multibase();
            if let Some(arr) = self.arrangements.get(&key) {
                let covers_all = self.hot_covers_all.get(&key).map(|v| *v).unwrap_or(true);
                if !arr.is_empty() && covers_all {
                    return Ok(arr.get_subjects_by_predicate_object(predicate, object_key));
                }
            }
        }

        // ── Cold path: AVET ProllyTree scan ───────────────────────────────────
        let head = self.commit_dag.read().await.head(graph_cid).cloned();
        let Some(commit) = head else { return Ok(vec![]); };

        let root_avet = match commit.index_roots.get("avet") {
            Some(r) => r.clone(),
            None    => return Ok(vec![]),
        };

        let bs = Arc::clone(&self.block_store);
        let mut prefix_vec = predicate.as_bytes().to_vec();
        prefix_vec.extend_from_slice(object_key.as_bytes());

        let entries = tokio::task::spawn_blocking(move || {
            ProllyTree::scan_prefix(&root_avet, &prefix_vec, &*bs)
        }).await
          .map_err(|e| anyhow::anyhow!("spawn_blocking panic: {e}"))??;

        // AVET val = subject_bytes[36]
        const CID_LEN: usize = 36;
        let mut subjects = Vec::new();
        for (_key, val) in entries {
            if val.len() < CID_LEN { continue; }
            let subj_arr: [u8; 36] = match val[..CID_LEN].try_into() {
                Ok(b)  => b,
                Err(_) => continue,
            };
            subjects.push(KotobaCid(subj_arr));
        }

        // Union with hot (post-replay partial view)
        if let Some(arr) = self.arrangements.get(&graph_cid.to_multibase()) {
            if !arr.is_empty() {
                let hot = arr.get_subjects_by_predicate_object(predicate, object_key);
                let mut seen: std::collections::HashSet<KotobaCid> = subjects.iter().cloned().collect();
                for s in hot {
                    if seen.insert(s.clone()) { subjects.push(s); }
                }
            }
        }
        Ok(subjects)
    }

    /// Cold-path VAET scan: resolve (predicate, subject) pairs for a given object CID.
    pub async fn reverse_lookup_cold(
        &self,
        graph_cid:  &KotobaCid,
        object_cid: &KotobaCid,
    ) -> anyhow::Result<Vec<(String, KotobaCid)>> {
        // ── Hot path ──────────────────────────────────────────────────────────
        {
            if let Some(arr) = self.arrangements.get(&graph_cid.to_multibase()) {
                if !arr.is_empty() {
                    let results = arr.vaet_entries()
                        .into_iter()
                        .filter(|(ocid, _, _)| ocid == object_cid)
                        .flat_map(|(_, pred, subjects)| {
                            subjects.into_iter().map(move |s| (pred.clone(), s))
                        })
                        .collect();
                    return Ok(results);
                }
            }
        }

        // ── Cold path: VAET ProllyTree scan ───────────────────────────────────
        let head = self.commit_dag.read().await.head(graph_cid).cloned();
        let Some(commit) = head else { return Ok(vec![]); };

        let root_vaet = match commit.index_roots.get("vaet") {
            Some(r) => r.clone(),
            None    => return Ok(vec![]),
        };

        let bs         = Arc::clone(&self.block_store);
        let prefix_vec = object_cid.0.to_vec();

        let entries = tokio::task::spawn_blocking(move || {
            ProllyTree::scan_prefix(&root_vaet, &prefix_vec, &*bs)
        }).await
          .map_err(|e| anyhow::anyhow!("spawn_blocking panic: {e}"))??;

        // VAET key = object_cid_bytes[36] || predicate_bytes; val = subject_bytes[36]
        const CID_LEN: usize = 36;
        let mut results = Vec::new();
        for (key, val) in entries {
            if key.len() <= CID_LEN || val.len() < CID_LEN { continue; }
            let predicate = match std::str::from_utf8(&key[CID_LEN..]) {
                Ok(p)  => p.to_string(),
                Err(_) => continue,
            };
            let subj_arr: [u8; 36] = match val[..CID_LEN].try_into() {
                Ok(b)  => b,
                Err(_) => continue,
            };
            results.push((predicate, KotobaCid(subj_arr)));
        }
        Ok(results)
    }

    // ── Complex / compound cold-path queries ──────────────────────────────────

    /// Multi-hop BFS traversal following `QuadObject::Cid` references.
    ///
    /// Starting from `start`, resolves up to `max_hops` hops of object-CID
    /// references across the committed ProllyTree (EAVT cold path per hop).
    /// Returns `(depth, quad)` pairs in BFS order; depth 0 = quads of `start`.
    ///
    /// Hot path: used when the Arrangement is non-empty (µs).
    /// Cold path: one `get_entity_quads_cold` call per frontier node.
    pub async fn multi_hop_cold(
        &self,
        graph_cid: &KotobaCid,
        start:     &KotobaCid,
        max_hops:  usize,
    ) -> anyhow::Result<Vec<(usize, Quad)>> {
        let mut result: Vec<(usize, Quad)> = Vec::new();
        let mut frontier = vec![start.clone()];
        let mut visited  = std::collections::HashSet::new();
        visited.insert(start.clone());

        for depth in 0..=max_hops {
            if frontier.is_empty() { break; }
            let mut next_frontier: Vec<KotobaCid> = Vec::new();
            for node in &frontier {
                let quads = self.get_entity_quads_cold(graph_cid, node).await?;
                for q in quads {
                    if let kotoba_kqe::quad::QuadObject::Cid(ref ref_cid) = q.object {
                        if depth < max_hops && visited.insert(ref_cid.clone()) {
                            next_frontier.push(ref_cid.clone());
                        }
                    }
                    result.push((depth, q));
                }
            }
            frontier = next_frontier;
        }
        Ok(result)
    }

    /// AVET×AVET intersection: subjects where `pred1 = val1` AND `pred2 = val2`.
    ///
    /// Hot path: two `get_subjects_by_predicate_object` calls + HashSet intersection.
    /// Cold path: two `lookup_subject_by_po_cold` calls + intersection.
    pub async fn join_by_two_predicates_cold(
        &self,
        graph_cid: &KotobaCid,
        pred1: &str, val1: &str,
        pred2: &str, val2: &str,
    ) -> anyhow::Result<Vec<KotobaCid>> {
        let set1: std::collections::HashSet<[u8; 36]> = self
            .lookup_subject_by_po_cold(graph_cid, pred1, val1).await?
            .into_iter().map(|c| c.0).collect();
        if set1.is_empty() { return Ok(vec![]); }

        let set2 = self.lookup_subject_by_po_cold(graph_cid, pred2, val2).await?;
        Ok(set2.into_iter().filter(|c| set1.contains(&c.0)).collect())
    }

    // ── SPARQL BGP → cold-path router ────────────────────────────────────────

    /// Route a SPARQL SELECT BGP to the optimal cold-path index.
    ///
    /// Supported single-triple patterns (WHERE clause):
    /// - Bound subject IRI `cid:{multibase}` → EAVT (`get_entity_quads_cold`)
    /// - Bound predicate + literal object → AVET (`lookup_subject_by_po_cold`)
    /// - Bound predicate only → AEVT (`quads_by_predicate_prefix_cold`)
    /// - Bound object IRI `cid:{multibase}` → VAET (`reverse_lookup_cold`)
    ///
    /// Two-triple patterns where both share `?s` + each has bound pred+literal:
    /// → join (`join_by_two_predicates_cold`)
    ///
    /// Object IRIs that start with `cid:` are decoded via `KotobaCid::from_multibase`.
    /// Returns synthetic `Quad` values for AVET/VAET results (pred and object known).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let quads = qs.cold_query_sparql_bgp(
    ///     &graph,
    ///     r#"SELECT * WHERE { ?s <role> "admin" }"#,
    /// ).await?;
    /// ```
    /// CID-addressed materialised view of a SPARQL query result.
    ///
    /// Computes a deterministic projector CID from
    /// `("kotoba-mv:v1", commit_cid_for_graph, query_form, normalised_sparql)`,
    /// looks it up in the BlockStore, and:
    ///   - hit  → deserialise and return cached `Vec<Quad>` (≈ µs, no compute)
    ///   - miss → run query, serialise result via dag-cbor, `put` under the
    ///            computed CID, return live result
    ///
    /// This turns repeated identical queries against a sealed graph commit into
    /// content-addressed lookups — the same query against the same commit
    /// always yields the same result, so the answer has a deterministic CID.
    ///
    /// Cache invalidation is automatic: a new commit yields a new graph commit
    /// CID, which produces a new MV CID — the old MV remains addressable but
    /// is no longer consulted by callers using the new graph state.
    pub async fn cold_query_sparql_bgp_cached(
        &self,
        graph_cid: &KotobaCid,
        sparql:    &str,
    ) -> anyhow::Result<(Vec<Quad>, KotobaCid, bool /* cache_hit */)> {
        // Resolve the latest commit CID for this graph (for cache-key freshness).
        let commit_cid = {
            let dag = self.commit_dag.read().await;
            dag.head(graph_cid).map(|c| c.cid.clone()).unwrap_or_else(|| graph_cid.clone())
        };
        let key = format!(
            "kotoba-mv:v1\n{}\n{}\nSELECT-MV\n{}",
            commit_cid.to_multibase(),
            graph_cid.to_multibase(),
            sparql.trim(),
        );
        let mv_cid = KotobaCid::from_bytes(key.as_bytes());

        // Cache hit?
        if let Some(blob) = self.block_store.get(&mv_cid)? {
            if let Ok(quads) = ciborium::from_reader::<Vec<Quad>, _>(&blob[..]) {
                return Ok((quads, mv_cid, true));
            }
        }

        // Cache miss: run live query, materialise, persist
        let quads = self.cold_query_sparql_bgp(graph_cid, sparql).await?;
        let mut bytes = Vec::new();
        ciborium::into_writer(&quads, &mut bytes)
            .map_err(|e| anyhow::anyhow!("MV serialise: {e}"))?;
        self.block_store.put(&mv_cid, &bytes)?;
        Ok((quads, mv_cid, false))
    }

    /// Evaluate a Datalog program against the IPFS-backed cold graph state.
    ///
    /// Pipeline:
    ///   1. Load all committed quads for `graph_cid` via the cold AEVT scan
    ///      (`quads_by_predicate_prefix_cold("")`).  Each quad fetch ultimately
    ///      hits the configured BlockStore, which may be a DistributedBlockStore
    ///      fronting Kubo HTTP peers — so this is a fully network-capable read.
    ///   2. Union with the hot arrangement (for uncommitted assertions).
    ///   3. Convert each quad into a `Delta::assert` and hand to the semi-naive
    ///      Datalog engine.
    ///   4. Return all derived `Delta` outputs.
    ///
    /// This bridges the in-memory KQE Datalog engine to IPFS substrate: every
    /// query is served by the same content-addressed BlockStore as SPARQL.
    pub async fn evaluate_datalog_cold(
        &self,
        graph_cid: &KotobaCid,
        program:   &DatalogProgram,
    ) -> anyhow::Result<Vec<Delta>> {
        // 1. Load committed facts via cold AEVT (empty prefix scans everything).
        let mut quads = self.quads_by_predicate_prefix_cold(graph_cid, "").await?;

        // 2. Union with hot arrangement for uncommitted state.
        if let Some(arr) = self.arrangements.get(&graph_cid.to_multibase()) {
            if !arr.is_empty() {
                let key = graph_cid.to_multibase();
                let hot_covers = self.hot_covers_all.get(&key).map(|v| *v).unwrap_or(true);
                // Same dedupe strategy as get_entity_quads_cold: (s, p, o-bytes)
                let mut seen: std::collections::HashSet<(KotobaCid, String, Vec<u8>)> = quads.iter()
                    .map(|q| (q.subject.clone(), q.predicate.clone(),
                        serde_json::to_vec(&q.object).unwrap_or_default()))
                    .collect();
                for hq in arr.quads(graph_cid) {
                    let k = (hq.subject.clone(), hq.predicate.clone(),
                        serde_json::to_vec(&hq.object).unwrap_or_default());
                    if seen.insert(k) { quads.push(hq); }
                }
                // If hot covers all and cold was empty, the cold scan returned
                // hot quads via the predicate-prefix scan's hot-path branch —
                // dedupe handles that case as well.
                let _ = hot_covers;
            }
        }

        // 3. Quads → Deltas
        let deltas: Vec<Delta> = quads.into_iter().map(Delta::assert).collect();

        // 4. Evaluate
        Ok(program.evaluate_delta(&deltas))
    }

    /// CACAO-authed Datalog query over IPFS — requires `quad:read` on the graph.
    pub async fn evaluate_datalog_cold_authed(
        &self,
        graph_cid: &KotobaCid,
        program:   &DatalogProgram,
        chain:     &DelegationChain,
    ) -> Result<Vec<Delta>, AccessError> {
        chain.verify(&graph_cid.to_multibase(), "quad:read")?;
        self.evaluate_datalog_cold(graph_cid, program).await
            .map_err(|e| AccessError::Internal(e.to_string()))
    }

    pub async fn cold_query_sparql_bgp(
        &self,
        graph_cid: &KotobaCid,
        sparql:    &str,
    ) -> anyhow::Result<Vec<Quad>> {
        // Use a base IRI so relative IRIs like <role> resolve to "k:role".
        let query = spargebra::SparqlParser::new()
            .with_base_iri(SPARQL_BGP_BASE_IRI)
            .map_err(|e| anyhow::anyhow!("base IRI error: {e}"))?
            .parse_query(sparql)
            .map_err(|e| anyhow::anyhow!("SPARQL parse error: {e}"))?;

        let pattern = match query {
            spargebra::Query::Select { pattern, .. } => pattern,
            _ => anyhow::bail!("only SELECT queries are supported"),
        };

        // Unwrap Project / Distinct wrappers to expose the inner pattern.
        let inner = unwrap_bgp_pattern(pattern);
        self.execute_sparql_graph_pattern(graph_cid, &inner).await
    }

    /// SPARQL ASK query — returns `true` if the WHERE pattern matches at least one quad.
    ///
    /// ```text
    /// ASK { <cid:alice> <role> "admin" }   → true if Alice has role=admin
    /// ASK { <cid:eve>   <role> "admin" }   → false if Eve doesn't exist
    /// ```
    pub async fn sparql_ask(
        &self,
        graph_cid: &KotobaCid,
        sparql:    &str,
    ) -> anyhow::Result<bool> {
        let query = spargebra::SparqlParser::new()
            .with_base_iri(SPARQL_BGP_BASE_IRI)
            .map_err(|e| anyhow::anyhow!("base IRI error: {e}"))?
            .parse_query(sparql)
            .map_err(|e| anyhow::anyhow!("SPARQL parse error: {e}"))?;

        let pattern = match query {
            spargebra::Query::Ask { pattern, .. } => pattern,
            _ => anyhow::bail!("sparql_ask: only ASK queries supported"),
        };

        let inner = unwrap_bgp_pattern(pattern);
        let matched = self.execute_sparql_graph_pattern(graph_cid, &inner).await?;
        Ok(!matched.is_empty())
    }

    /// CACAO-gated SPARQL ASK.  Verifies `quad:read` before executing.
    pub async fn sparql_ask_authed(
        &self,
        graph_cid: &KotobaCid,
        sparql:    &str,
        chain:     &DelegationChain,
    ) -> Result<bool, AccessError> {
        chain.verify(&graph_cid.to_multibase(), "quad:read")?;
        self.sparql_ask(graph_cid, sparql).await
            .map_err(|e| AccessError::Internal(e.to_string()))
    }

    /// SPARQL CONSTRUCT query — materialises a triple template over WHERE results.
    ///
    /// ```text
    /// CONSTRUCT { ?s <label> ?name }
    /// WHERE     { ?s <name> ?name . ?s <role> "admin" }
    /// ```
    ///
    /// Returns quads in `graph_cid` constructed by substituting WHERE bindings
    /// (subject var → matched quad subject; object var → matched quad object)
    /// into each CONSTRUCT triple pattern.  Predicates must be named nodes.
    pub async fn sparql_construct(
        &self,
        graph_cid: &KotobaCid,
        sparql:    &str,
    ) -> anyhow::Result<Vec<Quad>> {
        let query = spargebra::SparqlParser::new()
            .with_base_iri(SPARQL_BGP_BASE_IRI)
            .map_err(|e| anyhow::anyhow!("base IRI error: {e}"))?
            .parse_query(sparql)
            .map_err(|e| anyhow::anyhow!("SPARQL parse error: {e}"))?;

        let (template, pattern) = match query {
            spargebra::Query::Construct { template, pattern, .. } => (template, pattern),
            _ => anyhow::bail!("sparql_construct: only CONSTRUCT queries supported"),
        };

        let inner = unwrap_bgp_pattern(pattern);
        let matched = self.execute_sparql_graph_pattern(graph_cid, &inner).await?;

        let mut result = Vec::new();
        for triple_pat in &template {
            for mq in &matched {
                if let Some(q) = instantiate_quad_pattern(
                    &triple_pat_to_quad_pattern(triple_pat, graph_cid),
                    graph_cid,
                    mq,
                ) {
                    result.push(q);
                }
            }
        }
        Ok(result)
    }

    /// SPARQL DESCRIBE — returns all quads for every entity matched by the query.
    ///
    /// Supports two forms:
    /// - `DESCRIBE <cid:…>` — explicit IRI list (no WHERE clause)
    /// - `DESCRIBE ?s WHERE { ?s <role> "admin" }` — variable bound by WHERE pattern
    ///
    /// All quads stored under each matched subject in `graph_cid` are returned.
    pub async fn sparql_describe(
        &self,
        graph_cid: &KotobaCid,
        sparql:    &str,
    ) -> anyhow::Result<Vec<Quad>> {
        // spargebra's Describe variant embeds everything in `pattern`;
        // we use string-level extraction for the DESCRIBE target list, then
        // spargebra for the optional WHERE clause.
        let sparql_up = sparql.to_uppercase();
        let desc_pos  = sparql_up.find("DESCRIBE")
            .ok_or_else(|| anyhow::anyhow!("DESCRIBE keyword missing"))?;
        let after_desc = &sparql[desc_pos + 8..].trim_start();

        // Extract resource IRIs/vars before the optional WHERE clause
        let where_pos = sparql_up[desc_pos + 8..].find("WHERE").map(|p| p + desc_pos + 8);
        let target_str = if let Some(wp) = where_pos {
            &sparql[desc_pos + 8..wp]
        } else {
            after_desc
        };

        let mut subjects: Vec<KotobaCid> = Vec::new();

        // Explicit IRIs: <cid:mb>
        for cap in target_str.split('<').skip(1) {
            if let Some(end) = cap.find('>') {
                let iri = cap[..end].trim();
                let s   = strip_bgp_base(iri);
                if let Some(cid) = parse_cid_iri(s) {
                    subjects.push(cid);
                }
            }
        }

        // WHERE clause variables: execute pattern, collect subject CIDs
        if let Some(wp) = where_pos {
            let where_clause = &sparql[wp..];
            // Build a SELECT * with the same WHERE body so spargebra can parse it
            let select_sparql = format!("SELECT * {where_clause}");
            let query = spargebra::SparqlParser::new()
                .with_base_iri(SPARQL_BGP_BASE_IRI)
                .map_err(|e| anyhow::anyhow!("base IRI error: {e}"))?
                .parse_query(&select_sparql)
                .map_err(|e| anyhow::anyhow!("SPARQL parse error: {e}"))?;
            let pattern = match query {
                spargebra::Query::Select { pattern, .. } => pattern,
                _ => anyhow::bail!("unexpected query form"),
            };
            let inner   = unwrap_bgp_pattern(pattern);
            let matched = self.execute_sparql_graph_pattern(graph_cid, &inner).await?;
            for q in matched {
                if !subjects.contains(&q.subject) {
                    subjects.push(q.subject);
                }
            }
        }

        // Fetch all quads for each subject
        let mut result = Vec::new();
        for subj in subjects {
            let quads = self.get_entity_quads_cold(graph_cid, &subj).await?;
            result.extend(quads);
        }
        Ok(result)
    }

    /// CACAO-authed DESCRIBE — requires `quad:read` capability.
    pub async fn sparql_describe_authed(
        &self,
        graph_cid: &KotobaCid,
        sparql:    &str,
        chain:     &DelegationChain,
    ) -> Result<Vec<Quad>, AccessError> {
        chain.verify(&graph_cid.to_multibase(), "quad:read")?;
        self.sparql_describe(graph_cid, sparql).await
            .map_err(|e| AccessError::Internal(e.to_string()))
    }

    /// N-hop DESCRIBE — traverse `QuadObject::Cid` references for up to `max_hops`
    /// and return all quads in the subgraph reachable from the seed entities.
    ///
    /// Semantics:
    ///   Hop 0 = entities matched by the DESCRIBE query (seeds).
    ///   Hop k+1 = every CID appearing as an object in hop-k quads, not yet visited.
    ///
    /// Returns the deduplicated union of all quads about visited entities.
    /// `max_hops = 0` is equivalent to a plain `sparql_describe`.
    ///
    /// Useful for distributed entity-profile fetching across content-addressed
    /// graphs — each hop loads only the blocks needed for the next layer.
    pub async fn sparql_describe_n_hop(
        &self,
        graph_cid: &KotobaCid,
        sparql:    &str,
        max_hops:  usize,
    ) -> anyhow::Result<Vec<Quad>> {
        use std::collections::HashSet;

        let seed_quads = self.sparql_describe(graph_cid, sparql).await?;
        let mut visited: HashSet<KotobaCid> = HashSet::new();
        let mut frontier: Vec<KotobaCid>   = Vec::new();
        let mut result:   Vec<Quad>        = Vec::new();

        for q in &seed_quads {
            if visited.insert(q.subject.clone()) {
                frontier.push(q.subject.clone());
            }
        }
        result.extend(seed_quads);

        for _hop in 0..max_hops {
            let mut next: Vec<KotobaCid> = Vec::new();
            for q in &result {
                if let kotoba_kqe::quad::QuadObject::Cid(ref c) = q.object {
                    if visited.insert(c.clone()) {
                        next.push(c.clone());
                    }
                }
            }
            if next.is_empty() { break; }
            // Parallel per-subject fetch — each get_entity_quads_cold reads from
            // BlockStore (potentially network-bound via DistributedBlockStore).
            // Concurrent fetches drastically reduce wall time for wide hops.
            let fetches = next.iter().map(|subj| {
                let s = subj.clone();
                let g = graph_cid.clone();
                async move { self.get_entity_quads_cold(&g, &s).await }
            });
            let batches = futures::future::try_join_all(fetches).await?;
            for batch in batches {
                result.extend(batch);
            }
            frontier = next;
            let _ = &frontier;
        }
        Ok(result)
    }

    /// CACAO-authed N-hop DESCRIBE — requires `quad:read` capability on the graph.
    pub async fn sparql_describe_n_hop_authed(
        &self,
        graph_cid: &KotobaCid,
        sparql:    &str,
        max_hops:  usize,
        chain:     &DelegationChain,
    ) -> Result<Vec<Quad>, AccessError> {
        chain.verify(&graph_cid.to_multibase(), "quad:read")?;
        self.sparql_describe_n_hop(graph_cid, sparql, max_hops).await
            .map_err(|e| AccessError::Internal(e.to_string()))
    }

    /// Recursive SPARQL pattern executor.
    ///
    /// Handles: BGP, Filter, Union, LeftJoin (OPTIONAL).
    /// Multi-triple BGPs are dispatched to the 4-index cold-path router.
    async fn execute_sparql_graph_pattern(
        &self,
        graph_cid: &KotobaCid,
        pattern:   &spargebra::algebra::GraphPattern,
    ) -> anyhow::Result<Vec<Quad>> {
        use spargebra::algebra::GraphPattern;

        match pattern {
            // ── Plain BGP ───────────────────────────────────────────────────────
            GraphPattern::Bgp { patterns: triples } => {
                self.route_bgp_triples(graph_cid, triples).await
            }

            // ── FILTER { inner WHERE expr } ─────────────────────────────────────
            // Execute the inner pattern, then apply the filter expression.
            GraphPattern::Filter { inner, expr } => {
                use spargebra::algebra::Expression;
                // FILTER EXISTS { <pattern> } — semi-join: keep outer quads whose
                // subject appears in the inner pattern's results.
                if let Expression::Exists(exists_pattern) = expr {
                    let outer_quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, inner)).await?;
                    let inner_quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, exists_pattern)).await?;
                    let exists_subjects: std::collections::HashSet<String> =
                        inner_quads.iter().map(|q| q.subject.to_multibase()).collect();
                    return Ok(outer_quads.into_iter()
                        .filter(|q| exists_subjects.contains(&q.subject.to_multibase()))
                        .collect());
                }
                // FILTER NOT EXISTS { <pattern> } — anti-join: keep outer quads whose
                // subject does NOT appear in the inner pattern's results.
                if let Expression::Not(inner_expr) = expr {
                    if let Expression::Exists(exists_pattern) = inner_expr.as_ref() {
                        let outer_quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, inner)).await?;
                        let inner_quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, exists_pattern)).await?;
                        let exists_subjects: std::collections::HashSet<String> =
                            inner_quads.iter().map(|q| q.subject.to_multibase()).collect();
                        return Ok(outer_quads.into_iter()
                            .filter(|q| !exists_subjects.contains(&q.subject.to_multibase()))
                            .collect());
                    }
                }
                let quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, inner)).await?;
                Ok(quads.into_iter().filter(|q| eval_filter_expr(expr, q)).collect())
            }

            // ── UNION ────────────────────────────────────────────────────────────
            // Execute both sides and merge, deduplicating by (subject, predicate, object).
            GraphPattern::Union { left, right } => {
                let mut results = Box::pin(self.execute_sparql_graph_pattern(graph_cid, left)).await?;
                let right_quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, right)).await?;
                for q in right_quads {
                    if !results.iter().any(|r| quad_eq(r, &q)) {
                        results.push(q);
                    }
                }
                Ok(results)
            }

            // ── OPTIONAL (LeftJoin) ──────────────────────────────────────────────
            // Return all left-side quads; augment with right-side quads whose subject
            // already appears on the left.  Right quads subject to a FILTER expression
            // (the `expression` field of LeftJoin) are additionally checked.
            GraphPattern::LeftJoin { left, right, expression } => {
                let left_quads  = Box::pin(self.execute_sparql_graph_pattern(graph_cid, left)).await?;
                let right_quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, right)).await?;
                let left_subjects: std::collections::HashSet<String> =
                    left_quads.iter().map(|q| q.subject.to_multibase()).collect();
                let mut results = left_quads;
                for q in right_quads {
                    if left_subjects.contains(&q.subject.to_multibase()) {
                        let passes_expr = expression.as_ref().map_or(true, |e| eval_filter_expr(e, &q));
                        if passes_expr && !results.iter().any(|r| quad_eq(r, &q)) {
                            results.push(q);
                        }
                    }
                }
                Ok(results)
            }

            // ── Extend (aggregate variable rename: internal UUID → user var name) ──
            // GROUP BY aggregates use an internal UUID variable; Extend maps it to the
            // user-declared name.  We execute the inner pattern then rename predicates.
            GraphPattern::Extend { inner, variable, expression } => {
                let quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, inner)).await?;
                let from_name = if let spargebra::algebra::Expression::Variable(v) = expression {
                    v.as_str().to_string()
                } else {
                    return Ok(quads);
                };
                let to_name = variable.as_str().to_string();
                Ok(quads.into_iter().map(|mut q| {
                    if q.predicate == from_name { q.predicate = to_name.clone(); }
                    q
                }).collect())
            }

            // ── Join (VALUES filter -or- inner join by shared subject) ──────────
            // Special case: `VALUES ?v { … }` on the left acts as an inline-data
            // filter — keep right-side quads whose predicate matches a VALUES
            // variable AND whose object is one of the allowed literal values.
            //
            // Normal case: execute both sub-patterns (stripping any Project
            // wrapper), then keep quads whose subject appears in both result sets.
            GraphPattern::Join { left, right } => {
                if let GraphPattern::Values { variables: _, bindings } = left.as_ref() {
                    // Build the flat union of all allowed string values across all variables.
                    // VALUES binds object values (e.g. `VALUES ?r { "admin" }` constrains the
                    // quad object when `?r` appears as an object variable in the BGP).
                    let mut all_allowed: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    for row in bindings {
                        for val_opt in row {
                            if let Some(gt) = val_opt {
                                all_allowed.insert(ground_term_to_str(gt));
                            }
                        }
                    }
                    let right_inner = unwrap_bgp_pattern(*right.clone());
                    let right_quads =
                        Box::pin(self.execute_sparql_graph_pattern(graph_cid, &right_inner)).await?;
                    return Ok(right_quads.into_iter().filter(|q| {
                        match &q.object {
                            kotoba_kqe::quad::QuadObject::Text(t) => all_allowed.contains(t.as_str()),
                            // Non-text objects (CID references, etc.) are not constrained
                            _ => true,
                        }
                    }).collect());
                }

                // Sub-SELECT on left: use left for subject filtering only; return right quads.
                // `{ SELECT ?s WHERE { ... } } ?s <p> ?o` → only right-side quads that match
                // the subjects projected by the sub-SELECT.
                if matches!(left.as_ref(), GraphPattern::Project { .. }) {
                    let left_quads  = Box::pin(self.execute_sparql_graph_pattern(graph_cid, left)).await?;
                    let left_subjects: std::collections::HashSet<String> =
                        left_quads.iter().map(|q| q.subject.to_multibase()).collect();
                    let right_inner = unwrap_bgp_pattern(*right.clone());
                    let right_quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, &right_inner)).await?;
                    return Ok(right_quads.into_iter()
                        .filter(|q| left_subjects.contains(&q.subject.to_multibase()))
                        .collect());
                }

                let left_inner  = unwrap_bgp_pattern(*left.clone());
                let right_inner = unwrap_bgp_pattern(*right.clone());
                let left_quads  = Box::pin(self.execute_sparql_graph_pattern(graph_cid, &left_inner)).await?;
                let right_quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, &right_inner)).await?;
                let left_subjects: std::collections::HashSet<String> =
                    left_quads.iter().map(|q| q.subject.to_multibase()).collect();
                let right_subjects: std::collections::HashSet<String> =
                    right_quads.iter().map(|q| q.subject.to_multibase()).collect();
                // Inner join: both sides must have the subject
                let shared: std::collections::HashSet<&String> =
                    left_subjects.intersection(&right_subjects).collect();
                let mut results = Vec::new();
                for q in left_quads.into_iter().chain(right_quads) {
                    if shared.contains(&q.subject.to_multibase())
                        && !results.iter().any(|r| quad_eq(r, &q))
                    {
                        results.push(q);
                    }
                }
                Ok(results)
            }

            // ── GROUP BY + COUNT aggregate ────────────────────────────────────────
            // Execute inner pattern; group quads by their object text value
            // (or into one global group when GROUP BY has no variables);
            // return one synthetic Quad per group:
            //   subject = CID(group_key_bytes), predicate = agg_var_name, object = Text(count)
            GraphPattern::Group { inner, variables, aggregates } => {
                let quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, inner)).await?;
                let agg_var = aggregates.first().map(|(v, _)| v.as_str()).unwrap_or("count");
                let agg_expr = aggregates.first().map(|(_, e)| e);

                // When GROUP BY has no variables, all rows form one global group
                let mut groups: std::collections::HashMap<String, Vec<&Quad>> =
                    std::collections::HashMap::new();
                let global_group = variables.is_empty();
                for q in &quads {
                    let key = if global_group {
                        "*".to_string()
                    } else { match &q.object {
                        kotoba_kqe::quad::QuadObject::Text(t)    => t.clone(),
                        kotoba_kqe::quad::QuadObject::Cid(c)     => c.to_multibase(),
                        kotoba_kqe::quad::QuadObject::Integer(i) => i.to_string(),
                        kotoba_kqe::quad::QuadObject::Float(f)   => format!("{f}"),
                        kotoba_kqe::quad::QuadObject::Bool(b)    => b.to_string(),
                        kotoba_kqe::quad::QuadObject::Bytes(v)       => format!("bytes:{}", v.len()),
                        kotoba_kqe::quad::QuadObject::VectorF32(v)           => format!("vec:{}", v.len()),
                        kotoba_kqe::quad::QuadObject::TensorCid { cid, .. }  => cid.to_multibase(),
                        kotoba_kqe::quad::QuadObject::Encrypted { ct_cid, .. } => ct_cid.to_multibase(),
                    } };
                    groups.entry(key).or_default().push(q);
                }

                let mut results = Vec::new();
                for (key, members) in groups {
                    use spargebra::algebra::{AggregateExpression, AggregateFunction};
                    // Extract text values from member quads for numeric aggregates
                    let text_vals: Vec<&str> = members.iter().filter_map(|q| {
                        if let kotoba_kqe::quad::QuadObject::Text(t) = &q.object { Some(t.as_str()) } else { None }
                    }).collect();
                    let agg_str = match agg_expr {
                        Some(AggregateExpression::CountSolutions { .. }) |
                        Some(AggregateExpression::FunctionCall { name: AggregateFunction::Count, .. }) => {
                            members.len().to_string()
                        }
                        Some(AggregateExpression::FunctionCall { name: AggregateFunction::Sum, .. }) => {
                            // Try integer sum, fall back to float sum
                            let int_sum: Option<i64> = text_vals.iter().try_fold(0i64, |acc, s| {
                                s.parse::<i64>().ok().map(|v| acc + v)
                            });
                            if let Some(s) = int_sum {
                                s.to_string()
                            } else {
                                let f: f64 = text_vals.iter().filter_map(|s| s.parse::<f64>().ok()).sum();
                                format!("{f}")
                            }
                        }
                        Some(AggregateExpression::FunctionCall { name: AggregateFunction::Min, .. }) => {
                            text_vals.iter().min_by(|a, b| cmp_values(a, b))
                                .map(|s| s.to_string()).unwrap_or_default()
                        }
                        Some(AggregateExpression::FunctionCall { name: AggregateFunction::Max, .. }) => {
                            text_vals.iter().max_by(|a, b| cmp_values(a, b))
                                .map(|s| s.to_string()).unwrap_or_default()
                        }
                        Some(AggregateExpression::FunctionCall { name: AggregateFunction::Avg, .. }) => {
                            let nums: Vec<f64> = text_vals.iter().filter_map(|s| s.parse().ok()).collect();
                            if nums.is_empty() { String::new() }
                            else { format!("{:.2}", nums.iter().sum::<f64>() / nums.len() as f64) }
                        }
                        Some(AggregateExpression::FunctionCall { name: AggregateFunction::Sample, .. }) => {
                            text_vals.first().map(|s| s.to_string()).unwrap_or_default()
                        }
                        Some(AggregateExpression::FunctionCall {
                            name: AggregateFunction::GroupConcat { separator },
                            ..
                        }) => {
                            let sep = separator.as_deref().unwrap_or(" ");
                            text_vals.join(sep)
                        }
                        _ => members.len().to_string(),
                    };
                    results.push(Quad {
                        graph:     graph_cid.clone(),
                        subject:   KotobaCid::from_bytes(key.as_bytes()),
                        predicate: agg_var.to_string(),
                        object:    kotoba_kqe::quad::QuadObject::Text(agg_str),
                    });
                }
                // Sort by numeric value descending for stable output (fallback to string order)
                results.sort_by(|a, b| {
                    let va = if let kotoba_kqe::quad::QuadObject::Text(t) = &a.object { t.parse::<u64>().unwrap_or(0) } else { 0 };
                    let vb = if let kotoba_kqe::quad::QuadObject::Text(t) = &b.object { t.parse::<u64>().unwrap_or(0) } else { 0 };
                    vb.cmp(&va)
                });
                Ok(results)
            }

            // ── Property Path (pred+, pred*, pred/pred2) ─────────────────────────
            // ?s <pred>+ ?o  → BFS: collect all CID objects reachable via <pred>
            // ?s <pred>* ?o  → BFS including ?s itself (ZeroOrMore)
            // ?s <p1>/<p2> ?o → sequence: follow p1 then p2
            GraphPattern::Path { subject, path, object } => {
                self.eval_property_path(graph_cid, subject, path, object).await
            }

            // ── MINUS (set difference) ───────────────────────────────────────────
            // Return left-side quads whose subject does NOT appear in the right side.
            GraphPattern::Minus { left, right } => {
                let left_quads  = Box::pin(self.execute_sparql_graph_pattern(graph_cid, left)).await?;
                let right_quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, right)).await?;
                let right_subjects: std::collections::HashSet<String> =
                    right_quads.iter().map(|q| q.subject.to_multibase()).collect();
                Ok(left_quads.into_iter()
                    .filter(|q| !right_subjects.contains(&q.subject.to_multibase()))
                    .collect())
            }

            // ── VALUES (standalone inline-data) ─────────────────────────────────
            // Returns one synthetic Quad per (variable, binding) pair:
            //   subject = CID(value_bytes), predicate = variable_name, object = Text(value)
            // When VALUES appears as the left side of a Join the Join handler
            // short-circuits above; this arm handles the rare standalone case.
            GraphPattern::Values { variables, bindings } => {
                let mut results = Vec::new();
                for row in bindings {
                    for (var, val_opt) in variables.iter().zip(row) {
                        if let Some(gt) = val_opt {
                            let val_str = ground_term_to_str(gt);
                            results.push(Quad {
                                graph:     graph_cid.clone(),
                                subject:   KotobaCid::from_bytes(val_str.as_bytes()),
                                predicate: var.as_str().to_string(),
                                object:    kotoba_kqe::quad::QuadObject::Text(val_str),
                            });
                        }
                    }
                }
                Ok(results)
            }

            // ── ORDER BY ────────────────────────────────────────────────────────
            // Execute inner pattern then sort quads by object text value.
            // Slice (LIMIT/OFFSET) wraps OrderBy and applies the window after sorting.
            GraphPattern::OrderBy { inner, expression } => {
                let mut quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, inner)).await?;
                let descending = expression.first().map(|e| {
                    matches!(e, spargebra::algebra::OrderExpression::Desc(_))
                }).unwrap_or(false);
                quads.sort_by(|a, b| {
                    let av = match &a.object {
                        kotoba_kqe::quad::QuadObject::Text(t) => t.clone(),
                        _ => String::new(),
                    };
                    let bv = match &b.object {
                        kotoba_kqe::quad::QuadObject::Text(t) => t.clone(),
                        _ => String::new(),
                    };
                    if descending { bv.cmp(&av) } else { av.cmp(&bv) }
                });
                Ok(quads)
            }

            // ── SLICE (LIMIT / OFFSET) ────────────────────────────────────────
            // Strips Project wrappers from the inner pattern, executes it
            // (OrderBy is handled recursively above), then applies skip + take.
            GraphPattern::Slice { inner, start, length } => {
                let inner_p = unwrap_bgp_pattern(*inner.clone());
                let quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, &inner_p)).await?;
                let skip = *start;
                Ok(quads.into_iter().skip(skip).take(length.unwrap_or(usize::MAX)).collect())
            }

            // ── DISTINCT ─────────────────────────────────────────────────────
            // Deduplicate quads from the inner pattern by (subject, predicate, object).
            // Deduplication ignores the graph CID so cross-graph identical triples
            // are treated as the same solution.  This models SELECT DISTINCT projection
            // onto the full triple (not a projected-variable subset).
            GraphPattern::Distinct { inner } => {
                let inner_p = unwrap_bgp_pattern(*inner.clone());
                let quads = Box::pin(self.execute_sparql_graph_pattern(graph_cid, &inner_p)).await?;
                let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
                Ok(quads.into_iter().filter(|q| {
                    let obj_key = match &q.object {
                        kotoba_kqe::quad::QuadObject::Text(t)    => t.clone(),
                        kotoba_kqe::quad::QuadObject::Cid(c)     => c.to_multibase(),
                        kotoba_kqe::quad::QuadObject::Integer(i) => i.to_string(),
                        kotoba_kqe::quad::QuadObject::Float(f)   => format!("{f}"),
                        kotoba_kqe::quad::QuadObject::Bool(b)    => b.to_string(),
                        _ => format!("__opaque_{}_{}", q.subject.to_multibase(), q.predicate),
                    };
                    seen.insert(format!("{}|{}|{}",
                        q.subject.to_multibase(), q.predicate, obj_key))
                }).collect())
            }

            // ── GRAPH (named graph query) ────────────────────────────────────
            // `GRAPH <iri>  { … }` — execute inner in a specific named graph.
            //   IRI = multibase of KotobaCid, with optional `k:` base prefix.
            // `GRAPH ?g { … }` — execute inner across every known graph; merge.
            GraphPattern::Graph { name, inner } => {
                use spargebra::term::NamedNodePattern;
                match name {
                    NamedNodePattern::NamedNode(nn) => {
                        let iri = nn.as_str();
                        let mb  = iri.strip_prefix(SPARQL_BGP_BASE_IRI).unwrap_or(iri);
                        match KotobaCid::from_multibase(mb) {
                            Some(target_graph) => {
                                Box::pin(self.execute_sparql_graph_pattern(&target_graph, inner)).await
                            }
                            None => Ok(Vec::new()),
                        }
                    }
                    NamedNodePattern::Variable(_) => {
                        let graphs = self.all_graph_cids().await;
                        let mut results: Vec<Quad> = Vec::new();
                        for g in graphs {
                            let mut quads =
                                Box::pin(self.execute_sparql_graph_pattern(&g, inner)).await?;
                            results.append(&mut quads);
                        }
                        Ok(results)
                    }
                }
            }

            // ── Sub-SELECT (Project in non-root position) ────────────────────
            // When a sub-SELECT appears inside JOIN/UNION/FILTER context, spargebra
            // wraps the inner pattern in Project.  Execute the inner pattern and
            // return its results verbatim; variable projection is handled by the
            // outer Project at the top-level SELECT.
            GraphPattern::Project { inner, .. } => {
                Box::pin(self.execute_sparql_graph_pattern(graph_cid, inner)).await
            }

            // ── SERVICE <iri> { … } — SPARQL 1.1 federated query ──────────────
            //
            // Service IRI forms recognised:
            //   `<cid:mb>`              — graph CID, multibase-encoded
            //   `kotoba://graph/<mb>`   — fully qualified graph URI
            //   `kotoba://node/<did>`   — peer DID (not yet routed)
            //
            // The federation effect is implicit: blocks for the target graph
            // CID are loaded via the configured BlockStore, which may itself be
            // a DistributedBlockStore that pulls from remote IPFS peers.
            //
            // `silent=true` per SPARQL 1.1 spec swallows errors → returns empty.
            GraphPattern::Service { name, inner, silent } => {
                use spargebra::term::NamedNodePattern;
                let iri = match name {
                    NamedNodePattern::NamedNode(nn) => nn.as_str().to_string(),
                    NamedNodePattern::Variable(_) => {
                        if *silent { return Ok(Vec::new()); }
                        anyhow::bail!("SERVICE ?var: variable service endpoint not supported");
                    }
                };
                let stripped = iri.strip_prefix(SPARQL_BGP_BASE_IRI).unwrap_or(&iri);
                let mb_opt: Option<String> = if let Some(rest) = stripped.strip_prefix("kotoba://graph/") {
                    Some(rest.to_string())
                } else if stripped.starts_with("kotoba://node/") {
                    if *silent { return Ok(Vec::new()); }
                    anyhow::bail!("SERVICE kotoba://node/<did>: peer-DID routing not yet implemented");
                } else if let Some(rest) = stripped.strip_prefix("cid:") {
                    Some(rest.to_string())
                } else {
                    Some(stripped.to_string())
                };
                match mb_opt.and_then(|mb| KotobaCid::from_multibase(&mb)) {
                    Some(target_graph) => {
                        Box::pin(self.execute_sparql_graph_pattern(&target_graph, inner)).await
                    }
                    None => {
                        if *silent { Ok(Vec::new()) }
                        else { anyhow::bail!("SERVICE: unrecognised service IRI: {iri}") }
                    }
                }
            }

            other => anyhow::bail!(
                "unsupported SPARQL pattern type: {}",
                sparql_pattern_name(other)
            ),
        }
    }

    /// Evaluate a SPARQL property path pattern.
    ///
    /// Supports:
    /// - `<pred>+` (`OneOrMore`) — BFS over CID-typed edges with matching predicate (≥1 hop)
    /// - `<pred>*` (`ZeroOrMore`) — same but includes the start node (≥0 hops)
    /// - `<p1>/<p2>` (`Sequence`) — follow p1 then p2 (one hop each)
    /// - bare `<pred>` (`NamedNode`) — single-hop (equivalent to BGP triple)
    ///
    /// Subject must be bound as `cid:{multibase}`.  Object variable receives each
    /// reachable CID; existing CID-object quads along the path are returned.
    async fn eval_property_path(
        &self,
        graph_cid: &KotobaCid,
        subject:   &spargebra::term::TermPattern,
        path:      &spargebra::algebra::PropertyPathExpression,
        _object:   &spargebra::term::TermPattern,
    ) -> anyhow::Result<Vec<Quad>> {
        use spargebra::algebra::PropertyPathExpression;
        use spargebra::term::TermPattern;

        // Resolve bound subject CID.
        let start_cid = match subject {
            TermPattern::NamedNode(nn) => {
                parse_cid_iri(strip_bgp_base(nn.as_str()))
                    .ok_or_else(|| anyhow::anyhow!("property path: subject IRI is not a cid: IRI"))?
            }
            _ => anyhow::bail!("property path: subject must be a bound cid: IRI"),
        };

        match path {
            PropertyPathExpression::NamedNode(pred) => {
                let pred_str = strip_bgp_base(pred.as_str());
                let quads = self.get_entity_quads_cold(graph_cid, &start_cid).await?;
                Ok(quads.into_iter().filter(|q| q.predicate == pred_str).collect())
            }

            PropertyPathExpression::OneOrMore(inner) => {
                let pred = extract_named_node_from_path(inner)
                    .ok_or_else(|| anyhow::anyhow!("OneOrMore: only simple <pred>+ supported"))?;
                self.bfs_pred_path(graph_cid, &start_cid, pred, 1, 8).await
            }

            PropertyPathExpression::ZeroOrMore(inner) => {
                let pred = extract_named_node_from_path(inner)
                    .ok_or_else(|| anyhow::anyhow!("ZeroOrMore: only simple <pred>* supported"))?;
                let mut results = self.bfs_pred_path(graph_cid, &start_cid, pred, 0, 8).await?;
                // ZeroOrMore includes the start node's own quads with this predicate
                let own = self.get_entity_quads_cold(graph_cid, &start_cid).await?;
                for q in own {
                    if !results.iter().any(|r| quad_eq(r, &q)) {
                        results.push(q);
                    }
                }
                Ok(results)
            }

            PropertyPathExpression::Sequence(a, b) => {
                let pred_a = extract_named_node_from_path(a)
                    .ok_or_else(|| anyhow::anyhow!("Sequence: only simple pred/pred supported"))?;
                let pred_b = extract_named_node_from_path(b)
                    .ok_or_else(|| anyhow::anyhow!("Sequence: only simple pred/pred supported"))?;
                // Follow pred_a from start → get CID objects → follow pred_b from those
                let hop1 = self.get_entity_quads_cold(graph_cid, &start_cid).await?;
                let midpoints: Vec<KotobaCid> = hop1.into_iter().filter_map(|q| {
                    if q.predicate == pred_a {
                        if let kotoba_kqe::quad::QuadObject::Cid(c) = q.object { Some(c) } else { None }
                    } else { None }
                }).collect();
                let mut results = Vec::new();
                for mid in midpoints {
                    let hop2 = self.get_entity_quads_cold(graph_cid, &mid).await?;
                    for q in hop2 {
                        if q.predicate == pred_b && !results.iter().any(|r| quad_eq(r, &q)) {
                            results.push(q);
                        }
                    }
                }
                Ok(results)
            }

            // <p1> | <p2> — Alternative: union of both path results
            PropertyPathExpression::Alternative(a, b) => {
                let mut results = Box::pin(self.eval_property_path(graph_cid, subject, a, _object)).await?;
                let b_results = Box::pin(self.eval_property_path(graph_cid, subject, b, _object)).await?;
                for q in b_results {
                    if !results.iter().any(|r| quad_eq(r, &q)) {
                        results.push(q);
                    }
                }
                Ok(results)
            }

            // ^<pred> — Inverse: look up subjects that have pred → start_cid
            PropertyPathExpression::Reverse(inner) => {
                let pred = extract_named_node_from_path(inner)
                    .ok_or_else(|| anyhow::anyhow!("Reverse: only simple ^<pred> supported"))?;
                // Use AEVT scan with predicate prefix; filter by object == start_cid
                let all = self.quads_by_predicate_prefix_cold(graph_cid, pred).await?;
                Ok(all.into_iter().filter(|q| {
                    matches!(&q.object, kotoba_kqe::quad::QuadObject::Cid(c) if *c == start_cid)
                }).collect())
            }

            // <pred>? — ZeroOrOne: follow pred 0 or 1 times
            PropertyPathExpression::ZeroOrOne(inner) => {
                let pred = extract_named_node_from_path(inner)
                    .ok_or_else(|| anyhow::anyhow!("ZeroOrOne: only simple <pred>? supported"))?;
                // Zero hops: own quads of start_cid
                let own = self.get_entity_quads_cold(graph_cid, &start_cid).await?;
                // One hop: quads of the CID objects reachable via pred
                let mut results: Vec<Quad> = own.clone();
                for q in &own {
                    if q.predicate == pred {
                        if let kotoba_kqe::quad::QuadObject::Cid(target) = &q.object {
                            let hop = self.get_entity_quads_cold(graph_cid, target).await?;
                            for hq in hop {
                                if !results.iter().any(|r| quad_eq(r, &hq)) {
                                    results.push(hq);
                                }
                            }
                        }
                    }
                }
                Ok(results)
            }

            other => anyhow::bail!("unsupported property path type: {}", path_name(other)),
        }
    }

    /// BFS over CID-typed edges with a specific predicate.
    ///
    /// `min_depth=1` for `+` (OneOrMore), `min_depth=0` for `*` (ZeroOrMore).
    /// `max_depth` caps at 8 hops to prevent runaway traversal.
    async fn bfs_pred_path(
        &self,
        graph_cid:  &KotobaCid,
        start:      &KotobaCid,
        predicate:  &str,
        min_depth:  usize,
        max_depth:  usize,
    ) -> anyhow::Result<Vec<Quad>> {
        let mut results: Vec<Quad> = Vec::new();
        let mut frontier = vec![start.clone()];
        let mut visited  = std::collections::HashSet::new();
        visited.insert(start.clone());

        for depth in 1..=max_depth {
            if frontier.is_empty() { break; }
            let mut next_frontier: Vec<KotobaCid> = Vec::new();
            for node in &frontier {
                let quads = self.get_entity_quads_cold(graph_cid, node).await?;
                for q in quads {
                    if q.predicate != predicate { continue; }
                    if let kotoba_kqe::quad::QuadObject::Cid(ref ref_cid) = q.object {
                        if visited.insert(ref_cid.clone()) {
                            next_frontier.push(ref_cid.clone());
                        }
                        if depth >= min_depth && !results.iter().any(|r| quad_eq(r, &q)) {
                            results.push(q);
                        }
                    }
                }
            }
            frontier = next_frontier;
        }
        Ok(results)
    }

    /// Route a flat list of BGP triple patterns to the optimal cold-path index.
    async fn route_bgp_triples(
        &self,
        graph_cid: &KotobaCid,
        triples:   &[spargebra::term::TriplePattern],
    ) -> anyhow::Result<Vec<Quad>> {
        use spargebra::term::{NamedNodePattern, TermPattern};

        anyhow::ensure!(!triples.is_empty(), "SPARQL WHERE clause has no triple patterns");

        // ── Single-triple routing ─────────────────────────────────────────────
        if triples.len() == 1 {
            let tp = &triples[0];
            // Bound subject (named node)?
            if let TermPattern::NamedNode(nn) = &tp.subject {
                let iri = nn.as_str();
                let subj = parse_cid_iri(iri)
                    .ok_or_else(|| anyhow::anyhow!("subject IRI is not a valid cid: URI: {iri}"))?;
                let all = self.get_entity_quads_cold(graph_cid, &subj).await?;
                // If predicate is also bound, filter by predicate (and object if bound too)
                if let NamedNodePattern::NamedNode(pred_nn) = &tp.predicate {
                    let pred = strip_bgp_base(pred_nn.as_str());
                    let pred_filtered: Vec<Quad> = all.into_iter()
                        .filter(|q| q.predicate == pred)
                        .collect();
                    // Additionally filter by bound object if present
                    return match &tp.object {
                        TermPattern::Literal(lit) => {
                            let v = lit.value();
                            Ok(pred_filtered.into_iter().filter(|q| match &q.object {
                                kotoba_kqe::quad::QuadObject::Text(t) => t == v,
                                kotoba_kqe::quad::QuadObject::Integer(i) => {
                                    v.parse::<i64>().map_or(false, |n| *i == n)
                                }
                                kotoba_kqe::quad::QuadObject::Float(f) => {
                                    v.parse::<f64>().map_or(false, |n| (*f - n).abs() < f64::EPSILON)
                                }
                                kotoba_kqe::quad::QuadObject::Bool(b) => {
                                    v == "true" && *b || v == "false" && !b
                                }
                                _ => false,
                            }).collect())
                        }
                        TermPattern::NamedNode(obj_nn) => {
                            let obj_iri = strip_bgp_base(obj_nn.as_str());
                            if let Some(obj_cid) = parse_cid_iri(obj_iri) {
                                Ok(pred_filtered.into_iter().filter(|q| {
                                    matches!(&q.object, kotoba_kqe::quad::QuadObject::Cid(c) if *c == obj_cid)
                                }).collect())
                            } else {
                                // Named node that's not a CID — compare as text
                                Ok(pred_filtered.into_iter().filter(|q| {
                                    matches!(&q.object, kotoba_kqe::quad::QuadObject::Text(t) if t == obj_iri)
                                }).collect())
                            }
                        }
                        TermPattern::Variable(_) => Ok(pred_filtered), // unbound object
                        _ => Ok(pred_filtered),
                    };
                }
                return Ok(all);
            }

            // Bound predicate?
            if let NamedNodePattern::NamedNode(pred_nn) = &tp.predicate {
                let pred = strip_bgp_base(pred_nn.as_str()).to_string();

                // Bound object (literal or named node)?
                match &tp.object {
                    TermPattern::Literal(lit) => {
                        // AVET: pred + literal
                        let obj_key = lit.value().to_string();
                        let subjects = self.lookup_subject_by_po_cold(graph_cid, &pred, &obj_key).await?;
                        return Ok(subjects.into_iter().map(|s| Quad {
                            graph:    graph_cid.clone(),
                            subject:  s,
                            predicate: pred.clone(),
                            object:   kotoba_kqe::quad::QuadObject::Text(obj_key.clone()),
                        }).collect());
                    }
                    TermPattern::NamedNode(obj_nn) => {
                        let obj_iri = strip_bgp_base(obj_nn.as_str());
                        if let Some(obj_cid) = parse_cid_iri(obj_iri) {
                            // AVET: pred + cid-object
                            let obj_mb = obj_cid.to_multibase();
                            let subjects = self.lookup_subject_by_po_cold(graph_cid, &pred, &obj_mb).await?;
                            return Ok(subjects.into_iter().map(|s| Quad {
                                graph:    graph_cid.clone(),
                                subject:  s,
                                predicate: pred.clone(),
                                object:   kotoba_kqe::quad::QuadObject::Cid(obj_cid.clone()),
                            }).collect());
                        }
                        // Unrecognised IRI: fall through to AEVT
                    }
                    TermPattern::Variable(_) => { /* fall through to AEVT */ }
                    _ => { /* blank node objects: fall through */ }
                }

                // AEVT: only predicate bound
                return self.quads_by_predicate_prefix_cold(graph_cid, &pred).await;
            }

            // Bound object CID only?
            if let TermPattern::NamedNode(obj_nn) = &tp.object {
                if let Some(obj_cid) = parse_cid_iri(obj_nn.as_str()) {
                    // VAET
                    let pairs = self.reverse_lookup_cold(graph_cid, &obj_cid).await?;
                    return Ok(pairs.into_iter().map(|(pred, subj)| Quad {
                        graph:    graph_cid.clone(),
                        subject:  subj,
                        predicate: pred,
                        object:   kotoba_kqe::quad::QuadObject::Cid(obj_cid.clone()),
                    }).collect());
                }
            }

            anyhow::bail!("SPARQL BGP pattern is too unconstrained; bind at least subject, predicate, or predicate+object");
        }

        // ── Two-triple join routing ───────────────────────────────────────────
        if triples.len() == 2 {
            if let (
                Some((pred1, val1, svar1)),
                Some((pred2, val2, svar2)),
            ) = (
                extract_pred_literal_triple(&triples[0]),
                extract_pred_literal_triple(&triples[1]),
            ) {
                if svar1 == svar2 {
                    let subjects = self
                        .join_by_two_predicates_cold(graph_cid, &pred1, &val1, &pred2, &val2)
                        .await?;
                    let mut out = Vec::with_capacity(subjects.len() * 2);
                    for s in subjects {
                        out.push(Quad {
                            graph: graph_cid.clone(), subject: s.clone(),
                            predicate: pred1.clone(),
                            object: kotoba_kqe::quad::QuadObject::Text(val1.clone()),
                        });
                        out.push(Quad {
                            graph: graph_cid.clone(), subject: s,
                            predicate: pred2.clone(),
                            object: kotoba_kqe::quad::QuadObject::Text(val2.clone()),
                        });
                    }
                    return Ok(out);
                }
            }
        }

        // ── N-triple inner join (general case) ────────────────────────────────
        // Execute each triple independently as a 1-triple query, then keep only
        // quads whose subject appears in every per-triple result set.
        // This handles:
        //   - 2-triple BGPs that don't fit the fast AVET×AVET path above
        //   - 3+ triple BGPs
        // Complexity: Σ(cost of each 1-triple query) + O(N × |result|) for intersection.
        let mut per_triple: Vec<Vec<Quad>> = Vec::with_capacity(triples.len());
        for tp in triples {
            let single = std::slice::from_ref(tp);
            let quads  = Box::pin(self.route_bgp_triples(graph_cid, single)).await?;
            per_triple.push(quads);
        }

        // Intersect subject sets across all triples
        let mut shared: std::collections::HashSet<String> =
            per_triple[0].iter().map(|q| q.subject.to_multibase()).collect();
        for quads in &per_triple[1..] {
            let s: std::collections::HashSet<String> =
                quads.iter().map(|q| q.subject.to_multibase()).collect();
            shared = shared.intersection(&s).cloned().collect();
        }

        // Collect all quads for shared subjects (preserve order, deduplicate)
        let mut results: Vec<Quad> = Vec::new();
        for quads in per_triple {
            for q in quads {
                if shared.contains(&q.subject.to_multibase())
                    && !results.iter().any(|r| quad_eq(r, &q))
                {
                    results.push(q);
                }
            }
        }
        Ok(results)
    }

    /// CACAO-gated SPARQL BGP cold query.
    pub async fn cold_query_sparql_bgp_authed(
        &self,
        graph_cid: &KotobaCid,
        sparql:    &str,
        chain:     &DelegationChain,
    ) -> Result<Vec<Quad>, AccessError> {
        chain.verify(&graph_cid.to_multibase(), "quad:read")?;
        self.cold_query_sparql_bgp(graph_cid, sparql).await
            .map_err(|e| AccessError::Internal(e.to_string()))
    }

    /// CACAO-gated multi-graph SPARQL query.
    ///
    /// Verifies the chain's `quad:read` capability, then executes the SPARQL.
    /// When the CACAO contains multiple `kotoba://graph/{cid}` resources, the
    /// result is additionally filtered to only include quads from authorized
    /// named graphs.  A chain with no graph resources allows access to all graphs.
    ///
    /// Designed for `GRAPH ?g { … }` queries where a single token covers multiple
    /// IPFS-backed named graphs (e.g. sharded dataset access).
    pub async fn cold_query_sparql_bgp_multi_graph_authed(
        &self,
        default_graph: &KotobaCid,
        sparql:        &str,
        chain:         &DelegationChain,
    ) -> Result<Vec<Quad>, AccessError> {
        // Verify capability (no graph-scope check here — we filter results instead)
        chain.verify_capability_only("quad:read")?;

        // Execute query (may use GRAPH ?g to fan out across all committed graphs)
        let quads = self.cold_query_sparql_bgp(default_graph, sparql).await
            .map_err(|e| AccessError::Internal(e.to_string()))?;

        // Filter by authorized graph CIDs (empty = no restriction)
        let authorized = chain.authorized_graphs();
        if authorized.is_empty() {
            return Ok(quads);
        }
        let auth_set: std::collections::HashSet<&str> =
            authorized.iter().map(String::as_str).collect();
        Ok(quads.into_iter()
            .filter(|q| auth_set.contains(q.graph.to_multibase().as_str()))
            .collect())
    }

    // ── SPARQL UPDATE ─────────────────────────────────────────────────────────

    /// Execute a SPARQL 1.1 UPDATE statement against the store.
    ///
    /// Supported operations:
    /// - `INSERT DATA { <s> <p> "o" }` — asserts quads; uses `default_graph` for default graph.
    /// - `DELETE DATA { <s> <p> "o" }` — retracts quads; uses `default_graph` for default graph.
    /// - `INSERT DATA { GRAPH <cid> { ... } }` — inserts into the named graph.
    /// - `DELETE DATA { GRAPH <cid> { ... } }` — deletes from the named graph.
    /// - `INSERT { ?s <p> "v" } WHERE { ?s <q> "w" }` — pattern-driven insert.
    /// - `DELETE { ?s <p> "v" } WHERE { ?s <q> "w" }` — pattern-driven delete.
    ///
    /// Variable binding in WHERE→INSERT/DELETE: subject variable `?s` is bound from matched
    /// quad's subject CID; object variable binds from matched quad's object; predicates must
    /// be concrete named nodes.
    ///
    /// Other operations (Clear, Load, Create, Drop) are not yet supported.
    pub async fn sparql_update(
        &self,
        default_graph: &KotobaCid,
        sparql:        &str,
    ) -> anyhow::Result<usize> {
        use spargebra::Update;
        use spargebra::GraphUpdateOperation;

        let update = Update::parse(sparql, Some(SPARQL_BGP_BASE_IRI))
            .map_err(|e| anyhow::anyhow!("SPARQL UPDATE parse error: {e}"))?;

        let mut count = 0usize;

        for op in update.operations {
            match op {
                GraphUpdateOperation::InsertData { data } => {
                    for sq in data {
                        use spargebra::term::NamedOrBlankNode;
                        let graph_cid = sparql_graph_name_to_cid(&sq.graph_name, default_graph)?;
                        let subj_iri = match &sq.subject {
                            NamedOrBlankNode::NamedNode(nn) => nn.as_str(),
                            NamedOrBlankNode::BlankNode(_)  =>
                                anyhow::bail!("UPDATE INSERT: blank node subjects not supported"),
                        };
                        let subject   = sparql_named_node_to_cid(subj_iri)?;
                        let predicate = strip_bgp_base(sq.predicate.as_str()).to_string();
                        let object    = sparql_term_to_quad_object(&sq.object)?;
                        self.assert(Quad { graph: graph_cid, subject, predicate, object }).await;
                        count += 1;
                    }
                }
                GraphUpdateOperation::DeleteData { data } => {
                    for sq in data {
                        let graph_cid = sparql_graph_name_to_cid(&sq.graph_name, default_graph)?;
                        let subject   = sparql_named_node_to_cid(sq.subject.as_str())?;
                        let predicate = strip_bgp_base(sq.predicate.as_str()).to_string();
                        let object    = sparql_term_to_quad_object_ground(&sq.object)?;
                        self.retract(Quad { graph: graph_cid, subject, predicate, object }).await;
                        count += 1;
                    }
                }
                // INSERT { patterns } WHERE { graph_pattern }
                // DELETE { patterns } WHERE { graph_pattern }  (delete=[], insert=[...] or vice versa)
                GraphUpdateOperation::DeleteInsert { delete, insert, pattern, .. } => {
                    // Execute WHERE clause on the default graph
                    let matched = Box::pin(
                        self.execute_sparql_graph_pattern(default_graph, &pattern)
                    ).await?;

                    // DELETE first (remove matched quads that match the delete patterns)
                    for del_pat in &delete {
                        let graph_cid = match &del_pat.graph_name {
                            spargebra::term::GraphNamePattern::DefaultGraph => default_graph.clone(),
                            spargebra::term::GraphNamePattern::NamedNode(nn) => {
                                let s = strip_bgp_base(nn.as_str());
                                parse_cid_iri(s).ok_or_else(|| anyhow::anyhow!("DELETE: graph IRI not a CID: {}", nn.as_str()))?
                            }
                            spargebra::term::GraphNamePattern::Variable(_) => default_graph.clone(),
                        };
                        for mq in &matched {
                            if let Some(q) = instantiate_ground_quad_pattern(del_pat, &graph_cid, mq) {
                                self.retract(q).await;
                                count += 1;
                            }
                        }
                    }

                    // INSERT — materialise patterns for each matched quad
                    for ins_pat in &insert {
                        let graph_cid = match &ins_pat.graph_name {
                            spargebra::term::GraphNamePattern::DefaultGraph => default_graph.clone(),
                            spargebra::term::GraphNamePattern::NamedNode(nn) => {
                                let s = strip_bgp_base(nn.as_str());
                                parse_cid_iri(s).ok_or_else(|| anyhow::anyhow!("INSERT WHERE: graph IRI not a CID: {}", nn.as_str()))?
                            }
                            spargebra::term::GraphNamePattern::Variable(_) => default_graph.clone(),
                        };
                        for mq in &matched {
                            if let Some(q) = instantiate_quad_pattern(ins_pat, &graph_cid, mq) {
                                self.assert(q).await;
                                count += 1;
                            }
                        }
                    }
                }
                other => anyhow::bail!("unsupported SPARQL UPDATE operation: {other:?}"),
            }
        }
        Ok(count)
    }

    /// CACAO-gated SPARQL UPDATE. Verifies `quad:write` capability and graph scope
    /// on the default graph (covers no-GRAPH-clause updates) before executing.
    pub async fn sparql_update_authed(
        &self,
        default_graph: &KotobaCid,
        sparql:        &str,
        chain:         &DelegationChain,
    ) -> Result<usize, AccessError> {
        chain.verify(&default_graph.to_multibase(), "quad:write")?;
        self.sparql_update(default_graph, sparql).await
            .map_err(|e| AccessError::Internal(e.to_string()))
    }

    // ── CACAO-authed cold-path reads ──────────────────────────────────────────

    /// CACAO-gated EAVT cold read.  Verifies `quad:read` capability on `graph_cid`
    /// before fetching committed quads from the IPFS-backed ProllyTree.
    pub async fn get_entity_quads_cold_authed(
        &self,
        graph_cid: &KotobaCid,
        subject:   &KotobaCid,
        chain:     &DelegationChain,
    ) -> Result<Vec<Quad>, AccessError> {
        chain.verify(&graph_cid.to_multibase(), "quad:read")?;
        self.get_entity_quads_cold(graph_cid, subject).await
            .map_err(|e| AccessError::Internal(e.to_string()))
    }

    /// CACAO-gated AEVT cold read.
    pub async fn quads_by_predicate_prefix_cold_authed(
        &self,
        graph_cid:        &KotobaCid,
        predicate_prefix: &str,
        chain:            &DelegationChain,
    ) -> Result<Vec<Quad>, AccessError> {
        chain.verify(&graph_cid.to_multibase(), "quad:read")?;
        self.quads_by_predicate_prefix_cold(graph_cid, predicate_prefix).await
            .map_err(|e| AccessError::Internal(e.to_string()))
    }

    /// CACAO-gated AVET cold read.
    pub async fn lookup_subject_by_po_cold_authed(
        &self,
        graph_cid:  &KotobaCid,
        predicate:  &str,
        object_key: &str,
        chain:      &DelegationChain,
    ) -> Result<Vec<KotobaCid>, AccessError> {
        chain.verify(&graph_cid.to_multibase(), "quad:read")?;
        self.lookup_subject_by_po_cold(graph_cid, predicate, object_key).await
            .map_err(|e| AccessError::Internal(e.to_string()))
    }

    /// CACAO-gated multi-hop BFS cold traversal.
    pub async fn multi_hop_cold_authed(
        &self,
        graph_cid: &KotobaCid,
        start:     &KotobaCid,
        max_hops:  usize,
        chain:     &DelegationChain,
    ) -> Result<Vec<(usize, Quad)>, AccessError> {
        chain.verify(&graph_cid.to_multibase(), "quad:read")?;
        self.multi_hop_cold(graph_cid, start, max_hops).await
            .map_err(|e| AccessError::Internal(e.to_string()))
    }

    /// Clear the in-memory Arrangement for `graph_cid`, reclaiming RAM.
    /// Call after `commit()` in a batch-ingest cycle when working-set > budget.
    pub async fn reset_arrangement(&self, graph_cid: &KotobaCid) {
        let key = graph_cid.to_multibase();
        if let Some(mut arr) = self.arrangements.get_mut(&key) {
            arr.clear();
        }
        // Hot is now empty; subsequent queries go straight to cold.  Mark as
        // "covers nothing" — but the short-circuit only triggers when hot is
        // non-empty, so this is mostly bookkeeping.  Set true so a future
        // write into the now-empty arrangement restores the normal invariant.
        self.hot_covers_all.insert(key, true);
    }

    /// Import a commit from the local BlockStore into the CommitDag.
    ///
    /// Used during distributed sync: after a peer's blocks are replicated into this
    /// node's BlockStore (via block-copy or bitswap), call this with the known commit
    /// CID to make the graph queryable via cold-path reads.  The commit block must
    /// already exist in `self.block_store`.
    ///
    /// Returns `true` if the commit was found and imported, `false` if the block was
    /// not present in the store.
    pub async fn import_commit(&self, commit_cid: &KotobaCid) -> anyhow::Result<bool> {
        match Commit::load(commit_cid, &*self.block_store)? {
            None => Ok(false),
            Some(commit) => {
                self.commit_dag.write().await.add(commit);
                Ok(true)
            }
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
            match self.arrangements.get(&graph_cid.to_multibase()) {
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
        let tree_inputs: Vec<TreeInput> = vec![
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
                .spawn(move || -> TreeResult {
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
        // Record committed_seq (the JOURNAL's current seq, not the user-provided
        // commit-seq) + CommitDag heads as a tiny JSON blob in the Journal store.
        // On the next startup replay_from_journal() will skip all Journal entries
        // ≤ this seq — reducing startup cost from O(all history) to O(delta) and
        // preventing already-committed quads from being re-loaded into the hot
        // arrangement (which would shadow the ProllyTree cold path).
        let journal_seq = self.journal.current_seq().await;
        *self.committed_seq.write().await = journal_seq;
        {
            let heads = self.commit_dag.read().await.heads_as_map();
            let cp    = serde_json::json!({ "committed_seq": journal_seq, "heads": heads });
            let bytes = bytes::Bytes::from(cp.to_string().into_bytes());
            self.journal.write_checkpoint(bytes).await;
        }
        // Trim ring buffer (in-process memory free).
        self.journal.trim_before(journal_seq).await;
        // Trim persistent seq-index in B2 (fire-and-forget; old seq keys deleted).
        {
            let j = Arc::clone(&self.journal);
            tokio::spawn(async move { j.trim_persistent_before(journal_seq).await; });
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
    /// Stores that don't implement `all_cids()` (S3, kubo) return an empty vec — in that case
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

    /// Prune historical (non-HEAD) commit entries from the in-memory CommitDag where
    /// `commit.seq < before_seq`.  HEAD commits are always preserved.
    ///
    /// This bounds CommitDag memory growth in long-running nodes that commit frequently.
    /// Typically called after `gc_dead_blocks()` so that block GC runs first while all
    /// historical commits are still visible as GC roots.
    ///
    /// Returns the count of commit entries removed.
    pub async fn prune_old_commits(&self, before_seq: u64) -> usize {
        let mut dag = self.commit_dag.write().await;
        let pruned = dag.prune_non_head(before_seq);
        if pruned > 0 {
            tracing::info!(pruned, before_seq, "prune_old_commits: removed {pruned} historical commits");
        }
        pruned
    }

    /// Return the number of commits currently held in the in-memory CommitDag.
    pub async fn commit_dag_size(&self) -> usize {
        self.commit_dag.read().await.commit_count()
    }
}

// ── SPARQL BGP helper functions ───────────────────────────────────────────────

/// Base IRI used to resolve relative IRIs in `cold_query_sparql_bgp`.
/// Relative predicates like `<role>` resolve to `k:role`, which is then
/// stripped back to `"role"` by `strip_bgp_base`.
const SPARQL_BGP_BASE_IRI: &str = "k:";

/// Strip the `SPARQL_BGP_BASE_IRI` prefix if present; return the local name.
fn strip_bgp_base(iri: &str) -> &str {
    iri.strip_prefix(SPARQL_BGP_BASE_IRI).unwrap_or(iri)
}

/// Unwrap Project / Reduced wrappers to expose the inner BGP pattern.
/// DISTINCT is intentionally preserved — `execute_sparql_graph_pattern` handles
/// it via the `Distinct` arm and deduplicates the result set.
fn unwrap_bgp_pattern(pattern: spargebra::algebra::GraphPattern) -> spargebra::algebra::GraphPattern {
    use spargebra::algebra::GraphPattern;
    match pattern {
        GraphPattern::Project { inner, .. } => unwrap_bgp_pattern(*inner),
        GraphPattern::Reduced  { inner }    => unwrap_bgp_pattern(*inner),
        // Preserve Distinct and Extend so execute can handle them
        other => other,
    }
}

/// Parse a `cid:{multibase}` IRI into a `KotobaCid`.
///
/// Accepts bare multibase strings (no scheme) for convenience.
fn parse_cid_iri(iri: &str) -> Option<KotobaCid> {
    let mb = iri.strip_prefix("cid:").unwrap_or(iri);
    KotobaCid::from_multibase(mb)
}

/// Extract the plain string value from a `GroundTerm` (used by VALUES bindings).
///
/// spargebra's `Display` for a `Literal` wraps the value in double-quotes
/// (e.g. `"admin"`), so we strip them to recover the raw string.
fn ground_term_to_str(gt: &spargebra::term::GroundTerm) -> String {
    use spargebra::term::GroundTerm;
    match gt {
        GroundTerm::NamedNode(nn) => nn.as_str().to_string(),
        GroundTerm::Literal(lit)  => lit.value().to_string(),
        #[allow(unreachable_patterns)]
        other => {
            let s = other.to_string();
            // Fallback: strip surrounding quotes if any
            if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                s[1..s.len()-1].to_string()
            } else {
                s
            }
        }
    }
}

/// Structural equality check on two quads (ignores graph field — same graph assumed).
fn quad_eq(a: &Quad, b: &Quad) -> bool {
    a.subject == b.subject
        && a.predicate == b.predicate
        && match (&a.object, &b.object) {
            (kotoba_kqe::quad::QuadObject::Text(at), kotoba_kqe::quad::QuadObject::Text(bt)) => at == bt,
            (kotoba_kqe::quad::QuadObject::Cid(ac),  kotoba_kqe::quad::QuadObject::Cid(bc))  => ac == bc,
            _ => false,
        }
}

/// Evaluate a SPARQL FILTER expression against a single Quad.
///
/// The expression operates on the quad's `object` field as the bound variable value.
/// Supported expression types:
///   - `Not(expr)`                        → `!eval(expr, quad)`
///   - `Equal(Variable(_), Literal(v))`   → `quad.object.as_text() == v`
///   - `NotEqual(...)`                    → `quad.object.as_text() != v`
///   - `Or(a, b)`                         → `eval(a) || eval(b)`
///   - `And(a, b)`                        → `eval(a) && eval(b)`
///   - `FunctionCall(Contains, [_, lit])` → `quad.object.as_text().contains(v)`
///   - `Exists` / other                   → `true` (pass through)
// ── SPARQL UPDATE helpers ────────────────────────────────────────────────────

fn sparql_graph_name_to_cid(
    gn: &spargebra::term::GraphName,
    default: &KotobaCid,
) -> anyhow::Result<KotobaCid> {
    match gn {
        spargebra::term::GraphName::DefaultGraph => Ok(default.clone()),
        spargebra::term::GraphName::NamedNode(nn) => {
            let s = strip_bgp_base(nn.as_str());
            parse_cid_iri(s)
                .ok_or_else(|| anyhow::anyhow!("UPDATE: graph IRI is not a valid CID: {}", nn.as_str()))
        }
    }
}

fn sparql_named_node_to_cid(iri: &str) -> anyhow::Result<KotobaCid> {
    // Strip base prefix (k:) or cid: prefix then parse as multibase KotobaCid
    let s = strip_bgp_base(iri);
    parse_cid_iri(s)
        .ok_or_else(|| anyhow::anyhow!("UPDATE: subject IRI is not a valid CID: {iri}"))
}

fn sparql_term_to_quad_object(term: &spargebra::term::Term) -> anyhow::Result<kotoba_kqe::quad::QuadObject> {
    use spargebra::term::Term;
    match term {
        Term::Literal(lit) => {
            let v = lit.value();
            if let Ok(i) = v.parse::<i64>() { return Ok(kotoba_kqe::quad::QuadObject::Integer(i)); }
            if let Ok(f) = v.parse::<f64>() { return Ok(kotoba_kqe::quad::QuadObject::Float(f)); }
            if v == "true" || v == "false" {
                return Ok(kotoba_kqe::quad::QuadObject::Bool(v == "true"));
            }
            Ok(kotoba_kqe::quad::QuadObject::Text(v.to_string()))
        }
        Term::NamedNode(nn) => {
            let s = strip_bgp_base(nn.as_str());
            match KotobaCid::from_multibase(s) {
                Some(c) => Ok(kotoba_kqe::quad::QuadObject::Cid(c)),
                None    => Ok(kotoba_kqe::quad::QuadObject::Text(s.to_string())),
            }
        }
        Term::BlankNode(_) => anyhow::bail!("UPDATE: blank node objects are not supported"),
    }
}

fn sparql_term_to_quad_object_ground(term: &spargebra::term::GroundTerm) -> anyhow::Result<kotoba_kqe::quad::QuadObject> {
    use spargebra::term::GroundTerm;
    match term {
        GroundTerm::Literal(lit) => {
            let v = lit.value();
            if let Ok(i) = v.parse::<i64>() { return Ok(kotoba_kqe::quad::QuadObject::Integer(i)); }
            if let Ok(f) = v.parse::<f64>() { return Ok(kotoba_kqe::quad::QuadObject::Float(f)); }
            if v == "true" || v == "false" {
                return Ok(kotoba_kqe::quad::QuadObject::Bool(v == "true"));
            }
            Ok(kotoba_kqe::quad::QuadObject::Text(v.to_string()))
        }
        GroundTerm::NamedNode(nn) => {
            let s = strip_bgp_base(nn.as_str());
            match KotobaCid::from_multibase(s) {
                Some(c) => Ok(kotoba_kqe::quad::QuadObject::Cid(c)),
                None    => Ok(kotoba_kqe::quad::QuadObject::Text(s.to_string())),
            }
        }
    }
}

fn eval_filter_expr(expr: &spargebra::algebra::Expression, quad: &Quad) -> bool {
    use spargebra::algebra::Expression;
    use spargebra::algebra::Function;

    let obj_text = match &quad.object {
        kotoba_kqe::quad::QuadObject::Text(t) => Some(t.as_str()),
        _ => None,
    };

    match expr {
        Expression::Not(inner) => !eval_filter_expr(inner, quad),
        Expression::Or(a, b)   => eval_filter_expr(a, quad) || eval_filter_expr(b, quad),
        Expression::And(a, b)  => eval_filter_expr(a, quad) && eval_filter_expr(b, quad),

        Expression::Equal(left, right) => {
            extract_literal_from_expr(left, right)
                .or_else(|| extract_literal_from_expr(right, left))
                .map_or(true, |v| obj_text.map_or(false, |t| t == v.as_str()))
        }
        Expression::Greater(left, right) => {
            if let (Some(obj), Some(v)) = (
                obj_text,
                extract_literal_from_expr(left, right).or_else(|| extract_literal_from_expr(right, left)),
            ) {
                cmp_values(obj, v.as_str()) == std::cmp::Ordering::Greater
            } else { true }
        }
        Expression::GreaterOrEqual(left, right) => {
            if let (Some(obj), Some(v)) = (
                obj_text,
                extract_literal_from_expr(left, right).or_else(|| extract_literal_from_expr(right, left)),
            ) {
                cmp_values(obj, v.as_str()) != std::cmp::Ordering::Less
            } else { true }
        }
        Expression::Less(left, right) => {
            if let (Some(obj), Some(v)) = (
                obj_text,
                extract_literal_from_expr(left, right).or_else(|| extract_literal_from_expr(right, left)),
            ) {
                cmp_values(obj, v.as_str()) == std::cmp::Ordering::Less
            } else { true }
        }
        Expression::LessOrEqual(left, right) => {
            if let (Some(obj), Some(v)) = (
                obj_text,
                extract_literal_from_expr(left, right).or_else(|| extract_literal_from_expr(right, left)),
            ) {
                cmp_values(obj, v.as_str()) != std::cmp::Ordering::Greater
            } else { true }
        }

        Expression::FunctionCall(Function::Contains, args) if args.len() == 2 => {
            let substring = match &args[1] {
                Expression::Literal(lit) => Some(lit.value().to_string()),
                _ => None,
            };
            substring.map_or(true, |v| obj_text.map_or(false, |t| t.contains(v.as_str())))
        }
        Expression::FunctionCall(Function::StrStarts, args) if args.len() == 2 => {
            let prefix = match &args[1] {
                Expression::Literal(lit) => Some(lit.value().to_string()),
                _ => None,
            };
            prefix.map_or(true, |v| obj_text.map_or(false, |t| t.starts_with(v.as_str())))
        }

        // Unknown / unsupported expressions: pass-through (don't discard results)
        _ => true,
    }
}

/// Extract a literal string from `Equal(Variable(_), Literal(v))` or `Equal(Literal(v), Variable(_))`.
fn extract_literal_from_expr(
    var_side: &spargebra::algebra::Expression,
    lit_side: &spargebra::algebra::Expression,
) -> Option<String> {
    use spargebra::algebra::Expression;
    if matches!(var_side, Expression::Variable(_)) {
        if let Expression::Literal(lit) = lit_side {
            return Some(lit.value().to_string());
        }
    }
    None
}

/// Compare two string values, preferring numeric comparison when both parse as i64.
fn cmp_values(a: &str, b: &str) -> std::cmp::Ordering {
    if let (Ok(ai), Ok(bi)) = (a.parse::<i64>(), b.parse::<i64>()) {
        return ai.cmp(&bi);
    }
    if let (Ok(af), Ok(bf)) = (a.parse::<f64>(), b.parse::<f64>()) {
        return af.partial_cmp(&bf).unwrap_or(std::cmp::Ordering::Equal);
    }
    a.cmp(b)
}

/// Return a human-readable name for a GraphPattern variant (for error messages).
fn sparql_pattern_name(pattern: &spargebra::algebra::GraphPattern) -> &'static str {
    use spargebra::algebra::GraphPattern;
    match pattern {
        GraphPattern::Bgp { .. }       => "BGP",
        GraphPattern::Join { .. }      => "Join",
        GraphPattern::LeftJoin { .. }  => "LeftJoin",
        GraphPattern::Filter { .. }    => "Filter",
        GraphPattern::Union { .. }     => "Union",
        GraphPattern::Group { .. }     => "Group",
        GraphPattern::Extend { .. }    => "Extend",
        GraphPattern::Graph { .. }     => "Graph",
        GraphPattern::Minus { .. }     => "Minus",
        GraphPattern::Values { .. }    => "Values",
        GraphPattern::OrderBy { .. }   => "OrderBy",
        GraphPattern::Project { .. }   => "Project",
        GraphPattern::Distinct { .. }  => "Distinct",
        GraphPattern::Reduced { .. }   => "Reduced",
        GraphPattern::Slice { .. }     => "Slice",
        GraphPattern::Path { .. }      => "Path",
        GraphPattern::Service { .. }   => "Service",
        _ => "Unknown",
    }
}

/// Extract a variable name string from an aggregate `expr` argument.
fn extract_var_name_from_expr(expr: &spargebra::algebra::Expression) -> Option<&str> {
    if let spargebra::algebra::Expression::Variable(v) = expr {
        Some(v.as_str())
    } else {
        None
    }
}

/// Extract the predicate string from a simple `NamedNode` path expression.
fn extract_named_node_from_path(
    path: &spargebra::algebra::PropertyPathExpression,
) -> Option<&str> {
    use spargebra::algebra::PropertyPathExpression;
    if let PropertyPathExpression::NamedNode(nn) = path {
        Some(strip_bgp_base(nn.as_str()))
    } else {
        None
    }
}

/// Human-readable name for a property path expression variant.
fn path_name(path: &spargebra::algebra::PropertyPathExpression) -> &'static str {
    use spargebra::algebra::PropertyPathExpression;
    match path {
        PropertyPathExpression::NamedNode(_)    => "NamedNode",
        PropertyPathExpression::Reverse(_)      => "Reverse",
        PropertyPathExpression::Sequence(_, _)  => "Sequence",
        PropertyPathExpression::Alternative(_, _) => "Alternative",
        PropertyPathExpression::ZeroOrMore(_)   => "ZeroOrMore",
        PropertyPathExpression::OneOrMore(_)    => "OneOrMore",
        PropertyPathExpression::ZeroOrOne(_)    => "ZeroOrOne",
        PropertyPathExpression::NegatedPropertySet(_) => "NegatedPropertySet",
    }
}

/// Convert a CONSTRUCT `TriplePattern` to a `QuadPattern` by adding the default graph.
fn triple_pat_to_quad_pattern(
    tp: &spargebra::term::TriplePattern,
    graph_cid: &KotobaCid,
) -> spargebra::term::QuadPattern {
    use spargebra::term::GraphNamePattern;
    // Use DefaultGraph so that instantiate_quad_pattern's graph_cid parameter is authoritative.
    spargebra::term::QuadPattern {
        subject:    tp.subject.clone(),
        predicate:  tp.predicate.clone(),
        object:     tp.object.clone(),
        graph_name: GraphNamePattern::DefaultGraph,
    }
}

/// Instantiate a `QuadPattern` (INSERT clause) by substituting variables from a matched quad.
///
/// Rules:
/// - Subject `Variable(_)` → `matched.subject`
/// - Subject `NamedNode(nn)` → parse as CID
/// - Predicate `Variable(_)` → not supported, returns `None`
/// - Predicate `NamedNode(nn)` → use directly
/// - Object `Variable(_)` → `matched.object`
/// - Object `Literal` / `NamedNode` → convert to QuadObject
fn instantiate_quad_pattern(
    pat: &spargebra::term::QuadPattern,
    graph_cid: &KotobaCid,
    matched: &Quad,
) -> Option<Quad> {
    use spargebra::term::{TermPattern, NamedNodePattern};
    let subject = match &pat.subject {
        TermPattern::Variable(_) => matched.subject.clone(),
        TermPattern::NamedNode(nn) => {
            let s = strip_bgp_base(nn.as_str());
            parse_cid_iri(s)?
        }
        _ => return None,
    };
    let predicate = match &pat.predicate {
        NamedNodePattern::NamedNode(nn) => strip_bgp_base(nn.as_str()).to_string(),
        NamedNodePattern::Variable(_) => return None,
    };
    let object = match &pat.object {
        TermPattern::Variable(_) => matched.object.clone(),
        TermPattern::Literal(lit) => {
            let v = lit.value();
            if let Ok(i) = v.parse::<i64>() { kotoba_kqe::quad::QuadObject::Integer(i) }
            else if let Ok(f) = v.parse::<f64>() { kotoba_kqe::quad::QuadObject::Float(f) }
            else if v == "true" { kotoba_kqe::quad::QuadObject::Bool(true) }
            else if v == "false" { kotoba_kqe::quad::QuadObject::Bool(false) }
            else { kotoba_kqe::quad::QuadObject::Text(v.to_string()) }
        }
        TermPattern::NamedNode(nn) => {
            let s = strip_bgp_base(nn.as_str());
            match KotobaCid::from_multibase(s) {
                Some(c) => kotoba_kqe::quad::QuadObject::Cid(c),
                None    => kotoba_kqe::quad::QuadObject::Text(s.to_string()),
            }
        }
        _ => return None,
    };
    Some(Quad { graph: graph_cid.clone(), subject, predicate, object })
}

/// Instantiate a `GroundQuadPattern` (DELETE clause) by substituting variables from a matched quad.
fn instantiate_ground_quad_pattern(
    pat: &spargebra::term::GroundQuadPattern,
    graph_cid: &KotobaCid,
    matched: &Quad,
) -> Option<Quad> {
    use spargebra::term::{GroundTermPattern, NamedNodePattern};
    let subject = match &pat.subject {
        GroundTermPattern::Variable(_) => matched.subject.clone(),
        GroundTermPattern::NamedNode(nn) => {
            let s = strip_bgp_base(nn.as_str());
            parse_cid_iri(s)?
        }
        _ => return None,
    };
    let predicate = match &pat.predicate {
        NamedNodePattern::NamedNode(nn) => strip_bgp_base(nn.as_str()).to_string(),
        NamedNodePattern::Variable(_) => return None,
    };
    let object = match &pat.object {
        GroundTermPattern::Variable(_) => matched.object.clone(),
        GroundTermPattern::Literal(lit) => {
            let v = lit.value();
            if let Ok(i) = v.parse::<i64>() { kotoba_kqe::quad::QuadObject::Integer(i) }
            else if let Ok(f) = v.parse::<f64>() { kotoba_kqe::quad::QuadObject::Float(f) }
            else if v == "true" { kotoba_kqe::quad::QuadObject::Bool(true) }
            else if v == "false" { kotoba_kqe::quad::QuadObject::Bool(false) }
            else { kotoba_kqe::quad::QuadObject::Text(v.to_string()) }
        }
        GroundTermPattern::NamedNode(nn) => {
            let s = strip_bgp_base(nn.as_str());
            match KotobaCid::from_multibase(s) {
                Some(c) => kotoba_kqe::quad::QuadObject::Cid(c),
                None    => kotoba_kqe::quad::QuadObject::Text(s.to_string()),
            }
        }
        #[allow(unreachable_patterns)]
        _ => return None,
    };
    Some(Quad { graph: graph_cid.clone(), subject, predicate, object })
}

/// If `tp` is `?svar <pred> "literal"`, return `(pred, literal, svar_name)`.
fn extract_pred_literal_triple(
    tp: &spargebra::term::TriplePattern,
) -> Option<(String, String, String)> {
    use spargebra::term::{NamedNodePattern, TermPattern};
    let svar = match &tp.subject {
        TermPattern::Variable(v) => v.as_str().to_string(),
        _ => return None,
    };
    let pred = match &tp.predicate {
        NamedNodePattern::NamedNode(nn) => strip_bgp_base(nn.as_str()).to_string(),
        _ => return None,
    };
    let val = match &tp.object {
        TermPattern::Literal(lit) => lit.value().to_string(),
        _ => return None,
    };
    Some((pred, val, svar))
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

    #[tokio::test]
    async fn prune_old_commits_removes_historical_keeps_head() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        let graph = KotobaCid::from_bytes(b"prune-graph");

        // Three commits — each bumps committed_seq.
        for i in 0u64..3 {
            qs.assert(make_quad("prune-graph", &format!("s{i}"), "p", "v")).await;
            qs.commit("did:test", graph.clone(), i + 1).await.unwrap();
        }
        // After 3 commits the CommitDag holds 3 entries.
        assert_eq!(qs.commit_dag_size().await, 3);

        // Prune commits where seq < committed_seq (i.e. keep only the HEAD at seq=3).
        let pruned = qs.prune_old_commits(3).await;
        assert_eq!(pruned, 2, "two historical commits should be pruned");
        assert_eq!(qs.commit_dag_size().await, 1, "only HEAD survives");

        // HEAD is still reachable for GC and queries.
        let dag = qs.commit_dag.read().await;
        assert!(dag.head(&graph).is_some(), "HEAD must survive prune");
    }

    // ── additional gap tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn arrangement_unknown_graph_returns_none() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        let unknown     = KotobaCid::from_bytes(b"never-asserted");
        assert!(qs.arrangement(&unknown).await.is_none());
    }

    #[tokio::test]
    async fn head_commit_unknown_graph_returns_none() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        let unknown     = KotobaCid::from_bytes(b"no-commits-here");
        assert!(qs.head_commit(&unknown).await.is_none());
    }

    #[tokio::test]
    async fn commit_dag_size_is_zero_initially() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        assert_eq!(qs.commit_dag_size().await, 0);
    }

    #[tokio::test]
    async fn count_by_predicate_prefix_unknown_graph_returns_zero() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        let unknown     = KotobaCid::from_bytes(b"no-graph");
        assert_eq!(qs.count_by_predicate_prefix(&unknown, "ai.gftd/").await, 0);
    }

    #[tokio::test]
    async fn snapshot_deltas_unknown_graph_returns_empty() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        let unknown     = KotobaCid::from_bytes(b"empty-graph");
        let deltas      = qs.snapshot_deltas(&unknown).await;
        assert!(deltas.is_empty());
    }

    #[tokio::test]
    async fn commits_since_empty_when_no_commits() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);
        let graph       = KotobaCid::from_bytes(b"empty-dag-graph");
        let result      = qs.commits_since(&graph, None).await;
        assert!(result.is_empty(), "no commits → commits_since must return empty");
    }

    // ── complex / compound cold-path query tests ──────────────────────────────

    fn make_cid_from(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

    #[tokio::test]
    async fn multi_hop_cold_follows_cid_references() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);

        let graph = make_cid_from("hop-graph");
        let alice = make_cid_from("alice");
        let bob   = make_cid_from("bob");

        // alice --knows--> bob (CID ref)
        qs.assert(Quad {
            graph: graph.clone(), subject: alice.clone(),
            predicate: "knows".into(), object: QuadObject::Cid(bob.clone()),
        }).await;
        qs.assert(Quad {
            graph: graph.clone(), subject: alice.clone(),
            predicate: "name".into(), object: QuadObject::Text("Alice".into()),
        }).await;
        // bob's own quad
        qs.assert(Quad {
            graph: graph.clone(), subject: bob.clone(),
            predicate: "name".into(), object: QuadObject::Text("Bob".into()),
        }).await;

        qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.reset_arrangement(&graph).await;

        // 1-hop: depth 0 = alice quads, depth 1 = bob quads
        let hops = qs.multi_hop_cold(&graph, &alice, 1).await.unwrap();
        let depth_0: Vec<_> = hops.iter().filter(|(d, _)| *d == 0).collect();
        let depth_1: Vec<_> = hops.iter().filter(|(d, _)| *d == 1).collect();
        assert_eq!(depth_0.len(), 2, "alice has 2 quads");
        assert_eq!(depth_1.len(), 1, "bob has 1 quad (name)");
        assert_eq!(depth_1[0].1.predicate, "name");
    }

    #[tokio::test]
    async fn multi_hop_cold_max_hops_zero_returns_only_start() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);

        let graph   = make_cid_from("hop-zero");
        let alice   = make_cid_from("alice2");
        let bob     = make_cid_from("bob2");
        qs.assert(Quad {
            graph: graph.clone(), subject: alice.clone(),
            predicate: "knows".into(), object: QuadObject::Cid(bob.clone()),
        }).await;
        qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.reset_arrangement(&graph).await;

        let hops = qs.multi_hop_cold(&graph, &alice, 0).await.unwrap();
        assert_eq!(hops.len(), 1, "max_hops=0 returns only start quads");
        assert_eq!(hops[0].0, 0, "depth must be 0");
    }

    #[tokio::test]
    async fn join_by_two_predicates_cold_returns_intersection() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);

        let graph = make_cid_from("join-graph");
        let alice = make_cid_from("ja");
        let bob   = make_cid_from("jb");
        let carol = make_cid_from("jc");

        for (s, name, role) in [
            (&alice, "Alice", "admin"),
            (&bob,   "Bob",   "user"),
            (&carol, "Carol", "admin"),
        ] {
            qs.assert(Quad { graph: graph.clone(), subject: s.clone(),
                predicate: "name".into(), object: QuadObject::Text(name.into()) }).await;
            qs.assert(Quad { graph: graph.clone(), subject: s.clone(),
                predicate: "role".into(), object: QuadObject::Text(role.into()) }).await;
        }
        qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.reset_arrangement(&graph).await;

        // subjects where name=Alice AND role=admin → only alice
        let results = qs.join_by_two_predicates_cold(&graph, "name", "Alice", "role", "admin").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, alice.0);

        // subjects where role=admin → alice + carol
        let admins = qs.join_by_two_predicates_cold(&graph, "role", "admin", "role", "admin").await.unwrap();
        assert_eq!(admins.len(), 2);
    }

    #[tokio::test]
    async fn join_by_two_predicates_cold_empty_when_no_overlap() {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new());
        let qs          = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store) as _);

        let graph = make_cid_from("join-empty");
        let alice = make_cid_from("je-alice");
        qs.assert(Quad { graph: graph.clone(), subject: alice.clone(),
            predicate: "role".into(), object: QuadObject::Text("admin".into()) }).await;
        qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.reset_arrangement(&graph).await;

        let results = qs.join_by_two_predicates_cold(&graph, "role", "admin", "role", "superuser").await.unwrap();
        assert!(results.is_empty(), "no entity has both admin and superuser");
    }

    // ── CACAO-authed cold-path tests ──────────────────────────────────────────
    // Rejection tests fail before crypto (capability / graph-scope mismatch).
    // Acceptance tests use new_for_test() + verify_skip_sig() (test-only bypass).

    async fn setup_committed_qs(graph_key: &str, subject_key: &str, pred: &str, val: &str)
        -> (QuadStore, KotobaCid, KotobaCid)
    {
        let journal = Arc::new(Journal::new());
        let bs      = Arc::new(MemoryBlockStore::new());
        let qs      = QuadStore::new(Arc::clone(&journal), Arc::clone(&bs) as _);
        let g       = make_cid_from(graph_key);
        let s       = make_cid_from(subject_key);
        qs.assert(Quad { graph: g.clone(), subject: s.clone(),
            predicate: pred.into(), object: QuadObject::Text(val.into()) }).await;
        qs.commit("did:test", g.clone(), 1).await.unwrap();
        qs.reset_arrangement(&g).await;
        (qs, g, s)
    }

    #[tokio::test]
    async fn cacao_authed_read_rejected_wrong_capability() {
        let (qs, graph, subject) = setup_committed_qs("cacao-cap-g", "cacao-cap-s", "p", "v").await;
        let graph_mb = graph.to_multibase();
        // Chain grants quad:write, not quad:read
        let chain = DelegationChain::new_for_test(&graph_mb, "quad:write");
        let result = qs.get_entity_quads_cold_authed(&graph, &subject, &chain).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))),
            "quad:write chain must not satisfy quad:read");
    }

    #[tokio::test]
    async fn cacao_authed_read_rejected_wrong_graph() {
        let (qs, graph, subject) = setup_committed_qs("cacao-gph-g", "cacao-gph-s", "p", "v").await;
        // Chain grants read on a different graph
        let chain = DelegationChain::new_for_test("different-graph-cid", "quad:read");
        let result = qs.get_entity_quads_cold_authed(&graph, &subject, &chain).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))),
            "chain for wrong graph must be rejected");
    }

    #[tokio::test]
    async fn cacao_authed_aevt_rejected_wrong_capability() {
        let (qs, graph, _) = setup_committed_qs("cacao-aevt-g", "cacao-aevt-s", "name", "Alice").await;
        let graph_mb = graph.to_multibase();
        let chain = DelegationChain::new_for_test(&graph_mb, "quad:write");
        let result = qs.quads_by_predicate_prefix_cold_authed(&graph, "name", &chain).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cacao_authed_avet_rejected_wrong_graph() {
        let (qs, graph, _) = setup_committed_qs("cacao-avet-g", "cacao-avet-s", "role", "admin").await;
        let chain = DelegationChain::new_for_test("wrong-graph", "quad:read");
        let result = qs.lookup_subject_by_po_cold_authed(&graph, "role", "admin", &chain).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cacao_authed_multi_hop_rejected_wrong_graph() {
        let (qs, graph, subject) = setup_committed_qs("cacao-mh-g", "cacao-mh-s", "p", "v").await;
        let chain = DelegationChain::new_for_test("wrong-graph", "quad:read");
        let result = qs.multi_hop_cold_authed(&graph, &subject, 1, &chain).await;
        assert!(result.is_err(), "wrong graph must be rejected");
    }

    #[tokio::test]
    async fn cacao_authed_read_succeeds_with_correct_chain() {
        let (qs, graph, subject) = setup_committed_qs("cacao-ok-g", "cacao-ok-s", "name", "OkSubj").await;
        let graph_mb = graph.to_multibase();
        let chain    = DelegationChain::new_for_test(&graph_mb, "quad:read");
        // verify_skip_sig to confirm chain shape is correct, then use it for the authed call
        assert!(chain.verify_skip_sig(&graph_mb, "quad:read").is_ok());
        // The authed call will hit verify() which calls verify_signature() → will err on fake sig.
        // This confirms the auth layer is wired; real acceptance requires a properly signed CACAO.
        let result = qs.get_entity_quads_cold_authed(&graph, &subject, &chain).await;
        // We expect an error at the sig step, NOT at the capability/graph step.
        match result {
            Err(AccessError::Delegation(e)) => {
                let msg = e.to_string();
                assert!(!msg.contains("need 'quad:read'") && !msg.contains("graph mismatch"),
                    "error must be at sig step, not cap/graph: {msg}");
            }
            Ok(_) => {} // passes on future test infra with real crypto
            Err(AccessError::Internal(e)) => panic!("unexpected internal error: {e}"),
        }
    }

    // ─── assert_batch_authed tests ────────────────────────────────────────────

    #[tokio::test]
    async fn batch_authed_rejected_wrong_capability() {
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"batch-authed-g1");
        let subject = KotobaCid::from_bytes(b"batch-authed-s1");
        let graph_mb = graph.to_multibase();
        // chain grants quad:read — not quad:write
        let chain = DelegationChain::new_for_test(&graph_mb, "quad:read");
        let quads = vec![Quad {
            graph: graph.clone(),
            subject: subject.clone(),
            predicate: "role".to_string(),
            object: QuadObject::Text("admin".to_string()),
        }];
        let result = qs.assert_batch_authed(quads, &chain).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))),
            "wrong-capability chain must be rejected");
    }

    #[tokio::test]
    async fn batch_authed_rejected_wrong_graph() {
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph   = KotobaCid::from_bytes(b"batch-authed-g2");
        let subject = KotobaCid::from_bytes(b"batch-authed-s2");
        // chain is for a different graph
        let other_graph_mb = KotobaCid::from_bytes(b"other-graph").to_multibase();
        let chain = DelegationChain::new_for_test(&other_graph_mb, "quad:write");
        let quads = vec![Quad {
            graph: graph.clone(),
            subject,
            predicate: "role".to_string(),
            object: QuadObject::Text("admin".to_string()),
        }];
        let result = qs.assert_batch_authed(quads, &chain).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))),
            "wrong-graph chain must be rejected");
    }

    #[tokio::test]
    async fn batch_authed_succeeds_writes_quads() {
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph   = KotobaCid::from_bytes(b"batch-authed-g3");
        let subject = KotobaCid::from_bytes(b"batch-authed-s3");
        let graph_mb = graph.to_multibase();
        let chain = DelegationChain::new_for_test(&graph_mb, "quad:write");
        let quads = vec![
            Quad { graph: graph.clone(), subject: subject.clone(),
                   predicate: "name".to_string(),
                   object: QuadObject::Text("Alice".to_string()) },
            Quad { graph: graph.clone(), subject: subject.clone(),
                   predicate: "role".to_string(),
                   object: QuadObject::Text("admin".to_string()) },
        ];
        // verify_skip_sig to ensure chain shape is correct (sig check skipped in test)
        assert!(chain.verify_skip_sig(&graph_mb, "quad:write").is_ok());
        // assert_batch_authed calls chain.verify() which will fail on fake sig;
        // confirm it fails at sig step not cap/graph step
        let result = qs.assert_batch_authed(quads.clone(), &chain).await;
        match result {
            Err(AccessError::Delegation(e)) => {
                let msg = e.to_string();
                assert!(!msg.contains("need 'quad:write'") && !msg.contains("graph mismatch"),
                    "error must be at sig step: {msg}");
            }
            Ok(n) => assert_eq!(n, 2), // passes with real crypto
            Err(AccessError::Internal(e)) => panic!("unexpected internal error: {e}"),
        }
    }

    #[tokio::test]
    async fn batch_authed_rejects_multi_graph_wrong_graph() {
        // Batch spanning two named graphs: chain scoped to graph A only →
        // quad from graph B must cause rejection.
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph_a = KotobaCid::from_bytes(b"batch-multi-g-a");
        let graph_b = KotobaCid::from_bytes(b"batch-multi-g-b");
        let subj    = KotobaCid::from_bytes(b"batch-multi-s");
        let graph_a_mb = graph_a.to_multibase();
        let chain = DelegationChain::new_for_test(&graph_a_mb, "quad:write");
        let quads = vec![
            Quad { graph: graph_a.clone(), subject: subj.clone(),
                   predicate: "name".to_string(), object: QuadObject::Text("A".to_string()) },
            Quad { graph: graph_b.clone(), subject: subj.clone(),
                   predicate: "name".to_string(), object: QuadObject::Text("B".to_string()) },
        ];
        let result = qs.assert_batch_authed(quads, &chain).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))),
            "cross-graph batch with single-graph chain must be rejected");
    }

    // ── SPARQL BGP cold-path routing tests ────────────────────────────────────

    async fn setup_sparql_qs() -> (QuadStore, KotobaCid) {
        let qs    = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"sparql-bgp-graph");
        let alice = KotobaCid::from_bytes(b"alice");
        let bob   = KotobaCid::from_bytes(b"bob");
        let carol = KotobaCid::from_bytes(b"carol");

        for (subj, name, role) in [
            (&alice, "Alice", "admin"),
            (&bob,   "Bob",   "user"),
            (&carol, "Carol", "admin"),
        ] {
            qs.assert(Quad { graph: graph.clone(), subject: (*subj).clone(),
                predicate: "name".into(), object: QuadObject::Text(name.to_string()) }).await;
            qs.assert(Quad { graph: graph.clone(), subject: (*subj).clone(),
                predicate: "role".into(), object: QuadObject::Text(role.to_string()) }).await;
        }
        // alice knows bob (CID reference for VAET)
        qs.assert(Quad { graph: graph.clone(), subject: alice.clone(),
            predicate: "knows".into(), object: QuadObject::Cid(bob.clone()) }).await;

        qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.reset_arrangement(&graph).await;
        (qs, graph)
    }

    #[tokio::test]
    async fn sparql_bgp_avet_pred_literal() {
        // ?s <role> "admin" → AVET → returns Alice and Carol
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <role> "admin" }"#,
        ).await.unwrap();
        assert_eq!(quads.len(), 2, "two admins expected, got {}", quads.len());
        let preds: Vec<_> = quads.iter().map(|q| q.predicate.as_str()).collect();
        assert!(preds.iter().all(|&p| p == "role"), "predicate must be role");
    }

    #[tokio::test]
    async fn sparql_bgp_aevt_pred_only() {
        // ?s <name> ?o → AEVT → returns all 3 name quads
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT * WHERE { ?s <name> ?o }",
        ).await.unwrap();
        assert_eq!(quads.len(), 3, "three name quads expected");
        assert!(quads.iter().all(|q| q.predicate == "name"));
    }

    #[tokio::test]
    async fn sparql_bgp_eavt_bound_subject() {
        // <cid:alice> ?p ?o → EAVT → returns alice's quads
        let (qs, graph) = setup_sparql_qs().await;
        let alice_mb = KotobaCid::from_bytes(b"alice").to_multibase();
        let sparql = format!("SELECT * WHERE {{ <cid:{alice_mb}> ?p ?o }}");
        let quads = qs.cold_query_sparql_bgp(&graph, &sparql).await.unwrap();
        // alice has: name, role, knows → 3 quads
        assert_eq!(quads.len(), 3, "alice has 3 quads, got {}", quads.len());
        assert!(quads.iter().all(|q| q.subject == KotobaCid::from_bytes(b"alice")));
    }

    #[tokio::test]
    async fn sparql_bgp_vaet_bound_object_cid() {
        // ?s ?p <cid:bob> → VAET → alice knows bob
        let (qs, graph) = setup_sparql_qs().await;
        let bob_mb = KotobaCid::from_bytes(b"bob").to_multibase();
        let sparql = format!("SELECT * WHERE {{ ?s ?p <cid:{bob_mb}> }}");
        let quads = qs.cold_query_sparql_bgp(&graph, &sparql).await.unwrap();
        assert_eq!(quads.len(), 1, "one subject knows bob");
        assert_eq!(quads[0].predicate, "knows");
        assert_eq!(quads[0].subject, KotobaCid::from_bytes(b"alice"));
    }

    #[tokio::test]
    async fn sparql_bgp_join_two_predicates() {
        // ?s <name> "Alice" . ?s <role> "admin" → join → only alice
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <name> "Alice" . ?s <role> "admin" }"#,
        ).await.unwrap();
        // 2 synthetic quads per matched subject (name + role)
        assert_eq!(quads.len(), 2, "one subject × 2 quads expected");
        let preds: std::collections::HashSet<_> = quads.iter().map(|q| q.predicate.as_str()).collect();
        assert!(preds.contains("name") && preds.contains("role"));
    }

    #[tokio::test]
    async fn sparql_bgp_join_no_overlap() {
        // ?s <name> "Alice" . ?s <role> "user" → no match
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <name> "Alice" . ?s <role> "user" }"#,
        ).await.unwrap();
        assert!(quads.is_empty(), "Alice is admin not user");
    }

    // ─── N-triple BGP (general join) ─────────────────────────────────────────

    #[tokio::test]
    async fn sparql_bgp_three_triple_intersection() {
        // 3-triple BGP: ?s <role> "admin" . ?s <name> ?n . ?s <knows> ?o
        // Only Alice has role=admin AND has a name AND has a knows edge.
        // Carol has role=admin + name but NO knows edge → excluded.
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <role> "admin" . ?s <name> ?n . ?s <knows> ?o }"#,
        ).await.unwrap();
        // Alice: role, name, knows = 3 quads
        assert_eq!(quads.len(), 3, "Alice only (admin + name + knows = 3 quads), got {}", quads.len());
        let preds: std::collections::HashSet<_> = quads.iter().map(|q| q.predicate.as_str()).collect();
        assert!(preds.contains("role") && preds.contains("name") && preds.contains("knows"),
            "all 3 predicates expected");
        // All quads must be Alice's
        let alice = KotobaCid::from_bytes(b"alice");
        assert!(quads.iter().all(|q| q.subject == alice), "subject must be alice");
    }

    #[tokio::test]
    async fn sparql_bgp_three_triple_no_match() {
        // 3-triple BGP: ?s <role> "user" . ?s <name> ?n . ?s <knows> ?o
        // Bob is user+name but has NO knows edge → empty result
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <role> "user" . ?s <name> ?n . ?s <knows> ?o }"#,
        ).await.unwrap();
        assert!(quads.is_empty(), "Bob has no knows edge — intersection must be empty");
    }

    #[tokio::test]
    async fn sparql_bgp_two_triple_general_path_pred_only() {
        // 2-triple BGP where both triples have unbound objects (not pred+literal fast path)
        // ?s <name> ?n . ?s <role> ?r → all 3 subjects, each with name + role = 6 quads
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT * WHERE { ?s <name> ?n . ?s <role> ?r }",
        ).await.unwrap();
        // 3 subjects × 2 preds = 6 quads
        assert_eq!(quads.len(), 6, "3 subjects × 2 preds = 6 quads, got {}", quads.len());
        let preds: std::collections::HashSet<_> = quads.iter().map(|q| q.predicate.as_str()).collect();
        assert!(preds.contains("name") && preds.contains("role"));
    }

    #[tokio::test]
    async fn sparql_bgp_n_triple_with_cacao_auth() {
        // Real EdDSA CACAO + 3-triple BGP
        let (qs, graph) = setup_sparql_qs().await;
        let chain = make_real_eddsa_cacao(&graph.to_multibase(), "quad:read");
        let result = qs.cold_query_sparql_bgp_authed(
            &graph,
            r#"SELECT * WHERE { ?s <role> "admin" . ?s <name> ?n . ?s <knows> ?o }"#,
            &chain,
        ).await;
        assert!(result.is_ok(), "real EdDSA + 3-triple BGP: {:?}", result.err());
        let quads = result.unwrap();
        assert_eq!(quads.len(), 3, "Alice only (3 quads), got {}", quads.len());
    }

    // ── GraphPattern::Graph tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_graph_bound_named_graph_returns_quads() {
        // GRAPH <cid_multibase> { ?s <role> "admin" } → same as direct AVET query
        let (qs, graph) = setup_sparql_qs().await;
        let graph_iri = graph.to_multibase();
        let sparql = format!(r#"SELECT * WHERE {{ GRAPH <{}> {{ ?s <role> "admin" }} }}"#, graph_iri);
        let quads = qs.cold_query_sparql_bgp(&graph, &sparql).await.unwrap();
        assert_eq!(quads.len(), 2, "two admins in bound named graph, got {}", quads.len());
        assert!(quads.iter().all(|q| q.predicate == "role"),
            "all quads should have predicate=role");
    }

    #[tokio::test]
    async fn sparql_graph_bound_unknown_iri_returns_empty() {
        // GRAPH <unknown_cid> { ?s ?p ?o } → empty (graph not found)
        let (qs, graph) = setup_sparql_qs().await;
        let unknown = KotobaCid::from_bytes(b"unknown-graph-cid");
        let sparql = format!("SELECT * WHERE {{ GRAPH <{}> {{ ?s <name> ?n }} }}", unknown.to_multibase());
        let quads = qs.cold_query_sparql_bgp(&graph, &sparql).await.unwrap();
        assert!(quads.is_empty(), "unknown graph IRI should return empty, got {}", quads.len());
    }

    #[tokio::test]
    async fn sparql_graph_variable_multi_graph_returns_all() {
        // Two committed graphs; GRAPH ?g { ?s <role> "admin" } returns quads from both.
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph_a = KotobaCid::from_bytes(b"multi-graph-a");
        let graph_b = KotobaCid::from_bytes(b"multi-graph-b");
        let alice = KotobaCid::from_bytes(b"alice-multi");
        let dave  = KotobaCid::from_bytes(b"dave-multi");

        qs.assert(Quad { graph: graph_a.clone(), subject: alice.clone(),
            predicate: "role".into(), object: QuadObject::Text("admin".into()) }).await;
        qs.assert(Quad { graph: graph_b.clone(), subject: dave.clone(),
            predicate: "role".into(), object: QuadObject::Text("admin".into()) }).await;

        qs.commit("did:test-a", graph_a.clone(), 1).await.unwrap();
        qs.reset_arrangement(&graph_a).await;
        qs.commit("did:test-b", graph_b.clone(), 2).await.unwrap();
        qs.reset_arrangement(&graph_b).await;

        // Use graph_a as the "outer" default graph (just satisfies the function signature)
        let sparql = r#"SELECT * WHERE { GRAPH ?g { ?s <role> "admin" } }"#;
        let quads = qs.cold_query_sparql_bgp(&graph_a, sparql).await.unwrap();
        assert_eq!(quads.len(), 2,
            "one admin per graph × 2 graphs = 2 quads, got {}", quads.len());
        let graphs_seen: std::collections::HashSet<String> =
            quads.iter().map(|q| q.graph.to_multibase()).collect();
        assert_eq!(graphs_seen.len(), 2, "results should span both graphs");
    }

    #[tokio::test]
    async fn sparql_graph_variable_with_real_eddsa_cacao() {
        // Real EdDSA CACAO + GRAPH ?g { ?s <role> "admin" } spanning two graphs
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph_a = KotobaCid::from_bytes(b"cacao-graph-a");
        let graph_b = KotobaCid::from_bytes(b"cacao-graph-b");

        for (g, name) in [(&graph_a, "AdminA"), (&graph_b, "AdminB")] {
            let s = KotobaCid::from_bytes(name.as_bytes());
            qs.assert(Quad { graph: g.clone(), subject: s,
                predicate: "role".into(), object: QuadObject::Text("admin".into()) }).await;
            qs.commit(&format!("did:test-{name}"), g.clone(), 1).await.unwrap();
            qs.reset_arrangement(g).await;
        }

        // Auth is scoped to graph_a (the outer default graph passed to cold_query_sparql_bgp_authed)
        let chain = make_real_eddsa_cacao(&graph_a.to_multibase(), "quad:read");
        let sparql = r#"SELECT * WHERE { GRAPH ?g { ?s <role> "admin" } }"#;
        let result = qs.cold_query_sparql_bgp_authed(&graph_a, sparql, &chain).await;
        assert!(result.is_ok(), "real EdDSA CACAO + GRAPH ?g: {:?}", result.err());
        let quads = result.unwrap();
        assert_eq!(quads.len(), 2, "2 admin quads across 2 graphs, got {}", quads.len());
    }

    // ── DISTINCT tests ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_distinct_deduplicates_union_overlap() {
        // UNION of two overlapping BGPs; DISTINCT removes duplicate quads
        let (qs, graph) = setup_sparql_qs().await;
        // Without DISTINCT: both sides of UNION produce admins → Alice+Carol appears twice
        let no_distinct = r#"SELECT * WHERE {
            { ?s <role> "admin" } UNION { ?s <role> "admin" }
        }"#;
        let quads_dup = qs.cold_query_sparql_bgp(&graph, no_distinct).await.unwrap();
        // Our Union handler already deduplicates by quad_eq, so this is 2 even without DISTINCT
        assert_eq!(quads_dup.len(), 2);

        // With DISTINCT: explicit deduplication (same 2 unique quads)
        let with_distinct = r#"SELECT DISTINCT * WHERE {
            { ?s <role> "admin" } UNION { ?s <role> "admin" }
        }"#;
        let quads_dist = qs.cold_query_sparql_bgp(&graph, with_distinct).await.unwrap();
        assert_eq!(quads_dist.len(), 2, "DISTINCT should keep 2 unique admin quads, got {}", quads_dist.len());
    }

    #[tokio::test]
    async fn sparql_distinct_cross_graph() {
        // GRAPH ?g + DISTINCT: cross-graph deduplication by (s, p, o) ignoring graph CID
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let ga = KotobaCid::from_bytes(b"dist-graph-a");
        let gb = KotobaCid::from_bytes(b"dist-graph-b");
        let s  = KotobaCid::from_bytes(b"shared-subject");

        // Same triple in both graphs
        for g in [&ga, &gb] {
            qs.assert(Quad { graph: g.clone(), subject: s.clone(),
                predicate: "role".into(), object: QuadObject::Text("admin".into()) }).await;
            qs.commit("did:dist-test", g.clone(), 1).await.unwrap();
            qs.reset_arrangement(g).await;
        }

        // Without DISTINCT: GRAPH ?g returns 2 quads (same triple in 2 graphs)
        let no_dist = r#"SELECT * WHERE { GRAPH ?g { ?s <role> "admin" } }"#;
        let all = qs.cold_query_sparql_bgp(&ga, no_dist).await.unwrap();
        assert_eq!(all.len(), 2, "2 quads across 2 graphs without DISTINCT");

        // With DISTINCT: deduplicates by (s, p, o) → 1 quad
        let with_dist = r#"SELECT DISTINCT * WHERE { GRAPH ?g { ?s <role> "admin" } }"#;
        let distinct = qs.cold_query_sparql_bgp(&ga, with_dist).await.unwrap();
        assert_eq!(distinct.len(), 1, "DISTINCT across graphs deduplicates to 1 triple, got {}", distinct.len());
    }

    // ── HAVING tests (numeric filter on aggregate result) ─────────────────────

    #[tokio::test]
    async fn sparql_having_filters_aggregate_groups() {
        // SELECT ?r (COUNT(*) AS ?n) WHERE { ?s <role> ?r } GROUP BY ?r HAVING (?n > 1)
        // admin=2, user=1 → only admin passes HAVING
        let (qs, graph) = setup_sparql_qs().await;
        let sparql = "SELECT ?r (COUNT(*) AS ?n) WHERE { ?s <role> ?r } GROUP BY ?r HAVING (?n > 1)";
        let quads = qs.cold_query_sparql_bgp(&graph, sparql).await.unwrap();
        assert_eq!(quads.len(), 1, "only admin (count=2) passes HAVING > 1, got {}", quads.len());
        let obj = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { panic!() };
        assert_eq!(obj, "2", "count for admin should be 2, got {obj}");
    }

    #[tokio::test]
    async fn sparql_having_ge_passes_all() {
        // HAVING (?n >= 1) passes all 2 groups (admin=2, user=1)
        let (qs, graph) = setup_sparql_qs().await;
        let sparql = "SELECT ?r (COUNT(*) AS ?n) WHERE { ?s <role> ?r } GROUP BY ?r HAVING (?n >= 1)";
        let quads = qs.cold_query_sparql_bgp(&graph, sparql).await.unwrap();
        assert_eq!(quads.len(), 2, "both groups pass HAVING >= 1, got {}", quads.len());
    }

    // ── Multi-graph CACAO delegation tests ───────────────────────────────────

    #[tokio::test]
    async fn sparql_multi_graph_cacao_filters_unauthorized() {
        // CACAO authorizes graph_a only; GRAPH ?g returns quads from graph_a+graph_b
        // → multi-graph-authed should filter to graph_a only
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph_a = KotobaCid::from_bytes(b"multi-auth-a");
        let graph_b = KotobaCid::from_bytes(b"multi-auth-b");

        for (g, role) in [(&graph_a, "admin"), (&graph_b, "admin")] {
            let s = KotobaCid::from_bytes(role.as_bytes());
            qs.assert(Quad { graph: g.clone(), subject: s,
                predicate: "role".into(), object: QuadObject::Text(role.into()) }).await;
            qs.commit("did:auth-test", g.clone(), 1).await.unwrap();
            qs.reset_arrangement(g).await;
        }

        // CACAO only authorizes graph_a
        let chain = DelegationChain::new_for_test(&graph_a.to_multibase(), "quad:read");
        let sparql = r#"SELECT * WHERE { GRAPH ?g { ?s <role> "admin" } }"#;
        let result = qs.cold_query_sparql_bgp_multi_graph_authed(&graph_a, sparql, &chain).await;
        assert!(result.is_ok());
        let quads = result.unwrap();
        assert_eq!(quads.len(), 1, "CACAO covers only graph_a → 1 quad, got {}", quads.len());
        assert_eq!(quads[0].graph, graph_a, "quad should be from graph_a");
    }

    #[tokio::test]
    async fn sparql_multi_graph_cacao_two_graphs_authorized() {
        // CACAO with two kotoba://graph/ resources → both graphs accessible
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph_a = KotobaCid::from_bytes(b"two-auth-a");
        let graph_b = KotobaCid::from_bytes(b"two-auth-b");

        for g in [&graph_a, &graph_b] {
            let s = KotobaCid::from_bytes(&g.to_multibase().as_bytes()[..36]);
            qs.assert(Quad { graph: g.clone(), subject: s,
                predicate: "role".into(), object: QuadObject::Text("admin".into()) }).await;
            qs.commit("did:two-auth", g.clone(), 1).await.unwrap();
            qs.reset_arrangement(g).await;
        }

        // Build a real-sig CACAO covering two graphs
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::{SigningKey, Signer};
        use kotoba_auth::{Cacao, CacaoHeader, CacaoPayload, CacaoSig};
        use kotoba_auth::did_key::ed25519_pubkey_to_did_key;

        let sk  = SigningKey::from_bytes(&[77u8; 32]);
        let pk  = sk.verifying_key();
        let did = ed25519_pubkey_to_did_key(pk.as_bytes());
        let template = Cacao {
            h: CacaoHeader { t: "eip4361".to_string() },
            p: CacaoPayload {
                iss:       did,
                aud:       "https://kotoba.bench".to_string(),
                issued_at: "2026-01-01T00:00:00Z".to_string(),
                expiry:    Some("2099-01-01T00:00:00Z".to_string()),
                nonce:     "multi-graph-real-sig".to_string(),
                domain:    "kotoba.bench".to_string(),
                statement: None,
                version:   "1".to_string(),
                resources: vec![
                    "kotoba://can/quad:read".to_string(),
                    format!("kotoba://graph/{}", graph_a.to_multibase()),
                    format!("kotoba://graph/{}", graph_b.to_multibase()),
                ],
            },
            s: CacaoSig { t: "EdDSA".to_string(), s: String::new() },
        };
        let msg  = template.siwe_message();
        let sig  = sk.sign(msg.as_bytes());
        let chain = DelegationChain::new(Cacao {
            s: CacaoSig { t: "EdDSA".to_string(), s: URL_SAFE_NO_PAD.encode(sig.to_bytes()) },
            ..template
        });

        let sparql = r#"SELECT * WHERE { GRAPH ?g { ?s <role> "admin" } }"#;
        let result = qs.cold_query_sparql_bgp_multi_graph_authed(&graph_a, sparql, &chain).await;
        assert!(result.is_ok(), "multi-graph real EdDSA: {:?}", result.err());
        let quads = result.unwrap();
        assert_eq!(quads.len(), 2, "2 authorized graphs → 2 quads, got {}", quads.len());
    }

    #[tokio::test]
    async fn sparql_bgp_authed_rejected_wrong_capability() {
        let (qs, graph) = setup_sparql_qs().await;
        let chain = DelegationChain::new_for_test(&graph.to_multibase(), "quad:write");
        let result = qs.cold_query_sparql_bgp_authed(
            &graph,
            r#"SELECT * WHERE { ?s <role> "admin" }"#,
            &chain,
        ).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))));
    }

    // ─── Sub-SELECT ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_sub_select_in_join() {
        // SELECT ?s ?n WHERE {
        //   { SELECT ?s WHERE { ?s <role> "admin" } }
        //   ?s <name> ?n .
        // }
        // Expected: Alice and Carol (admins) with their names
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT ?s ?n WHERE {
                { SELECT ?s WHERE { ?s <role> "admin" } }
                ?s <name> ?n .
            }"#,
        ).await.unwrap();
        // Inner sub-SELECT returns 2 admin quads; join with name predicate gives 2 name quads
        assert_eq!(quads.len(), 2, "sub-SELECT join: 2 admins × 1 name each = 2, got {}", quads.len());
        let names: Vec<String> = quads.iter().filter_map(|q| {
            if q.predicate == "name" {
                if let QuadObject::Text(t) = &q.object { Some(t.clone()) } else { None }
            } else { None }
        }).collect();
        assert!(names.contains(&"Alice".to_string()), "Alice must be in sub-SELECT result");
        assert!(names.contains(&"Carol".to_string()), "Carol must be in sub-SELECT result");
    }

    #[tokio::test]
    async fn sparql_sub_select_with_aggregate() {
        // Sub-SELECT with COUNT: join count result with outer query
        // SELECT ?r ?n WHERE {
        //   { SELECT ?r (COUNT(*) AS ?n) WHERE { ?s <role> ?r } GROUP BY ?r }
        // }
        // Expected: 2 rows — admin→2, user→1
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT ?r ?n WHERE { { SELECT ?r (COUNT(*) AS ?n) WHERE { ?s <role> ?r } GROUP BY ?r } }",
        ).await.unwrap();
        assert_eq!(quads.len(), 2, "sub-SELECT aggregate: 2 role groups, got {}", quads.len());
        let counts: Vec<String> = quads.iter()
            .filter_map(|q| if let QuadObject::Text(t) = &q.object { Some(t.clone()) } else { None })
            .collect();
        assert!(counts.contains(&"2".to_string()), "admin group count=2");
        assert!(counts.contains(&"1".to_string()), "user group count=1");
    }

    #[tokio::test]
    async fn sparql_bgp_authed_rejected_wrong_graph() {
        let (qs, graph) = setup_sparql_qs().await;
        let wrong = KotobaCid::from_bytes(b"wrong-graph");
        let chain = DelegationChain::new_for_test(&wrong.to_multibase(), "quad:read");
        let result = qs.cold_query_sparql_bgp_authed(
            &graph,
            r#"SELECT * WHERE { ?s <role> "admin" }"#,
            &chain,
        ).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))));
    }

    // ─── CACAO-authed SPARQL UPDATE ───────────────────────────────────────────

    #[tokio::test]
    async fn sparql_update_authed_allowed() {
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"authed-write-graph");
        let chain = make_real_eddsa_cacao(&graph.to_multibase(), "quad:write");
        let s_mb  = KotobaCid::from_bytes(b"authed-subject").to_multibase();

        let sparql = format!(r#"INSERT DATA {{ <cid:{s_mb}> <label> "Authed" }}"#);
        let result = qs.sparql_update_authed(&graph, &sparql, &chain).await;
        assert!(result.is_ok(), "write-capable chain must succeed: {result:?}");
        assert_eq!(result.unwrap(), 1);
    }

    #[tokio::test]
    async fn sparql_update_authed_denied_wrong_graph() {
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"target-graph");
        let wrong = KotobaCid::from_bytes(b"other-graph");
        let chain = DelegationChain::new_for_test(&wrong.to_multibase(), "quad:write");
        let s_mb  = KotobaCid::from_bytes(b"denied-subject").to_multibase();

        let sparql = format!(r#"INSERT DATA {{ <cid:{s_mb}> <label> "Denied" }}"#);
        let result = qs.sparql_update_authed(&graph, &sparql, &chain).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))),
            "wrong-graph chain must be denied");
    }

    #[tokio::test]
    async fn sparql_update_authed_denied_wrong_capability() {
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"read-only-graph");
        let chain = DelegationChain::new_for_test(&graph.to_multibase(), "quad:read");
        let s_mb  = KotobaCid::from_bytes(b"read-only-subject").to_multibase();

        let sparql = format!(r#"INSERT DATA {{ <cid:{s_mb}> <label> "ReadOnly" }}"#);
        let result = qs.sparql_update_authed(&graph, &sparql, &chain).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))),
            "read-only chain must be denied for write");
    }

    // ─── CACAO EdDSA E2E: real signature, real cold-path authed query ─────────

    /// Build a Cacao with a real Ed25519 signature that grants `capability` on `graph_cid`.
    fn make_real_eddsa_cacao(graph_mb: &str, capability: &str) -> DelegationChain {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::{SigningKey, Signer};
        use kotoba_auth::cacao::{Cacao, CacaoHeader, CacaoPayload, CacaoSig};
        use kotoba_auth::did_key::ed25519_pubkey_to_did_key;

        let sk  = SigningKey::from_bytes(&[13u8; 32]);
        let pk  = sk.verifying_key();
        let did = ed25519_pubkey_to_did_key(pk.as_bytes());

        let template = Cacao {
            h: CacaoHeader { t: "eip4361".to_string() },
            p: CacaoPayload {
                iss:       did,
                aud:       "https://kotoba.test".to_string(),
                issued_at: "2026-01-01T00:00:00Z".to_string(),
                expiry:    Some("2099-01-01T00:00:00Z".to_string()),
                nonce:     "real-sig-e2e".to_string(),
                domain:    "kotoba.test".to_string(),
                statement: None,
                version:   "1".to_string(),
                resources: vec![
                    format!("kotoba://can/{capability}"),
                    format!("kotoba://graph/{graph_mb}"),
                ],
            },
            s: CacaoSig { t: "EdDSA".to_string(), s: String::new() },
        };
        let msg     = template.siwe_message();
        let sig     = sk.sign(msg.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let cacao   = Cacao { s: CacaoSig { t: "EdDSA".to_string(), s: sig_b64 }, ..template };
        DelegationChain::new(cacao)
    }

    #[tokio::test]
    async fn sparql_bgp_authed_real_sig_succeeds() {
        let (qs, graph) = setup_sparql_qs().await;
        let graph_mb = graph.to_multibase();
        let chain = make_real_eddsa_cacao(&graph_mb, "quad:read");

        // Real Ed25519 verify + cold-path SPARQL query must succeed.
        let result = qs.cold_query_sparql_bgp_authed(
            &graph,
            r#"SELECT * WHERE { ?s <role> "admin" }"#,
            &chain,
        ).await;
        assert!(result.is_ok(), "real EdDSA CACAO chain must pass: {:?}", result.err());
        let quads = result.unwrap();
        assert_eq!(quads.len(), 2, "Alice + Carol have role=admin");
    }

    #[tokio::test]
    async fn get_entity_quads_cold_authed_real_sig_succeeds() {
        let (qs, graph) = setup_sparql_qs().await;
        let graph_mb = graph.to_multibase();
        let chain    = make_real_eddsa_cacao(&graph_mb, "quad:read");
        let alice    = KotobaCid::from_bytes(b"alice");

        let result = qs.get_entity_quads_cold_authed(&graph, &alice, &chain).await;
        assert!(result.is_ok(), "real EdDSA get_entity cold authed: {:?}", result.err());
        let quads = result.unwrap();
        // Alice has name + role + knows = 3 quads
        assert!(!quads.is_empty(), "Alice's quads must be returned");
    }

    #[tokio::test]
    async fn sparql_authed_real_sig_aggregate_count_by_role() {
        // Real EdDSA CACAO + GROUP BY COUNT(*) via cold_query_sparql_bgp_authed
        let (qs, graph) = setup_sparql_qs().await;
        let graph_mb = graph.to_multibase();
        let chain = make_real_eddsa_cacao(&graph_mb, "quad:read");

        let result = qs.cold_query_sparql_bgp_authed(
            &graph,
            "SELECT ?r (COUNT(*) AS ?n) WHERE { ?s <role> ?r } GROUP BY ?r",
            &chain,
        ).await;
        assert!(result.is_ok(), "real EdDSA CACAO GROUP BY aggregate: {:?}", result.err());
        let quads = result.unwrap();
        // admin=2, user=1 → 2 result quads
        assert_eq!(quads.len(), 2, "GROUP BY role returns 2 groups (admin, user)");
        // First result (desc by count) should be admin with count 2
        assert_eq!(
            quads[0].object,
            QuadObject::Text("2".to_string()),
            "admin group must have count=2"
        );
    }

    #[tokio::test]
    async fn sparql_authed_real_sig_orderby_limit() {
        // Real EdDSA CACAO + ORDER BY + LIMIT via cold_query_sparql_bgp_authed
        let (qs, graph) = setup_sparql_qs().await;
        let graph_mb = graph.to_multibase();
        let chain = make_real_eddsa_cacao(&graph_mb, "quad:read");

        let result = qs.cold_query_sparql_bgp_authed(
            &graph,
            "SELECT ?s ?r WHERE { ?s <role> ?r } ORDER BY ?r LIMIT 2",
            &chain,
        ).await;
        assert!(result.is_ok(), "real EdDSA CACAO ORDER BY LIMIT: {:?}", result.err());
        let quads = result.unwrap();
        assert_eq!(quads.len(), 2, "LIMIT 2 must return 2 quads");
        // ASC sort: admin < user → first 2 must be admin
        assert!(
            quads.iter().all(|q| q.object == QuadObject::Text("admin".into())),
            "first 2 ASC quads must be admin"
        );
    }

    #[tokio::test]
    async fn sparql_authed_real_sig_minus() {
        // Real EdDSA CACAO + MINUS
        let (qs, graph) = setup_sparql_qs().await;
        let graph_mb = graph.to_multibase();
        let chain = make_real_eddsa_cacao(&graph_mb, "quad:read");

        let result = qs.cold_query_sparql_bgp_authed(
            &graph,
            r#"SELECT * WHERE { ?s <role> ?r MINUS { ?s <role> "admin" } }"#,
            &chain,
        ).await;
        assert!(result.is_ok(), "real EdDSA CACAO MINUS: {:?}", result.err());
        let quads = result.unwrap();
        assert_eq!(quads.len(), 1, "MINUS admin leaves only Bob (user)");
        assert_eq!(quads[0].object, QuadObject::Text("user".into()));
    }

    // ─── SPARQL JOIN ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_bgp_explicit_join_subquery() {
        // spargebra emits a Join node when two subqueries are combined.
        // { SELECT ?s WHERE { ?s <name> ?n } } JOIN { SELECT ?s WHERE { ?s <role> "admin" } }
        // → subjects in both = Alice + Carol; Bob appears only in role(user), not in admin
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { { SELECT ?s WHERE { ?s <name> ?n } } { SELECT ?s WHERE { ?s <role> "admin" } } }"#,
        ).await.unwrap();
        // Inner join: subjects must appear on both sides (Alice + Carol = admins with names)
        // Left: name quads for Alice + Carol + Bob (3); Right: role=admin for Alice+Carol (2)
        // Shared subjects: Alice + Carol → left(Alice-name + Carol-name) + right(Alice-role + Carol-role) = 4 quads
        let subjects: std::collections::HashSet<String> =
            quads.iter().map(|q| q.subject.to_multibase()).collect();
        let bob_mb = KotobaCid::from_bytes(b"bob").to_multibase();
        assert!(!subjects.contains(&bob_mb), "Bob is not admin — excluded by inner join");
        assert!(subjects.len() == 2, "Alice and Carol are the only shared subjects");
    }

    #[tokio::test]
    async fn sparql_aggregate_count_by_role() {
        // SELECT ?r (COUNT(*) AS ?n) WHERE { ?s <role> ?r } GROUP BY ?r
        // Expects: admin→2, user→1
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT ?r (COUNT(*) AS ?n) WHERE { ?s <role> ?r } GROUP BY ?r",
        ).await.unwrap();
        assert_eq!(quads.len(), 2, "two distinct role groups expected, got {}", quads.len());
        // Sorted descending by count: admin (2) first, user (1) second
        let counts: Vec<String> = quads.iter().filter_map(|q| {
            if let QuadObject::Text(t) = &q.object { Some(t.clone()) } else { None }
        }).collect();
        assert_eq!(counts[0], "2", "admin group has 2 members");
        assert_eq!(counts[1], "1", "user group has 1 member");
        // Predicate is the aggregate variable name
        assert!(quads.iter().all(|q| q.predicate == "n"), "predicate = agg var 'n'");
    }

    #[tokio::test]
    async fn sparql_aggregate_count_all() {
        // SELECT (COUNT(*) AS ?total) WHERE { ?s <role> ?r }
        // Expects: one group with count=3 (no GROUP BY = single global aggregate)
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT (COUNT(*) AS ?total) WHERE { ?s <role> ?r }",
        ).await.unwrap();
        // Without GROUP BY spargebra emits a single empty-variables Group
        // All 3 role quads go into one group → count = 3
        assert_eq!(quads.len(), 1, "one global aggregate row expected, got {}", quads.len());
        let count_val = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { "?".into() };
        assert_eq!(count_val, "3", "3 role quads total");
    }

    #[tokio::test]
    async fn sparql_aggregate_min_name() {
        // SELECT (MIN(?n) AS ?m) WHERE { ?s <name> ?n }
        // Data: Alice, Bob, Carol → alphabetically MIN = "Alice"
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT (MIN(?n) AS ?m) WHERE { ?s <name> ?n }",
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "one aggregate row expected");
        let val = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { "?".into() };
        assert_eq!(val, "Alice", "MIN of Alice/Bob/Carol = Alice");
    }

    #[tokio::test]
    async fn sparql_aggregate_max_name() {
        // SELECT (MAX(?n) AS ?m) WHERE { ?s <name> ?n }
        // Data: Alice, Bob, Carol → alphabetically MAX = "Carol"
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT (MAX(?n) AS ?m) WHERE { ?s <name> ?n }",
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "one aggregate row expected");
        let val = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { "?".into() };
        assert_eq!(val, "Carol", "MAX of Alice/Bob/Carol = Carol");
    }

    #[tokio::test]
    async fn sparql_aggregate_sample_name() {
        // SELECT (SAMPLE(?n) AS ?any) WHERE { ?s <name> ?n }
        // Returns any one name — just verify it is one of the valid names
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT (SAMPLE(?n) AS ?any) WHERE { ?s <name> ?n }",
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "one aggregate row expected");
        let val = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { "?".into() };
        assert!(
            ["Alice", "Bob", "Carol"].contains(&val.as_str()),
            "SAMPLE must be one of the names, got {val:?}"
        );
    }

    #[tokio::test]
    async fn sparql_aggregate_group_concat_names() {
        // SELECT (GROUP_CONCAT(?n) AS ?all) WHERE { ?s <name> ?n }
        // All names joined by space; order may vary, but all three must appear
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT (GROUP_CONCAT(?n) AS ?all) WHERE { ?s <name> ?n }",
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "one aggregate row expected");
        let val = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { "?".into() };
        assert!(val.contains("Alice"), "result must contain Alice");
        assert!(val.contains("Bob"),   "result must contain Bob");
        assert!(val.contains("Carol"), "result must contain Carol");
    }

    #[tokio::test]
    async fn sparql_aggregate_sum_numeric() {
        // Insert numeric score quads and verify SUM
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"agg-sum-graph");
        let a = KotobaCid::from_bytes(b"player-a");
        let b_node = KotobaCid::from_bytes(b"player-b");
        let c = KotobaCid::from_bytes(b"player-c");
        for (subj, score) in [(&a, "10"), (&b_node, "25"), (&c, "15")] {
            qs.assert(Quad { graph: graph.clone(), subject: (*subj).clone(),
                predicate: "score".into(), object: QuadObject::Text(score.to_string()) }).await;
        }
        qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.reset_arrangement(&graph).await;

        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT (SUM(?s) AS ?total) WHERE { ?p <score> ?s }",
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "one aggregate row");
        let val = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { "?".into() };
        assert_eq!(val, "50", "SUM(10+25+15) = 50");
    }

    #[tokio::test]
    async fn sparql_aggregate_avg_numeric() {
        // Insert numeric score quads and verify AVG
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"agg-avg-graph");
        let a = KotobaCid::from_bytes(b"player-a2");
        let b_node = KotobaCid::from_bytes(b"player-b2");
        let c = KotobaCid::from_bytes(b"player-c2");
        for (subj, score) in [(&a, "10"), (&b_node, "20"), (&c, "30")] {
            qs.assert(Quad { graph: graph.clone(), subject: (*subj).clone(),
                predicate: "score".into(), object: QuadObject::Text(score.to_string()) }).await;
        }
        qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.reset_arrangement(&graph).await;

        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT (AVG(?s) AS ?avg) WHERE { ?p <score> ?s }",
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "one aggregate row");
        let val = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { "?".into() };
        assert_eq!(val, "20.00", "AVG(10+20+30)/3 = 20.00");
    }

    #[tokio::test]
    async fn sparql_aggregate_min_numeric() {
        // Numeric MIN: ensure cmp_values numeric comparison is used (not lexicographic)
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"agg-min-num-graph");
        for (i, score) in ["9", "10", "100"].iter().enumerate() {
            let subj = KotobaCid::from_bytes(format!("player-num-{i}").as_bytes());
            qs.assert(Quad { graph: graph.clone(), subject: subj,
                predicate: "score".into(), object: QuadObject::Text(score.to_string()) }).await;
        }
        qs.commit("did:test", graph.clone(), 1).await.unwrap();
        qs.reset_arrangement(&graph).await;

        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT (MIN(?s) AS ?m) WHERE { ?p <score> ?s }",
        ).await.unwrap();
        assert_eq!(quads.len(), 1);
        let val = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { "?".into() };
        // Lexicographic min would give "10" (since "1" < "9"), numeric gives "9"
        assert_eq!(val, "9", "numeric MIN(9,10,100) = 9, not lexicographic '10'");
    }

    // ─── SPARQL UPDATE ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_update_insert_data() {
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"update-test-graph");
        let alice_mb = KotobaCid::from_bytes(b"alice-update").to_multibase();

        // INSERT DATA using SPARQL UPDATE syntax
        let insert_sparql = format!(
            r#"INSERT DATA {{ <cid:{alice_mb}> <name> "Alice" . <cid:{alice_mb}> <role> "admin" }}"#
        );
        let count = qs.sparql_update(&graph, &insert_sparql).await.unwrap();
        assert_eq!(count, 2, "INSERT DATA should insert 2 quads");

        // Query back via BGP
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            &format!(r#"SELECT * WHERE {{ <cid:{alice_mb}> <role> ?r }}"#),
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "inserted role quad must be queryable");
        let role = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { "?".into() };
        assert_eq!(role, "admin");
    }

    #[tokio::test]
    async fn sparql_update_delete_data() {
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"update-delete-graph");
        let alice = KotobaCid::from_bytes(b"alice-del");
        let alice_mb = alice.to_multibase();

        // Assert first
        qs.assert(Quad { graph: graph.clone(), subject: alice.clone(),
            predicate: "role".into(), object: QuadObject::Text("admin".into()) }).await;
        qs.assert(Quad { graph: graph.clone(), subject: alice.clone(),
            predicate: "name".into(), object: QuadObject::Text("Alice".into()) }).await;

        // DELETE DATA via SPARQL UPDATE
        let delete_sparql = format!(
            r#"DELETE DATA {{ <cid:{alice_mb}> <role> "admin" }}"#
        );
        let count = qs.sparql_update(&graph, &delete_sparql).await.unwrap();
        assert_eq!(count, 1, "DELETE DATA should retract 1 quad");

        // Role quad should be gone; name should remain
        let role_quads = qs.cold_query_sparql_bgp(
            &graph,
            &format!(r#"SELECT * WHERE {{ <cid:{alice_mb}> <role> ?r }}"#),
        ).await.unwrap();
        assert!(role_quads.is_empty(), "role quad must be deleted");

        let name_quads = qs.cold_query_sparql_bgp(
            &graph,
            &format!(r#"SELECT * WHERE {{ <cid:{alice_mb}> <name> ?n }}"#),
        ).await.unwrap();
        assert_eq!(name_quads.len(), 1, "name quad must survive DELETE DATA");
    }

    #[tokio::test]
    async fn sparql_update_insert_named_graph() {
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let default_graph = KotobaCid::from_bytes(b"ng-default");
        let named_graph   = KotobaCid::from_bytes(b"ng-named");
        let subject       = KotobaCid::from_bytes(b"ng-subject");
        let graph_mb   = named_graph.to_multibase();
        let subject_mb = subject.to_multibase();

        // INSERT into named graph via GRAPH clause
        let insert_sparql = format!(
            r#"INSERT DATA {{ GRAPH <cid:{graph_mb}> {{ <cid:{subject_mb}> <label> "TestNode" }} }}"#
        );
        let count = qs.sparql_update(&default_graph, &insert_sparql).await.unwrap();
        assert_eq!(count, 1, "INSERT into named graph: 1 quad");

        // Query the named graph
        let quads = qs.cold_query_sparql_bgp(
            &named_graph,
            &format!(r#"SELECT * WHERE {{ <cid:{subject_mb}> <label> ?l }}"#),
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "quad must be in named graph");
        let label = if let QuadObject::Text(t) = &quads[0].object { t.clone() } else { "?".into() };
        assert_eq!(label, "TestNode");
    }

    #[tokio::test]
    async fn sparql_update_insert_where_marks_admins() {
        // INSERT { ?s <verified> "yes" } WHERE { ?s <role> "admin" }
        // Expect: Alice + Carol each get a <verified> quad
        let (qs, graph) = setup_sparql_qs().await;
        let graph_mb = graph.to_multibase();
        let alice    = KotobaCid::from_bytes(b"alice");
        let alice_mb = alice.to_multibase();

        let sparql = format!(
            r#"INSERT {{ ?s <verified> "yes" }} WHERE {{ ?s <role> "admin" }}"#
        );
        let count = qs.sparql_update(&graph, &sparql).await.unwrap();
        assert_eq!(count, 2, "2 admin subjects → 2 inserts");

        // Query: Alice must now have <verified>=yes
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            &format!(r#"SELECT * WHERE {{ <cid:{alice_mb}> <verified> ?v }}"#),
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "Alice must have verified quad");
        assert_eq!(quads[0].object, QuadObject::Text("yes".into()));
        let _ = graph_mb; // suppress unused warning
    }

    #[tokio::test]
    async fn sparql_update_delete_where_removes_by_pattern() {
        // DELETE { ?s <role> ?r } WHERE { ?s <role> ?r . FILTER(?r = "user") }
        // Uses hot-only store (no commit/reset) so retract() removes from hot arrangement.
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let graph = KotobaCid::from_bytes(b"del-where-graph");
        let alice = KotobaCid::from_bytes(b"dw-alice");
        let bob   = KotobaCid::from_bytes(b"dw-bob");
        let carol = KotobaCid::from_bytes(b"dw-carol");
        let bob_mb   = bob.to_multibase();
        let alice_mb = alice.to_multibase();

        // Insert hot-only (no commit → arrangement is the source of truth)
        for (subj, role) in [(&alice, "admin"), (&bob, "user"), (&carol, "admin")] {
            qs.assert(Quad { graph: graph.clone(), subject: (*subj).clone(),
                predicate: "role".into(), object: QuadObject::Text(role.to_string()) }).await;
        }

        let sparql = r#"DELETE { ?s <role> ?r } WHERE { ?s <role> ?r . FILTER(?r = "user") }"#;
        let count = qs.sparql_update(&graph, sparql).await.unwrap();
        assert!(count >= 1, "at least 1 retract for Bob's role");

        // Bob must no longer have a <role> quad (hot arrangement should reflect retract)
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            &format!(r#"SELECT * WHERE {{ <cid:{bob_mb}> <role> ?r }}"#),
        ).await.unwrap();
        assert_eq!(quads.len(), 0, "Bob's role must be retracted, got {quads:?}");

        // Alice still has her role (admin was not deleted)
        let alice_role = qs.cold_query_sparql_bgp(
            &graph,
            &format!(r#"SELECT * WHERE {{ <cid:{alice_mb}> <role> ?r }}"#),
        ).await.unwrap();
        assert_eq!(alice_role.len(), 1, "Alice's role must survive");
    }

    // ─── SPARQL CONSTRUCT ─────────────────────────────────────────────────────
    //
    // CONSTRUCT substitutes variables from matched quads into template triples.
    // Variable binding is position-based: ?s → matched.subject, ?o → matched.object.
    // For unambiguous results, the WHERE clause should have a single triple binding
    // the same variables as the CONSTRUCT template.

    #[tokio::test]
    async fn sparql_construct_single_triple_where() {
        // CONSTRUCT { ?s <label> ?n } WHERE { ?s <role> "admin" }
        // Each admin quad binds ?s=admin_subject, ?n=object("admin")
        // Expect: 2 quads with predicate=label and object=Text("admin")
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.sparql_construct(
            &graph,
            r#"CONSTRUCT { ?s <label> ?n } WHERE { ?s <role> "admin" }"#,
        ).await.unwrap();
        assert_eq!(quads.len(), 2, "2 admin role quads → 2 CONSTRUCT results, got {}", quads.len());
        assert!(quads.iter().all(|q| q.predicate == "label"), "all must have predicate=label");
        // object = Text("admin") because role quads have object Text("admin")
        assert!(quads.iter().all(|q| q.object == QuadObject::Text("admin".into())),
            "object must be admin");
    }

    #[tokio::test]
    async fn sparql_construct_cross_predicate_copy() {
        // CONSTRUCT { ?s <fullname> ?n } WHERE { ?s <name> ?n }
        // Expect: 3 quads (copy name → fullname for all subjects)
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.sparql_construct(
            &graph,
            r#"CONSTRUCT { ?s <fullname> ?n } WHERE { ?s <name> ?n }"#,
        ).await.unwrap();
        assert_eq!(quads.len(), 3, "CONSTRUCT copies name to fullname for all 3 subjects");
        assert!(quads.iter().all(|q| q.predicate == "fullname"), "predicate must be fullname");
        let names: Vec<String> = quads.iter()
            .filter_map(|q| if let QuadObject::Text(t) = &q.object { Some(t.clone()) } else { None })
            .collect();
        assert!(names.contains(&"Alice".to_string()));
        assert!(names.contains(&"Bob".to_string()));
        assert!(names.contains(&"Carol".to_string()));
    }

    // ─── SPARQL ASK ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_ask_existing_pattern_returns_true() {
        let (qs, graph) = setup_sparql_qs().await;
        let alice    = KotobaCid::from_bytes(b"alice");
        let alice_mb = alice.to_multibase();
        let result = qs.sparql_ask(
            &graph,
            &format!(r#"ASK {{ <cid:{alice_mb}> <role> "admin" }}"#),
        ).await.unwrap();
        assert!(result, "Alice is admin → ASK must return true");
    }

    #[tokio::test]
    async fn sparql_ask_missing_pattern_returns_false() {
        let (qs, graph) = setup_sparql_qs().await;
        let bob    = KotobaCid::from_bytes(b"bob");
        let bob_mb = bob.to_multibase();
        let result = qs.sparql_ask(
            &graph,
            &format!(r#"ASK {{ <cid:{bob_mb}> <role> "admin" }}"#),
        ).await.unwrap();
        assert!(!result, "Bob is user not admin → ASK must return false");
    }

    #[tokio::test]
    async fn sparql_ask_authed_allowed() {
        let (qs, graph) = setup_sparql_qs().await;
        let chain = make_real_eddsa_cacao(&graph.to_multibase(), "quad:read");
        let alice_mb = KotobaCid::from_bytes(b"alice").to_multibase();
        let result = qs.sparql_ask_authed(
            &graph,
            &format!(r#"ASK {{ <cid:{alice_mb}> <role> "admin" }}"#),
            &chain,
        ).await;
        assert!(matches!(result, Ok(true)), "real EdDSA authed ASK must return Ok(true): {result:?}");
    }

    #[tokio::test]
    async fn sparql_ask_authed_denied_wrong_graph() {
        let (qs, graph) = setup_sparql_qs().await;
        let wrong = KotobaCid::from_bytes(b"wrong-graph");
        let chain = make_real_eddsa_cacao(&wrong.to_multibase(), "quad:read");
        let alice_mb = KotobaCid::from_bytes(b"alice").to_multibase();
        let result = qs.sparql_ask_authed(
            &graph,
            &format!(r#"ASK {{ <cid:{alice_mb}> <role> "admin" }}"#),
            &chain,
        ).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))), "wrong graph must be denied");
    }

    // ─── SPARQL FILTER / UNION / OPTIONAL ────────────────────────────────────

    #[tokio::test]
    async fn sparql_bgp_filter_not_equal() {
        // { ?s <role> ?r FILTER(?r != "admin") } → only Bob (role=user)
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <role> ?r FILTER(?r != "admin") }"#,
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "only Bob expected, got {}", quads.len());
        let obj = match &quads[0].object {
            QuadObject::Text(t) => t.clone(),
            _ => panic!("expected text object"),
        };
        assert_eq!(obj, "user");
    }

    #[tokio::test]
    async fn sparql_bgp_filter_contains() {
        // { ?s <name> ?n FILTER(contains(?n, "ol")) } → only Carol
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <name> ?n FILTER(contains(?n, "ol")) }"#,
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "only Carol expected, got {}", quads.len());
        let obj = match &quads[0].object {
            QuadObject::Text(t) => t.clone(),
            _ => panic!("expected text object"),
        };
        assert_eq!(obj, "Carol");
    }

    #[tokio::test]
    async fn sparql_filter_exists_semi_join() {
        // { ?s <role> ?r FILTER EXISTS { ?s <knows> ?x } }
        // Only Alice has a <knows> edge (alice knows bob) → only Alice's role quad
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT * WHERE { ?s <role> ?r FILTER EXISTS { ?s <knows> ?x } }",
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "only Alice has <knows> edge, got {}", quads.len());
        let obj = match &quads[0].object {
            QuadObject::Text(t) => t.clone(),
            _ => panic!("expected text object"),
        };
        assert_eq!(obj, "admin", "Alice is admin");
    }

    #[tokio::test]
    async fn sparql_filter_not_exists_anti_join() {
        // { ?s <role> ?r FILTER NOT EXISTS { ?s <knows> ?x } }
        // Bob and Carol have no <knows> edges → 2 role quads (Bob user, Carol admin)
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT * WHERE { ?s <role> ?r FILTER NOT EXISTS { ?s <knows> ?x } }",
        ).await.unwrap();
        assert_eq!(quads.len(), 2, "Bob and Carol have no <knows>, got {}", quads.len());
        let roles: Vec<String> = quads.iter().filter_map(|q| {
            if let QuadObject::Text(t) = &q.object { Some(t.clone()) } else { None }
        }).collect();
        assert!(roles.contains(&"user".to_string()), "Bob (user) must be in result");
        assert!(roles.contains(&"admin".to_string()), "Carol (admin) must be in result");
    }

    #[tokio::test]
    async fn sparql_bgp_union() {
        // { { ?s <role> "admin" } UNION { ?s <role> "user" } } → Alice + Carol + Bob (3 quads)
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { { ?s <role> "admin" } UNION { ?s <role> "user" } }"#,
        ).await.unwrap();
        assert_eq!(quads.len(), 3, "all three role quads expected, got {}", quads.len());
        let values: std::collections::HashSet<String> = quads.iter().filter_map(|q| {
            if let QuadObject::Text(t) = &q.object { Some(t.clone()) } else { None }
        }).collect();
        assert!(values.contains("admin") && values.contains("user"));
    }

    #[tokio::test]
    async fn sparql_bgp_optional() {
        // { ?s <name> ?n OPTIONAL { ?s <role> ?r } } → name quads for all 3 + role quads for all 3
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <name> ?n OPTIONAL { ?s <role> ?r } }"#,
        ).await.unwrap();
        // 3 name quads (mandatory) + 3 role quads (optional, all subjects have roles)
        assert_eq!(quads.len(), 6, "3 name + 3 role quads expected, got {}", quads.len());
        let preds: std::collections::HashSet<&str> = quads.iter().map(|q| q.predicate.as_str()).collect();
        assert!(preds.contains("name") && preds.contains("role"));
    }

    // ─── SPARQL Property Paths ────────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_property_path_one_or_more() {
        // alice --knows--> bob (CID edge in test data)
        // <cid:alice> <knows>+ ?o → should return the knows quad from alice→bob
        let (qs, graph) = setup_sparql_qs().await;
        let alice_mb = KotobaCid::from_bytes(b"alice").to_multibase();
        let sparql = format!("SELECT * WHERE {{ <cid:{alice_mb}> <knows>+ ?o }}");
        let quads = qs.cold_query_sparql_bgp(&graph, &sparql).await.unwrap();
        assert_eq!(quads.len(), 1, "one knows+ hop expected, got {}", quads.len());
        assert_eq!(quads[0].predicate, "knows");
        // object should be the bob CID
        let bob_cid = KotobaCid::from_bytes(b"bob");
        assert_eq!(
            quads[0].object,
            kotoba_kqe::quad::QuadObject::Cid(bob_cid),
        );
    }

    #[tokio::test]
    async fn sparql_property_path_zero_or_more_includes_start() {
        // <cid:alice> <knows>* ?o → includes alice's own quads AND knows-edge quads
        let (qs, graph) = setup_sparql_qs().await;
        let alice_mb = KotobaCid::from_bytes(b"alice").to_multibase();
        let sparql = format!("SELECT * WHERE {{ <cid:{alice_mb}> <knows>* ?o }}");
        let quads = qs.cold_query_sparql_bgp(&graph, &sparql).await.unwrap();
        // ZeroOrMore: knows+ result (1 quad) + alice's own quads (name + role + knows = 3)
        // deduped — the knows quad appears in both, dedup gives us ≥1 and ≤4
        assert!(!quads.is_empty(), "zero-or-more must return at least one quad");
        let preds: std::collections::HashSet<&str> =
            quads.iter().map(|q| q.predicate.as_str()).collect();
        assert!(preds.contains("knows"), "knows predicate must appear");
    }

    #[tokio::test]
    async fn sparql_property_path_no_cid_edges_returns_empty() {
        // bob has no CID-typed "knows" edge → <cid:bob> <knows>+ ?o is empty
        let (qs, graph) = setup_sparql_qs().await;
        let bob_mb = KotobaCid::from_bytes(b"bob").to_multibase();
        let sparql = format!("SELECT * WHERE {{ <cid:{bob_mb}> <knows>+ ?o }}");
        let quads = qs.cold_query_sparql_bgp(&graph, &sparql).await.unwrap();
        assert!(quads.is_empty(), "bob has no outgoing knows edges");
    }

    // ─── Property path: Alternative / Reverse / ZeroOrOne ────────────────────

    #[tokio::test]
    async fn sparql_property_path_alternative() {
        // <cid:alice> (<name>|<role>) ?o → Alice's name and role quads (2 quads)
        let (qs, graph) = setup_sparql_qs().await;
        let alice_mb = KotobaCid::from_bytes(b"alice").to_multibase();
        let sparql = format!("SELECT * WHERE {{ <cid:{alice_mb}> <name>|<role> ?o }}");
        let quads = qs.cold_query_sparql_bgp(&graph, &sparql).await.unwrap();
        assert_eq!(quads.len(), 2, "name + role = 2 quads, got {}", quads.len());
        let vals: Vec<String> = quads.iter().filter_map(|q| {
            if let QuadObject::Text(t) = &q.object { Some(t.clone()) } else { None }
        }).collect();
        assert!(vals.contains(&"Alice".to_string()), "name quad expected");
        assert!(vals.contains(&"admin".to_string()), "role quad expected");
    }

    #[tokio::test]
    async fn sparql_property_path_reverse() {
        // <cid:bob> ^<knows> ?o → who knows bob? Alice knows bob → Alice's know quad
        let (qs, graph) = setup_sparql_qs().await;
        let bob_mb = KotobaCid::from_bytes(b"bob").to_multibase();
        let sparql = format!("SELECT * WHERE {{ <cid:{bob_mb}> ^<knows> ?o }}");
        let quads = qs.cold_query_sparql_bgp(&graph, &sparql).await.unwrap();
        assert_eq!(quads.len(), 1, "only Alice knows bob, got {}", quads.len());
        assert_eq!(quads[0].predicate, "knows", "predicate = knows");
        let alice_cid = KotobaCid::from_bytes(b"alice");
        assert_eq!(quads[0].subject, alice_cid, "subject = alice");
    }

    #[tokio::test]
    async fn sparql_property_path_zero_or_one() {
        // <cid:alice> <knows>? ?o → 0 or 1 hops via knows
        // alice knows bob → includes alice's own quads + bob's quads (via knows edge)
        let (qs, graph) = setup_sparql_qs().await;
        let alice_mb = KotobaCid::from_bytes(b"alice").to_multibase();
        let sparql = format!("SELECT * WHERE {{ <cid:{alice_mb}> <knows>? ?o }}");
        let quads = qs.cold_query_sparql_bgp(&graph, &sparql).await.unwrap();
        // Alice's own quads: name, role, knows (3) + Bob's quads: name, role (2) = up to 5
        assert!(quads.len() >= 2, "at least alice's quads expected, got {}", quads.len());
        let predicates: Vec<&str> = quads.iter().map(|q| q.predicate.as_str()).collect();
        assert!(predicates.contains(&"name"), "name predicate expected");
    }

    // ─── import_commit tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn import_commit_makes_graph_queryable() {
        // Node A (peer): commits quads to its own MemoryBlockStore.
        let peer_bs = Arc::new(MemoryBlockStore::new());
        let peer_qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::clone(&peer_bs) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>,
        );
        let graph   = make_cid_from("import-g");
        let subject = make_cid_from("import-s1");
        peer_qs.assert(Quad {
            graph:    graph.clone(),
            subject:  subject.clone(),
            predicate: "name".into(),
            object:   QuadObject::Text("ImportEntity".into()),
        }).await;
        let commit_cid = peer_qs.commit("did:peer", graph.clone(), 1).await.unwrap();
        peer_qs.reset_arrangement(&graph).await;

        // Replicate peer's blocks into node B's store.
        let local_b = Arc::new(MemoryBlockStore::new());
        for cid in peer_bs.all_cids() {
            if let Ok(Some(data)) = peer_bs.get(&cid) {
                local_b.put(&cid, &data).unwrap();
            }
        }

        // Node B: no quads, no commit — only the replicated blocks.
        let qs_b = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::clone(&local_b) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>,
        );
        assert!(qs_b.head_commit(&graph).await.is_none(), "before import: no head");

        // import_commit() populates the CommitDag from the replicated block store.
        let imported = qs_b.import_commit(&commit_cid).await.unwrap();
        assert!(imported, "commit block must be found in local_b after replication");
        assert!(qs_b.head_commit(&graph).await.is_some(), "after import: head exists");

        // Cold query must succeed via ProllyTree blocks in local_b.
        let result = qs_b.get_entity_quads_cold(&graph, &subject).await.unwrap();
        assert!(!result.is_empty(), "replicated entity quads readable after import_commit");
    }

    #[tokio::test]
    async fn import_commit_missing_block_returns_false() {
        // Get a real commit CID from a peer.
        let peer_bs = Arc::new(MemoryBlockStore::new());
        let peer_qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::clone(&peer_bs) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>,
        );
        let graph = make_cid_from("import-miss-g");
        peer_qs.assert(Quad {
            graph: graph.clone(),
            subject: make_cid_from("s"),
            predicate: "p".into(),
            object: QuadObject::Text("v".into()),
        }).await;
        let commit_cid = peer_qs.commit("did:peer", graph.clone(), 1).await.unwrap();

        // Node B has an empty store — commit block not present.
        let qs_b = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>,
        );
        let imported = qs_b.import_commit(&commit_cid).await.unwrap();
        assert!(!imported, "commit not in store → import returns false");
        assert!(qs_b.head_commit(&graph).await.is_none());
    }

    // ── MINUS ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_minus_excludes_admins() {
        // SELECT ?s WHERE { ?s <role> ?r MINUS { ?s <role> "admin" } }
        // → only Bob (role = "user") survives
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <role> ?r MINUS { ?s <role> "admin" } }"#,
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "only Bob survives MINUS, got {}", quads.len());
        assert_eq!(
            quads[0].object,
            QuadObject::Text("user".to_string()),
            "surviving quad must have role=user"
        );
    }

    #[tokio::test]
    async fn sparql_minus_full_overlap_returns_empty() {
        // MINUS right-side is identical to left → all excluded → empty
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <role> ?r MINUS { ?s <role> ?r } }"#,
        ).await.unwrap();
        assert!(quads.is_empty(), "full overlap MINUS must return empty");
    }

    // ── VALUES ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_values_inline_filter() {
        // VALUES ?r { "admin" } restricts ?s <role> ?r to admin subjects only
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { VALUES ?r { "admin" } ?s <role> ?r }"#,
        ).await.unwrap();
        assert_eq!(quads.len(), 2, "VALUES filter: 2 admins expected, got {}", quads.len());
        assert!(
            quads.iter().all(|q| q.predicate == "role"),
            "all quads should have predicate role"
        );
        assert!(
            quads.iter().all(|q| q.object == QuadObject::Text("admin".into())),
            "all quads must have object=admin"
        );
    }

    #[tokio::test]
    async fn sparql_values_multiple_bindings() {
        // VALUES ?r { "admin" "user" } → all 3 role quads pass through
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { VALUES ?r { "admin" "user" } ?s <role> ?r }"#,
        ).await.unwrap();
        assert_eq!(quads.len(), 3, "VALUES with both values: all 3 roles, got {}", quads.len());
    }

    #[tokio::test]
    async fn sparql_values_no_match_returns_empty() {
        // VALUES with a value not in the store → empty
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { VALUES ?r { "viewer" } ?s <role> ?r }"#,
        ).await.unwrap();
        assert!(quads.is_empty(), "VALUES with unmatched value must return empty");
    }

    // ── ORDER BY + LIMIT (Slice) ───────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_orderby_asc_limit() {
        // SELECT ?s ?r WHERE { ?s <role> ?r } ORDER BY ASC(?r) LIMIT 2
        // role values: admin (Alice), admin (Carol), user (Bob)
        // Sorted ASC: admin, admin, user → LIMIT 2 → 2 admin quads
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT ?s ?r WHERE { ?s <role> ?r } ORDER BY ASC(?r) LIMIT 2",
        ).await.unwrap();
        assert_eq!(quads.len(), 2, "LIMIT 2 must return exactly 2 quads, got {}", quads.len());
        // Both must be admin
        assert!(
            quads.iter().all(|q| q.object == QuadObject::Text("admin".into())),
            "first 2 (ASC) must be admin quads"
        );
    }

    #[tokio::test]
    async fn sparql_orderby_desc_limit_1() {
        // DESC → user first; LIMIT 1 → Bob's role quad
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT ?s ?r WHERE { ?s <role> ?r } ORDER BY DESC(?r) LIMIT 1",
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "LIMIT 1 must return 1 quad");
        assert_eq!(quads[0].object, QuadObject::Text("user".into()), "DESC first should be user");
    }

    #[tokio::test]
    async fn sparql_orderby_offset() {
        // OFFSET 2 on 3 quads → 1 quad
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &graph,
            "SELECT ?s ?r WHERE { ?s <role> ?r } ORDER BY ?r OFFSET 2",
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "OFFSET 2 of 3 = 1 remaining, got {}", quads.len());
    }

    // ─── SPARQL DESCRIBE ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn sparql_describe_explicit_iri() {
        // DESCRIBE <cid:alice> → all quads for Alice (name + role = 2 quads)
        let (qs, graph) = setup_sparql_qs().await;
        let alice_mb = KotobaCid::from_bytes(b"alice").to_multibase();
        let quads = qs.sparql_describe(
            &graph,
            &format!("DESCRIBE <cid:{alice_mb}>"),
        ).await.unwrap();
        // Alice has: name="Alice", role="admin", knows->bob
        assert_eq!(quads.len(), 3, "DESCRIBE alice: 3 quads expected, got {}", quads.len());
        assert!(quads.iter().all(|q| q.subject == KotobaCid::from_bytes(b"alice")),
            "all quads must be about Alice");
    }

    #[tokio::test]
    async fn sparql_describe_where_clause() {
        // DESCRIBE ?s WHERE { ?s <role> "admin" } → Alice + Carol, each with 2 quads
        let (qs, graph) = setup_sparql_qs().await;
        let quads = qs.sparql_describe(
            &graph,
            r#"DESCRIBE ?s WHERE { ?s <role> "admin" }"#,
        ).await.unwrap();
        // Alice: name + role + knows = 3; Carol: name + role = 2 → 5 total
        assert_eq!(quads.len(), 5, "DESCRIBE admins: 5 quads (Alice 3 + Carol 2), got {}", quads.len());
        // All subjects must be Alice or Carol
        let alice = KotobaCid::from_bytes(b"alice");
        let carol = KotobaCid::from_bytes(b"carol");
        assert!(quads.iter().all(|q| q.subject == alice || q.subject == carol),
            "subjects must be admin entities");
    }

    #[tokio::test]
    async fn sparql_describe_unknown_iri_returns_empty() {
        // DESCRIBE <cid:nobody> — not in store → empty
        let (qs, graph) = setup_sparql_qs().await;
        let nobody_mb = KotobaCid::from_bytes(b"nobody").to_multibase();
        let quads = qs.sparql_describe(
            &graph,
            &format!("DESCRIBE <cid:{nobody_mb}>"),
        ).await.unwrap();
        assert!(quads.is_empty(), "DESCRIBE unknown entity must return empty");
    }

    #[tokio::test]
    async fn sparql_describe_authed_allowed() {
        // Real Ed25519 chain → Ok(quads)
        let (qs, graph) = setup_sparql_qs().await;
        let chain = make_real_eddsa_cacao(&graph.to_multibase(), "quad:read");
        let alice_mb = KotobaCid::from_bytes(b"alice").to_multibase();
        let result = qs.sparql_describe_authed(
            &graph,
            &format!("DESCRIBE <cid:{alice_mb}>"),
            &chain,
        ).await;
        assert!(result.is_ok(), "authed DESCRIBE must succeed: {result:?}");
        assert_eq!(result.unwrap().len(), 3, "Alice: 3 quads (name+role+knows)");
    }

    #[tokio::test]
    async fn sparql_describe_authed_denied_wrong_graph() {
        // Chain for wrong graph → AccessError
        let (qs, graph) = setup_sparql_qs().await;
        let wrong = KotobaCid::from_bytes(b"wrong-graph");
        let chain = make_real_eddsa_cacao(&wrong.to_multibase(), "quad:read");
        let alice_mb = KotobaCid::from_bytes(b"alice").to_multibase();
        let result = qs.sparql_describe_authed(
            &graph,
            &format!("DESCRIBE <cid:{alice_mb}>"),
            &chain,
        ).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))), "wrong graph must be denied");
    }

    // ─── SPARQL SERVICE (federated query) ──────────────────────────────────────

    async fn setup_two_graph_qs() -> (QuadStore, KotobaCid, KotobaCid) {
        // Two graphs, each with role triples; SERVICE federates from one to the other.
        let qs    = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let g1 = KotobaCid::from_bytes(b"svc-graph-1");
        let g2 = KotobaCid::from_bytes(b"svc-graph-2");
        let alice = KotobaCid::from_bytes(b"svc-alice");
        let bob   = KotobaCid::from_bytes(b"svc-bob");

        qs.assert(Quad { graph: g1.clone(), subject: alice.clone(),
            predicate: "role".into(), object: QuadObject::Text("admin".into()) }).await;
        qs.assert(Quad { graph: g2.clone(), subject: bob.clone(),
            predicate: "role".into(), object: QuadObject::Text("user".into()) }).await;
        qs.assert(Quad { graph: g2.clone(), subject: alice.clone(),
            predicate: "role".into(), object: QuadObject::Text("viewer".into()) }).await;

        qs.commit("did:test", g1.clone(), 1).await.unwrap();
        qs.commit("did:test", g2.clone(), 2).await.unwrap();
        qs.reset_arrangement(&g1).await;
        qs.reset_arrangement(&g2).await;
        (qs, g1, g2)
    }

    #[tokio::test]
    async fn sparql_service_cid_iri_federates_to_remote_graph() {
        // SERVICE <cid:g2> { ?s <role> ?r } from g1 context → returns g2 quads
        let (qs, g1, g2) = setup_two_graph_qs().await;
        let g2_mb = g2.to_multibase();
        let quads = qs.cold_query_sparql_bgp(
            &g1,
            &format!("SELECT * WHERE {{ SERVICE <cid:{g2_mb}> {{ ?s <role> ?r }} }}"),
        ).await.unwrap();
        assert_eq!(quads.len(), 2, "g2 has 2 role quads (bob=user, alice=viewer), got {}", quads.len());
        assert!(quads.iter().all(|q| q.graph == g2),
            "all returned quads must be from g2");
    }

    #[tokio::test]
    async fn sparql_service_kotoba_graph_uri_form() {
        // SERVICE <kotoba://graph/<mb>> { ... } long URI form
        let (qs, g1, g2) = setup_two_graph_qs().await;
        let g2_mb = g2.to_multibase();
        let quads = qs.cold_query_sparql_bgp(
            &g1,
            &format!("SELECT * WHERE {{ SERVICE <kotoba://graph/{g2_mb}> {{ ?s <role> ?r }} }}"),
        ).await.unwrap();
        assert_eq!(quads.len(), 2, "kotoba://graph/ form must work, got {}", quads.len());
    }

    #[tokio::test]
    async fn sparql_service_silent_returns_empty_on_unknown_iri() {
        // SERVICE SILENT <cid:nonexistent> { ... } → empty (no error)
        let (qs, g1, _g2) = setup_two_graph_qs().await;
        let quads = qs.cold_query_sparql_bgp(
            &g1,
            "SELECT * WHERE { SERVICE SILENT <kotoba://node/did:does-not-exist> { ?s <role> ?r } }",
        ).await.unwrap();
        assert!(quads.is_empty(), "SILENT must swallow unknown service and return empty");
    }

    #[tokio::test]
    async fn sparql_service_non_silent_errors_on_unrouted_node() {
        // SERVICE <kotoba://node/did:foo> { ... } without SILENT → error
        let (qs, g1, _g2) = setup_two_graph_qs().await;
        let result = qs.cold_query_sparql_bgp(
            &g1,
            "SELECT * WHERE { SERVICE <kotoba://node/did:foo> { ?s <role> ?r } }",
        ).await;
        assert!(result.is_err(), "non-silent unrouted SERVICE must error");
    }

    #[tokio::test]
    async fn sparql_service_with_filter_inner() {
        // SERVICE wraps a FILTER pattern — filter applies on remote graph
        let (qs, g1, g2) = setup_two_graph_qs().await;
        let g2_mb = g2.to_multibase();
        let quads = qs.cold_query_sparql_bgp(
            &g1,
            &format!(r#"SELECT * WHERE {{ SERVICE <cid:{g2_mb}> {{ ?s <role> ?r FILTER(?r = "user") }} }}"#),
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "only bob=user matches inside SERVICE FILTER, got {}", quads.len());
        let obj = match &quads[0].object {
            QuadObject::Text(t) => t.clone(),
            _ => panic!("expected text"),
        };
        assert_eq!(obj, "user");
    }

    // ─── SPARQL N-hop DESCRIBE (multi-pop traversal) ───────────────────────────

    /// Setup: alice --knows--> bob --knows--> carol --knows--> dave
    /// + each entity has a name quad.
    async fn setup_chain_qs() -> (QuadStore, KotobaCid, [KotobaCid; 4]) {
        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let g = KotobaCid::from_bytes(b"nhop-graph");
        let people = [
            KotobaCid::from_bytes(b"nhop-alice"),
            KotobaCid::from_bytes(b"nhop-bob"),
            KotobaCid::from_bytes(b"nhop-carol"),
            KotobaCid::from_bytes(b"nhop-dave"),
        ];
        let names = ["Alice", "Bob", "Carol", "Dave"];
        for (p, n) in people.iter().zip(names.iter()) {
            qs.assert(Quad { graph: g.clone(), subject: p.clone(),
                predicate: "name".into(), object: QuadObject::Text((*n).into()) }).await;
        }
        for i in 0..3 {
            qs.assert(Quad { graph: g.clone(), subject: people[i].clone(),
                predicate: "knows".into(), object: QuadObject::Cid(people[i+1].clone()) }).await;
        }
        qs.commit("did:nhop", g.clone(), 1).await.unwrap();
        qs.reset_arrangement(&g).await;
        (qs, g, people)
    }

    #[tokio::test]
    async fn nhop_describe_zero_hops_equals_describe() {
        let (qs, g, people) = setup_chain_qs().await;
        let alice_mb = people[0].to_multibase();
        let plain = qs.sparql_describe(&g, &format!("DESCRIBE <cid:{alice_mb}>"))
            .await.unwrap();
        let zero  = qs.sparql_describe_n_hop(&g, &format!("DESCRIBE <cid:{alice_mb}>"), 0)
            .await.unwrap();
        assert_eq!(zero.len(), plain.len(), "0-hop == plain DESCRIBE");
    }

    #[tokio::test]
    async fn nhop_describe_one_hop_includes_neighbor() {
        // Alice has: name + knows->bob = 2 quads
        // 1-hop adds Bob: name + knows->carol = 2 quads → 4 total
        let (qs, g, people) = setup_chain_qs().await;
        let alice_mb = people[0].to_multibase();
        let quads = qs.sparql_describe_n_hop(
            &g,
            &format!("DESCRIBE <cid:{alice_mb}>"),
            1,
        ).await.unwrap();
        assert_eq!(quads.len(), 4, "1-hop should include Alice + Bob = 4 quads, got {}", quads.len());
        let subjects: std::collections::HashSet<_> =
            quads.iter().map(|q| q.subject.clone()).collect();
        assert!(subjects.contains(&people[0]), "must contain Alice");
        assert!(subjects.contains(&people[1]), "must contain Bob (1-hop neighbor)");
        assert!(!subjects.contains(&people[2]), "must NOT contain Carol (2-hop)");
    }

    #[tokio::test]
    async fn nhop_describe_three_hops_traverses_whole_chain() {
        // 3 hops: Alice → Bob → Carol → Dave
        // Each has name + (knows for 0..2) = 4 + 2 + 2 + 2 - 1 (dave no knows) = 7
        // alice=2, bob=2, carol=2, dave=1 → 7 quads
        let (qs, g, people) = setup_chain_qs().await;
        let alice_mb = people[0].to_multibase();
        let quads = qs.sparql_describe_n_hop(
            &g,
            &format!("DESCRIBE <cid:{alice_mb}>"),
            3,
        ).await.unwrap();
        let subjects: std::collections::HashSet<_> =
            quads.iter().map(|q| q.subject.clone()).collect();
        assert_eq!(subjects.len(), 4, "3-hop must reach all 4 entities, got {}", subjects.len());
        for p in &people {
            assert!(subjects.contains(p), "must contain {}", p.to_multibase());
        }
    }

    #[tokio::test]
    async fn nhop_describe_stops_when_no_more_cid_objects() {
        // Dave has no outgoing CID refs → traversal stops naturally
        let (qs, g, people) = setup_chain_qs().await;
        let dave_mb = people[3].to_multibase();
        let quads = qs.sparql_describe_n_hop(
            &g,
            &format!("DESCRIBE <cid:{dave_mb}>"),
            10,
        ).await.unwrap();
        assert_eq!(quads.len(), 1, "Dave alone (just name), got {}", quads.len());
    }

    #[tokio::test]
    async fn nhop_describe_authed_real_eddsa() {
        let (qs, g, people) = setup_chain_qs().await;
        let chain = make_real_eddsa_cacao(&g.to_multibase(), "quad:read");
        let alice_mb = people[0].to_multibase();
        let result = qs.sparql_describe_n_hop_authed(
            &g,
            &format!("DESCRIBE <cid:{alice_mb}>"),
            2,
            &chain,
        ).await;
        assert!(result.is_ok(), "authed n-hop DESCRIBE must succeed: {result:?}");
        // 2-hop: Alice (name+knows) + Bob (name+knows) + Carol (name+knows) = 6
        assert_eq!(result.unwrap().len(), 6, "2-hop quads count");
    }

    #[tokio::test]
    async fn nhop_describe_authed_denied_wrong_graph() {
        let (qs, g, people) = setup_chain_qs().await;
        let wrong = KotobaCid::from_bytes(b"nhop-wrong-graph");
        let chain = make_real_eddsa_cacao(&wrong.to_multibase(), "quad:read");
        let alice_mb = people[0].to_multibase();
        let result = qs.sparql_describe_n_hop_authed(
            &g,
            &format!("DESCRIBE <cid:{alice_mb}>"),
            2,
            &chain,
        ).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))), "wrong graph denied");
    }

    // ─── CACAO + SERVICE + multi-graph integration ──────────────────────────────

    /// Build a real-signed CACAO authorizing multiple graphs (uses the new
    /// multi-graph CACAO support added to kotoba-auth).
    fn make_multigraph_cacao(graph_mbs: &[&str], capability: &str) -> DelegationChain {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::{SigningKey, Signer};
        use kotoba_auth::cacao::{Cacao, CacaoHeader, CacaoPayload, CacaoSig};
        use kotoba_auth::did_key::ed25519_pubkey_to_did_key;

        let sk  = SigningKey::from_bytes(&[17u8; 32]);
        let pk  = sk.verifying_key();
        let did = ed25519_pubkey_to_did_key(pk.as_bytes());

        let mut resources = vec![format!("kotoba://can/{capability}")];
        for g in graph_mbs {
            resources.push(format!("kotoba://graph/{g}"));
        }
        let template = Cacao {
            h: CacaoHeader { t: "eip4361".to_string() },
            p: CacaoPayload {
                iss:       did,
                aud:       "https://kotoba.test".to_string(),
                issued_at: "2026-01-01T00:00:00Z".to_string(),
                expiry:    Some("2099-01-01T00:00:00Z".to_string()),
                nonce:     "multi-graph-cacao".to_string(),
                domain:    "kotoba.test".to_string(),
                statement: None,
                version:   "1".to_string(),
                resources,
            },
            s: CacaoSig { t: "EdDSA".to_string(), s: String::new() },
        };
        let msg     = template.siwe_message();
        let sig     = sk.sign(msg.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let cacao   = Cacao { s: CacaoSig { t: "EdDSA".to_string(), s: sig_b64 }, ..template };
        DelegationChain::new(cacao)
    }

    #[tokio::test]
    async fn cacao_service_multigraph_authed_both_graphs() {
        // CACAO authorizes g1 + g2; SERVICE federates from g1 to g2; verify() succeeds.
        let (qs, g1, g2) = setup_two_graph_qs().await;
        let g1_mb = g1.to_multibase();
        let g2_mb = g2.to_multibase();
        let chain = make_multigraph_cacao(&[&g1_mb, &g2_mb], "quad:read");

        // 1) Local g1 query
        let local = qs.cold_query_sparql_bgp_authed(
            &g1,
            "SELECT * WHERE { ?s <role> ?r }",
            &chain,
        ).await.unwrap();
        assert_eq!(local.len(), 1, "g1 has 1 quad (alice=admin)");

        // 2) Federated query via SERVICE — caller is in g1, fetches g2 quads.
        //    Use the multi_graph_authed wrapper which post-filters by authorized graphs.
        let federated = qs.cold_query_sparql_bgp_multi_graph_authed(
            &g1,
            &format!("SELECT * WHERE {{ SERVICE <cid:{g2_mb}> {{ ?s <role> ?r }} }}"),
            &chain,
        ).await.unwrap();
        assert_eq!(federated.len(), 2, "g2 has 2 role quads (bob=user, alice=viewer)");
        assert!(federated.iter().all(|q| q.graph == g2),
            "all federated results must be from g2");
    }

    #[tokio::test]
    async fn cacao_service_multigraph_denies_unauthorized_target() {
        // CACAO authorizes only g1; SERVICE targets g2 → multi_graph_authed
        // post-filters and returns empty (results not in authorized_graphs).
        let (qs, g1, g2) = setup_two_graph_qs().await;
        let g1_mb = g1.to_multibase();
        let g2_mb = g2.to_multibase();
        let chain = make_multigraph_cacao(&[&g1_mb], "quad:read");

        let federated = qs.cold_query_sparql_bgp_multi_graph_authed(
            &g1,
            &format!("SELECT * WHERE {{ SERVICE <cid:{g2_mb}> {{ ?s <role> ?r }} }}"),
            &chain,
        ).await.unwrap();
        assert!(federated.is_empty(),
            "g2 quads must be filtered out (not in authorized_graphs), got {}", federated.len());
    }

    // ─── Crash recovery via WAL replay ─────────────────────────────────────────

    #[tokio::test]
    async fn crash_recovery_committed_data_survives_journal_replay() {
        // Scenario: store A asserts + commits → write checkpoint.  A is dropped.
        // Store B is brought up against the SAME BlockStore + Journal head_path.
        // After replay_from_journal it must serve the committed data via cold query.
        let dir       = tempfile::tempdir().unwrap();
        let head_path = dir.path().join("journal_head.json");
        let block_store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(MemoryBlockStore::new());

        let graph = KotobaCid::from_bytes(b"crash-recovery-graph");
        let alice = KotobaCid::from_bytes(b"crash-alice");
        let bob   = KotobaCid::from_bytes(b"crash-bob");

        // --- Instance A: insert + commit ---
        {
            let journal_a = Arc::new(Journal::with_block_store(
                Arc::clone(&block_store), head_path.clone(),
            ));
            let qs_a = QuadStore::new(Arc::clone(&journal_a), Arc::clone(&block_store));
            qs_a.assert(Quad { graph: graph.clone(), subject: alice.clone(),
                predicate: "name".into(), object: QuadObject::Text("Alice".into()) }).await;
            qs_a.assert(Quad { graph: graph.clone(), subject: alice.clone(),
                predicate: "role".into(), object: QuadObject::Text("admin".into()) }).await;
            qs_a.assert(Quad { graph: graph.clone(), subject: bob.clone(),
                predicate: "role".into(), object: QuadObject::Text("user".into()) }).await;
            qs_a.commit("did:test", graph.clone(), 1).await.unwrap();
            // A goes out of scope — simulates process crash AFTER commit
        }

        // --- Instance B: reopen against same store + journal head_path ---
        let journal_b = Arc::new(Journal::with_block_store(
            Arc::clone(&block_store), head_path.clone(),
        ));
        let qs_b = QuadStore::new(Arc::clone(&journal_b), Arc::clone(&block_store));
        qs_b.replay_from_journal().await;

        // Verify committed quads are queryable via cold path
        let quads = qs_b.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <role> ?r }"#,
        ).await.unwrap();
        assert_eq!(quads.len(), 2, "2 role quads must survive crash, got {}", quads.len());

        let entity_quads = qs_b.get_entity_quads_cold(&graph, &alice).await.unwrap();
        assert_eq!(entity_quads.len(), 2, "Alice's name + role survive, got {}", entity_quads.len());
    }

    #[tokio::test]
    async fn crash_recovery_uncommitted_writes_recovered_from_wal() {
        // Scenario: assert quads WITHOUT commit, drop instance, reopen.
        // Replay should restore hot-path arrangement from journal entries.
        let dir       = tempfile::tempdir().unwrap();
        let head_path = dir.path().join("journal_head.json");
        let block_store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(MemoryBlockStore::new());

        let graph = KotobaCid::from_bytes(b"wal-only-graph");

        {
            let journal_a = Arc::new(Journal::with_block_store(
                Arc::clone(&block_store), head_path.clone(),
            ));
            let qs_a = QuadStore::new(Arc::clone(&journal_a), Arc::clone(&block_store));
            qs_a.assert(Quad { graph: graph.clone(),
                subject: KotobaCid::from_bytes(b"wal-s1"),
                predicate: "label".into(),
                object: QuadObject::Text("pre-commit-1".into()) }).await;
            qs_a.assert(Quad { graph: graph.clone(),
                subject: KotobaCid::from_bytes(b"wal-s2"),
                predicate: "label".into(),
                object: QuadObject::Text("pre-commit-2".into()) }).await;
            // NO commit — simulates crash before commit; checkpoint never written
        }

        let journal_b = Arc::new(Journal::with_block_store(
            Arc::clone(&block_store), head_path.clone(),
        ));
        let qs_b = QuadStore::new(Arc::clone(&journal_b), Arc::clone(&block_store));
        qs_b.replay_from_journal().await;

        // The two quads should be present in the hot arrangement after replay.
        // Hot query via predicate scan.
        let arr_ref = qs_b.arrangements.get(&graph.to_multibase())
            .expect("graph must have arrangement after replay");
        let subjects: Vec<_> = arr_ref.get_subjects_by_predicate("label");
        assert_eq!(subjects.len(), 2, "2 WAL-restored quads expected, got {}", subjects.len());
    }

    #[tokio::test]
    async fn crash_recovery_committed_plus_uncommitted_recovered() {
        // Mixed: commit some quads, assert MORE without commit, crash, reopen.
        // Both batches must be queryable post-replay.
        let dir       = tempfile::tempdir().unwrap();
        let head_path = dir.path().join("journal_head.json");
        let block_store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(MemoryBlockStore::new());

        let graph = KotobaCid::from_bytes(b"mixed-recovery-graph");

        {
            let journal_a = Arc::new(Journal::with_block_store(
                Arc::clone(&block_store), head_path.clone(),
            ));
            let qs_a = QuadStore::new(Arc::clone(&journal_a), Arc::clone(&block_store));
            // Batch 1: assert + commit
            qs_a.assert(Quad { graph: graph.clone(),
                subject: KotobaCid::from_bytes(b"mix-1"),
                predicate: "role".into(),
                object: QuadObject::Text("admin".into()) }).await;
            qs_a.commit("did:test", graph.clone(), 1).await.unwrap();
            // Batch 2: assert WITHOUT commit
            qs_a.assert(Quad { graph: graph.clone(),
                subject: KotobaCid::from_bytes(b"mix-2"),
                predicate: "role".into(),
                object: QuadObject::Text("editor".into()) }).await;
        }

        let journal_b = Arc::new(Journal::with_block_store(
            Arc::clone(&block_store), head_path.clone(),
        ));
        let qs_b = QuadStore::new(Arc::clone(&journal_b), Arc::clone(&block_store));
        qs_b.replay_from_journal().await;

        // Uncommitted quad: visible via hot arrangement (WAL-restored)
        let arr_ref = qs_b.arrangements.get(&graph.to_multibase())
            .expect("hot arrangement present");
        let editors: Vec<_> = arr_ref.get_subjects_by_predicate_object("role", "editor");
        assert_eq!(editors.len(), 1, "uncommitted WAL editor quad must be hot");
        drop(arr_ref);

        // Committed quad: hot path currently shadows cold when arrangement is
        // non-empty (route_bgp_triples returns early on hot hit). After
        // reset_arrangement clears hot, cold ProllyTree serves the committed
        // admin quad. This documents the current hot-vs-cold semantics —
        // a true union semantics would query both layers, but that is a
        // separate design change.
        qs_b.reset_arrangement(&graph).await;
        let cold = qs_b.cold_query_sparql_bgp(&graph,
            r#"SELECT * WHERE { ?s <role> "admin" }"#).await.unwrap();
        assert_eq!(cold.len(), 1, "committed quad must be cold-readable after hot clear");
    }

    #[tokio::test]
    async fn sparql_bgp_hot_cold_union_after_replay() {
        // SPARQL BGP query after replay must see BOTH committed (cold) and
        // WAL-restored (hot) quads — uses the union path via
        // quads_by_predicate_prefix_cold + lookup_subject_by_po_cold.
        let dir       = tempfile::tempdir().unwrap();
        let head_path = dir.path().join("journal_head.json");
        let block_store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(MemoryBlockStore::new());
        let graph = KotobaCid::from_bytes(b"sparql-union-graph");

        {
            let journal_a = Arc::new(Journal::with_block_store(
                Arc::clone(&block_store), head_path.clone(),
            ));
            let qs_a = QuadStore::new(Arc::clone(&journal_a), Arc::clone(&block_store));
            qs_a.assert(Quad { graph: graph.clone(),
                subject: KotobaCid::from_bytes(b"un-alice"),
                predicate: "role".into(),
                object: QuadObject::Text("admin".into()) }).await;
            qs_a.commit("did:union", graph.clone(), 1).await.unwrap();
            // Uncommitted: another admin role only in WAL
            qs_a.assert(Quad { graph: graph.clone(),
                subject: KotobaCid::from_bytes(b"un-bob"),
                predicate: "role".into(),
                object: QuadObject::Text("admin".into()) }).await;
        }

        let journal_b = Arc::new(Journal::with_block_store(
            Arc::clone(&block_store), head_path.clone(),
        ));
        let qs_b = QuadStore::new(Arc::clone(&journal_b), Arc::clone(&block_store));
        qs_b.replay_from_journal().await;

        let admins = qs_b.cold_query_sparql_bgp(
            &graph,
            r#"SELECT * WHERE { ?s <role> "admin" }"#,
        ).await.unwrap();
        assert_eq!(admins.len(), 2,
            "BGP must return committed un-alice + WAL un-bob = 2 admins, got {}",
            admins.len());
    }

    // ─── Datalog over IPFS-backed cold storage ────────────────────────────────

    #[tokio::test]
    async fn datalog_cold_evaluates_against_prolly_tree_facts() {
        // Datalog rule: transitive_closure(?x, ?z) :- knows(?x, ?y), knows(?y, ?z).
        // Set up a 2-hop knows chain, commit to ProllyTree (cold), then evaluate
        // the program — every join must be served by BlockStore-backed scans.
        use kotoba_kqe::datalog::{DatalogProgram, DatalogRule, Atom, BodyLiteral, Term};

        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let g = KotobaCid::from_bytes(b"datalog-cold-graph");
        let a = KotobaCid::from_bytes(b"dl-alice");
        let b = KotobaCid::from_bytes(b"dl-bob");
        let c = KotobaCid::from_bytes(b"dl-carol");

        qs.assert(Quad { graph: g.clone(), subject: a.clone(),
            predicate: "knows".into(), object: QuadObject::Cid(b.clone()) }).await;
        qs.assert(Quad { graph: g.clone(), subject: b.clone(),
            predicate: "knows".into(), object: QuadObject::Cid(c.clone()) }).await;
        qs.commit("did:dl", g.clone(), 1).await.unwrap();
        qs.reset_arrangement(&g).await;  // force cold path

        let mut program = DatalogProgram::new();
        program.add_rule(DatalogRule {
            head: Atom { relation: "closure".into(),
                args: vec![Term::Variable("x".into()), Term::Variable("z".into())] },
            body: vec![
                BodyLiteral::Positive(Atom { relation: "knows".into(),
                    args: vec![Term::Variable("x".into()), Term::Variable("y".into())] }),
                BodyLiteral::Positive(Atom { relation: "knows".into(),
                    args: vec![Term::Variable("y".into()), Term::Variable("z".into())] }),
            ],
        });

        let derived = qs.evaluate_datalog_cold(&g, &program).await.unwrap();
        assert_eq!(derived.len(), 1, "1 closure fact expected, got {}", derived.len());
        assert_eq!(derived[0].quad.subject, a, "closure subject must be alice");
        match derived[0].quad.object {
            QuadObject::Cid(ref oc) => assert_eq!(*oc, c, "closure object must be carol"),
            _ => panic!("closure object must be a CID"),
        }
    }

    #[tokio::test]
    async fn datalog_cold_unions_hot_uncommitted_facts() {
        use kotoba_kqe::datalog::{DatalogProgram, DatalogRule, Atom, BodyLiteral, Term};

        let qs = QuadStore::new(
            Arc::new(Journal::new()),
            Arc::new(MemoryBlockStore::new()) as Arc<dyn BlockStore + Send + Sync>,
        );
        let g = KotobaCid::from_bytes(b"datalog-mix-graph");
        let a = KotobaCid::from_bytes(b"mix-alice");
        let b = KotobaCid::from_bytes(b"mix-bob");
        let c = KotobaCid::from_bytes(b"mix-carol");

        qs.assert(Quad { graph: g.clone(), subject: a.clone(),
            predicate: "knows".into(), object: QuadObject::Cid(b.clone()) }).await;
        qs.commit("did:dl-mix", g.clone(), 1).await.unwrap();
        // Uncommitted edge — hot only
        qs.assert(Quad { graph: g.clone(), subject: b.clone(),
            predicate: "knows".into(), object: QuadObject::Cid(c.clone()) }).await;

        let mut program = DatalogProgram::new();
        program.add_rule(DatalogRule {
            head: Atom { relation: "closure".into(),
                args: vec![Term::Variable("x".into()), Term::Variable("z".into())] },
            body: vec![
                BodyLiteral::Positive(Atom { relation: "knows".into(),
                    args: vec![Term::Variable("x".into()), Term::Variable("y".into())] }),
                BodyLiteral::Positive(Atom { relation: "knows".into(),
                    args: vec![Term::Variable("y".into()), Term::Variable("z".into())] }),
            ],
        });

        let derived = qs.evaluate_datalog_cold(&g, &program).await.unwrap();
        assert_eq!(derived.len(), 1,
            "must derive closure(a,c) from hot+cold facts, got {}", derived.len());
    }

    #[tokio::test]
    async fn datalog_cold_authed_real_eddsa() {
        use kotoba_kqe::datalog::{DatalogProgram, DatalogRule, Atom, BodyLiteral, Term};

        let (qs, g, _people) = setup_chain_qs().await;
        let chain = make_real_eddsa_cacao(&g.to_multibase(), "quad:read");

        let mut program = DatalogProgram::new();
        program.add_rule(DatalogRule {
            head: Atom { relation: "two_hop".into(),
                args: vec![Term::Variable("x".into()), Term::Variable("z".into())] },
            body: vec![
                BodyLiteral::Positive(Atom { relation: "knows".into(),
                    args: vec![Term::Variable("x".into()), Term::Variable("y".into())] }),
                BodyLiteral::Positive(Atom { relation: "knows".into(),
                    args: vec![Term::Variable("y".into()), Term::Variable("z".into())] }),
            ],
        });

        let result = qs.evaluate_datalog_cold_authed(&g, &program, &chain).await;
        assert!(result.is_ok(), "authed datalog must succeed: {result:?}");
        // setup_chain_qs: alice→bob→carol→dave; 2-hop = (alice,carol), (bob,dave) = 2
        let derived = result.unwrap();
        assert_eq!(derived.len(), 2, "2 two-hop closures expected, got {}", derived.len());
    }

    #[tokio::test]
    async fn datalog_cold_authed_denied_wrong_graph() {
        use kotoba_kqe::datalog::DatalogProgram;
        let (qs, g, _people) = setup_chain_qs().await;
        let wrong = KotobaCid::from_bytes(b"datalog-wrong-graph");
        let chain = make_real_eddsa_cacao(&wrong.to_multibase(), "quad:read");
        let program = DatalogProgram::new();
        let result = qs.evaluate_datalog_cold_authed(&g, &program, &chain).await;
        assert!(matches!(result, Err(AccessError::Delegation(_))),
            "wrong-graph CACAO must be denied");
    }

    #[tokio::test]
    async fn hot_cold_union_after_replay_returns_both_layers() {
        // Verifies hot_covers_all flag: after replay puts uncommitted in hot,
        // get_entity_quads_cold must union hot+cold instead of short-circuiting.
        let dir       = tempfile::tempdir().unwrap();
        let head_path = dir.path().join("journal_head.json");
        let block_store: Arc<dyn BlockStore + Send + Sync> =
            Arc::new(MemoryBlockStore::new());

        let graph = KotobaCid::from_bytes(b"hot-cold-union-graph");
        let alice = KotobaCid::from_bytes(b"hcu-alice");

        {
            let journal_a = Arc::new(Journal::with_block_store(
                Arc::clone(&block_store), head_path.clone(),
            ));
            let qs_a = QuadStore::new(Arc::clone(&journal_a), Arc::clone(&block_store));
            // committed: name + role
            qs_a.assert(Quad { graph: graph.clone(), subject: alice.clone(),
                predicate: "name".into(), object: QuadObject::Text("Alice".into()) }).await;
            qs_a.assert(Quad { graph: graph.clone(), subject: alice.clone(),
                predicate: "role".into(), object: QuadObject::Text("admin".into()) }).await;
            qs_a.commit("did:test", graph.clone(), 1).await.unwrap();
            // uncommitted: an extra label quad — only in hot/journal
            qs_a.assert(Quad { graph: graph.clone(), subject: alice.clone(),
                predicate: "label".into(), object: QuadObject::Text("VIP".into()) }).await;
        }

        let journal_b = Arc::new(Journal::with_block_store(
            Arc::clone(&block_store), head_path.clone(),
        ));
        let qs_b = QuadStore::new(Arc::clone(&journal_b), Arc::clone(&block_store));
        qs_b.replay_from_journal().await;

        // Without union: would have returned only the WAL-restored "label" (1 quad).
        // With union: cold name+role + hot label = 3 quads.
        let quads = qs_b.get_entity_quads_cold(&graph, &alice).await.unwrap();
        assert_eq!(quads.len(), 3,
            "hot∪cold must return committed name+role + uncommitted label, got {}", quads.len());
        let preds: std::collections::HashSet<_> = quads.iter()
            .map(|q| q.predicate.as_str()).collect();
        assert!(preds.contains("name"),  "cold name must be visible");
        assert!(preds.contains("role"),  "cold role must be visible");
        assert!(preds.contains("label"), "hot label must be visible");
    }

    // ─── CID-addressed materialised view cache ─────────────────────────────────

    #[tokio::test]
    async fn cached_query_first_call_miss_second_hit() {
        // First call: cache miss, computes result + persists under MV CID.
        // Second call: cache hit, returns same result with same CID, no recompute.
        let (qs, graph) = setup_sparql_qs().await;
        let q = r#"SELECT * WHERE { ?s <role> "admin" }"#;
        let (r1, cid1, hit1) = qs.cold_query_sparql_bgp_cached(&graph, q).await.unwrap();
        let (r2, cid2, hit2) = qs.cold_query_sparql_bgp_cached(&graph, q).await.unwrap();

        assert!(!hit1, "first call must be a miss");
        assert!(hit2,  "second call must be a hit");
        assert_eq!(cid1, cid2, "MV CID must be stable across calls");
        assert_eq!(r1.len(), r2.len(), "cached result must equal live result");
        assert_eq!(r1, r2, "byte-identical cached vs live");
        assert_eq!(r1.len(), 2, "2 admins expected");
    }

    #[tokio::test]
    async fn cached_query_distinct_sparql_distinct_cids() {
        // Different SPARQL strings → different MV CIDs.
        let (qs, graph) = setup_sparql_qs().await;
        let (_, cid_a, _) = qs.cold_query_sparql_bgp_cached(
            &graph, r#"SELECT * WHERE { ?s <role> "admin" }"#).await.unwrap();
        let (_, cid_b, _) = qs.cold_query_sparql_bgp_cached(
            &graph, r#"SELECT * WHERE { ?s <role> "user" }"#).await.unwrap();
        assert_ne!(cid_a, cid_b, "different queries must yield different MV CIDs");
    }

    #[tokio::test]
    async fn cached_query_aggregate_persists_under_cid() {
        // GROUP BY aggregate query — exactly the case where CID-MV is most valuable.
        let (qs, graph) = setup_sparql_qs().await;
        let q = "SELECT ?r (COUNT(*) AS ?n) WHERE { ?s <role> ?r } GROUP BY ?r";
        let (r1, cid1, hit1) = qs.cold_query_sparql_bgp_cached(&graph, q).await.unwrap();
        assert!(!hit1, "first aggregate call must be a miss");
        assert_eq!(r1.len(), 2, "two role groups");
        let (r2, cid2, hit2) = qs.cold_query_sparql_bgp_cached(&graph, q).await.unwrap();
        assert!(hit2, "second aggregate call must be a hit");
        assert_eq!(cid1, cid2, "aggregate MV CID stable");
        assert_eq!(r1, r2, "aggregate result identical");
    }

    #[tokio::test]
    async fn cacao_service_silent_unknown_endpoint_returns_empty_under_auth() {
        // SERVICE SILENT to unknown endpoint under CACAO gating still returns empty
        let (qs, g1, _g2) = setup_two_graph_qs().await;
        let g1_mb = g1.to_multibase();
        let chain = make_multigraph_cacao(&[&g1_mb], "quad:read");

        let result = qs.cold_query_sparql_bgp_multi_graph_authed(
            &g1,
            "SELECT * WHERE { SERVICE SILENT <kotoba://node/did:not-routed> { ?s <role> ?r } }",
            &chain,
        ).await.unwrap();
        assert!(result.is_empty(), "SILENT unknown service must return empty under CACAO");
    }
}
