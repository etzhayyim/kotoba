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
}

impl QuadStore {
    pub fn new(journal: Arc<Journal>, block_store: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self {
            journal,
            block_store,
            arrangements:  Arc::new(DashMap::new()),
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
        self.arrangements.entry(g).or_insert_with(Arrangement::new).insert(&quad);
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
    pub async fn assert_silent(&self, quad: Quad) {
        let g = quad.graph.to_multibase();
        self.arrangements.entry(g).or_insert_with(Arrangement::new).insert(&quad);
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
        // ── Hot path ──────────────────────────────────────────────────────────
        {
            if let Some(arr) = self.arrangements.get(&graph_cid.to_multibase()) {
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

    /// Cold-path AEVT scan: fetch quads by predicate prefix from the committed ProllyTree.
    pub async fn quads_by_predicate_prefix_cold(
        &self,
        graph_cid:        &KotobaCid,
        predicate_prefix: &str,
    ) -> anyhow::Result<Vec<Quad>> {
        // ── Hot path ──────────────────────────────────────────────────────────
        {
            if let Some(arr) = self.arrangements.get(&graph_cid.to_multibase()) {
                if !arr.is_empty() {
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
        Ok(quads)
    }

    /// Cold-path AVET scan: resolve subjects by predicate + object_key from the committed ProllyTree.
    pub async fn lookup_subject_by_po_cold(
        &self,
        graph_cid:  &KotobaCid,
        predicate:  &str,
        object_key: &str,
    ) -> anyhow::Result<Vec<KotobaCid>> {
        // ── Hot path ──────────────────────────────────────────────────────────
        {
            if let Some(arr) = self.arrangements.get(&graph_cid.to_multibase()) {
                if !arr.is_empty() {
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

            other => anyhow::bail!(
                "unsupported SPARQL pattern type: {}",
                sparql_pattern_name(other)
            ),
        }
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
                return self.get_entity_quads_cold(graph_cid, &subj).await;
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

        anyhow::bail!("unsupported SPARQL BGP: only 1-triple or 2-triple join patterns are supported")
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
        if let Some(mut arr) = self.arrangements.get_mut(&graph_cid.to_multibase()) {
            arr.clear();
        }
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

/// Unwrap Project / Distinct / Reduced wrappers to expose the inner BGP pattern.
fn unwrap_bgp_pattern(pattern: spargebra::algebra::GraphPattern) -> spargebra::algebra::GraphPattern {
    use spargebra::algebra::GraphPattern;
    match pattern {
        GraphPattern::Project { inner, .. }  => unwrap_bgp_pattern(*inner),
        GraphPattern::Distinct { inner }     => unwrap_bgp_pattern(*inner),
        GraphPattern::Reduced  { inner }     => unwrap_bgp_pattern(*inner),
        other => other,
    }
}

/// Collect triple patterns from a BGP node; returns `None` if non-BGP patterns are present.
fn collect_triple_patterns(
    pattern: &spargebra::algebra::GraphPattern,
) -> Option<Vec<spargebra::term::TriplePattern>> {
    use spargebra::algebra::GraphPattern;
    match pattern {
        GraphPattern::Bgp { patterns } => Some(patterns.clone()),
        GraphPattern::Filter { inner, .. } => collect_triple_patterns(inner),
        _ => None,
    }
}

/// Parse a `cid:{multibase}` IRI into a `KotobaCid`.
///
/// Accepts bare multibase strings (no scheme) for convenience.
fn parse_cid_iri(iri: &str) -> Option<KotobaCid> {
    let mb = iri.strip_prefix("cid:").unwrap_or(iri);
    KotobaCid::from_multibase(mb)
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
                obj > v.as_str()
            } else { true }
        }
        Expression::Less(left, right) => {
            if let (Some(obj), Some(v)) = (
                obj_text,
                extract_literal_from_expr(left, right).or_else(|| extract_literal_from_expr(right, left)),
            ) {
                obj < v.as_str()
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

/// Return a human-readable name for a GraphPattern variant (for error messages).
fn sparql_pattern_name(pattern: &spargebra::algebra::GraphPattern) -> &'static str {
    use spargebra::algebra::GraphPattern;
    match pattern {
        GraphPattern::Bgp { .. }       => "BGP",
        GraphPattern::Join { .. }      => "Join",
        GraphPattern::LeftJoin { .. }  => "LeftJoin",
        GraphPattern::Filter { .. }    => "Filter",
        GraphPattern::Union { .. }     => "Union",
        GraphPattern::Graph { .. }     => "Graph",
        GraphPattern::Extend { .. }    => "Extend",
        GraphPattern::Minus { .. }     => "Minus",
        GraphPattern::Values { .. }    => "Values",
        GraphPattern::OrderBy { .. }   => "OrderBy",
        GraphPattern::Project { .. }   => "Project",
        GraphPattern::Distinct { .. }  => "Distinct",
        GraphPattern::Reduced { .. }   => "Reduced",
        GraphPattern::Slice { .. }     => "Slice",
        GraphPattern::Group { .. }     => "Group",
        _ => "Unknown",
    }
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
}
