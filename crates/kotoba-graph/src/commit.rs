use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Commit — 4-ProllyTree root snapshot per named graph (≅ AT Protocol Repo Commit)
/// T in KOTOBA's Datom model: content-addressed, not integer.
///
/// `root` = EAVT (SPO) tree root — kept for backward compatibility.
/// `index_roots` = the other 3 covering-index roots: "aevt", "avet", "vaet".
///
/// The `cid` field is NOT included in the CBOR serialization — it is derived as
/// `blake3(CBOR(rest_of_fields))` and restored on load from the block-store key.
/// Old commits (without `index_roots`) load with an empty map (field defaults to `{}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    #[serde(skip)]
    pub cid:         KotobaCid,                    // derived; not stored in block bytes
    pub graph:       KotobaCid,                    // named graph
    pub root:        KotobaCid,                    // EAVT (SPO) ProllyTree root CID
    pub prev:        Option<KotobaCid>,            // parent commit (DAG)
    pub author:      String,                       // DID
    pub seq:         u64,                          // monotonic (≅ AT Protocol rev)
    pub ts:          u64,                          // unix seconds
    /// Additional covering-index roots: "aevt" / "avet" / "vaet".
    /// Omitted from CBOR when empty (old-format commits remain CID-stable on read).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub index_roots: HashMap<String, KotobaCid>,
}

impl Commit {
    /// Build a new commit, computing its CID from the CBOR of the payload fields.
    pub fn seal(
        graph:       KotobaCid,
        root:        KotobaCid,
        prev:        Option<KotobaCid>,
        author:      String,
        seq:         u64,
        index_roots: HashMap<String, KotobaCid>,
    ) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut c = Self {
            cid: KotobaCid([0u8; 36]),
            graph, root, prev, author, seq, ts, index_roots,
        };

        // Compute CID from CBOR of payload (cid field is skipped by serde)
        let mut buf = Vec::new();
        ciborium::into_writer(&c, &mut buf).expect("cbor commit seal");
        c.cid = KotobaCid::from_bytes(&buf);
        c
    }

    /// CBOR-encode payload (cid skipped) and write to block store.
    /// Returns the commit CID (= `self.cid`).
    pub fn persist(&self, store: &dyn BlockStore) -> anyhow::Result<KotobaCid> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| anyhow::anyhow!("cbor encode commit: {e}"))?;
        let cid = KotobaCid::from_bytes(&buf);
        anyhow::ensure!(cid == self.cid, "commit CID mismatch on persist");
        store.put(&cid, &buf)?;
        Ok(cid)
    }

    /// Load a Commit from the block store; restores `cid` from the store key.
    pub fn load(cid: &KotobaCid, store: &dyn BlockStore) -> anyhow::Result<Option<Self>> {
        match store.get(cid)? {
            None => Ok(None),
            Some(bytes) => {
                let mut commit: Self = ciborium::from_reader(&bytes[..])
                    .map_err(|e| anyhow::anyhow!("cbor decode commit: {e}"))?;
                commit.cid = cid.clone();
                Ok(Some(commit))
            }
        }
    }
}

/// CommitDag — Pregel checkpoint store (≅ LangGraph checkpoint)
pub struct CommitDag {
    commits: HashMap<String, Commit>,    // cid → commit
    heads:   HashMap<String, KotobaCid>, // graph_cid → head commit_cid
}

impl Default for CommitDag {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitDag {
    pub fn new() -> Self {
        Self { commits: HashMap::new(), heads: HashMap::new() }
    }

    pub fn add(&mut self, commit: Commit) {
        let graph_key = commit.graph.to_multibase();
        let cid_key   = commit.cid.to_multibase();
        self.heads.insert(graph_key, commit.cid.clone());
        self.commits.insert(cid_key, commit);
    }

    pub fn head(&self, graph_cid: &KotobaCid) -> Option<&Commit> {
        self.heads.get(&graph_cid.to_multibase())
            .and_then(|c| self.commits.get(&c.to_multibase()))
    }

    /// Look up any commit by CID (not just heads).
    pub fn get(&self, cid: &KotobaCid) -> Option<&Commit> {
        self.commits.get(&cid.to_multibase())
    }

    /// Return all head commit CIDs as a map from graph multibase → commit multibase.
    /// Used by `kqe.get-head` in WASM guests.
    pub fn heads_as_map(&self) -> std::collections::HashMap<String, String> {
        self.heads.iter()
            .map(|(graph_mb, commit_cid)| (graph_mb.clone(), commit_cid.to_multibase()))
            .collect()
    }

    /// Compute the set of all live block CIDs referenced by every commit in the DAG.
    ///
    /// Includes: commit blocks + all ProllyTree block CIDs reachable from each commit's
    /// 4 index roots (eavt, aevt, avet, vaet).  Used by `QuadStore::gc_dead_blocks`.
    pub fn all_live_cids(
        &self,
        store: &dyn BlockStore,
    ) -> anyhow::Result<std::collections::HashSet<KotobaCid>> {
        use kotoba_core::prolly::ProllyTree;
        let mut live = std::collections::HashSet::new();
        for commit in self.commits.values() {
            live.insert(commit.cid.clone());
            let roots = std::iter::once(&commit.root)
                .chain(commit.index_roots.values());
            for root in roots {
                for cid in ProllyTree::walk_all_cids(root, store)? {
                    live.insert(cid);
                }
            }
        }
        Ok(live)
    }

    /// Prune non-HEAD commits with `seq < before_seq` from the in-memory DAG.
    ///
    /// HEAD commits (pointed to by `heads`) are always retained regardless of seq,
    /// because gc_dead_blocks() uses them as GC roots.  Only historical (non-HEAD)
    /// commits are eligible for removal.
    ///
    /// Returns the number of commit entries removed.
    pub fn prune_non_head(&mut self, before_seq: u64) -> usize {
        // Collect the set of all current HEAD CID multibase strings.
        let head_cids: std::collections::HashSet<String> =
            self.heads.values().map(|c| c.to_multibase()).collect();

        let before = self.commits.len();
        self.commits.retain(|cid_mb, commit| {
            // Always keep: HEAD commits and commits at/after before_seq.
            head_cids.contains(cid_mb) || commit.seq >= before_seq
        });
        before - self.commits.len()
    }

    /// Return the total number of commits stored (HEAD + historical).
    pub fn commit_count(&self) -> usize {
        self.commits.len()
    }

    /// Persist the head commit for `graph_cid` to the block store.
    pub fn persist_head(
        &self,
        graph_cid: &KotobaCid,
        store: &dyn BlockStore,
    ) -> anyhow::Result<Option<KotobaCid>> {
        match self.head(graph_cid) {
            None => Ok(None),
            Some(commit) => commit.persist(store).map(Some),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_store::MemoryBlockStore;

    #[test]
    fn commit_roundtrip() {
        let store = MemoryBlockStore::new();
        let graph  = KotobaCid::from_bytes(b"graph");
        let root   = KotobaCid::from_bytes(b"root");
        let commit = Commit::seal(graph.clone(), root.clone(), None, "did:test".into(), 1, HashMap::new());
        let cid    = commit.persist(&store).unwrap();
        let loaded = Commit::load(&cid, &store).unwrap().unwrap();
        assert_eq!(loaded.author, "did:test");
        assert_eq!(loaded.seq, 1);
        assert_eq!(loaded.root, root);
    }

    #[test]
    fn commit_with_index_roots_roundtrip() {
        let store  = MemoryBlockStore::new();
        let graph  = KotobaCid::from_bytes(b"graph-idx");
        let root   = KotobaCid::from_bytes(b"eavt-root");
        let mut idx = HashMap::new();
        idx.insert("aevt".to_string(), KotobaCid::from_bytes(b"aevt-root"));
        idx.insert("avet".to_string(), KotobaCid::from_bytes(b"avet-root"));
        idx.insert("vaet".to_string(), KotobaCid::from_bytes(b"vaet-root"));
        let commit = Commit::seal(graph.clone(), root.clone(), None, "did:test".into(), 2, idx.clone());
        let cid    = commit.persist(&store).unwrap();
        let loaded = Commit::load(&cid, &store).unwrap().unwrap();
        assert_eq!(loaded.index_roots.get("aevt"), idx.get("aevt"));
        assert_eq!(loaded.index_roots.len(), 3);
    }

    #[test]
    fn commit_dag_head_roundtrip() {
        let store  = MemoryBlockStore::new();
        let graph  = KotobaCid::from_bytes(b"graph1");
        let root   = KotobaCid::from_bytes(b"root1");
        let commit = Commit::seal(graph.clone(), root.clone(), None, "did:x".into(), 0, HashMap::new());

        let mut dag = CommitDag::new();
        dag.add(commit);
        let cid = dag.persist_head(&graph, &store).unwrap().unwrap();
        let loaded = Commit::load(&cid, &store).unwrap().unwrap();
        assert_eq!(loaded.graph, graph);
    }

    #[test]
    fn prune_non_head_removes_old_non_head_commits() {
        let graph = KotobaCid::from_bytes(b"g");
        let mut dag = CommitDag::new();

        // Add 3 commits seq 0, 1, 2; the last one becomes HEAD.
        for seq in 0u64..3 {
            let root = KotobaCid::from_bytes(format!("root-{seq}").as_bytes());
            let c = Commit::seal(graph.clone(), root, None, "did:x".into(), seq, HashMap::new());
            dag.add(c);
        }
        assert_eq!(dag.commit_count(), 3);

        // Prune commits with seq < 2 (non-HEAD); HEAD (seq=2) must survive.
        let pruned = dag.prune_non_head(2);
        assert_eq!(pruned, 2, "expected 2 old commits pruned");
        assert_eq!(dag.commit_count(), 1, "only HEAD should remain");

        // HEAD is still accessible.
        let head = dag.head(&graph).expect("head must survive pruning");
        assert_eq!(head.seq, 2);
    }

    #[test]
    fn prune_non_head_always_keeps_head_even_below_seq_threshold() {
        let graph = KotobaCid::from_bytes(b"g2");
        let root  = KotobaCid::from_bytes(b"r");
        let mut dag = CommitDag::new();
        // Only one commit at seq=0; it is HEAD.
        let c = Commit::seal(graph.clone(), root, None, "did:x".into(), 0, HashMap::new());
        dag.add(c);

        // Prune with before_seq=100 (higher than HEAD seq); HEAD must still survive.
        let pruned = dag.prune_non_head(100);
        assert_eq!(pruned, 0, "HEAD must not be pruned regardless of seq threshold");
        assert_eq!(dag.commit_count(), 1);
    }

    #[test]
    fn prune_non_head_leaves_recent_non_head_commits() {
        let graph = KotobaCid::from_bytes(b"g3");
        let mut dag = CommitDag::new();
        for seq in 0u64..5 {
            let root = KotobaCid::from_bytes(format!("r{seq}").as_bytes());
            let c = Commit::seal(graph.clone(), root, None, "did:x".into(), seq, HashMap::new());
            dag.add(c);
        }
        // Prune commits with seq < 3; seq 3 is recent non-HEAD, seq 4 is HEAD.
        let pruned = dag.prune_non_head(3);
        // Commits 0, 1, 2 should be gone (seq < 3, non-HEAD).
        assert_eq!(pruned, 3);
        // Commits 3 (recent) and 4 (HEAD) survive.
        assert_eq!(dag.commit_count(), 2);
    }

    #[test]
    fn commit_load_missing_returns_none() {
        let store = MemoryBlockStore::new();
        let missing = KotobaCid::from_bytes(b"does-not-exist");
        let result = Commit::load(&missing, &store).unwrap();
        assert!(result.is_none(), "loading an absent CID should return Ok(None)");
    }

    #[test]
    fn commit_dag_get_non_head_by_cid() {
        let graph = KotobaCid::from_bytes(b"g-get");
        let mut dag = CommitDag::new();

        let c0 = Commit::seal(graph.clone(), KotobaCid::from_bytes(b"root0"), None, "did:x".into(), 0, HashMap::new());
        let cid0 = c0.cid.clone();
        let c1 = Commit::seal(graph.clone(), KotobaCid::from_bytes(b"root1"), None, "did:x".into(), 1, HashMap::new());
        dag.add(c0);
        dag.add(c1);

        // c0 is no longer HEAD but should still be retrievable by CID
        let found = dag.get(&cid0);
        assert!(found.is_some(), "get() must return non-HEAD commits by CID");
        assert_eq!(found.unwrap().seq, 0);
    }

    #[test]
    fn commit_dag_heads_as_map_shape() {
        let g1 = KotobaCid::from_bytes(b"graph-a");
        let g2 = KotobaCid::from_bytes(b"graph-b");
        let mut dag = CommitDag::new();

        dag.add(Commit::seal(g1.clone(), KotobaCid::from_bytes(b"r1"), None, "did:a".into(), 0, HashMap::new()));
        dag.add(Commit::seal(g2.clone(), KotobaCid::from_bytes(b"r2"), None, "did:b".into(), 0, HashMap::new()));

        let map = dag.heads_as_map();
        assert_eq!(map.len(), 2, "heads_as_map should have one entry per graph");
        // Keys are multibase strings
        assert!(map.contains_key(&g1.to_multibase()));
        assert!(map.contains_key(&g2.to_multibase()));
    }

    #[test]
    fn commit_dag_default_is_empty() {
        let dag = CommitDag::default();
        assert_eq!(dag.commit_count(), 0);
        let heads = dag.heads_as_map();
        assert!(heads.is_empty(), "default CommitDag should have no heads");
    }
}
