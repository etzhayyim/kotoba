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
}
