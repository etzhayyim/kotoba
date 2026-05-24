use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Commit — Prolly Tree root snapshot per named graph (≅ AT Protocol Repo Commit)
/// T in KOTOBA's Datom model: content-addressed, not integer
///
/// The `cid` field is NOT included in the CBOR serialization — it is derived as
/// `blake3(CBOR(rest_of_fields))` and restored on load from the block-store key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    #[serde(skip)]
    pub cid:    KotobaCid,          // derived; not stored in block bytes
    pub graph:  KotobaCid,          // named graph
    pub root:   KotobaCid,          // Prolly Tree root CID
    pub prev:   Option<KotobaCid>,  // parent commit (DAG)
    pub author: String,             // DID
    pub seq:    u64,                // monotonic (≅ AT Protocol rev)
    pub ts:     u64,                // unix seconds
}

impl Commit {
    /// Build a new commit, computing its CID from the CBOR of the payload fields.
    pub fn seal(
        graph:  KotobaCid,
        root:   KotobaCid,
        prev:   Option<KotobaCid>,
        author: String,
        seq:    u64,
    ) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut c = Self { cid: KotobaCid([0u8; 36]), graph, root, prev, author, seq, ts };

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

    /// Return all head commit CIDs as a map from graph multibase → commit multibase.
    /// Used by `kqe.get-head` in WASM guests.
    pub fn heads_as_map(&self) -> std::collections::HashMap<String, String> {
        self.heads.iter()
            .map(|(graph_mb, commit_cid)| (graph_mb.clone(), commit_cid.to_multibase()))
            .collect()
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
        let commit = Commit::seal(graph.clone(), root.clone(), None, "did:test".into(), 1);
        let cid    = commit.persist(&store).unwrap();
        let loaded = Commit::load(&cid, &store).unwrap().unwrap();
        assert_eq!(loaded.author, "did:test");
        assert_eq!(loaded.seq, 1);
        assert_eq!(loaded.root, root);
    }

    #[test]
    fn commit_dag_head_roundtrip() {
        let store  = MemoryBlockStore::new();
        let graph  = KotobaCid::from_bytes(b"graph1");
        let root   = KotobaCid::from_bytes(b"root1");
        let commit = Commit::seal(graph.clone(), root.clone(), None, "did:x".into(), 0);

        let mut dag = CommitDag::new();
        dag.add(commit);
        let cid = dag.persist_head(&graph, &store).unwrap().unwrap();
        let loaded = Commit::load(&cid, &store).unwrap().unwrap();
        assert_eq!(loaded.graph, graph);
    }
}
