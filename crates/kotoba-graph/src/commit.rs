use kotoba_core::cid::KotobaCid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Commit — Prolly Tree root snapshot per named graph (≅ AT Protocol Repo Commit)
/// T in KOTOBA's Datom model: content-addressed, not integer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub cid:        KotobaCid,          // blake3(CBOR(self))
    pub graph:      KotobaCid,          // named graph
    pub root:       KotobaCid,          // Prolly Tree root
    pub prev:       Option<KotobaCid>,  // parent commit (DAG)
    pub author:     String,             // DID
    pub seq:        u64,                // monotonic (≅ AT Protocol rev)
    pub ts:         u64,
}

/// CommitDag — Pregel checkpoint store (≅ LangGraph checkpoint)
pub struct CommitDag {
    commits: HashMap<String, Commit>,  // cid → commit
    heads:   HashMap<String, KotobaCid>, // graph_cid → head commit_cid
}

impl CommitDag {
    pub fn new() -> Self {
        Self { commits: HashMap::new(), heads: HashMap::new() }
    }

    pub fn add(&mut self, commit: Commit) {
        let graph_key = commit.graph.to_multibase();
        let cid_key = commit.cid.to_multibase();
        self.heads.insert(graph_key, commit.cid.clone());
        self.commits.insert(cid_key, commit);
    }

    pub fn head(&self, graph_cid: &KotobaCid) -> Option<&Commit> {
        self.heads.get(&graph_cid.to_multibase())
            .and_then(|c| self.commits.get(&c.to_multibase()))
    }
}
