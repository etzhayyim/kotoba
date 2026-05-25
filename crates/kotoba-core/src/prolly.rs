use crate::cid::KotobaCid;
use crate::store::BlockStore;
use std::collections::BTreeMap;

/// Prolly Tree — probabilistic boundary, content-addressed ordered set
/// boundary condition: blake3(node_bytes)[0..4] == 0x00000000 (1/2^32 prob → ~4B chunk)
pub const BOUNDARY_MASK: u32 = 0x0000_00FF; // tune for ~256 byte chunks in PoC

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProllyNode {
    Leaf {
        entries: Vec<(Vec<u8>, Vec<u8>)>, // (key, value) sorted
        cid:     KotobaCid,
    },
    Internal {
        children: Vec<(Vec<u8>, KotobaCid)>, // (boundary_key, child_cid)
        cid:      KotobaCid,
    },
}

impl ProllyNode {
    pub fn cid(&self) -> &KotobaCid {
        match self {
            Self::Leaf { cid, .. } => cid,
            Self::Internal { cid, .. } => cid,
        }
    }

    pub fn is_boundary(key: &[u8]) -> bool {
        let hash = blake3::hash(key);
        let prefix = u32::from_be_bytes(hash.as_bytes()[0..4].try_into().unwrap());
        (prefix & BOUNDARY_MASK) == 0
    }
}

#[derive(Debug, Default)]
pub struct ProllyTree {
    pub root: Option<KotobaCid>,
    nodes: BTreeMap<KotobaCid, ProllyNode>,
}

impl ProllyTree {
    pub fn new() -> Self { Self::default() }

    pub fn root_cid(&self) -> Option<&KotobaCid> {
        self.root.as_ref()
    }

    /// Diff two roots → returns (only_in_a, only_in_b)
    pub fn diff(a_root: &KotobaCid, b_root: &KotobaCid) -> (Vec<KotobaCid>, Vec<KotobaCid>) {
        if a_root == b_root { return (vec![], vec![]); }
        // Full diff implementation: walk tree, compare children CIDs
        // Placeholder — O(|diff|) implementation in Phase 1
        (vec![a_root.clone()], vec![b_root.clone()])
    }

    /// Serialize a node to DAG-CBOR and write it to the block store.
    /// Returns the node's CID (= blake3(cbor_bytes)).
    pub fn put_node(node: &ProllyNode, store: &dyn BlockStore) -> anyhow::Result<KotobaCid> {
        let mut buf = Vec::new();
        ciborium::into_writer(node, &mut buf)
            .map_err(|e| anyhow::anyhow!("cbor encode: {e}"))?;
        let cid = KotobaCid::from_bytes(&buf);
        store.put(&cid, &buf)?;
        Ok(cid)
    }

    /// Load a ProllyNode from the block store by CID.
    pub fn load_node(cid: &KotobaCid, store: &dyn BlockStore) -> anyhow::Result<Option<ProllyNode>> {
        match store.get(cid)? {
            None => Ok(None),
            Some(bytes) => {
                let node: ProllyNode = ciborium::from_reader(&bytes[..])
                    .map_err(|e| anyhow::anyhow!("cbor decode: {e}"))?;
                Ok(Some(node))
            }
        }
    }

    /// Flush all in-memory nodes to the block store.
    /// Returns the root CID if the tree has a root.
    pub fn flush(&self, store: &dyn BlockStore) -> anyhow::Result<Option<KotobaCid>> {
        for node in self.nodes.values() {
            Self::put_node(node, store)?;
        }
        Ok(self.root.clone())
    }

    /// Build a complete ProllyTree from a flat entry list, writing every
    /// node to `store`.  Returns the root CID.
    ///
    /// Algorithm (single-pass bottom-up):
    ///   1. Sort entries by key.
    ///   2. Split into Leaf chunks at probabilistic boundaries
    ///      (`is_boundary` fires ~1/256 of the time with BOUNDARY_MASK=0xFF,
    ///       giving chunks of ~256 entries on average).
    ///   3. Persist each Leaf; collect (max_key, leaf_cid) pairs.
    ///   4. If >1 leaf, recursively build Internal levels until a single root
    ///      remains — each level applies the same boundary split to child keys.
    pub fn build_tree(
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        store:   &dyn BlockStore,
    ) -> anyhow::Result<KotobaCid> {
        if entries.is_empty() {
            let leaf = ProllyNode::Leaf { entries: vec![], cid: KotobaCid::default() };
            return Self::put_node(&leaf, store);
        }

        let mut sorted = entries;
        sorted.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let leaf_ptrs = Self::build_leaf_level(sorted, store)?;
        if leaf_ptrs.len() == 1 {
            return Ok(leaf_ptrs.into_iter().next().unwrap().1);
        }
        Self::build_internal_level(leaf_ptrs, store)
    }

    fn build_leaf_level(
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        store:   &dyn BlockStore,
    ) -> anyhow::Result<Vec<(Vec<u8>, KotobaCid)>> {
        let mut ptrs: Vec<(Vec<u8>, KotobaCid)> = Vec::new();
        let mut chunk: Vec<(Vec<u8>, Vec<u8>)>   = Vec::new();

        for entry in entries {
            let at_boundary = ProllyNode::is_boundary(&entry.0);
            chunk.push(entry);
            if at_boundary {
                let max_key = chunk.last().unwrap().0.clone();
                let leaf    = ProllyNode::Leaf { entries: std::mem::take(&mut chunk), cid: KotobaCid::default() };
                let cid     = Self::put_node(&leaf, store)?;
                ptrs.push((max_key, cid));
            }
        }
        if !chunk.is_empty() {
            let max_key = chunk.last().unwrap().0.clone();
            let leaf    = ProllyNode::Leaf { entries: chunk, cid: KotobaCid::default() };
            let cid     = Self::put_node(&leaf, store)?;
            ptrs.push((max_key, cid));
        }
        Ok(ptrs)
    }

    /// Point-query: look up `key` in the ProllyTree rooted at `root_cid`.
    ///
    /// Each tree level requires one `store.get()` call — on a cold BlockStore
    /// (IPFS / S3) this multiplies the network RTT by the tree depth.
    /// With ~256-entry leaves, depth = ceil(log256(N)):
    ///   - 1K entries  → 1–2 levels → 1–2 RTTs
    ///   - 1M entries  → 3–4 levels → 3–4 RTTs
    ///   - 1B entries  → 5–6 levels → 5–6 RTTs
    ///
    /// Returns `None` if the key is not found.
    pub fn get(
        root: &KotobaCid,
        key:  &[u8],
        store: &dyn BlockStore,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let Some(node) = Self::load_node(root, store)? else {
            return Ok(None);
        };
        match node {
            ProllyNode::Leaf { entries, .. } => {
                Ok(entries.into_iter().find(|(k, _)| k.as_slice() == key).map(|(_, v)| v))
            }
            ProllyNode::Internal { children, .. } => {
                // Find the first child whose max_key >= key, then recurse.
                let child_cid = children
                    .into_iter()
                    .find(|(max_key, _)| max_key.as_slice() >= key)
                    .map(|(_, cid)| cid);
                match child_cid {
                    Some(cid) => Self::get(&cid, key, store),
                    None      => Ok(None),
                }
            }
        }
    }

    fn build_internal_level(
        children: Vec<(Vec<u8>, KotobaCid)>,
        store:    &dyn BlockStore,
    ) -> anyhow::Result<KotobaCid> {
        let mut ptrs: Vec<(Vec<u8>, KotobaCid)> = Vec::new();
        let mut chunk: Vec<(Vec<u8>, KotobaCid)> = Vec::new();

        for child in children {
            // Use the child CID (not the max key) to determine internal-level
            // boundaries.  The key would cause infinite recursion because the
            // same key keeps triggering the boundary check at every level.
            // The CID changes at each level (it's the hash of node content), so
            // the boundary condition will not repeat indefinitely.
            let at_boundary = ProllyNode::is_boundary(&child.1.0);
            chunk.push(child);
            if at_boundary {
                let max_key = chunk.last().unwrap().0.clone();
                let node    = ProllyNode::Internal { children: std::mem::take(&mut chunk), cid: KotobaCid::default() };
                let cid     = Self::put_node(&node, store)?;
                ptrs.push((max_key, cid));
            }
        }
        if !chunk.is_empty() {
            let max_key = chunk.last().unwrap().0.clone();
            let node    = ProllyNode::Internal { children: chunk, cid: KotobaCid::default() };
            let cid     = Self::put_node(&node, store)?;
            ptrs.push((max_key, cid));
        }

        if ptrs.len() == 1 {
            return Ok(ptrs.into_iter().next().unwrap().1);
        }
        // Another level needed — ptrs.len() >= 2; CID-based boundaries
        // guarantee convergence because CIDs change each time nodes are rebuilt.
        Self::build_internal_level(ptrs, store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::BlockStore;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    /// Minimal in-process block store for unit tests (avoids circular dep on kotoba-store).
    struct MemoryBlockStore {
        blocks: Arc<RwLock<HashMap<[u8; 36], Bytes>>>,
    }

    impl MemoryBlockStore {
        fn new() -> Self {
            Self { blocks: Arc::new(RwLock::new(HashMap::new())) }
        }
        fn block_count(&self) -> usize {
            self.blocks.read().unwrap().len()
        }
    }

    impl BlockStore for MemoryBlockStore {
        fn put(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
            self.blocks.write().unwrap().insert(cid.0, Bytes::copy_from_slice(data));
            Ok(())
        }
        fn get(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>> {
            Ok(self.blocks.read().unwrap().get(&cid.0).cloned())
        }
        fn has(&self, cid: &KotobaCid) -> bool {
            self.blocks.read().unwrap().contains_key(&cid.0)
        }
    }

    #[test]
    fn put_and_load_leaf_node() {
        let store = MemoryBlockStore::new();
        let node = ProllyNode::Leaf {
            entries: vec![(b"key1".to_vec(), b"val1".to_vec())],
            cid: KotobaCid::from_bytes(b"dummy"),
        };
        let cid = ProllyTree::put_node(&node, &store).unwrap();
        let loaded = ProllyTree::load_node(&cid, &store).unwrap().unwrap();
        match loaded {
            ProllyNode::Leaf { entries, .. } => {
                assert_eq!(entries[0].0, b"key1");
            }
            _ => panic!("expected leaf"),
        }
    }

    #[test]
    fn flush_empty_tree_returns_none() {
        let store = MemoryBlockStore::new();
        let tree = ProllyTree::new();
        let root = tree.flush(&store).unwrap();
        assert!(root.is_none());
        assert_eq!(store.block_count(), 0);
    }
}
