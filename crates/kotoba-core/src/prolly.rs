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

    /// Walk the ProllyTree from `root` and return all referenced block CIDs (root inclusive).
    ///
    /// Recursively follows all `Internal` node children.  Leaf entries are not followed
    /// (their values are opaque bytes, not CID references).  Used by GC to compute the
    /// live set reachable from a commit's ProllyTree roots.
    pub fn walk_all_cids(root: &KotobaCid, store: &dyn BlockStore) -> anyhow::Result<Vec<KotobaCid>> {
        let mut out = vec![root.clone()];
        let Some(node) = Self::load_node(root, store)? else { return Ok(out); };
        if let ProllyNode::Internal { children, .. } = node {
            for (_, child_cid) in children {
                out.extend(Self::walk_all_cids(&child_cid, store)?);
            }
        }
        Ok(out)
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
    ///      giving chunks of ~256 entries on average).
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

    /// Return all `(key, value)` pairs whose key starts with `prefix`.
    ///
    /// Because the ProllyTree is lexicographically sorted, all matching entries
    /// are contiguous. Traversal skips subtrees whose max_key precedes `prefix`
    /// and stops as soon as a subtree's entries no longer start with `prefix`.
    ///
    /// Cost: O(log N + M) block loads, where M = number of matching leaf entries.
    pub fn scan_prefix(
        root:   &KotobaCid,
        prefix: &[u8],
        store:  &dyn BlockStore,
    ) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let Some(node) = Self::load_node(root, store)? else {
            return Ok(vec![]);
        };
        match node {
            ProllyNode::Leaf { entries, .. } => {
                Ok(entries.into_iter()
                    .filter(|(k, _)| k.starts_with(prefix))
                    .collect())
            }
            ProllyNode::Internal { children, .. } => {
                let mut result = Vec::new();
                let mut found_any = false;
                for (max_key, child_cid) in children {
                    // Skip subtrees entirely before our prefix range.
                    if max_key.as_slice() < prefix {
                        continue;
                    }
                    let batch = Self::scan_prefix(&child_cid, prefix, store)?;
                    if batch.is_empty() {
                        // If we've already found matches, the first empty batch
                        // means we've passed the prefix range — stop.
                        if found_any {
                            break;
                        }
                    } else {
                        found_any = true;
                        result.extend(batch);
                    }
                }
                Ok(result)
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

    // ── regression: build_internal_level must use CID not max_key ────────────
    //
    // Before the fix, build_internal_level called is_boundary(&child.0) — the
    // same max_key that fired the boundary at leaf level.  That key would fire
    // again at every recursive call → unbounded recursion → stack overflow.
    //
    // Any test that builds a tree large enough to produce ≥2 leaf chunks will
    // fail with a stack overflow if the regression is reintroduced.

    /// Regression: build_tree must terminate for 1K entries.
    /// With BOUNDARY_MASK=0xFF (1/256 rate) and 1K entries, ~4 boundary keys
    /// appear, producing multiple leaf chunks and triggering build_internal_level.
    /// Before the fix this overflowed the stack; after the fix it completes.
    #[test]
    fn build_tree_1k_terminates_and_get_works() {
        let store = MemoryBlockStore::new();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0u64..1_000)
            .map(|i| (i.to_le_bytes().to_vec(), format!("v{i}").into_bytes()))
            .collect();
        let root = ProllyTree::build_tree(entries, &store).unwrap();

        // A key in the middle must be found.
        let key = 500u64.to_le_bytes().to_vec();
        let val = ProllyTree::get(&root, &key, &store).unwrap();
        assert_eq!(val.as_deref(), Some(b"v500".as_ref()));

        // First and last key.
        let v0 = ProllyTree::get(&root, &0u64.to_le_bytes(), &store).unwrap();
        assert_eq!(v0.as_deref(), Some(b"v0".as_ref()));
        let v999 = ProllyTree::get(&root, &999u64.to_le_bytes(), &store).unwrap();
        assert_eq!(v999.as_deref(), Some(b"v999".as_ref()));
    }

    /// Regression: larger tree (10K entries) must also terminate.
    #[test]
    fn build_tree_10k_terminates() {
        let store = MemoryBlockStore::new();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0u64..10_000)
            .map(|i| (i.to_le_bytes().to_vec(), format!("v{i}").into_bytes()))
            .collect();
        let root = ProllyTree::build_tree(entries, &store).unwrap();
        let val = ProllyTree::get(&root, &5_000u64.to_le_bytes(), &store).unwrap();
        assert_eq!(val.as_deref(), Some(b"v5000".as_ref()));
    }

    /// Missing key returns None (does not panic or recurse).
    #[test]
    fn build_tree_get_missing_key() {
        let store = MemoryBlockStore::new();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0u64..100)
            .map(|i| (i.to_le_bytes().to_vec(), b"x".to_vec()))
            .collect();
        let root = ProllyTree::build_tree(entries, &store).unwrap();
        let val = ProllyTree::get(&root, &999u64.to_le_bytes(), &store).unwrap();
        assert!(val.is_none());
    }

    /// Single entry: tree = just one leaf node; get must still work.
    #[test]
    fn build_tree_single_entry() {
        let store = MemoryBlockStore::new();
        let entries = vec![(b"only".to_vec(), b"value".to_vec())];
        let root = ProllyTree::build_tree(entries, &store).unwrap();
        let val = ProllyTree::get(&root, b"only", &store).unwrap();
        assert_eq!(val.as_deref(), Some(b"value".as_ref()));
        let none = ProllyTree::get(&root, b"other", &store).unwrap();
        assert!(none.is_none());
    }

    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn flush_empty_tree_returns_none() {
        let store = MemoryBlockStore::new();
        let tree = ProllyTree::new();
        let root = tree.flush(&store).unwrap();
        assert!(root.is_none());
        assert_eq!(store.block_count(), 0);
    }

    // ── scan_prefix ──────────────────────────────────────────────────────────

    /// scan_prefix returns all entries whose key starts with the given prefix.
    #[test]
    fn scan_prefix_returns_matching_entries() {
        let store = MemoryBlockStore::new();
        // Keys: "alice:name", "alice:knows", "bob:name", "charlie:name"
        let entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b"alice:knows".to_vec(), b"bob".to_vec()),
            (b"alice:name".to_vec(),  b"Alice".to_vec()),
            (b"bob:name".to_vec(),    b"Bob".to_vec()),
            (b"charlie:name".to_vec(), b"Charlie".to_vec()),
        ];
        let root = ProllyTree::build_tree(entries, &store).unwrap();

        let matches = ProllyTree::scan_prefix(&root, b"alice:", &store).unwrap();
        assert_eq!(matches.len(), 2, "expected 2 entries for alice prefix");
        let keys: std::collections::HashSet<Vec<u8>> =
            matches.iter().map(|(k, _)| k.clone()).collect();
        assert!(keys.contains(b"alice:knows".as_ref() as &[u8]),
            "alice:knows must be found");
        assert!(keys.contains(b"alice:name".as_ref() as &[u8]),
            "alice:name must be found");
    }

    /// scan_prefix with no matching entries returns empty vec.
    #[test]
    fn scan_prefix_empty_result_for_absent_prefix() {
        let store = MemoryBlockStore::new();
        let entries: Vec<(Vec<u8>, Vec<u8>)> = (0u64..100)
            .map(|i| (format!("x{i:04}").into_bytes(), b"v".to_vec()))
            .collect();
        let root = ProllyTree::build_tree(entries, &store).unwrap();
        let matches = ProllyTree::scan_prefix(&root, b"zzz", &store).unwrap();
        assert!(matches.is_empty(), "no entries should match absent prefix");
    }

    /// scan_prefix on a larger tree (1K entries) terminates and finds correct entries.
    #[test]
    fn scan_prefix_larger_tree() {
        let store = MemoryBlockStore::new();
        // prefix "b" entries: "b000".."b049" (50 entries) interleaved with "a*" and "c*"
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for i in 0u32..500 { entries.push((format!("a{i:04}").into_bytes(), b"va".to_vec())); }
        for i in 0u32..50  { entries.push((format!("b{i:04}").into_bytes(), b"vb".to_vec())); }
        for i in 0u32..450 { entries.push((format!("c{i:04}").into_bytes(), b"vc".to_vec())); }
        entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        let root = ProllyTree::build_tree(entries, &store).unwrap();

        let matches = ProllyTree::scan_prefix(&root, b"b", &store).unwrap();
        assert_eq!(matches.len(), 50, "expected 50 'b' entries");
        assert!(matches.iter().all(|(k, _)| k.starts_with(b"b")));
    }
}
