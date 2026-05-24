use crate::cid::KotobaCid;
use std::collections::BTreeMap;

/// Prolly Tree — probabilistic boundary, content-addressed ordered set
/// boundary condition: blake3(node_bytes)[0..4] == 0x00000000 (1/2^32 prob → ~4B chunk)
pub const BOUNDARY_MASK: u32 = 0x0000_00FF; // tune for ~256 byte chunks in PoC

#[derive(Debug, Clone)]
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
}
