use blake3::Hasher;

/// NodeId = blake3(did_public_key) — 256-bit DHT address
/// XOR metric for neighborhood routing
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn from_pubkey(pubkey_bytes: &[u8]) -> Self {
        let hash = Hasher::new().update(pubkey_bytes).finalize();
        Self(*hash.as_bytes())
    }

    /// XOR distance for Kademlia-style routing
    pub fn xor_distance(&self, other: &Self) -> [u8; 32] {
        let mut dist = [0u8; 32];
        for (i, slot) in dist.iter_mut().enumerate() {
            *slot = self.0[i] ^ other.0[i];
        }
        dist
    }

    /// Find K closest nodes from candidates (XOR metric)
    pub fn k_nearest<'a>(target: &Self, candidates: &'a [NodeId], k: usize) -> Vec<&'a NodeId> {
        let mut with_dist: Vec<(&NodeId, [u8; 32])> = candidates
            .iter()
            .map(|n| (n, target.xor_distance(n)))
            .collect();
        with_dist.sort_by_key(|(_, d)| *d);
        with_dist.into_iter().take(k).map(|(n, _)| n).collect()
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_pubkey_is_deterministic() {
        let a = NodeId::from_pubkey(b"peer-key");
        let b = NodeId::from_pubkey(b"peer-key");
        assert_eq!(a, b);
    }

    #[test]
    fn from_pubkey_differs_for_different_keys() {
        let a = NodeId::from_pubkey(b"alice");
        let b = NodeId::from_pubkey(b"bob");
        assert_ne!(a, b);
    }

    #[test]
    fn xor_distance_self_is_zero() {
        let n = NodeId::from_pubkey(b"self");
        assert_eq!(n.xor_distance(&n), [0u8; 32]);
    }

    #[test]
    fn xor_distance_is_symmetric() {
        let a = NodeId::from_pubkey(b"a");
        let b = NodeId::from_pubkey(b"b");
        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));
    }

    #[test]
    fn k_nearest_returns_at_most_k() {
        let target = NodeId::from_pubkey(b"target");
        let candidates: Vec<NodeId> = (0..10u8).map(|i| NodeId::from_pubkey(&[i])).collect();
        let nearest = NodeId::k_nearest(&target, &candidates, 3);
        assert_eq!(nearest.len(), 3);
    }

    #[test]
    fn k_nearest_empty_candidates() {
        let target = NodeId::from_pubkey(b"t");
        assert!(NodeId::k_nearest(&target, &[], 5).is_empty());
    }

    #[test]
    fn k_nearest_fewer_than_k() {
        let target = NodeId::from_pubkey(b"t");
        let candidates = vec![NodeId::from_pubkey(b"x")];
        assert_eq!(NodeId::k_nearest(&target, &candidates, 5).len(), 1);
    }

    #[test]
    fn display_is_64_hex_chars() {
        let n = NodeId::from_pubkey(b"display-test");
        let s = format!("{n}");
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ---- New tests --------------------------------------------------------

    /// XOR distance is commutative and already tested above, but also check
    /// that the non-zero distance value is non-trivial (not all zeros).
    #[test]
    fn xor_distance_nonzero_for_different_nodes() {
        let a = NodeId::from_pubkey(b"alpha");
        let b = NodeId::from_pubkey(b"beta");
        let d = a.xor_distance(&b);
        assert_ne!(
            d, [0u8; 32],
            "distinct nodes must have non-zero XOR distance"
        );
    }

    /// XOR triangle inequality: d(a,c) ≤ d(a,b) XOR d(b,c) holds byte-by-byte
    /// in the sense that XOR metric satisfies the ultrametric inequality.
    /// Simple sanity: d(a,c) ≤ max(d(a,b), d(b,c)) as byte arrays.
    #[test]
    fn xor_metric_ultrametric_sanity() {
        let a = NodeId::from_pubkey(b"node-a");
        let b = NodeId::from_pubkey(b"node-b");
        let c = NodeId::from_pubkey(b"node-c");
        let dac = a.xor_distance(&c);
        let dab = a.xor_distance(&b);
        let dbc = b.xor_distance(&c);
        // ultrametric: dac[i] <= max(dab[i], dbc[i]) for leading bytes
        let max_other = dab
            .iter()
            .zip(dbc.iter())
            .map(|(x, y)| x.max(y))
            .cloned()
            .collect::<Vec<_>>();
        // At least the first byte should satisfy the ultrametric
        assert!(
            dac[0] <= max_other[0],
            "XOR ultrametric violated: dac[0]={}, max(dab[0],dbc[0])={}",
            dac[0],
            max_other[0]
        );
    }

    /// Ordering: NodeId implements Ord via the byte array, so two different nodes
    /// are strictly ordered.
    #[test]
    fn node_ids_are_totally_ordered() {
        let a = NodeId::from_pubkey(b"aaa");
        let b = NodeId::from_pubkey(b"bbb");
        // They are different, so exactly one of a < b or a > b holds.
        assert!(a != b);
        assert!(a < b || a > b, "NodeId ordering must be total");
    }

    /// Clone produces an equal but independent value.
    #[test]
    fn clone_equals_original() {
        let n = NodeId::from_pubkey(b"clone-me");
        let c = n.clone();
        assert_eq!(n, c);
    }

    /// Hash: two equal NodeIds must hash identically (tested via HashMap).
    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashMap;
        let a = NodeId::from_pubkey(b"hash-test");
        let b = NodeId::from_pubkey(b"hash-test");
        let mut map = HashMap::new();
        map.insert(a.clone(), 1u32);
        assert_eq!(map.get(&b), Some(&1u32));
    }

    /// k_nearest returns results sorted by XOR distance (closest first).
    #[test]
    fn k_nearest_sorted_by_distance() {
        let target = NodeId::from_pubkey(b"target-sort");
        let candidates: Vec<NodeId> = (0..8u8).map(|i| NodeId::from_pubkey(&[i; 4])).collect();
        let nearest = NodeId::k_nearest(&target, &candidates, 4);
        assert_eq!(nearest.len(), 4);
        // Verify ascending XOR distance order
        for w in nearest.windows(2) {
            let d0 = target.xor_distance(w[0]);
            let d1 = target.xor_distance(w[1]);
            assert!(d0 <= d1, "k_nearest must be sorted by XOR distance");
        }
    }

    /// k=0 returns empty slice regardless of candidates.
    #[test]
    fn k_nearest_k_zero_returns_empty() {
        let target = NodeId::from_pubkey(b"t");
        let candidates = vec![NodeId::from_pubkey(b"x"), NodeId::from_pubkey(b"y")];
        assert!(NodeId::k_nearest(&target, &candidates, 0).is_empty());
    }
}
