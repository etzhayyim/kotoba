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
        for i in 0..32 { dist[i] = self.0[i] ^ other.0[i]; }
        dist
    }

    /// Find K closest nodes from candidates (XOR metric)
    pub fn k_nearest<'a>(target: &Self, candidates: &'a [NodeId], k: usize) -> Vec<&'a NodeId> {
        let mut with_dist: Vec<(&NodeId, [u8; 32])> = candidates.iter()
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
