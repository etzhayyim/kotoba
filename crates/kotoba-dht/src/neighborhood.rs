use super::node_id::NodeId;

pub const K: usize = 7; // Kademlia replication factor

/// Neighborhood — K-nearest DHT nodes by XOR distance
pub struct Neighborhood {
    pub local: NodeId,
    pub peers: Vec<NodeId>,
}

impl Neighborhood {
    pub fn new(local: NodeId) -> Self {
        Self {
            local,
            peers: Vec::new(),
        }
    }

    pub fn add_peer(&mut self, peer: NodeId) {
        if !self.peers.contains(&peer) {
            self.peers.push(peer);
            self.peers.sort_by_key(|p| self.local.xor_distance(p));
            self.peers.truncate(K * 8); // keep routing table manageable
        }
    }

    /// K nearest to a target CID address
    pub fn responsible_for(&self, address: &NodeId) -> Vec<&NodeId> {
        NodeId::k_nearest(address, &self.peers, K)
    }

    /// Is this local node responsible for a given address?
    pub fn is_responsible(&self, address: &NodeId) -> bool {
        let nearest = NodeId::k_nearest(address, &self.peers, K);
        nearest.contains(&&self.local) || nearest.len() < K
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(tag: &[u8]) -> NodeId {
        NodeId::from_pubkey(tag)
    }

    #[test]
    fn add_peer_deduplicates() {
        let mut nb = Neighborhood::new(nid(b"local"));
        nb.add_peer(nid(b"alice"));
        nb.add_peer(nid(b"alice"));
        assert_eq!(nb.peers.len(), 1);
    }

    #[test]
    fn add_peer_truncates_to_k_times_8() {
        let mut nb = Neighborhood::new(nid(b"local"));
        for i in 0..100u8 {
            nb.add_peer(nid(&[i]));
        }
        assert!(nb.peers.len() <= K * 8);
    }

    #[test]
    fn responsible_for_returns_at_most_k() {
        let mut nb = Neighborhood::new(nid(b"local"));
        for i in 0..20u8 {
            nb.add_peer(nid(&[i]));
        }
        let resp = nb.responsible_for(&nid(b"target"));
        assert!(resp.len() <= K);
    }

    #[test]
    fn is_responsible_with_fewer_than_k_peers() {
        let local = nid(b"only-node");
        let mut nb = Neighborhood::new(local.clone());
        // With < K peers, every node is responsible (nearest.len() < K)
        assert!(nb.is_responsible(&nid(b"any-address")));
        // Add local to peers so it appears in k_nearest
        nb.add_peer(nid(b"peer1"));
        // Still < K peers so always responsible
        assert!(nb.is_responsible(&nid(b"any-address")));
    }

    #[test]
    fn peers_are_sorted_by_xor_distance() {
        let local = nid(b"local");
        let mut nb = Neighborhood::new(local.clone());
        for i in 0..10u8 {
            nb.add_peer(nid(&[i, 42]));
        }
        // Verify sorted order
        let dists: Vec<_> = nb.peers.iter().map(|p| local.xor_distance(p)).collect();
        let mut sorted = dists.clone();
        sorted.sort();
        assert_eq!(dists, sorted);
    }

    #[test]
    fn new_neighborhood_has_empty_peers() {
        let nb = Neighborhood::new(nid(b"solo"));
        assert!(nb.peers.is_empty());
    }

    #[test]
    fn responsible_for_empty_peers_returns_empty() {
        let nb = Neighborhood::new(nid(b"loner"));
        let resp = nb.responsible_for(&nid(b"target"));
        assert!(
            resp.is_empty(),
            "no peers → responsible_for should return empty vec"
        );
    }

    #[test]
    fn is_responsible_with_no_peers_is_true() {
        let nb = Neighborhood::new(nid(b"loner"));
        // nearest.len() < K always when peers is empty
        assert!(nb.is_responsible(&nid(b"anything")));
    }

    #[test]
    fn add_peer_maintains_exactly_k_times_8_limit() {
        let mut nb = Neighborhood::new(nid(b"local"));
        let limit = K * 8;
        for i in 0..=limit + 5 {
            nb.add_peer(nid(&(i as u64).to_le_bytes()));
        }
        assert!(nb.peers.len() <= limit);
    }
}
