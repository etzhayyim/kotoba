use super::node_id::NodeId;

pub const K: usize = 7; // Kademlia replication factor

/// Neighborhood — K-nearest DHT nodes by XOR distance
pub struct Neighborhood {
    pub local: NodeId,
    pub peers: Vec<NodeId>,
}

impl Neighborhood {
    pub fn new(local: NodeId) -> Self {
        Self { local, peers: Vec::new() }
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
