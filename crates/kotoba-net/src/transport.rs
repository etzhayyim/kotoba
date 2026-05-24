/// KOTOBA transport: libp2p QUIC + Noise XX + yamux
/// NKey (Ed25519) ≡ did:key — same keypair for transport and DID auth
pub struct KotobaTransport {
    pub local_peer_id: String, // libp2p PeerId
    // libp2p Swarm initialization in full implementation
}

impl KotobaTransport {
    pub fn new() -> Self {
        Self { local_peer_id: String::new() }
    }
}
