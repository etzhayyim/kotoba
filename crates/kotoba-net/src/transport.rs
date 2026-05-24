use libp2p::Multiaddr;

/// Default listen address for KOTOBA nodes — QUIC-v1 over UDP, OS-assigned port.
pub const DEFAULT_LISTEN_ADDR: &str = "/ip4/0.0.0.0/udp/0/quic-v1";

/// Returns the default QUIC listen `Multiaddr`.
pub fn default_listen_addr() -> Multiaddr {
    DEFAULT_LISTEN_ADDR.parse().expect("valid QUIC multiaddr")
}

/// Build a QUIC listen `Multiaddr` on a specific UDP port.
pub fn quic_addr(port: u16) -> Multiaddr {
    format!("/ip4/0.0.0.0/udp/{port}/quic-v1")
        .parse()
        .expect("valid QUIC multiaddr")
}
