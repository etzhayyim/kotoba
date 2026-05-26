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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_listen_addr_parses() {
        let addr = default_listen_addr();
        assert!(addr.to_string().contains("quic-v1"));
        assert!(addr.to_string().contains("0.0.0.0"));
    }

    #[test]
    fn quic_addr_port_zero_matches_default() {
        assert_eq!(quic_addr(0), default_listen_addr());
    }

    #[test]
    fn quic_addr_contains_port() {
        let addr = quic_addr(9000);
        assert!(addr.to_string().contains("9000"), "multiaddr should contain port 9000: {addr}");
    }

    #[test]
    fn quic_addr_uses_quic_v1_protocol() {
        let addr = quic_addr(4242);
        assert!(addr.to_string().ends_with("quic-v1"), "should end with quic-v1: {addr}");
    }
}
