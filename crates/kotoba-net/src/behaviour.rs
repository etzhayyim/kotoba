use crate::bitswap::BitswapCodec;
use libp2p::{gossipsub, identify, kad, ping, request_response, swarm::NetworkBehaviour};

/// Combined NetworkBehaviour for KOTOBA nodes.
///
/// The `#[derive(NetworkBehaviour)]` macro (libp2p "macros" feature) auto-generates:
///   - `KotobaBehaviourEvent` enum with one variant per field
///   - `poll()` / `handle_pending_inbound_connection()` / etc. delegation
#[derive(NetworkBehaviour)]
pub struct KotobaBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub bitswap: request_response::Behaviour<BitswapCodec>,
}
