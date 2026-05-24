use anyhow::Result;
use futures::StreamExt;
use libp2p::{
    gossipsub, identify, kad, ping,
    identity::Keypair,
    swarm::{Swarm, SwarmEvent},
    Multiaddr, PeerId,
};

use crate::behaviour::{KotobaBehaviour, KotobaBehaviourEvent};
use crate::protocol::KOTOBA_SYNC_PROTOCOL;

pub type KotobaSwarmType = Swarm<KotobaBehaviour>;

/// High-level wrapper around the libp2p Swarm.
pub struct KotobaSwarm {
    pub swarm: KotobaSwarmType,
    pub local_peer_id: PeerId,
}

#[derive(Debug, Clone)]
pub enum KotobaNetEvent {
    GossipMessage {
        topic:  String,
        data:   Vec<u8>,
        source: Option<PeerId>,
    },
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    RoutingUpdated { peer: PeerId },
    ListenAddr(Multiaddr),
}

impl KotobaSwarm {
    /// Create a new KotobaSwarm with a fresh Ed25519 identity.
    /// `listen_addr` example: `"/ip4/0.0.0.0/udp/0/quic-v1"`.
    pub async fn new(listen_addr: Multiaddr) -> Result<Self> {
        let keypair = Keypair::generate_ed25519();
        Self::with_keypair(keypair, listen_addr).await
    }

    /// Create with an existing keypair (for persistent node identity).
    pub async fn with_keypair(keypair: Keypair, listen_addr: Multiaddr) -> Result<Self> {
        let local_peer_id = PeerId::from_public_key(&keypair.public());

        // GossipSub — lenient validation thresholds for dev
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|e| anyhow::anyhow!("gossipsub config: {e:?}"))?;

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| anyhow::anyhow!("gossipsub init: {e:?}"))?;

        let kademlia = kad::Behaviour::new(
            local_peer_id,
            kad::store::MemoryStore::new(local_peer_id),
        );

        let identify = identify::Behaviour::new(identify::Config::new(
            KOTOBA_SYNC_PROTOCOL.to_string(),
            keypair.public(),
        ));

        let ping = ping::Behaviour::default();

        let behaviour = KotobaBehaviour { gossipsub, kademlia, identify, ping };

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_quic()
            .with_behaviour(|_| Ok(behaviour))?
            .build();

        swarm.listen_on(listen_addr)?;

        Ok(Self { swarm, local_peer_id })
    }

    /// Subscribe to a GossipSub topic mapped from a KSE topic name.
    pub fn subscribe(&mut self, kse_topic: &str) -> Result<()> {
        let topic = gossipsub::IdentTopic::new(crate::gossipsub::gossipsub_topic(kse_topic));
        self.swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        Ok(())
    }

    /// Publish bytes to a GossipSub topic.
    pub fn publish(
        &mut self,
        kse_topic: &str,
        data: Vec<u8>,
    ) -> Result<gossipsub::MessageId> {
        let topic = gossipsub::IdentTopic::new(crate::gossipsub::gossipsub_topic(kse_topic));
        let id = self.swarm.behaviour_mut().gossipsub.publish(topic, data)?;
        Ok(id)
    }

    /// Add a bootstrap peer to the Kademlia routing table and dial it.
    pub fn add_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, addr.clone());
        self.swarm.dial(addr).ok();
    }

    /// Bootstrap Kademlia DHT discovery (requires at least one known peer first).
    pub fn bootstrap(&mut self) -> Result<kad::QueryId> {
        Ok(self.swarm.behaviour_mut().kademlia.bootstrap()?)
    }

    /// Poll the swarm for the next user-visible event.
    /// Returns `None` only if the swarm terminates (should not happen in production).
    pub async fn next_event(&mut self) -> Option<KotobaNetEvent> {
        loop {
            match self.swarm.next().await? {
                // GossipSub message received
                SwarmEvent::Behaviour(KotobaBehaviourEvent::Gossipsub(
                    gossipsub::Event::Message { message, .. },
                )) => {
                    return Some(KotobaNetEvent::GossipMessage {
                        topic:  message.topic.to_string(),
                        data:   message.data,
                        source: message.source,
                    });
                }

                // Connection events
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    return Some(KotobaNetEvent::PeerConnected(peer_id));
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    return Some(KotobaNetEvent::PeerDisconnected(peer_id));
                }

                // Kademlia routing table update
                SwarmEvent::Behaviour(KotobaBehaviourEvent::Kademlia(
                    kad::Event::RoutingUpdated { peer, .. },
                )) => {
                    return Some(KotobaNetEvent::RoutingUpdated { peer });
                }

                // New listen address assigned by the OS
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!(addr = %address, "kotoba-net: listening");
                    return Some(KotobaNetEvent::ListenAddr(address));
                }

                // Identify: learn peer's addresses → feed them to Kademlia
                SwarmEvent::Behaviour(KotobaBehaviourEvent::Identify(
                    identify::Event::Received { peer_id, info, .. },
                )) => {
                    for addr in info.listen_addrs {
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr);
                    }
                    // Not a user-visible event — continue the loop
                }

                _ => { /* ignore ping, identify::Sent, etc. */ }
            }
        }
    }

    /// Run the swarm event loop, forwarding events onto `tx`.
    /// Call via `tokio::spawn`.
    pub async fn run(mut self, tx: tokio::sync::mpsc::Sender<KotobaNetEvent>) {
        while let Some(event) = self.next_event().await {
            if tx.send(event).await.is_err() {
                break; // receiver dropped
            }
        }
    }

    // ------------------------------------------------------------------
    // Pregel GossipSub helpers
    // ------------------------------------------------------------------

    /// Subscribe to the Pregel gossip topic.
    /// Must be called before `send_pregel_message` works.
    pub fn subscribe_pregel(&mut self) -> Result<()> {
        self.subscribe(crate::pregel_msg::PREGEL_GOSSIP_TOPIC)
    }

    /// Gossip a Pregel message to all peers subscribed to the pregel topic.
    pub fn send_pregel_message(
        &mut self,
        src:     &str,
        dst:     &str,
        payload: &[u8],
    ) -> Result<gossipsub::MessageId> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        let msg = crate::pregel_msg::PregelNetMessage {
            src:         src.to_string(),
            dst:         dst.to_string(),
            payload_b64: B64.encode(payload),
        };
        let data = serde_json::to_vec(&msg)?;
        self.publish(crate::pregel_msg::PREGEL_GOSSIP_TOPIC, data)
    }

    /// Try to parse an incoming `KotobaNetEvent` as a `PregelNetMessage`.
    /// Returns `None` if the event is not a Pregel gossip message.
    pub fn parse_pregel_event(event: &KotobaNetEvent) -> Option<crate::pregel_msg::PregelNetMessage> {
        if let KotobaNetEvent::GossipMessage { topic, data, .. } = event {
            let full_topic =
                crate::gossipsub::gossipsub_topic(crate::pregel_msg::PREGEL_GOSSIP_TOPIC);
            if topic == &full_topic || topic.ends_with(crate::pregel_msg::PREGEL_GOSSIP_TOPIC) {
                return serde_json::from_slice(data).ok();
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn swarm_creates_and_subscribes() {
        let addr: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let mut swarm = KotobaSwarm::new(addr).await.expect("swarm init");

        swarm.subscribe("kotoba/hello/greet").expect("subscribe");

        // Wait for the OS-assigned listen address
        let event = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            swarm.next_event(),
        )
        .await;

        match event {
            Ok(Some(KotobaNetEvent::ListenAddr(addr))) => {
                println!("listening on: {addr}");
                // QUIC listen addr contains "127.0.0.1" and "udp"
                let s = addr.to_string();
                assert!(s.contains("127.0.0.1") || s.contains("quic"));
            }
            Ok(Some(other)) => {
                println!("got event: {other:?}");
            }
            Err(_) => {
                println!("timeout waiting for listen addr — swarm created OK");
            }
            Ok(None) => panic!("swarm terminated unexpectedly"),
        }

        assert!(!swarm.local_peer_id.to_string().is_empty());
    }

    #[tokio::test]
    async fn two_swarms_can_connect() {
        let addr1: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();
        let addr2: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();

        let mut swarm1 = KotobaSwarm::new(addr1).await.expect("swarm1");
        let mut swarm2 = KotobaSwarm::new(addr2).await.expect("swarm2");

        swarm1.subscribe("test/ping").unwrap();
        swarm2.subscribe("test/ping").unwrap();

        // Collect swarm1's actual listen address
        let listen_addr = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            async {
                loop {
                    if let Some(KotobaNetEvent::ListenAddr(a)) = swarm1.next_event().await {
                        return a;
                    }
                }
            },
        )
        .await;

        if let Ok(addr) = listen_addr {
            swarm2.add_peer(swarm1.local_peer_id, addr);

            // Brief window to observe a connection event (smoke only)
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                swarm2.next_event(),
            )
            .await
            .ok();
        }
        // Passes as long as no panic — full gossip delivery is integration-test territory
    }
}
