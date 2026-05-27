use crate::store::MemBlockStore;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use cid::Cid;
use futures::StreamExt;
use libp2p::{
    noise,
    request_response::{self, Behaviour as RRBehaviour, Codec, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

// ── Protocol codec ─────────────────────────────────────────────────────────────

const PROTOCOL_NAME: &str = "/kotoba/ipfs/1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockRequest {
    Want { cid: Vec<u8> },   // CID bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockResponse {
    Block { cid: Vec<u8>, data: Vec<u8> },
    NotFound { cid: Vec<u8> },
}

#[derive(Clone, Default)]
struct IpfsCodec;

#[async_trait]
impl Codec for IpfsCodec {
    type Protocol = &'static str;
    type Request = BlockRequest;
    type Response = BlockResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where T: futures::AsyncRead + Unpin + Send {
        let mut buf = Vec::new();
        futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
        ciborium::from_reader(&buf[..]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where T: futures::AsyncRead + Unpin + Send {
        let mut buf = Vec::new();
        futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
        ciborium::from_reader(&buf[..]).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where T: futures::AsyncWrite + Unpin + Send {
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        futures::AsyncWriteExt::write_all(io, &buf).await
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, resp: Self::Response) -> io::Result<()>
    where T: futures::AsyncWrite + Unpin + Send {
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        futures::AsyncWriteExt::write_all(io, &buf).await
    }
}

// ── Combined behaviour ──────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct IpfsBehaviour {
    rr: RRBehaviour<IpfsCodec>,
    identify: libp2p::identify::Behaviour,
}

// ── Command bus ─────────────────────────────────────────────────────────────────

type GetResp = oneshot::Sender<Result<Vec<u8>>>;

enum Cmd {
    PutBlock { data: Vec<u8>, resp: oneshot::Sender<Cid> },
    GetBlock { cid: Cid, peer: PeerId, resp: GetResp },
    Dial     { addr: Multiaddr },
    Peers    { resp: oneshot::Sender<Vec<PeerId>> },
}

// ── Public handle ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct KotobaIpfsNode {
    tx: mpsc::UnboundedSender<Cmd>,
    peer_id: PeerId,
}

impl KotobaIpfsNode {
    /// Store a block locally; returns its CIDv1 SHA2-256.
    pub async fn put_block(&self, data: Vec<u8>) -> Result<Cid> {
        let (resp, rx) = oneshot::channel();
        self.tx.send(Cmd::PutBlock { data, resp })?;
        Ok(rx.await?)
    }

    /// Get a block from local store or fetch from `peer` via the block-exchange protocol.
    pub async fn get_block(&self, cid: Cid, peer: PeerId) -> Result<Vec<u8>> {
        let (resp, rx) = oneshot::channel();
        self.tx.send(Cmd::GetBlock { cid, peer, resp })?;
        rx.await?
    }

    pub fn dial(&self, addr: Multiaddr) -> Result<()> {
        Ok(self.tx.send(Cmd::Dial { addr })?)
    }

    pub async fn connected_peers(&self) -> Result<Vec<PeerId>> {
        let (resp, rx) = oneshot::channel();
        self.tx.send(Cmd::Peers { resp })?;
        Ok(rx.await?)
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
}

// ── Config ───────────────────────────────────────────────────────────────────────

pub struct IpfsConfig {
    pub listen: Multiaddr,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self { listen: "/ip4/127.0.0.1/tcp/0".parse().unwrap() }
    }
}

impl IpfsConfig {
    pub fn new() -> Self { Self::default() }

    pub async fn start(self) -> Result<KotobaIpfsNode> {
        let store = MemBlockStore::new();
        let store_clone = store.clone();

        let swarm: Swarm<IpfsBehaviour> = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
            .with_behaviour(|kp| {
                let rr = RRBehaviour::new(
                    [(PROTOCOL_NAME, ProtocolSupport::Full)],
                    request_response::Config::default(),
                );
                let identify = libp2p::identify::Behaviour::new(
                    libp2p::identify::Config::new("/kotoba-ipfs/1.0.0".into(), kp.public()),
                );
                IpfsBehaviour { rr, identify }
            })?
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(std::time::Duration::from_secs(30))
            })
            .build();

        let peer_id = *swarm.local_peer_id();
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(event_loop(swarm, store_clone, rx, self.listen));
        Ok(KotobaIpfsNode { tx, peer_id })
    }
}

// ── Event loop ────────────────────────────────────────────────────────────────────

async fn event_loop(
    mut swarm: Swarm<IpfsBehaviour>,
    store: MemBlockStore,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    listen: Multiaddr,
) {
    if let Err(e) = swarm.listen_on(listen) {
        tracing::error!("listen_on failed: {e}");
        return;
    }

    // outbound requests: request_id → oneshot response channel
    let mut pending: HashMap<request_response::OutboundRequestId, (Cid, GetResp)> = HashMap::new();

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                match cmd {
                    None => break,
                    Some(Cmd::PutBlock { data, resp }) => {
                        let _ = resp.send(store.put(data));
                    }
                    Some(Cmd::GetBlock { cid, peer, resp }) => {
                        if let Some(data) = store.get_local(&cid) {
                            let _ = resp.send(Ok(data));
                        } else {
                            let req_id = swarm.behaviour_mut().rr.send_request(
                                &peer,
                                BlockRequest::Want { cid: cid.to_bytes() },
                            );
                            pending.insert(req_id, (cid, resp));
                        }
                    }
                    Some(Cmd::Dial { addr }) => {
                        if let Err(e) = swarm.dial(addr.clone()) {
                            tracing::warn!("dial {addr} failed: {e}");
                        }
                    }
                    Some(Cmd::Peers { resp }) => {
                        let peers: Vec<PeerId> = swarm.connected_peers().copied().collect();
                        let _ = resp.send(peers);
                    }
                }
            }
            event = swarm.next() => {
                let Some(ev) = event else { break };
                handle_event(ev, &store, &mut swarm, &mut pending);
            }
        }
    }
}

fn handle_event(
    event: SwarmEvent<IpfsBehaviourEvent>,
    store: &MemBlockStore,
    swarm: &mut Swarm<IpfsBehaviour>,
    pending: &mut HashMap<request_response::OutboundRequestId, (Cid, GetResp)>,
) {
    match event {
        SwarmEvent::Behaviour(IpfsBehaviourEvent::Rr(rr_event)) => {
            use request_response::Event as RRE;
            match rr_event {
                // Inbound: a remote wants a block from us
                RRE::Message { message: request_response::Message::Request { request, channel, .. }, .. } => {
                    let BlockRequest::Want { cid: cid_bytes } = request;
                    let resp = match Cid::try_from(cid_bytes.as_slice()).ok().and_then(|c| store.get_local(&c)) {
                        Some(data) => BlockResponse::Block { cid: cid_bytes, data },
                        None       => BlockResponse::NotFound { cid: cid_bytes },
                    };
                    let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
                }
                // Outbound: we received a response for a block we wanted
                RRE::Message { message: request_response::Message::Response { request_id, response }, .. } => {
                    if let Some((cid, sender)) = pending.remove(&request_id) {
                        let answer = match response {
                            BlockResponse::Block { data, .. } => {
                                store.insert(cid, data.clone());
                                Ok(data)
                            }
                            BlockResponse::NotFound { .. } => Err(anyhow!("remote: block not found")),
                        };
                        let _ = sender.send(answer);
                    }
                }
                RRE::OutboundFailure { request_id, error, .. } => {
                    if let Some((_, sender)) = pending.remove(&request_id) {
                        let _ = sender.send(Err(anyhow!("outbound failure: {error}")));
                    }
                }
                _ => {}
            }
        }
        SwarmEvent::Behaviour(IpfsBehaviourEvent::Identify(ev)) => {
            debug!("identify: {ev:?}");
        }
        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::info!(%address, "kotoba-ipfs listening");
        }
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            debug!(%peer_id, "connected");
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            debug!(%peer_id, "disconnected");
        }
        _ => {}
    }
}
