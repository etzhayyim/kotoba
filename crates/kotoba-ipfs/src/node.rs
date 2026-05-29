//! Lightweight kotoba IPFS-compatible node.
//!
//! This is intentionally not a full IPFS daemon.  It owns the parts kotoba
//! needs first: IPFS CID-compatible block addressing, local persistence hooks,
//! pin state, and a tiny TCP block exchange protocol between kotoba nodes.

use crate::cid::{cid_for_bytes, dag_cbor_block, raw_cid};
use crate::ipns::{IpnsName, IpnsRecord};
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use ciborium::value::Value as CborValue;
use ipld_core::cid::Cid as IpldCid;
use ipld_core::ipld::Ipld;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

const PROTOCOL: &str = "kotoba-ipfs/1";
const NOT_FOUND: u64 = u64::MAX;
static NEXT_PEER: AtomicU64 = AtomicU64::new(1);

/// Minimal peer identifier used by the self-owned kotoba block exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(u64);

impl PeerId {
    fn new() -> Self {
        Self(NEXT_PEER.fetch_add(1, Ordering::Relaxed))
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kotoba-{:016x}", self.0)
    }
}

impl FromStr for PeerId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let hex = s
            .strip_prefix("kotoba-")
            .ok_or_else(|| anyhow!("invalid peer id: {s}"))?;
        Ok(Self(u64::from_str_radix(hex, 16)?))
    }
}

/// Minimal multiaddr parser for `/ip4|ip6/.../tcp/...[/p2p/...]`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Multiaddr {
    socket: SocketAddr,
    peer: Option<PeerId>,
}

impl Multiaddr {
    pub fn socket(&self) -> SocketAddr {
        self.socket
    }

    pub fn peer(&self) -> Option<PeerId> {
        self.peer
    }

    fn with_peer(mut self, peer: PeerId) -> Self {
        self.peer = Some(peer);
        self
    }
}

impl fmt::Display for Multiaddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.socket.ip() {
            IpAddr::V4(ip) => write!(f, "/ip4/{ip}/tcp/{}", self.socket.port())?,
            IpAddr::V6(ip) => write!(f, "/ip6/{ip}/tcp/{}", self.socket.port())?,
        }
        if let Some(peer) = self.peer {
            write!(f, "/p2p/{peer}")?;
        }
        Ok(())
    }
}

impl FromStr for Multiaddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
        let mut ip = None;
        let mut port = None;
        let mut peer = None;
        let mut i = 0;
        while i < parts.len() {
            match parts[i] {
                "ip4" => {
                    let value = parts
                        .get(i + 1)
                        .ok_or_else(|| anyhow!("missing ip4 value: {s}"))?;
                    ip = Some(IpAddr::V4(value.parse()?));
                    i += 2;
                }
                "ip6" => {
                    let value = parts
                        .get(i + 1)
                        .ok_or_else(|| anyhow!("missing ip6 value: {s}"))?;
                    ip = Some(IpAddr::V6(value.parse()?));
                    i += 2;
                }
                "tcp" => {
                    let value = parts
                        .get(i + 1)
                        .ok_or_else(|| anyhow!("missing tcp value: {s}"))?;
                    port = Some(value.parse::<u16>()?);
                    i += 2;
                }
                "p2p" => {
                    let value = parts
                        .get(i + 1)
                        .ok_or_else(|| anyhow!("missing p2p value: {s}"))?;
                    peer = Some(value.parse()?);
                    i += 2;
                }
                other => bail!("unsupported multiaddr protocol {other}: {s}"),
            }
        }
        Ok(Self {
            socket: SocketAddr::new(
                ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                port.ok_or_else(|| anyhow!("missing tcp port: {s}"))?,
            ),
            peer,
        })
    }
}

/// Configuration for [`KotobaIpfsNode::start`].
#[derive(Clone, Debug, Default)]
pub struct IpfsConfig {
    /// Optional TCP listen multiaddr. Example: `/ip4/0.0.0.0/tcp/0`.
    pub listen: Option<Multiaddr>,
    /// Reserved for durable repo support. The current implementation is
    /// in-memory but keeps this field stable for callers.
    pub repo_path: Option<PathBuf>,
    /// Known peers to seed into the dial table.
    pub bootstrap: Vec<Multiaddr>,
    /// Kept for config compatibility. The lightweight node never joins the
    /// public IPFS DHT directly.
    pub public_dht: bool,
    /// Kept for config compatibility.
    pub mdns: bool,
    /// Kept for config compatibility.
    pub relay: bool,
    /// `fetch_block` timeout when fetching from a peer.
    pub fetch_timeout: Duration,
}

impl IpfsConfig {
    pub fn new() -> Self {
        Self {
            fetch_timeout: Duration::from_secs(30),
            ..Default::default()
        }
    }

    pub async fn start(self) -> Result<KotobaIpfsNode> {
        KotobaIpfsNode::start(self).await
    }

    pub fn with_listen(mut self, addr: Multiaddr) -> Self {
        self.listen = Some(addr);
        self
    }
    pub fn with_repo_path<P: Into<PathBuf>>(mut self, p: P) -> Self {
        self.repo_path = Some(p.into());
        self
    }
    pub fn with_bootstrap(mut self, addrs: Vec<Multiaddr>) -> Self {
        self.bootstrap = addrs;
        self
    }
    pub fn with_public_dht(mut self, on: bool) -> Self {
        self.public_dht = on;
        self
    }
    pub fn with_mdns(mut self, on: bool) -> Self {
        self.mdns = on;
        self
    }
    pub fn with_relay(mut self, on: bool) -> Self {
        self.relay = on;
        self
    }
    pub fn with_fetch_timeout(mut self, d: Duration) -> Self {
        self.fetch_timeout = d;
        self
    }
}

#[derive(Default)]
struct State {
    blocks: RwLock<HashMap<IpldCid, Bytes>>,
    pins: RwLock<HashSet<IpldCid>>,
    peers: RwLock<HashMap<PeerId, SocketAddr>>,
    bootstrap: RwLock<HashSet<Multiaddr>>,
    providers: RwLock<HashMap<IpldCid, HashSet<PeerId>>>,
    files: RwLock<HashMap<String, IpldCid>>,
    dirs: RwLock<HashSet<String>>,
    names: RwLock<HashMap<IpnsName, IpnsRecord>>,
    listen_addrs: RwLock<Vec<Multiaddr>>,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    repo_path: Option<PathBuf>,
}

/// Handle to a running kotoba IPFS-compatible node.
pub struct KotobaIpfsNode {
    peer_id: PeerId,
    state: Arc<State>,
    fetch_timeout: Duration,
    listener: Option<JoinHandle<()>>,
}

impl KotobaIpfsNode {
    /// Start a lightweight node with the given config.
    pub async fn start(cfg: IpfsConfig) -> Result<Self> {
        if let Some(path) = &cfg.repo_path {
            std::fs::create_dir_all(blocks_dir(path))
                .with_context(|| format!("create repo blocks path {path:?}"))?;
            std::fs::create_dir_all(pins_dir(path))
                .with_context(|| format!("create repo pins path {path:?}"))?;
        }

        let peer_id = PeerId::new();
        let state = Arc::new(State {
            repo_path: cfg.repo_path.clone(),
            ..State::default()
        });
        load_repo(&state).await?;

        for addr in cfg.bootstrap {
            state.bootstrap.write().await.insert(addr.clone());
            if let Ok((peer, socket)) = split_peer_addr(&addr) {
                state.peers.write().await.insert(peer, socket);
            }
        }

        let listener = if let Some(addr) = cfg.listen {
            Some(spawn_listener(peer_id, Arc::clone(&state), addr).await?)
        } else {
            None
        };

        Ok(Self {
            peer_id,
            state,
            fetch_timeout: cfg.fetch_timeout,
            listener,
        })
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Kubo-like `id`: local peer id plus current listen addresses.
    pub async fn id(&self) -> Result<NodeId> {
        Ok(NodeId {
            id: self.peer_id,
            addresses: self.listen_addrs().await?,
        })
    }

    /// Kubo-like `version` for this lightweight implementation.
    pub fn version(&self) -> NodeVersion {
        NodeVersion {
            version: env!("CARGO_PKG_VERSION"),
            agent: "kotoba-ipfs",
            protocol: PROTOCOL,
        }
    }

    pub async fn listen_addrs(&self) -> Result<Vec<Multiaddr>> {
        Ok(self.state.listen_addrs.read().await.clone())
    }

    pub async fn add_peer(&self, peer: PeerId, addrs: Vec<Multiaddr>) -> Result<()> {
        let socket = addrs
            .iter()
            .find_map(|addr| multiaddr_to_socket(addr).ok())
            .ok_or_else(|| anyhow!("add_peer: no tcp socket multiaddr"))?;
        self.state.peers.write().await.insert(peer, socket);
        Ok(())
    }

    /// Kubo-like `bootstrap/add`: remember a peer multiaddr and seed the local routing table.
    pub async fn bootstrap_add(&self, addr: Multiaddr) -> Result<Vec<Multiaddr>> {
        if let Ok((peer, socket)) = split_peer_addr(&addr) {
            self.state.peers.write().await.insert(peer, socket);
        }
        self.state.bootstrap.write().await.insert(addr.clone());
        Ok(vec![addr])
    }

    /// Kubo-like `bootstrap/list`.
    pub async fn bootstrap_list(&self) -> Result<Vec<Multiaddr>> {
        let mut addrs: Vec<_> = self.state.bootstrap.read().await.iter().cloned().collect();
        addrs.sort_by_key(|addr| addr.to_string());
        Ok(addrs)
    }

    /// Kubo-like `bootstrap/rm`: remove a remembered bootstrap multiaddr.
    pub async fn bootstrap_rm(&self, addr: &Multiaddr) -> Result<Vec<Multiaddr>> {
        let removed = self.state.bootstrap.write().await.remove(addr);
        if removed {
            Ok(vec![addr.clone()])
        } else {
            Ok(Vec::new())
        }
    }

    /// Kubo-like `bootstrap/rm --all`.
    pub async fn bootstrap_clear(&self) -> Result<Vec<Multiaddr>> {
        let mut bootstrap = self.state.bootstrap.write().await;
        let mut removed: Vec<_> = bootstrap.drain().collect();
        removed.sort_by_key(|addr| addr.to_string());
        Ok(removed)
    }

    pub fn dial(&self, addr: Multiaddr) -> Result<()> {
        let (peer, socket) = split_peer_addr(&addr)?;
        self.state
            .peers
            .try_write()
            .map_err(|_| anyhow!("peer table busy"))?
            .insert(peer, socket);
        Ok(())
    }

    /// Kubo-like `swarm/connect`: add a peer address to the local dial table.
    pub async fn swarm_connect(&self, addr: Multiaddr) -> Result<SwarmConnect> {
        let (peer, socket) = split_peer_addr(&addr)?;
        self.state.peers.write().await.insert(peer, socket);
        Ok(SwarmConnect { peer, addr })
    }

    /// Kubo-like `swarm/disconnect`: remove a peer from the local dial table.
    pub async fn swarm_disconnect(&self, peer: PeerId) -> Result<Option<SwarmPeer>> {
        let removed = self.state.peers.write().await.remove(&peer);
        Ok(removed.map(|socket| SwarmPeer {
            peer,
            addr: socket_to_multiaddr(socket).with_peer(peer),
        }))
    }

    pub async fn connected_peers(&self) -> Result<Vec<PeerId>> {
        Ok(self.state.peers.read().await.keys().copied().collect())
    }

    /// Kubo-like `swarm/peers`.
    pub async fn swarm_peers(&self) -> Result<Vec<SwarmPeer>> {
        let mut peers: Vec<_> = self
            .state
            .peers
            .read()
            .await
            .iter()
            .map(|(peer, socket)| SwarmPeer {
                peer: *peer,
                addr: socket_to_multiaddr(*socket).with_peer(*peer),
            })
            .collect();
        peers.sort_by_key(|p| p.peer.0);
        Ok(peers)
    }

    /// Kubo-like `dht/findpeer` over the local routing table.
    pub async fn dht_find_peer(&self, peer: PeerId) -> Result<Vec<Multiaddr>> {
        Ok(self
            .state
            .peers
            .read()
            .await
            .get(&peer)
            .map(|socket| vec![socket_to_multiaddr(*socket).with_peer(peer)])
            .unwrap_or_default())
    }

    /// Kubo-like `dht/provide` for the local provider table.
    ///
    /// The lightweight node does not publish to the public IPFS DHT; it records
    /// local provider intent so kotoba peers can expose Kubo-shaped routing
    /// state without depending on libp2p/kad in the hot build.
    pub async fn dht_provide(&self, cid: &IpldCid) -> Result<()> {
        self.get_block(cid).await?;
        self.state
            .providers
            .write()
            .await
            .entry(*cid)
            .or_default()
            .insert(self.peer_id);
        Ok(())
    }

    /// Kubo-like `dht/findprovs` over the local provider table.
    pub async fn dht_find_providers(&self, cid: &IpldCid) -> Result<Vec<Provider>> {
        let providers = self.state.providers.read().await;
        let peers = providers.get(cid).cloned().unwrap_or_default();
        drop(providers);

        let peer_addrs = self.state.peers.read().await;
        let listen_addrs = self.state.listen_addrs.read().await;
        let mut out: Vec<_> = peers
            .into_iter()
            .map(|peer| {
                let addrs = if peer == self.peer_id {
                    listen_addrs.clone()
                } else {
                    peer_addrs
                        .get(&peer)
                        .map(|socket| vec![socket_to_multiaddr(*socket).with_peer(peer)])
                        .unwrap_or_default()
                };
                Provider { peer, addrs }
            })
            .collect();
        out.sort_by_key(|provider| provider.peer.0);
        Ok(out)
    }

    /// Store a block under an IPFS CID after verifying the CID matches `data`.
    pub async fn put_block(&self, cid: &IpldCid, data: &[u8]) -> Result<()> {
        verify_cid(cid, data)?;
        self.state
            .blocks
            .write()
            .await
            .insert(*cid, Bytes::copy_from_slice(data));
        persist_block(&self.state, cid, data).await?;
        Ok(())
    }

    /// Kubo-like `block/put`.
    pub async fn block_put(&self, cid: &IpldCid, data: &[u8]) -> Result<()> {
        self.put_block(cid, data).await
    }

    /// Kubo-like `block/put` with an explicit multicodec.
    pub async fn block_put_codec(&self, codec: u64, data: &[u8]) -> Result<BlockPut> {
        let cid = self.put_codec_block(codec, data).await?;
        Ok(BlockPut {
            cid,
            size: data.len() as u64,
        })
    }

    /// Store arbitrary bytes as an IPFS raw block (CIDv1/raw/sha2-256).
    pub async fn put_raw_block(&self, data: &[u8]) -> Result<IpldCid> {
        let cid = raw_cid(data);
        self.put_block(&cid, data).await?;
        Ok(cid)
    }

    /// Kubo-like `add` for a single raw file payload.
    pub async fn add(&self, data: &[u8]) -> Result<IpldCid> {
        self.put_raw_block(data).await
    }

    /// Store bytes with an explicit multicodec (CIDv1/{codec}/sha2-256).
    pub async fn put_codec_block(&self, codec: u64, data: &[u8]) -> Result<IpldCid> {
        let cid = cid_for_bytes(codec, data);
        self.put_block(&cid, data).await?;
        Ok(cid)
    }

    /// Encode and store a dag-cbor block (CIDv1/dag-cbor/sha2-256).
    pub async fn put_dag_cbor<T: Serialize>(&self, value: &T) -> Result<IpldCid> {
        let (cid, data) = dag_cbor_block(value)?;
        self.put_block(&cid, &data).await?;
        Ok(cid)
    }

    /// Kubo-like `dag/put` for dag-cbor values.
    pub async fn dag_put<T: Serialize>(&self, value: &T) -> Result<IpldCid> {
        self.put_dag_cbor(value).await
    }

    pub async fn get_block(&self, cid: &IpldCid) -> Result<Bytes> {
        if let Some(bytes) = self.state.blocks.read().await.get(cid).cloned() {
            return Ok(bytes);
        }
        if let Some(bytes) = load_block(&self.state, cid).await? {
            self.state.blocks.write().await.insert(*cid, bytes.clone());
            return Ok(bytes);
        }
        Err(anyhow!("block not found: {cid}"))
    }

    /// Kubo-like `block/get`.
    pub async fn block_get(&self, cid: &IpldCid) -> Result<Bytes> {
        self.get_block(cid).await
    }

    /// Kubo-like `cat` for raw blocks.
    pub async fn cat(&self, cid: &IpldCid) -> Result<Bytes> {
        if cid.codec() != crate::cid::CODEC_RAW {
            bail!("cat only supports raw blocks, got codec {}", cid.codec());
        }
        self.get_block(cid).await
    }

    /// Kubo-like path resolver for `/ipfs/<cid>` and locally published `/ipns/<name>`.
    pub async fn resolve_path(&self, path: impl AsRef<str>) -> Result<PathResolve> {
        let path = path.as_ref();
        let (root, rem_path) = if let Some(rest) = path.strip_prefix("/ipfs/") {
            split_ipld_path(rest).and_then(|(cid, rem)| Ok((cid.parse::<IpldCid>()?, rem)))?
        } else if let Some(rest) = path.strip_prefix("/ipns/") {
            let (name, rem) = split_ipld_path(rest)?;
            let resolved = self.name_resolve(name).await?;
            (resolved.cid, rem)
        } else {
            bail!("unsupported path; expected /ipfs/<cid> or /ipns/<name>: {path}");
        };

        if rem_path.is_empty() {
            self.get_block(&root).await?;
            return Ok(PathResolve {
                cid: root,
                rem_path,
            });
        }
        let resolved = self.dag_resolve(&root, &rem_path).await?;
        Ok(PathResolve {
            cid: resolved.cid,
            rem_path: resolved.rem_path,
        })
    }

    /// Kubo-like `cat` for `/ipfs/<cid>` or `/ipns/<name>` paths.
    pub async fn cat_path(&self, path: impl AsRef<str>) -> Result<Bytes> {
        let resolved = self.resolve_path(path).await?;
        if !resolved.rem_path.is_empty() {
            bail!(
                "cat path did not resolve to a block CID; remaining path: {}",
                resolved.rem_path
            );
        }
        self.cat(&resolved.cid).await
    }

    /// Kubo-like `dag/get` for dag-cbor blocks.
    pub async fn dag_get<T: DeserializeOwned>(&self, cid: &IpldCid) -> Result<T> {
        if cid.codec() != crate::cid::CODEC_DAG_CBOR {
            bail!(
                "dag_get only supports dag-cbor blocks, got codec {}",
                cid.codec()
            );
        }
        let bytes = self.get_block(cid).await?;
        ciborium::from_reader(&bytes[..]).map_err(|e| anyhow!("dag-cbor decode: {e}"))
    }

    /// Kubo-like `dag/get` decoded into the IPLD data model.
    pub async fn dag_get_ipld(&self, cid: &IpldCid) -> Result<Ipld> {
        if cid.codec() != crate::cid::CODEC_DAG_CBOR {
            bail!(
                "dag_get_ipld only supports dag-cbor blocks, got codec {}",
                cid.codec()
            );
        }
        let bytes = self.get_block(cid).await?;
        let value: CborValue =
            ciborium::from_reader(&bytes[..]).map_err(|e| anyhow!("dag-cbor decode: {e}"))?;
        cbor_value_to_ipld(value)
    }

    /// Kubo-like `dag/stat` for local single-block DAG nodes.
    pub async fn dag_stat(&self, cid: &IpldCid) -> Result<DagStat> {
        if cid.codec() != crate::cid::CODEC_DAG_CBOR {
            bail!(
                "dag_stat only supports dag-cbor blocks, got codec {}",
                cid.codec()
            );
        }
        let object = self.object_stat(cid).await?;
        Ok(DagStat {
            cid: object.cid,
            codec: object.codec,
            size: object.block_size,
        })
    }

    /// Kubo-like `dag/resolve` for local dag-cbor roots and direct IPLD links.
    pub async fn dag_resolve(&self, cid: &IpldCid, path: impl AsRef<str>) -> Result<DagResolve> {
        let path = normalize_ipld_path(path.as_ref())?;
        if path.is_empty() {
            self.get_block(cid).await?;
            return Ok(DagResolve {
                cid: *cid,
                rem_path: String::new(),
            });
        }
        if cid.codec() != crate::cid::CODEC_DAG_CBOR {
            bail!(
                "dag_resolve only traverses dag-cbor blocks, got codec {}",
                cid.codec()
            );
        }

        let root = self.dag_get_ipld(cid).await?;
        let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let mut current = &root;
        for (idx, segment) in segments.iter().enumerate() {
            match current {
                Ipld::Link(link) => {
                    return Ok(DagResolve {
                        cid: *link,
                        rem_path: segments[idx..].join("/"),
                    });
                }
                Ipld::Map(map) => {
                    current = map
                        .get(*segment)
                        .ok_or_else(|| anyhow!("dag path not found: {path}"))?;
                }
                Ipld::List(list) => {
                    let index = segment
                        .parse::<usize>()
                        .map_err(|_| anyhow!("invalid dag list index: {segment}"))?;
                    current = list
                        .get(index)
                        .ok_or_else(|| anyhow!("dag path not found: {path}"))?;
                }
                other => bail!("cannot traverse {:?} at path segment {segment}", other),
            }
        }

        match current {
            Ipld::Link(link) => Ok(DagResolve {
                cid: *link,
                rem_path: String::new(),
            }),
            _ => Ok(DagResolve {
                cid: *cid,
                rem_path: path,
            }),
        }
    }

    pub async fn fetch_block(&self, cid: &IpldCid, peer: PeerId) -> Result<Bytes> {
        if let Some(bytes) = self.state.blocks.read().await.get(cid).cloned() {
            return Ok(bytes);
        }
        let socket = *self
            .state
            .peers
            .read()
            .await
            .get(&peer)
            .ok_or_else(|| anyhow!("unknown peer: {peer}"))?;
        let fut = fetch_from_socket(socket, cid);
        let bytes = tokio::time::timeout(self.fetch_timeout, fut)
            .await
            .map_err(|_| anyhow!("fetch_block: timeout after {:?}", self.fetch_timeout))??;
        verify_cid(cid, &bytes)?;
        self.state.bytes_out.fetch_add(
            format!("GET {PROTOCOL} {cid}\n").len() as u64,
            Ordering::Relaxed,
        );
        self.state
            .bytes_in
            .fetch_add(8 + bytes.len() as u64, Ordering::Relaxed);
        self.state.blocks.write().await.insert(*cid, bytes.clone());
        Ok(bytes)
    }

    pub async fn has_block(&self, cid: &IpldCid) -> Result<bool> {
        if self.state.blocks.read().await.contains_key(cid) {
            return Ok(true);
        }
        Ok(block_path(&self.state, cid).is_some_and(|path| path.exists()))
    }

    /// Kubo-like `block/stat`.
    pub async fn block_stat(&self, cid: &IpldCid) -> Result<BlockStat> {
        let bytes = self.get_block(cid).await?;
        Ok(BlockStat {
            cid: *cid,
            size: bytes.len() as u64,
        })
    }

    /// Kubo-like `object/stat` for local single-block objects.
    pub async fn object_stat(&self, cid: &IpldCid) -> Result<ObjectStat> {
        let bytes = self.get_block(cid).await?;
        Ok(ObjectStat {
            cid: *cid,
            codec: cid.codec(),
            block_size: bytes.len() as u64,
            cumulative_size: bytes.len() as u64,
        })
    }

    /// Kubo-like `block/rm`.
    pub async fn delete_block(&self, cid: &IpldCid) -> Result<bool> {
        let mut removed = self.state.blocks.write().await.remove(cid).is_some();
        self.state.pins.write().await.remove(cid);
        if let Some(path) = block_path(&self.state, cid) {
            match tokio::fs::remove_file(&path).await {
                Ok(()) => removed = true,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err).with_context(|| format!("remove block {path:?}")),
            }
        }
        remove_pin_file(&self.state, cid).await?;
        Ok(removed)
    }

    /// Kubo-like `block/rm`.
    pub async fn block_rm(&self, cid: &IpldCid) -> Result<bool> {
        self.delete_block(cid).await
    }

    /// Kubo-like local block listing.
    pub async fn list_blocks(&self) -> Result<Vec<IpldCid>> {
        let mut cids: HashSet<IpldCid> = self.state.blocks.read().await.keys().copied().collect();
        if let Some(repo) = &self.state.repo_path {
            let mut entries = tokio::fs::read_dir(blocks_dir(repo)).await?;
            while let Some(entry) = entries.next_entry().await? {
                if let Some(name) = entry.file_name().to_str() {
                    if let Ok(cid) = name.parse::<IpldCid>() {
                        cids.insert(cid);
                    }
                }
            }
        }
        let mut cids: Vec<IpldCid> = cids.into_iter().collect();
        cids.sort();
        Ok(cids)
    }

    /// Kubo-like `refs/local`.
    pub async fn refs_local(&self) -> Result<Vec<IpldCid>> {
        self.list_blocks().await
    }

    /// Kubo-like `refs` for locally available raw and dag-cbor blocks.
    pub async fn refs(&self, cid: &IpldCid, recursive: bool) -> Result<Vec<IpldCid>> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        self.refs_inner(cid, recursive, &mut seen, &mut out).await?;
        Ok(out)
    }

    pub async fn pin(&self, cid: &IpldCid) -> Result<()> {
        self.get_block(cid).await?;
        self.state.pins.write().await.insert(*cid);
        self.state
            .providers
            .write()
            .await
            .entry(*cid)
            .or_default()
            .insert(self.peer_id);
        persist_pin(&self.state, cid).await?;
        Ok(())
    }

    /// Kubo-like `pin/add`.
    pub async fn pin_add(&self, cid: &IpldCid) -> Result<()> {
        self.pin(cid).await
    }

    pub async fn unpin(&self, cid: &IpldCid) -> Result<()> {
        self.state.pins.write().await.remove(cid);
        remove_pin_file(&self.state, cid).await?;
        Ok(())
    }

    /// Kubo-like `pin/rm`.
    pub async fn pin_rm(&self, cid: &IpldCid) -> Result<()> {
        self.unpin(cid).await
    }

    /// Kubo-like `pin/update`: replace one recursive pin with another.
    pub async fn pin_update(&self, old: &IpldCid, new: &IpldCid) -> Result<()> {
        self.get_block(new).await?;
        let mut pins = self.state.pins.write().await;
        if !pins.remove(old) {
            bail!("pin not found: {old}");
        }
        pins.insert(*new);
        drop(pins);
        remove_pin_file(&self.state, old).await?;
        persist_pin(&self.state, new).await?;
        Ok(())
    }

    pub async fn is_pinned(&self, cid: &IpldCid) -> Result<bool> {
        Ok(self.state.pins.read().await.contains(cid))
    }

    /// Kubo-like `pin/ls`.
    pub async fn list_pins(&self) -> Result<Vec<IpldCid>> {
        let mut pins: Vec<IpldCid> = self.state.pins.read().await.iter().copied().collect();
        pins.sort();
        Ok(pins)
    }

    /// Kubo-like `pin/ls`.
    pub async fn pin_ls(&self) -> Result<Vec<IpldCid>> {
        self.list_pins().await
    }

    /// Kubo-like `pin/verify` for locally pinned roots.
    pub async fn pin_verify(&self) -> Result<Vec<PinVerify>> {
        let pins = self.list_pins().await?;
        let mut out = Vec::with_capacity(pins.len());
        for cid in pins {
            let error = match self.get_block(&cid).await {
                Ok(_) => match self.refs(&cid, true).await {
                    Ok(_) => None,
                    Err(err) => Some(format!("pinned DAG is incomplete: {err}")),
                },
                Err(err) => Some(format!("pinned block not found: {cid}: {err}")),
            };
            out.push(PinVerify {
                cid,
                ok: error.is_none(),
                error,
            });
        }
        Ok(out)
    }

    /// Kubo-like `repo/stat`.
    pub async fn repo_stat(&self) -> Result<RepoStat> {
        let cids = self.list_blocks().await?;
        let mut total_size = 0u64;
        for cid in &cids {
            total_size += self.block_stat(cid).await?.size;
        }
        Ok(RepoStat {
            num_objects: cids.len() as u64,
            repo_size: total_size,
        })
    }

    pub async fn gc(&self) -> Result<Vec<IpldCid>> {
        let roots = self.live_roots().await;
        let mut live = roots.clone();
        for root in roots {
            if let Ok(refs) = self.refs(&root, true).await {
                live.extend(refs);
            }
        }
        let mut blocks = self.state.blocks.write().await;
        let remove: Vec<IpldCid> = blocks
            .keys()
            .filter(|cid| !live.contains(cid))
            .copied()
            .collect();
        for cid in &remove {
            blocks.remove(cid);
            if let Some(path) = block_path(&self.state, cid) {
                match tokio::fs::remove_file(path).await {
                    Ok(()) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }
        Ok(remove)
    }

    /// Kubo-like `repo/gc`.
    pub async fn repo_gc(&self) -> Result<Vec<IpldCid>> {
        self.gc().await
    }

    /// Kubo-like `repo/verify`: verify every locally known block against its CID.
    pub async fn repo_verify(&self) -> Result<RepoVerify> {
        let cids = self.list_blocks().await?;
        let mut errors = Vec::new();
        for cid in &cids {
            match self.get_block(cid).await {
                Ok(bytes) => {
                    if let Err(err) = verify_cid(cid, &bytes) {
                        errors.push(RepoVerifyError {
                            cid: *cid,
                            error: err.to_string(),
                        });
                    }
                }
                Err(err) => errors.push(RepoVerifyError {
                    cid: *cid,
                    error: err.to_string(),
                }),
            }
        }
        Ok(RepoVerify {
            checked: cids.len() as u64,
            ok: errors.is_empty(),
            errors,
        })
    }

    /// Kubo-like `stats/bw` for the lightweight block-exchange transport.
    pub fn stats_bw(&self) -> BandwidthStats {
        BandwidthStats {
            total_in: self.state.bytes_in.load(Ordering::Relaxed),
            total_out: self.state.bytes_out.load(Ordering::Relaxed),
        }
    }

    /// Kubo-like `stats/bitswap` summarized from the local block exchange state.
    pub async fn stats_bitswap(&self) -> Result<BitswapStats> {
        let repo = self.repo_stat().await?;
        let provider_entries = self
            .state
            .providers
            .read()
            .await
            .values()
            .map(|peers| peers.len() as u64)
            .sum();
        Ok(BitswapStats {
            blocks_received: repo.num_objects,
            data_received: repo.repo_size,
            data_sent: self.state.bytes_out.load(Ordering::Relaxed),
            dup_blks_received: 0,
            dup_data_received: 0,
            wantlist: Vec::new(),
            peers: self.connected_peers().await?,
            provide_buf_len: provider_entries,
        })
    }

    /// Kubo-like `name/publish` for the local node name table.
    pub async fn name_publish(
        &self,
        name: impl Into<String>,
        cid: &IpldCid,
        valid_until: impl Into<String>,
    ) -> Result<IpnsRecord> {
        let name = IpnsName::new(name);
        let sequence = self
            .state
            .names
            .read()
            .await
            .get(&name)
            .map(|record| record.sequence + 1)
            .unwrap_or(1);
        let record = IpnsRecord::new(name.0.clone(), cid, sequence, valid_until);
        self.state.names.write().await.insert(name, record.clone());
        Ok(record)
    }

    /// Kubo-like `name/resolve` for records published through this node.
    pub async fn name_resolve(&self, name: impl Into<String>) -> Result<NameResolve> {
        let name = IpnsName::new(name);
        let record = self
            .state
            .names
            .read()
            .await
            .get(&name)
            .cloned()
            .ok_or_else(|| anyhow!("IPNS name not found: {}", name.0))?;
        let cid = record
            .value
            .parse::<IpldCid>()
            .map_err(|e| anyhow!("invalid IPNS record CID: {e}"))?;
        Ok(NameResolve {
            name: record.name.clone(),
            path: format!("/ipfs/{cid}"),
            cid,
            record,
        })
    }

    /// Kubo-like MFS `files/write`: bind an MFS path to a CID.
    pub async fn files_write(&self, path: impl AsRef<str>, cid: &IpldCid) -> Result<()> {
        self.get_block(cid).await?;
        let path = normalize_mfs_path(path.as_ref())?;
        self.state.files.write().await.insert(path, *cid);
        Ok(())
    }

    /// Kubo-like MFS `files/write` for bytes, stored as CIDv1/raw/sha2-256.
    pub async fn files_write_bytes(
        &self,
        path: impl AsRef<str>,
        data: &[u8],
        parents: bool,
    ) -> Result<MfsStat> {
        let path = normalize_mfs_path(path.as_ref())?;
        if parents {
            for dir in ancestor_dirs(&path) {
                self.files_mkdir(dir, true).await?;
            }
        }
        let cid = self.put_raw_block(data).await?;
        self.files_write(&path, &cid).await?;
        self.files_stat(&path).await
    }

    /// Kubo-like MFS `files/mkdir`.
    pub async fn files_mkdir(&self, path: impl AsRef<str>, parents: bool) -> Result<()> {
        let path = normalize_mfs_path(path.as_ref())?;
        if path == "/" {
            return Ok(());
        }
        if parents {
            let mut dirs = self.state.dirs.write().await;
            for dir in ancestor_dirs(&path) {
                dirs.insert(dir);
            }
            dirs.insert(path);
            return Ok(());
        }
        let Some(parent) = parent_mfs_dir(&path) else {
            return Ok(());
        };
        if parent != "/" && !self.state.dirs.read().await.contains(&parent) {
            bail!("mfs parent directory not found: {parent}");
        }
        self.state.dirs.write().await.insert(path);
        Ok(())
    }

    /// Kubo-like MFS `files/cp` for local MFS paths and `/ipfs/<cid>` sources.
    pub async fn files_cp(&self, source: impl AsRef<str>, dest: impl AsRef<str>) -> Result<()> {
        let source = source.as_ref();
        let dest = normalize_mfs_path(dest.as_ref())?;
        self.ensure_mfs_parent(&dest).await?;
        if let Some(cid) = ipfs_path_cid(source)? {
            self.get_block(&cid).await?;
            self.state.files.write().await.insert(dest, cid);
            return Ok(());
        }
        let source = normalize_mfs_path(source)?;
        let cid = *self
            .state
            .files
            .read()
            .await
            .get(&source)
            .ok_or_else(|| anyhow!("mfs path not found: {source}"))?;
        self.state.files.write().await.insert(dest, cid);
        Ok(())
    }

    /// Kubo-like MFS `files/mv` for local MFS files or directories.
    pub async fn files_mv(&self, source: impl AsRef<str>, dest: impl AsRef<str>) -> Result<()> {
        let source = normalize_mfs_path(source.as_ref())?;
        let dest = normalize_mfs_path(dest.as_ref())?;
        if source == "/" {
            bail!("cannot move MFS root");
        }
        if dest == source || dest.starts_with(&format!("{source}/")) {
            bail!("cannot move MFS path into itself: {source} -> {dest}");
        }
        self.ensure_mfs_parent(&dest).await?;

        let mut files = self.state.files.write().await;
        let mut dirs = self.state.dirs.write().await;
        if files.contains_key(&dest) || dirs.contains(&dest) {
            bail!("mfs destination already exists: {dest}");
        }
        if let Some(cid) = files.remove(&source) {
            files.insert(dest, cid);
            return Ok(());
        }
        if !dirs.contains(&source) {
            bail!("mfs path not found: {source}");
        }

        let file_moves: Vec<_> = files
            .iter()
            .filter(|(path, _)| path.starts_with(&format!("{source}/")))
            .map(|(path, cid)| (path.clone(), *cid))
            .collect();
        let dir_moves: Vec<_> = dirs
            .iter()
            .filter(|path| *path == &source || path.starts_with(&format!("{source}/")))
            .cloned()
            .collect();

        for (path, _) in &file_moves {
            files.remove(path);
        }
        for path in &dir_moves {
            dirs.remove(path);
        }
        for path in dir_moves {
            dirs.insert(rebase_mfs_path(&path, &source, &dest));
        }
        for (path, cid) in file_moves {
            files.insert(rebase_mfs_path(&path, &source, &dest), cid);
        }
        Ok(())
    }

    /// Kubo-like MFS `files/read`.
    pub async fn files_read(&self, path: impl AsRef<str>) -> Result<Bytes> {
        let path = normalize_mfs_path(path.as_ref())?;
        let cid = *self
            .state
            .files
            .read()
            .await
            .get(&path)
            .ok_or_else(|| anyhow!("mfs path not found: {path}"))?;
        self.get_block(&cid).await
    }

    /// Kubo-like MFS `files/stat`.
    pub async fn files_stat(&self, path: impl AsRef<str>) -> Result<MfsStat> {
        let path = normalize_mfs_path(path.as_ref())?;
        let cid = *self
            .state
            .files
            .read()
            .await
            .get(&path)
            .ok_or_else(|| anyhow!("mfs path not found: {path}"))?;
        let stat = self.block_stat(&cid).await?;
        Ok(MfsStat {
            path,
            cid,
            size: stat.size,
        })
    }

    /// Kubo-like MFS `files/flush`.
    ///
    /// Blocks and pin files are persisted eagerly in this lightweight node, so
    /// flush is a durability boundary that validates and returns the current
    /// file stat.
    pub async fn files_flush(&self, path: impl AsRef<str>) -> Result<MfsStat> {
        self.files_stat(path).await
    }

    /// Kubo-like MFS `files/ls`.
    pub async fn files_ls(&self, prefix: impl AsRef<str>) -> Result<Vec<MfsEntry>> {
        let prefix = normalize_mfs_path(prefix.as_ref())?;
        let child_prefix = if prefix == "/" {
            "/".to_string()
        } else {
            format!("{prefix}/")
        };
        let dirs = self.state.dirs.read().await;
        let files = self.state.files.read().await;
        let mut entries: Vec<_> = dirs
            .iter()
            .filter(|path| *path != &prefix && path.starts_with(&child_prefix))
            .map(|path| MfsEntry {
                path: path.clone(),
                cid: None,
            })
            .chain(
                files
                    .iter()
                    .filter(|(path, _)| *path == &prefix || path.starts_with(&child_prefix))
                    .map(|(path, cid)| MfsEntry {
                        path: path.clone(),
                        cid: Some(*cid),
                    }),
            )
            .collect();
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        entries.dedup_by(|a, b| a.path == b.path && a.cid == b.cid);
        Ok(entries)
    }

    /// Kubo-like MFS `files/rm`.
    pub async fn files_rm(&self, path: impl AsRef<str>, recursive: bool) -> Result<usize> {
        let path = normalize_mfs_path(path.as_ref())?;
        let mut removed = 0usize;
        let mut files = self.state.files.write().await;
        let mut dirs = self.state.dirs.write().await;
        if recursive {
            let keys: Vec<_> = files
                .keys()
                .filter(|p| *p == &path || p.starts_with(&format!("{path}/")))
                .cloned()
                .collect();
            removed += keys.len();
            for key in keys {
                files.remove(&key);
            }
            let dir_keys: Vec<_> = dirs
                .iter()
                .filter(|p| *p == &path || p.starts_with(&format!("{path}/")))
                .cloned()
                .collect();
            removed += dir_keys.len();
            for key in dir_keys {
                dirs.remove(&key);
            }
            return Ok(removed);
        }
        removed += files.remove(&path).is_some() as usize;
        removed += dirs.remove(&path) as usize;
        Ok(removed)
    }

    pub async fn shutdown(self) {
        if let Some(listener) = self.listener {
            listener.abort();
        }
    }

    async fn ensure_mfs_parent(&self, path: &str) -> Result<()> {
        let Some(parent) = parent_mfs_dir(path) else {
            return Ok(());
        };
        if parent != "/" && !self.state.dirs.read().await.contains(&parent) {
            bail!("mfs parent directory not found: {parent}");
        }
        Ok(())
    }

    async fn live_roots(&self) -> HashSet<IpldCid> {
        let mut roots = self.state.pins.read().await.clone();
        roots.extend(self.state.files.read().await.values().copied());
        roots
    }

    async fn refs_inner(
        &self,
        cid: &IpldCid,
        recursive: bool,
        seen: &mut HashSet<IpldCid>,
        out: &mut Vec<IpldCid>,
    ) -> Result<()> {
        if !seen.insert(*cid) {
            return Ok(());
        }
        if cid.codec() != crate::cid::CODEC_DAG_CBOR {
            self.get_block(cid).await?;
            return Ok(());
        }
        let root = self.dag_get_ipld(cid).await?;
        let mut links = Vec::new();
        root.references(&mut links);
        links.sort();
        links.dedup();
        for link in links {
            out.push(link);
            if recursive {
                Box::pin(self.refs_inner(&link, true, seen, out)).await?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeId {
    pub id: PeerId,
    pub addresses: Vec<Multiaddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeVersion {
    pub version: &'static str,
    pub agent: &'static str,
    pub protocol: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwarmPeer {
    pub peer: PeerId,
    pub addr: Multiaddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwarmConnect {
    pub peer: PeerId,
    pub addr: Multiaddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provider {
    pub peer: PeerId,
    pub addrs: Vec<Multiaddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinVerify {
    pub cid: IpldCid,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MfsEntry {
    pub path: String,
    pub cid: Option<IpldCid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockStat {
    pub cid: IpldCid,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockPut {
    pub cid: IpldCid,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectStat {
    pub cid: IpldCid,
    pub codec: u64,
    pub block_size: u64,
    pub cumulative_size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DagStat {
    pub cid: IpldCid,
    pub codec: u64,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagResolve {
    pub cid: IpldCid,
    pub rem_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathResolve {
    pub cid: IpldCid,
    pub rem_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MfsStat {
    pub path: String,
    pub cid: IpldCid,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameResolve {
    pub name: IpnsName,
    pub path: String,
    pub cid: IpldCid,
    pub record: IpnsRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepoStat {
    pub num_objects: u64,
    pub repo_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoVerify {
    pub checked: u64,
    pub ok: bool,
    pub errors: Vec<RepoVerifyError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoVerifyError {
    pub cid: IpldCid,
    pub error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BandwidthStats {
    pub total_in: u64,
    pub total_out: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitswapStats {
    pub blocks_received: u64,
    pub data_received: u64,
    pub data_sent: u64,
    pub dup_blks_received: u64,
    pub dup_data_received: u64,
    pub wantlist: Vec<IpldCid>,
    pub peers: Vec<PeerId>,
    pub provide_buf_len: u64,
}

impl Clone for KotobaIpfsNode {
    fn clone(&self) -> Self {
        Self {
            peer_id: self.peer_id,
            state: Arc::clone(&self.state),
            fetch_timeout: self.fetch_timeout,
            listener: None,
        }
    }
}

async fn spawn_listener(
    peer_id: PeerId,
    state: Arc<State>,
    addr: Multiaddr,
) -> Result<JoinHandle<()>> {
    let socket = multiaddr_to_socket(&addr)?;
    let listener = TcpListener::bind(socket)
        .await
        .with_context(|| format!("bind {addr}"))?;
    let local = listener.local_addr()?;
    let advertised = socket_to_multiaddr(local).with_peer(peer_id);
    state.listen_addrs.write().await.push(advertised);
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(err) = serve_stream(state, stream).await {
                            tracing::debug!(error = %err, "kotoba-ipfs stream failed");
                        }
                    });
                }
                Err(err) => {
                    tracing::debug!(error = %err, "kotoba-ipfs accept failed");
                    break;
                }
            }
        }
    });
    Ok(handle)
}

async fn serve_stream(state: Arc<State>, stream: TcpStream) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("GET"), Some(protocol), Some(cid_s), None) if protocol == PROTOCOL => {
            let cid: IpldCid = cid_s.parse().map_err(|e| anyhow!("parse cid: {e}"))?;
            let bytes = state.blocks.read().await.get(&cid).cloned();
            let stream = reader.get_mut();
            match bytes {
                Some(bytes) => {
                    state
                        .bytes_out
                        .fetch_add(8 + bytes.len() as u64, Ordering::Relaxed);
                    stream
                        .write_all(&(bytes.len() as u64).to_be_bytes())
                        .await?;
                    stream.write_all(&bytes).await?;
                }
                None => {
                    state.bytes_out.fetch_add(8, Ordering::Relaxed);
                    stream.write_all(&NOT_FOUND.to_be_bytes()).await?;
                }
            }
            stream.flush().await?;
            Ok(())
        }
        _ => bail!("invalid request"),
    }
}

async fn fetch_from_socket(socket: SocketAddr, cid: &IpldCid) -> Result<Bytes> {
    let mut stream = TcpStream::connect(socket)
        .await
        .with_context(|| format!("connect {socket}"))?;
    stream
        .write_all(format!("GET {PROTOCOL} {cid}\n").as_bytes())
        .await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf).await?;
    let len = u64::from_be_bytes(len_buf);
    if len == NOT_FOUND {
        bail!("block not found on peer: {cid}");
    }
    if len > usize::MAX as u64 {
        bail!("block too large: {len}");
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

fn verify_cid(cid: &IpldCid, data: &[u8]) -> Result<()> {
    let expected = cid_for_bytes(cid.codec(), data);
    if expected != *cid {
        bail!("cid/data mismatch: got {cid}, computed {expected}");
    }
    Ok(())
}

fn normalize_mfs_path(path: &str) -> Result<String> {
    if path.is_empty() {
        bail!("mfs path must not be empty");
    }
    if !path.starts_with('/') {
        bail!("mfs path must be absolute: {path}");
    }
    let normalized = path.trim_end_matches('/');
    Ok(if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized.to_string()
    })
}

fn normalize_ipld_path(path: &str) -> Result<String> {
    let path = path.trim();
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.contains("//") {
        bail!("invalid dag path: {path}");
    }
    Ok(path.trim_end_matches('/').to_string())
}

fn ancestor_dirs(path: &str) -> Vec<String> {
    let Some(parent) = parent_mfs_dir(path) else {
        return vec![];
    };
    let mut dirs = Vec::new();
    let mut current = parent;
    while current != "/" {
        dirs.push(current.clone());
        let Some(next) = parent_mfs_dir(&current) else {
            break;
        };
        current = next;
    }
    dirs.reverse();
    dirs
}

fn parent_mfs_dir(path: &str) -> Option<String> {
    if path == "/" {
        return None;
    }
    let (parent, _) = path.rsplit_once('/')?;
    Some(if parent.is_empty() {
        "/".to_string()
    } else {
        parent.to_string()
    })
}

fn ipfs_path_cid(path: &str) -> Result<Option<IpldCid>> {
    let Some(rest) = path.strip_prefix("/ipfs/") else {
        return Ok(None);
    };
    let cid = rest
        .split('/')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("invalid IPFS path: {path}"))?
        .parse::<IpldCid>()
        .map_err(|err| anyhow!("invalid IPFS path CID: {err}"))?;
    Ok(Some(cid))
}

fn split_ipld_path(path: &str) -> Result<(&str, String)> {
    let (root, rem) = path.split_once('/').unwrap_or((path, ""));
    if root.is_empty() {
        bail!("invalid IPLD path: missing root");
    }
    Ok((root, rem.to_string()))
}

fn cbor_value_to_ipld(value: CborValue) -> Result<Ipld> {
    Ok(match value {
        CborValue::Null => Ipld::Null,
        CborValue::Bool(value) => Ipld::Bool(value),
        CborValue::Integer(value) => Ipld::Integer(i128::from(value)),
        CborValue::Float(value) => Ipld::Float(value),
        CborValue::Text(value) => Ipld::String(value),
        CborValue::Bytes(value) => Ipld::Bytes(value),
        CborValue::Array(values) => Ipld::List(
            values
                .into_iter()
                .map(cbor_value_to_ipld)
                .collect::<Result<Vec<_>>>()?,
        ),
        CborValue::Map(entries) => {
            let mut map = BTreeMap::new();
            for (key, value) in entries {
                let CborValue::Text(key) = key else {
                    bail!("dag-cbor IPLD map key must be text");
                };
                map.insert(key, cbor_value_to_ipld(value)?);
            }
            Ipld::Map(map)
        }
        CborValue::Tag(42, value) => {
            let CborValue::Bytes(bytes) = *value else {
                bail!("dag-cbor CID link tag must contain bytes");
            };
            let raw = bytes.strip_prefix(&[0]).unwrap_or(bytes.as_slice());
            Ipld::Link(
                IpldCid::read_bytes(raw).map_err(|e| anyhow!("dag-cbor CID link decode: {e}"))?,
            )
        }
        CborValue::Tag(tag, _) => bail!("unsupported dag-cbor tag {tag}"),
        _ => bail!("unsupported dag-cbor value"),
    })
}

fn rebase_mfs_path(path: &str, source: &str, dest: &str) -> String {
    if path == source {
        return dest.to_string();
    }
    let suffix = path.strip_prefix(source).unwrap_or_default();
    format!("{dest}{suffix}")
}

async fn load_repo(state: &Arc<State>) -> Result<()> {
    let Some(repo) = &state.repo_path else {
        return Ok(());
    };

    let mut blocks = tokio::fs::read_dir(blocks_dir(repo)).await?;
    while let Some(entry) = blocks.next_entry().await? {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(cid) = name.parse::<IpldCid>() else {
            continue;
        };
        let data = tokio::fs::read(entry.path()).await?;
        verify_cid(&cid, &data)?;
        state.blocks.write().await.insert(cid, Bytes::from(data));
    }

    let mut pins = tokio::fs::read_dir(pins_dir(repo)).await?;
    while let Some(entry) = pins.next_entry().await? {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Ok(cid) = name.parse::<IpldCid>() {
            state.pins.write().await.insert(cid);
        }
    }

    Ok(())
}

async fn persist_block(state: &State, cid: &IpldCid, data: &[u8]) -> Result<()> {
    let Some(path) = block_path(state, cid) else {
        return Ok(());
    };
    tokio::fs::write(&path, data)
        .await
        .with_context(|| format!("write block {path:?}"))?;
    Ok(())
}

async fn load_block(state: &State, cid: &IpldCid) -> Result<Option<Bytes>> {
    let Some(path) = block_path(state, cid) else {
        return Ok(None);
    };
    match tokio::fs::read(&path).await {
        Ok(data) => {
            verify_cid(cid, &data)?;
            Ok(Some(Bytes::from(data)))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("read block {path:?}")),
    }
}

async fn persist_pin(state: &State, cid: &IpldCid) -> Result<()> {
    let Some(repo) = &state.repo_path else {
        return Ok(());
    };
    let path = pins_dir(repo).join(cid.to_string());
    tokio::fs::write(&path, b"recursive\n")
        .await
        .with_context(|| format!("write pin {path:?}"))?;
    Ok(())
}

async fn remove_pin_file(state: &State, cid: &IpldCid) -> Result<()> {
    let Some(repo) = &state.repo_path else {
        return Ok(());
    };
    let path = pins_dir(repo).join(cid.to_string());
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove pin {path:?}")),
    }
}

fn blocks_dir(repo: &Path) -> PathBuf {
    repo.join("blocks")
}

fn pins_dir(repo: &Path) -> PathBuf {
    repo.join("pins")
}

fn block_path(state: &State, cid: &IpldCid) -> Option<PathBuf> {
    state
        .repo_path
        .as_ref()
        .map(|repo| blocks_dir(repo).join(cid.to_string()))
}

fn split_peer_addr(addr: &Multiaddr) -> Result<(PeerId, SocketAddr)> {
    let peer = addr
        .peer()
        .ok_or_else(|| anyhow!("missing /p2p peer id: {addr}"))?;
    Ok((peer, addr.socket()))
}

fn multiaddr_to_socket(addr: &Multiaddr) -> Result<SocketAddr> {
    Ok(addr.socket())
}

fn socket_to_multiaddr(socket: SocketAddr) -> Multiaddr {
    Multiaddr { socket, peer: None }
}
