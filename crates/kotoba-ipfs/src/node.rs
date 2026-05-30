//! Lightweight kotoba IPFS-compatible node.
//!
//! This is intentionally not a full IPFS daemon.  It owns the parts kotoba
//! needs first: IPFS CID-compatible block addressing, local persistence hooks,
//! pin state, and a tiny TCP block exchange protocol between kotoba nodes.

use crate::cid::{
    cid_for_bytes, dag_cbor_block, dag_pb_object_block, decode_dag_pb_node,
    decode_unixfs_file_data, raw_cid, unixfs_chunked_file_blocks, unixfs_directory_block,
    unixfs_file_block,
};
use crate::ipns::{IpnsName, IpnsRecord};
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use ciborium::value::Value as CborValue;
use ipld_core::cid::Cid as IpldCid;
use ipld_core::ipld::Ipld;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
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
    pins: RwLock<HashMap<IpldCid, PinKind>>,
    peers: RwLock<HashMap<PeerId, SocketAddr>>,
    bootstrap: RwLock<HashSet<Multiaddr>>,
    providers: RwLock<HashMap<IpldCid, HashSet<PeerId>>>,
    files: RwLock<HashMap<String, IpldCid>>,
    dirs: RwLock<HashSet<String>>,
    names: RwLock<HashMap<IpnsName, IpnsRecord>>,
    keys: RwLock<HashMap<String, KeyEntry>>,
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

    /// Kubo-like `dht/findprovs` over the local and known-peer provider tables.
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
        drop(peer_addrs);
        drop(listen_addrs);

        let mut remote = self.find_providers_from_known_peers(cid).await?;
        out.append(&mut remote);
        out.sort_by_key(|provider| provider.peer.0);
        out.dedup_by_key(|provider| provider.peer.0);
        Ok(out)
    }

    async fn find_providers_from_known_peers(&self, cid: &IpldCid) -> Result<Vec<Provider>> {
        let mut peers: Vec<_> = self
            .state
            .peers
            .read()
            .await
            .iter()
            .map(|(peer, socket)| (*peer, *socket))
            .collect();
        peers.sort_by_key(|(peer, _)| peer.0);
        let mut out = Vec::new();
        let mut errors = Vec::new();
        for (peer, socket) in peers {
            let fut = fetch_providers_from_socket(socket, cid);
            match tokio::time::timeout(self.fetch_timeout, fut).await {
                Ok(Ok(mut providers)) => {
                    self.state.bytes_out.fetch_add(
                        format!("PROVIDERS {PROTOCOL} {cid}\n").len() as u64,
                        Ordering::Relaxed,
                    );
                    let encoded = cbor_len(&provider_wire_rows(&providers))?;
                    self.state
                        .bytes_in
                        .fetch_add(8 + encoded, Ordering::Relaxed);
                    out.append(&mut providers);
                }
                Ok(Err(err)) => errors.push(format!("{peer}: {err}")),
                Err(_) => errors.push(format!(
                    "{peer}: dht_find_providers timeout after {:?}",
                    self.fetch_timeout
                )),
            }
        }
        if !errors.is_empty() {
            tracing::debug!(cid = %cid, errors = ?errors, "known peers did not return providers");
        }
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

    /// Kubo-compatible `add` for a single UnixFS/dag-pb file block.
    pub async fn add_unixfs_file(&self, data: &[u8]) -> Result<IpldCid> {
        let (cid, block) = unixfs_file_block(data);
        self.put_block(&cid, &block).await?;
        Ok(cid)
    }

    /// Kubo-compatible chunked `add` using CIDv1/raw leaves and a dag-pb UnixFS root.
    pub async fn add_unixfs_file_chunked(&self, data: &[u8], chunk_size: usize) -> Result<IpldCid> {
        let (root, root_block, leaves) = unixfs_chunked_file_blocks(data, chunk_size)?;
        for (cid, block) in leaves {
            self.put_block(&cid, &block).await?;
        }
        self.put_block(&root, &root_block).await?;
        Ok(root)
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
        if let Some(bytes) = self.fetch_block_from_known_peers(cid).await? {
            return Ok(bytes);
        }
        Err(anyhow!("block not found locally or on known peers: {cid}"))
    }

    /// Kubo-like `block/get`.
    pub async fn block_get(&self, cid: &IpldCid) -> Result<Bytes> {
        self.get_block(cid).await
    }

    /// Kubo-like `cat` for raw blocks and UnixFS/dag-pb files.
    pub async fn cat(&self, cid: &IpldCid) -> Result<Bytes> {
        if cid.codec() == crate::cid::CODEC_RAW {
            return self.get_block(cid).await;
        }
        if cid.codec() == crate::cid::CODEC_DAG_PB {
            return self.cat_dag_pb(cid).await.map(Bytes::from);
        }
        bail!(
            "cat only supports raw blocks and UnixFS dag-pb files, got codec {}",
            cid.codec()
        );
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
        let bytes = self.get_block(cid).await?;
        match cid.codec() {
            crate::cid::CODEC_DAG_CBOR => {
                let value: CborValue = ciborium::from_reader(&bytes[..])
                    .map_err(|e| anyhow!("dag-cbor decode: {e}"))?;
                cbor_value_to_ipld(value)
            }
            crate::cid::CODEC_DAG_PB => dag_pb_node_to_ipld(decode_dag_pb_node(&bytes)?),
            _ => bail!(
                "dag_get_ipld only supports dag-cbor and dag-pb blocks, got codec {}",
                cid.codec()
            ),
        }
    }

    /// Kubo-like `dag/stat` for local single-block DAG nodes.
    pub async fn dag_stat(&self, cid: &IpldCid) -> Result<DagStat> {
        if !matches!(
            cid.codec(),
            crate::cid::CODEC_DAG_CBOR | crate::cid::CODEC_DAG_PB
        ) {
            bail!(
                "dag_stat only supports dag-cbor and dag-pb blocks, got codec {}",
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

    /// Kubo-like `dag/export`: write a CAR v1 stream rooted at `cid`.
    pub async fn dag_export(&self, cid: &IpldCid, recursive: bool) -> Result<Bytes> {
        let mut roots = vec![*cid];
        let mut blocks = vec![*cid];
        if recursive {
            blocks.extend(self.refs(cid, true).await?);
        }
        blocks.sort();
        blocks.dedup();
        roots.sort();
        let mut out = Vec::new();
        write_car_header(&mut out, &roots)?;
        for block_cid in blocks {
            let data = self.get_block(&block_cid).await?;
            write_car_block(&mut out, &block_cid, &data)?;
        }
        Ok(Bytes::from(out))
    }

    /// Kubo-like `dag/import`: read a CAR v1 stream into the local block store.
    pub async fn dag_import(&self, car: &[u8]) -> Result<DagImport> {
        let mut pos = 0;
        let header_len = read_uvarint(car, &mut pos)? as usize;
        if pos + header_len > car.len() {
            bail!("CAR header exceeds input length");
        }
        let roots = read_car_header(&car[pos..pos + header_len])?;
        pos += header_len;

        let mut blocks = Vec::new();
        while pos < car.len() {
            let section_len = read_uvarint(car, &mut pos)? as usize;
            if section_len == 0 {
                continue;
            }
            if pos + section_len > car.len() {
                bail!("CAR block section exceeds input length");
            }
            let section = &car[pos..pos + section_len];
            let (cid, cid_len) = read_car_cid(section)?;
            let data = &section[cid_len..];
            self.put_block(&cid, data).await?;
            blocks.push(cid);
            pos += section_len;
        }
        Ok(DagImport { roots, blocks })
    }

    /// Kubo-like `dag/resolve` for local dag-cbor roots, dag-pb links, and direct IPLD links.
    pub async fn dag_resolve(&self, cid: &IpldCid, path: impl AsRef<str>) -> Result<DagResolve> {
        let path = normalize_ipld_path(path.as_ref())?;
        if path.is_empty() {
            self.get_block(cid).await?;
            return Ok(DagResolve {
                cid: *cid,
                rem_path: String::new(),
            });
        }
        if cid.codec() == crate::cid::CODEC_DAG_PB {
            return self.dag_resolve_pb(cid, &path).await;
        }
        if cid.codec() != crate::cid::CODEC_DAG_CBOR {
            bail!(
                "dag_resolve only traverses dag-cbor or dag-pb blocks, got codec {}",
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
        self.fetch_block_from_socket(cid, socket).await
    }

    async fn fetch_block_from_known_peers(&self, cid: &IpldCid) -> Result<Option<Bytes>> {
        let mut peers: Vec<_> = self
            .state
            .peers
            .read()
            .await
            .iter()
            .map(|(peer, socket)| (*peer, *socket))
            .collect();
        peers.sort_by_key(|(peer, _)| peer.0);
        let mut errors = Vec::new();
        for (peer, socket) in peers {
            match self.fetch_block_from_socket(cid, socket).await {
                Ok(bytes) => return Ok(Some(bytes)),
                Err(err) => errors.push(format!("{peer}: {err}")),
            }
        }
        if !errors.is_empty() {
            tracing::debug!(cid = %cid, errors = ?errors, "known peers did not provide block");
        }
        Ok(None)
    }

    async fn fetch_block_from_socket(&self, cid: &IpldCid, socket: SocketAddr) -> Result<Bytes> {
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
        persist_block(&self.state, cid, &bytes).await?;
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
        let mut cumulative_size = bytes.len() as u64;
        if cid.codec() == crate::cid::CODEC_DAG_PB {
            for link in decode_dag_pb_node(&bytes)?.links {
                cumulative_size += Box::pin(self.object_stat(&link.cid)).await?.cumulative_size;
            }
        }
        Ok(ObjectStat {
            cid: *cid,
            codec: cid.codec(),
            block_size: bytes.len() as u64,
            cumulative_size,
        })
    }

    /// Kubo-like `object/data` for locally available dag-pb objects.
    pub async fn object_data(&self, cid: &IpldCid) -> Result<Bytes> {
        if cid.codec() != crate::cid::CODEC_DAG_PB {
            bail!(
                "object_data only supports dag-pb blocks, got codec {}",
                cid.codec()
            );
        }
        Ok(Bytes::from(
            decode_dag_pb_node(&self.get_block(cid).await?)?
                .data
                .unwrap_or_default(),
        ))
    }

    /// Kubo-like `object/get` for locally available dag-pb objects.
    pub async fn object_get(&self, cid: &IpldCid) -> Result<ObjectGet> {
        if cid.codec() != crate::cid::CODEC_DAG_PB {
            bail!(
                "object_get only supports dag-pb blocks, got codec {}",
                cid.codec()
            );
        }
        let node = decode_dag_pb_node(&self.get_block(cid).await?)?;
        Ok(ObjectGet {
            cid: *cid,
            data: node.data.unwrap_or_default(),
            links: node
                .links
                .into_iter()
                .map(|link| ObjectLink {
                    name: link.name,
                    cid: link.cid,
                })
                .collect(),
        })
    }

    /// Kubo-like `object/links` for locally available dag-pb or dag-cbor objects.
    pub async fn object_links(&self, cid: &IpldCid) -> Result<Vec<ObjectLink>> {
        if cid.codec() == crate::cid::CODEC_DAG_PB {
            return Ok(decode_dag_pb_node(&self.get_block(cid).await?)?
                .links
                .into_iter()
                .map(|link| ObjectLink {
                    name: link.name,
                    cid: link.cid,
                })
                .collect());
        }
        Ok(self
            .refs(cid, false)
            .await?
            .into_iter()
            .map(|cid| ObjectLink {
                name: String::new(),
                cid,
            })
            .collect())
    }

    /// Kubo-like `object/put` for dag-pb objects.
    pub async fn object_put(&self, data: &[u8], links: Vec<ObjectLink>) -> Result<IpldCid> {
        let links = links
            .into_iter()
            .map(|link| crate::cid::DagPbLink {
                name: link.name,
                cid: link.cid,
                tsize: None,
            })
            .collect::<Vec<_>>();
        let (cid, block) = dag_pb_object_block(data, &links);
        self.put_block(&cid, &block).await?;
        Ok(cid)
    }

    /// Kubo-like `object/new` for an empty dag-pb object.
    pub async fn object_new(&self) -> Result<IpldCid> {
        self.object_put(&[], Vec::new()).await
    }

    /// Kubo-like `object/patch/add-link` for dag-pb objects.
    pub async fn object_patch_add_link(
        &self,
        cid: &IpldCid,
        name: impl Into<String>,
        child: IpldCid,
    ) -> Result<IpldCid> {
        let mut object = self.object_get(cid).await?;
        let name = name.into();
        object.links.retain(|link| link.name != name);
        object.links.push(ObjectLink { name, cid: child });
        object.links.sort_by(|a, b| a.name.cmp(&b.name));
        self.object_put(&object.data, object.links).await
    }

    /// Kubo-like `object/patch/rm-link` for dag-pb objects.
    pub async fn object_patch_rm_link(
        &self,
        cid: &IpldCid,
        name: impl AsRef<str>,
    ) -> Result<IpldCid> {
        let mut object = self.object_get(cid).await?;
        let name = name.as_ref();
        let before = object.links.len();
        object.links.retain(|link| link.name != name);
        if object.links.len() == before {
            bail!("object link not found: {name}");
        }
        self.object_put(&object.data, object.links).await
    }

    /// Kubo-like `object/patch/append-data` for dag-pb objects.
    pub async fn object_patch_append_data(
        &self,
        cid: &IpldCid,
        data: impl AsRef<[u8]>,
    ) -> Result<IpldCid> {
        let mut object = self.object_get(cid).await?;
        object.data.extend_from_slice(data.as_ref());
        self.object_put(&object.data, object.links).await
    }

    /// Kubo-like `object/patch/set-data` for dag-pb objects.
    pub async fn object_patch_set_data(
        &self,
        cid: &IpldCid,
        data: impl AsRef<[u8]>,
    ) -> Result<IpldCid> {
        let object = self.object_get(cid).await?;
        self.object_put(data.as_ref(), object.links).await
    }

    /// Remove a local block without pin protection.
    pub async fn delete_block(&self, cid: &IpldCid) -> Result<bool> {
        self.block_rm_force(cid).await
    }

    /// Kubo-like `block/rm` with `force=true`.
    pub async fn block_rm_force(&self, cid: &IpldCid) -> Result<bool> {
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
        if self.is_pinned_or_indirect(cid).await? {
            bail!("cannot remove pinned block without force: {cid}");
        }
        self.block_rm_force(cid).await
    }

    /// Kubo-like `block/rm` for a batch of CIDs.
    pub async fn block_rm_many(
        &self,
        cids: impl IntoIterator<Item = IpldCid>,
        force: bool,
    ) -> Result<Vec<BlockRm>> {
        let mut removed = Vec::new();
        for cid in cids {
            let result = if force {
                self.block_rm_force(&cid).await
            } else {
                self.block_rm(&cid).await
            };
            removed.push(match result {
                Ok(was_removed) => BlockRm {
                    cid,
                    removed: was_removed,
                    error: None,
                },
                Err(err) => BlockRm {
                    cid,
                    removed: false,
                    error: Some(err.to_string()),
                },
            });
        }
        Ok(removed)
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
        self.pin_add(cid).await
    }

    /// Kubo-like `pin/add` with `recursive=true`.
    pub async fn pin_add(&self, cid: &IpldCid) -> Result<()> {
        self.get_block(cid).await?;
        self.state
            .pins
            .write()
            .await
            .insert(*cid, PinKind::Recursive);
        self.state
            .providers
            .write()
            .await
            .entry(*cid)
            .or_default()
            .insert(self.peer_id);
        persist_pin(&self.state, cid, PinKind::Recursive).await?;
        Ok(())
    }

    /// Kubo-like `pin/add` with `recursive=false`.
    pub async fn pin_add_direct(&self, cid: &IpldCid) -> Result<()> {
        self.get_block(cid).await?;
        self.state.pins.write().await.insert(*cid, PinKind::Direct);
        persist_pin(&self.state, cid, PinKind::Direct).await?;
        Ok(())
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
        if pins.remove(old).is_none() {
            bail!("pin not found: {old}");
        }
        pins.insert(*new, PinKind::Recursive);
        drop(pins);
        remove_pin_file(&self.state, old).await?;
        persist_pin(&self.state, new, PinKind::Recursive).await?;
        Ok(())
    }

    pub async fn is_pinned(&self, cid: &IpldCid) -> Result<bool> {
        Ok(self.state.pins.read().await.contains_key(cid))
    }

    /// Kubo-like `pin/ls`.
    pub async fn list_pins(&self) -> Result<Vec<IpldCid>> {
        let mut pins: Vec<IpldCid> = self.state.pins.read().await.keys().copied().collect();
        pins.sort();
        Ok(pins)
    }

    /// Kubo-like `pin/ls`.
    ///
    /// Direct and recursive pin roots preserve their kind; locally reachable
    /// descendants of recursive roots are returned as `indirect`, matching
    /// Kubo's root-vs-child pin semantics.
    pub async fn pin_ls(&self) -> Result<Vec<PinLsEntry>> {
        let roots = self.state.pins.read().await.clone();
        let mut entries = BTreeMap::<IpldCid, PinKind>::new();
        for (root, kind) in &roots {
            entries.insert(*root, *kind);
        }
        for (root, kind) in roots {
            if kind != PinKind::Recursive {
                continue;
            }
            for child in self.refs(&root, true).await? {
                entries.entry(child).or_insert(PinKind::Indirect);
            }
        }
        Ok(entries
            .into_iter()
            .map(|(cid, kind)| PinLsEntry { cid, kind })
            .collect())
    }

    /// Kubo-like `pin/verify` for locally pinned roots.
    pub async fn pin_verify(&self) -> Result<Vec<PinVerify>> {
        let mut pins: Vec<_> = self.state.pins.read().await.clone().into_iter().collect();
        pins.sort_by_key(|(cid, _)| *cid);
        let mut out = Vec::with_capacity(pins.len());
        for (cid, kind) in pins {
            let error = match self.get_block(&cid).await {
                Ok(_) if kind == PinKind::Recursive => match self.refs(&cid, true).await {
                    Ok(_) => None,
                    Err(err) => Some(format!("pinned DAG is incomplete: {err}")),
                },
                Ok(_) => None,
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
        persist_repo_state(&self.state).await?;
        Ok(record)
    }

    /// Kubo-like `name/resolve` for records published through this node.
    pub async fn name_resolve(&self, name: impl Into<String>) -> Result<NameResolve> {
        let name = IpnsName::new(name);
        let local = self.state.names.read().await.get(&name).cloned();
        let record = match local {
            Some(record) => record,
            None => self
                .resolve_name_from_known_peers(&name)
                .await?
                .ok_or_else(|| {
                    anyhow!("IPNS name not found locally or on known peers: {}", name.0)
                })?,
        };
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

    async fn resolve_name_from_known_peers(&self, name: &IpnsName) -> Result<Option<IpnsRecord>> {
        let mut peers: Vec<_> = self
            .state
            .peers
            .read()
            .await
            .iter()
            .map(|(peer, socket)| (*peer, *socket))
            .collect();
        peers.sort_by_key(|(peer, _)| peer.0);
        let mut errors = Vec::new();
        for (peer, socket) in peers {
            let fut = fetch_name_from_socket(socket, name);
            match tokio::time::timeout(self.fetch_timeout, fut).await {
                Ok(Ok(record)) => {
                    self.state.bytes_out.fetch_add(
                        format!("NAME {PROTOCOL} {}\n", name.0).len() as u64,
                        Ordering::Relaxed,
                    );
                    let encoded = cbor_len(&record)?;
                    self.state
                        .bytes_in
                        .fetch_add(8 + encoded, Ordering::Relaxed);
                    self.state
                        .names
                        .write()
                        .await
                        .insert(name.clone(), record.clone());
                    return Ok(Some(record));
                }
                Ok(Err(err)) => errors.push(format!("{peer}: {err}")),
                Err(_) => errors.push(format!(
                    "{peer}: name_resolve timeout after {:?}",
                    self.fetch_timeout
                )),
            }
        }
        if !errors.is_empty() {
            tracing::debug!(name = %name.0, errors = ?errors, "known peers did not provide IPNS name");
        }
        Ok(None)
    }

    /// Kubo-like `key/gen`: create a named local publishing key.
    pub async fn key_gen(&self, name: impl Into<String>) -> Result<KeyEntry> {
        let name = validate_key_name(name.into())?;
        let mut keys = self.state.keys.write().await;
        if keys.contains_key(&name) {
            bail!("key already exists: {name}");
        }
        let ordinal = keys.len() + 1;
        let id = format!(
            "k51-{}",
            raw_cid(format!("kotoba-ipfs-key:v1:{}:{}:{ordinal}", self.peer_id.0, name).as_bytes())
        );
        let key = KeyEntry {
            name: name.clone(),
            id,
        };
        keys.insert(name, key.clone());
        drop(keys);
        persist_repo_state(&self.state).await?;
        Ok(key)
    }

    /// Kubo-like `key/list`: list locally managed publishing keys.
    pub async fn key_list(&self) -> Result<Vec<KeyEntry>> {
        let mut keys: Vec<_> = self.state.keys.read().await.values().cloned().collect();
        keys.push(self.self_key());
        keys.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(keys)
    }

    /// Kubo-like `key/rename`: rename a local publishing key, preserving its id.
    pub async fn key_rename(
        &self,
        old: impl AsRef<str>,
        new: impl Into<String>,
        force: bool,
    ) -> Result<KeyEntry> {
        let old = old.as_ref();
        if old == "self" {
            bail!("key name is reserved: self");
        }
        let new = validate_key_name(new.into())?;
        if old == new {
            let key = self
                .state
                .keys
                .read()
                .await
                .get(old)
                .cloned()
                .ok_or_else(|| anyhow!("key not found: {old}"))?;
            return Ok(key);
        }
        let mut keys = self.state.keys.write().await;
        if keys.contains_key(&new) && !force {
            bail!("key already exists: {new}");
        }
        let mut key = keys
            .remove(old)
            .ok_or_else(|| anyhow!("key not found: {old}"))?;
        if force {
            keys.remove(&new);
        }
        key.name = new.clone();
        keys.insert(new, key.clone());
        drop(keys);
        persist_repo_state(&self.state).await?;
        Ok(key)
    }

    /// Kubo-like `key/rm`: remove a local publishing key.
    pub async fn key_rm(&self, name: impl AsRef<str>) -> Result<KeyEntry> {
        let name = name.as_ref();
        if name.trim().is_empty() {
            bail!("key name must not be empty");
        }
        if name == "self" {
            bail!("key name is reserved: self");
        }
        let key = self
            .state
            .keys
            .write()
            .await
            .remove(name)
            .ok_or_else(|| anyhow!("key not found: {name}"))?;
        persist_repo_state(&self.state).await?;
        Ok(key)
    }

    fn self_key(&self) -> KeyEntry {
        KeyEntry {
            name: "self".to_string(),
            id: format!(
                "k51-{}",
                raw_cid(format!("kotoba-ipfs-self-key:v1:{}", self.peer_id.0).as_bytes())
            ),
        }
    }

    /// Kubo-like MFS `files/write`: bind an MFS path to a CID.
    pub async fn files_write(&self, path: impl AsRef<str>, cid: &IpldCid) -> Result<()> {
        self.get_block(cid).await?;
        let path = normalize_mfs_path(path.as_ref())?;
        self.state.files.write().await.insert(path, *cid);
        persist_repo_state(&self.state).await?;
        Ok(())
    }

    /// Kubo-like MFS `files/touch`: create an empty file if the path is missing.
    pub async fn files_touch(&self, path: impl AsRef<str>, parents: bool) -> Result<MfsStat> {
        let path = normalize_mfs_path(path.as_ref())?;
        if self.state.files.read().await.contains_key(&path) {
            return self.files_stat(&path).await;
        }
        if parents {
            for dir in ancestor_dirs(&path) {
                self.files_mkdir(dir, true).await?;
            }
        } else {
            self.ensure_mfs_parent(&path).await?;
        }
        let cid = self.put_raw_block(&[]).await?;
        self.state.files.write().await.insert(path.clone(), cid);
        persist_repo_state(&self.state).await?;
        self.files_stat(&path).await
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

    /// Kubo-like MFS `files/write` byte update.
    ///
    /// This models Kubo's common `--offset`, `--truncate`, `--create`, and
    /// `--parents` flags for this lightweight path-to-CID MFS.  Writes beyond
    /// the current end create a sparse byte range filled with zeroes.
    pub async fn files_write_bytes_at(
        &self,
        path: impl AsRef<str>,
        data: &[u8],
        offset: u64,
        create: bool,
        parents: bool,
        truncate: bool,
    ) -> Result<MfsStat> {
        let path = normalize_mfs_path(path.as_ref())?;
        if parents {
            for dir in ancestor_dirs(&path) {
                self.files_mkdir(dir, true).await?;
            }
        } else {
            self.ensure_mfs_parent(&path).await?;
        }

        let existing = if self.state.files.read().await.contains_key(&path) {
            self.files_read(&path).await?.to_vec()
        } else if create {
            Vec::new()
        } else {
            bail!("mfs path not found: {path}");
        };

        let offset = usize::try_from(offset).context("files/write offset does not fit usize")?;
        let mut out = if truncate { Vec::new() } else { existing };
        if out.len() < offset {
            out.resize(offset, 0);
        }
        let end = offset
            .checked_add(data.len())
            .context("files/write offset plus data length overflowed")?;
        if out.len() < end {
            out.resize(end, 0);
        }
        out[offset..end].copy_from_slice(data);

        let cid = self.put_raw_block(&out).await?;
        self.state.files.write().await.insert(path.clone(), cid);
        persist_repo_state(&self.state).await?;
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
            drop(dirs);
            persist_repo_state(&self.state).await?;
            return Ok(());
        }
        let Some(parent) = parent_mfs_dir(&path) else {
            return Ok(());
        };
        if parent != "/" && !self.state.dirs.read().await.contains(&parent) {
            bail!("mfs parent directory not found: {parent}");
        }
        self.state.dirs.write().await.insert(path);
        persist_repo_state(&self.state).await?;
        Ok(())
    }

    /// Kubo-like MFS `files/cp` for local MFS paths and resolved `/ipfs`/`/ipns` sources.
    pub async fn files_cp(&self, source: impl AsRef<str>, dest: impl AsRef<str>) -> Result<()> {
        let source = source.as_ref();
        let dest = normalize_mfs_path(dest.as_ref())?;
        self.ensure_mfs_parent(&dest).await?;
        if is_ipld_path(source) {
            let resolved = self.resolve_path(source).await?;
            if !resolved.rem_path.is_empty() {
                bail!(
                    "files/cp source did not resolve to a block CID; remaining path: {}",
                    resolved.rem_path
                );
            }
            self.get_block(&resolved.cid).await?;
            self.state.files.write().await.insert(dest, resolved.cid);
            persist_repo_state(&self.state).await?;
            return Ok(());
        }
        let source = normalize_mfs_path(source)?;
        if dest == source || dest.starts_with(&format!("{source}/")) {
            bail!("cannot copy MFS path into itself: {source} -> {dest}");
        }

        let mut files = self.state.files.write().await;
        let mut dirs = self.state.dirs.write().await;
        if let Some(cid) = files.get(&source).copied() {
            files.insert(dest, cid);
            drop(files);
            drop(dirs);
            persist_repo_state(&self.state).await?;
            return Ok(());
        }
        if source != "/" && !dirs.contains(&source) {
            bail!("mfs path not found: {source}");
        }
        if files.contains_key(&dest) || dirs.contains(&dest) {
            bail!("mfs destination already exists: {dest}");
        }

        let source_prefix = if source == "/" {
            "/".to_string()
        } else {
            format!("{source}/")
        };
        let file_copies: Vec<_> = files
            .iter()
            .filter(|(path, _)| path.starts_with(&source_prefix))
            .map(|(path, cid)| (path.clone(), *cid))
            .collect();
        let dir_copies: Vec<_> = dirs
            .iter()
            .filter(|path| *path == &source || path.starts_with(&source_prefix))
            .cloned()
            .collect();

        dirs.insert(dest.clone());
        for path in dir_copies {
            dirs.insert(rebase_mfs_path(&path, &source, &dest));
        }
        for (path, cid) in file_copies {
            files.insert(rebase_mfs_path(&path, &source, &dest), cid);
        }
        drop(files);
        drop(dirs);
        persist_repo_state(&self.state).await?;
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
            drop(files);
            drop(dirs);
            persist_repo_state(&self.state).await?;
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
        drop(files);
        drop(dirs);
        persist_repo_state(&self.state).await?;
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
        self.cat(&cid).await
    }

    /// Kubo-like MFS `files/read` with `--offset` and `--count`.
    pub async fn files_read_range(
        &self,
        path: impl AsRef<str>,
        offset: u64,
        count: Option<u64>,
    ) -> Result<Bytes> {
        let data = self.files_read(path).await?;
        let offset = usize::try_from(offset).context("files/read offset does not fit usize")?;
        if offset > data.len() {
            bail!(
                "files/read offset {offset} exceeds file size {}",
                data.len()
            );
        }
        let end = match count {
            Some(count) => offset
                .checked_add(usize::try_from(count).context("files/read count does not fit usize")?)
                .context("files/read offset plus count overflowed")?
                .min(data.len()),
            None => data.len(),
        };
        Ok(Bytes::copy_from_slice(&data[offset..end]))
    }

    /// Kubo-like MFS `files/stat`.
    pub async fn files_stat(&self, path: impl AsRef<str>) -> Result<MfsStat> {
        let path = normalize_mfs_path(path.as_ref())?;
        if let Some(cid) = self.state.files.read().await.get(&path).copied() {
            let size = self.mfs_file_size(&cid).await?;
            let object = self.object_stat(&cid).await?;
            return Ok(MfsStat {
                path,
                cid: Some(cid),
                kind: MfsKind::File,
                size,
                cumulative_size: object.cumulative_size,
                blocks: self.block_count(&cid).await?,
            });
        }

        if path == "/" || self.state.dirs.read().await.contains(&path) {
            let cids = self.mfs_file_cids_under(&path).await;
            let mut size = 0;
            let mut blocks = HashSet::new();
            for cid in cids {
                size += self.mfs_file_size(&cid).await?;
                self.collect_reachable_blocks(&cid, &mut blocks).await?;
            }
            let cid = self.materialize_mfs_dir(&path).await?;
            let cumulative_size = self.object_stat(&cid).await?.cumulative_size;
            self.collect_reachable_blocks(&cid, &mut blocks).await?;
            return Ok(MfsStat {
                path,
                cid: Some(cid),
                kind: MfsKind::Directory,
                size,
                cumulative_size,
                blocks: blocks.len() as u64,
            });
        }

        Err(anyhow!("mfs path not found: {path}"))
    }

    /// Kubo-like MFS `files/flush`.
    ///
    /// Blocks and pin files are persisted eagerly in this lightweight node, so
    /// flush is a durability boundary that validates and returns the current
    /// file stat.
    pub async fn files_flush(&self, path: impl AsRef<str>) -> Result<MfsStat> {
        persist_repo_state(&self.state).await?;
        self.files_stat(path).await
    }

    /// Kubo-like MFS `files/chcid` for file paths.
    ///
    /// This lightweight MFS stores paths as direct file-CID bindings rather
    /// than materialized directory DAGs, so `chcid` rewrites the target file
    /// block into the requested root codec and updates the path binding.
    /// Supported codecs are `raw` and `dag-pb` UnixFS file blocks.
    pub async fn files_chcid(&self, path: impl AsRef<str>, codec: u64) -> Result<MfsStat> {
        let path = normalize_mfs_path(path.as_ref())?;
        let data = self.files_read(&path).await?;
        let new_cid = match codec {
            crate::cid::CODEC_RAW => self.put_raw_block(&data).await?,
            crate::cid::CODEC_DAG_PB => {
                let (cid, block) = unixfs_file_block(&data);
                self.put_block(&cid, &block).await?;
                cid
            }
            other => bail!("files/chcid unsupported codec: {other}"),
        };
        self.state.files.write().await.insert(path.clone(), new_cid);
        persist_repo_state(&self.state).await?;
        self.files_stat(&path).await
    }

    /// Kubo-like MFS `files/du`: sum file payload sizes reachable from an MFS path.
    pub async fn files_du(&self, path: impl AsRef<str>, recursive: bool) -> Result<u64> {
        let path = normalize_mfs_path(path.as_ref())?;
        let files = self.state.files.read().await;
        let mut cids = Vec::new();
        if let Some(cid) = files.get(&path) {
            cids.push(*cid);
        } else {
            let child_prefix = if path == "/" {
                "/".to_string()
            } else {
                format!("{path}/")
            };
            if !recursive && path != "/" {
                bail!("files/du on directory requires recursive=true: {path}");
            }
            cids.extend(
                files
                    .iter()
                    .filter(|(file_path, _)| file_path.starts_with(&child_prefix))
                    .map(|(_, cid)| *cid),
            );
        }
        drop(files);

        let mut total = 0;
        for cid in cids {
            total += self.mfs_file_size(&cid).await?;
        }
        Ok(total)
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
        let mut entries = BTreeMap::<String, Option<IpldCid>>::new();
        for path in dirs
            .iter()
            .filter(|path| *path != &prefix && path.starts_with(&child_prefix))
        {
            if let Some(child) = immediate_mfs_child(&prefix, path) {
                entries.entry(child).or_insert(None);
            }
        }
        for (path, cid) in files
            .iter()
            .filter(|(path, _)| *path == &prefix || path.starts_with(&child_prefix))
        {
            if let Some(child) = immediate_mfs_child(&prefix, path) {
                entries.entry(child).or_insert(Some(*cid));
            }
        }
        let mut out = Vec::new();
        for (path, cid) in entries {
            let cid = match cid {
                Some(cid) => Some(cid),
                None => Some(self.materialize_mfs_dir(&path).await?),
            };
            out.push(MfsEntry { path, cid });
        }
        Ok(out)
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
            drop(files);
            drop(dirs);
            persist_repo_state(&self.state).await?;
            return Ok(removed);
        }

        if dirs.contains(&path) {
            let child_prefix = format!("{path}/");
            if files.keys().any(|p| p.starts_with(&child_prefix))
                || dirs.iter().any(|p| p.starts_with(&child_prefix))
            {
                bail!("mfs directory is not empty; use recursive=true: {path}");
            }
        }
        removed += files.remove(&path).is_some() as usize;
        removed += dirs.remove(&path) as usize;
        drop(files);
        drop(dirs);
        persist_repo_state(&self.state).await?;
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
        let mut roots: HashSet<_> = self.state.pins.read().await.keys().copied().collect();
        roots.extend(self.state.files.read().await.values().copied());
        roots
    }

    async fn is_pinned_or_indirect(&self, cid: &IpldCid) -> Result<bool> {
        let pins = self.state.pins.read().await.clone();
        if pins.contains_key(cid) {
            return Ok(true);
        }
        for (root, kind) in pins {
            if kind != PinKind::Recursive {
                continue;
            }
            if self.refs(&root, true).await?.contains(cid) {
                return Ok(true);
            }
        }
        Ok(false)
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
            if cid.codec() == crate::cid::CODEC_DAG_PB {
                for link in decode_dag_pb_node(&self.get_block(cid).await?)?.links {
                    out.push(link.cid);
                    if recursive {
                        Box::pin(self.refs_inner(&link.cid, true, seen, out)).await?;
                    }
                }
            } else {
                self.get_block(cid).await?;
            }
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

    async fn cat_dag_pb(&self, cid: &IpldCid) -> Result<Vec<u8>> {
        let bytes = self.get_block(cid).await?;
        let node = decode_dag_pb_node(&bytes)?;
        let mut out = decode_unixfs_file_data(node.data.as_deref().unwrap_or_default())?;
        for link in node.links {
            let child = Box::pin(self.cat(&link.cid)).await?;
            out.extend_from_slice(&child);
        }
        Ok(out)
    }

    async fn mfs_file_size(&self, cid: &IpldCid) -> Result<u64> {
        match cid.codec() {
            crate::cid::CODEC_RAW | crate::cid::CODEC_DAG_PB => {
                Ok(self.cat(cid).await?.len() as u64)
            }
            _ => Ok(self.block_stat(cid).await?.size),
        }
    }

    async fn block_count(&self, cid: &IpldCid) -> Result<u64> {
        let mut blocks = HashSet::new();
        self.collect_reachable_blocks(cid, &mut blocks).await?;
        Ok(blocks.len() as u64)
    }

    async fn collect_reachable_blocks(
        &self,
        cid: &IpldCid,
        blocks: &mut HashSet<IpldCid>,
    ) -> Result<()> {
        if !blocks.insert(*cid) {
            return Ok(());
        }
        for child in self.refs(cid, false).await? {
            Box::pin(self.collect_reachable_blocks(&child, blocks)).await?;
        }
        Ok(())
    }

    async fn mfs_file_cids_under(&self, path: &str) -> Vec<IpldCid> {
        let child_prefix = if path == "/" {
            "/".to_string()
        } else {
            format!("{path}/")
        };
        self.state
            .files
            .read()
            .await
            .iter()
            .filter(|(file_path, _)| *file_path == path || file_path.starts_with(&child_prefix))
            .map(|(_, cid)| *cid)
            .collect()
    }

    async fn materialize_mfs_dir(&self, path: &str) -> Result<IpldCid> {
        let path = normalize_mfs_path(path)?;
        if path != "/" && !self.state.dirs.read().await.contains(&path) {
            bail!("mfs directory not found: {path}");
        }
        let child_prefix = if path == "/" {
            "/".to_string()
        } else {
            format!("{path}/")
        };

        let dirs = self.state.dirs.read().await;
        let files = self.state.files.read().await;
        let mut children = BTreeMap::<String, Option<IpldCid>>::new();
        for dir in dirs
            .iter()
            .filter(|dir| *dir != &path && dir.starts_with(&child_prefix))
        {
            if let Some(child) = immediate_mfs_child(&path, dir) {
                children.entry(child).or_insert(None);
            }
        }
        for (file_path, cid) in files
            .iter()
            .filter(|(file_path, _)| *file_path != &path && file_path.starts_with(&child_prefix))
        {
            if let Some(child) = immediate_mfs_child(&path, file_path) {
                children.entry(child).or_insert(Some(*cid));
            }
        }
        drop(files);
        drop(dirs);

        let mut links = Vec::new();
        for (child_path, child_cid) in children {
            let cid = match child_cid {
                Some(cid) => cid,
                None => Box::pin(self.materialize_mfs_dir(&child_path)).await?,
            };
            links.push(crate::cid::DagPbLink {
                name: mfs_basename(&child_path).to_string(),
                tsize: Some(self.object_stat(&cid).await?.cumulative_size),
                cid,
            });
        }
        let (cid, block) = unixfs_directory_block(&links);
        self.put_block(&cid, &block).await?;
        Ok(cid)
    }

    async fn dag_resolve_pb(&self, cid: &IpldCid, path: &str) -> Result<DagResolve> {
        let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let mut current = *cid;
        for (idx, segment) in segments.iter().enumerate() {
            if current.codec() != crate::cid::CODEC_DAG_PB {
                return Ok(DagResolve {
                    cid: current,
                    rem_path: segments[idx..].join("/"),
                });
            }
            let node = decode_dag_pb_node(&self.get_block(&current).await?)?;
            let link = if let Some(named) = node.links.iter().find(|link| link.name == *segment) {
                named
            } else {
                let index = segment
                    .parse::<usize>()
                    .map_err(|_| anyhow!("dag-pb path not found: {path}"))?;
                node.links
                    .get(index)
                    .ok_or_else(|| anyhow!("dag-pb path not found: {path}"))?
            };
            current = link.cid;
        }
        Ok(DagResolve {
            cid: current,
            rem_path: String::new(),
        })
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinKind {
    Direct,
    Recursive,
    Indirect,
}

impl PinKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Recursive => "recursive",
            Self::Indirect => "indirect",
        }
    }

    fn stored_from_str(value: &str) -> Option<Self> {
        match value.trim() {
            "direct" => Some(Self::Direct),
            "recursive" | "" => Some(Self::Recursive),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinLsEntry {
    pub cid: IpldCid,
    pub kind: PinKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MfsEntry {
    pub path: String,
    pub cid: Option<IpldCid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MfsKind {
    File,
    Directory,
}

impl MfsKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRm {
    pub cid: IpldCid,
    pub removed: bool,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectStat {
    pub cid: IpldCid,
    pub codec: u64,
    pub block_size: u64,
    pub cumulative_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectLink {
    pub name: String,
    pub cid: IpldCid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectGet {
    pub cid: IpldCid,
    pub data: Vec<u8>,
    pub links: Vec<ObjectLink>,
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
pub struct DagImport {
    pub roots: Vec<IpldCid>,
    pub blocks: Vec<IpldCid>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathResolve {
    pub cid: IpldCid,
    pub rem_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MfsStat {
    pub path: String,
    pub cid: Option<IpldCid>,
    pub kind: MfsKind,
    pub size: u64,
    pub cumulative_size: u64,
    pub blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameResolve {
    pub name: IpnsName,
    pub path: String,
    pub cid: IpldCid,
    pub record: IpnsRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    pub name: String,
    pub id: String,
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

#[derive(Debug, Default, Serialize, Deserialize)]
struct RepoStateManifest {
    #[serde(default)]
    files: BTreeMap<String, String>,
    #[serde(default)]
    dirs: Vec<String>,
    #[serde(default)]
    names: Vec<IpnsRecord>,
    #[serde(default)]
    keys: Vec<KeyEntry>,
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
                    let peer_id = peer_id;
                    tokio::spawn(async move {
                        if let Err(err) = serve_stream(peer_id, state, stream).await {
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

async fn serve_stream(peer_id: PeerId, state: Arc<State>, stream: TcpStream) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let mut parts = line.split_whitespace();
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("GET"), Some(protocol), Some(cid_s), None) if protocol == PROTOCOL => {
            let cid: IpldCid = cid_s.parse().map_err(|e| anyhow!("parse cid: {e}"))?;
            let bytes = match state.blocks.read().await.get(&cid).cloned() {
                Some(bytes) => Some(bytes),
                None => match load_block(&state, &cid).await? {
                    Some(bytes) => {
                        state.blocks.write().await.insert(cid, bytes.clone());
                        Some(bytes)
                    }
                    None => None,
                },
            };
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
        (Some("NAME"), Some(protocol), Some(name_s), None) if protocol == PROTOCOL => {
            let name = IpnsName::new(name_s.to_string());
            let record = state.names.read().await.get(&name).cloned();
            let stream = reader.get_mut();
            match record {
                Some(record) => {
                    let mut bytes = Vec::new();
                    ciborium::into_writer(&record, &mut bytes)
                        .map_err(|e| anyhow!("ipns record cbor encode: {e}"))?;
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
        (Some("PROVIDERS"), Some(protocol), Some(cid_s), None) if protocol == PROTOCOL => {
            let cid: IpldCid = cid_s.parse().map_err(|e| anyhow!("parse cid: {e}"))?;
            let providers = state.providers.read().await;
            let peers = providers.get(&cid).cloned().unwrap_or_default();
            drop(providers);
            let peer_addrs = state.peers.read().await;
            let listen_addrs = state.listen_addrs.read().await;
            let out: Vec<_> = peers
                .into_iter()
                .map(|peer| {
                    let addrs = if peer == peer_id {
                        listen_addrs
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                    } else {
                        peer_addrs
                            .get(&peer)
                            .map(|socket| {
                                vec![socket_to_multiaddr(*socket).with_peer(peer).to_string()]
                            })
                            .unwrap_or_default()
                    };
                    (peer.0, addrs)
                })
                .collect();
            let mut bytes = Vec::new();
            ciborium::into_writer(&out, &mut bytes)
                .map_err(|e| anyhow!("providers cbor encode: {e}"))?;
            let stream = reader.get_mut();
            state
                .bytes_out
                .fetch_add(8 + bytes.len() as u64, Ordering::Relaxed);
            stream
                .write_all(&(bytes.len() as u64).to_be_bytes())
                .await?;
            stream.write_all(&bytes).await?;
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

async fn fetch_name_from_socket(socket: SocketAddr, name: &IpnsName) -> Result<IpnsRecord> {
    let mut stream = TcpStream::connect(socket)
        .await
        .with_context(|| format!("connect {socket}"))?;
    stream
        .write_all(format!("NAME {PROTOCOL} {}\n", name.0).as_bytes())
        .await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf).await?;
    let len = u64::from_be_bytes(len_buf);
    if len == NOT_FOUND {
        bail!("IPNS name not found on peer: {}", name.0);
    }
    if len > usize::MAX as u64 {
        bail!("IPNS record too large: {len}");
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    ciborium::from_reader(&buf[..]).map_err(|e| anyhow!("ipns record cbor decode: {e}"))
}

async fn fetch_providers_from_socket(socket: SocketAddr, cid: &IpldCid) -> Result<Vec<Provider>> {
    let mut stream = TcpStream::connect(socket)
        .await
        .with_context(|| format!("connect {socket}"))?;
    stream
        .write_all(format!("PROVIDERS {PROTOCOL} {cid}\n").as_bytes())
        .await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf).await?;
    let len = u64::from_be_bytes(len_buf);
    if len > usize::MAX as u64 {
        bail!("provider response too large: {len}");
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    let rows: Vec<(u64, Vec<String>)> =
        ciborium::from_reader(&buf[..]).map_err(|e| anyhow!("providers cbor decode: {e}"))?;
    rows.into_iter()
        .map(|(peer, addrs)| {
            let addrs = addrs
                .into_iter()
                .map(|addr| addr.parse::<Multiaddr>())
                .collect::<Result<Vec<_>>>()?;
            Ok(Provider {
                peer: PeerId(peer),
                addrs,
            })
        })
        .collect()
}

fn cbor_len<T: Serialize>(value: &T) -> Result<u64> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|e| anyhow!("cbor encode: {e}"))?;
    Ok(bytes.len() as u64)
}

fn provider_wire_rows(providers: &[Provider]) -> Vec<(u64, Vec<String>)> {
    providers
        .iter()
        .map(|provider| {
            (
                provider.peer.0,
                provider.addrs.iter().map(ToString::to_string).collect(),
            )
        })
        .collect()
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

fn immediate_mfs_child(prefix: &str, path: &str) -> Option<String> {
    if path == prefix {
        return Some(path.to_string());
    }
    let rest = if prefix == "/" {
        path.strip_prefix('/')?
    } else {
        path.strip_prefix(&format!("{prefix}/"))?
    };
    let name = rest.split('/').next().filter(|name| !name.is_empty())?;
    Some(if prefix == "/" {
        format!("/{name}")
    } else {
        format!("{prefix}/{name}")
    })
}

fn mfs_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_ipld_path(path: &str) -> bool {
    path.starts_with("/ipfs/") || path.starts_with("/ipns/")
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

fn dag_pb_node_to_ipld(node: crate::cid::DagPbNode) -> Result<Ipld> {
    let mut map = BTreeMap::new();
    map.insert(
        "Data".to_string(),
        Ipld::Bytes(node.data.unwrap_or_default()),
    );
    map.insert(
        "Links".to_string(),
        Ipld::List(
            node.links
                .into_iter()
                .map(|link| {
                    let mut link_map = BTreeMap::new();
                    link_map.insert("Hash".to_string(), Ipld::Link(link.cid));
                    link_map.insert("Name".to_string(), Ipld::String(link.name));
                    if let Some(tsize) = link.tsize {
                        link_map.insert("Tsize".to_string(), Ipld::Integer(i128::from(tsize)));
                    }
                    Ipld::Map(link_map)
                })
                .collect(),
        ),
    );
    Ok(Ipld::Map(map))
}

fn write_car_header(out: &mut Vec<u8>, roots: &[IpldCid]) -> Result<()> {
    let root_values = roots
        .iter()
        .map(|cid| {
            let mut bytes = vec![0];
            bytes.extend(cid.to_bytes());
            CborValue::Tag(42, Box::new(CborValue::Bytes(bytes)))
        })
        .collect();
    let header = CborValue::Map(vec![
        (
            CborValue::Text("roots".to_string()),
            CborValue::Array(root_values),
        ),
        (
            CborValue::Text("version".to_string()),
            CborValue::Integer(1.into()),
        ),
    ]);
    let mut data = Vec::new();
    ciborium::into_writer(&header, &mut data).map_err(|e| anyhow!("CAR header encode: {e}"))?;
    write_uvarint(out, data.len() as u64);
    out.extend(data);
    Ok(())
}

fn read_car_header(data: &[u8]) -> Result<Vec<IpldCid>> {
    let value: CborValue =
        ciborium::from_reader(data).map_err(|e| anyhow!("CAR header decode: {e}"))?;
    let CborValue::Map(entries) = value else {
        bail!("CAR header must be a map");
    };
    let mut version = None;
    let mut roots = None;
    for (key, value) in entries {
        let CborValue::Text(key) = key else {
            bail!("CAR header key must be text");
        };
        match key.as_str() {
            "version" => version = Some(value),
            "roots" => roots = Some(value),
            _ => {}
        }
    }
    if version != Some(CborValue::Integer(1.into())) {
        bail!("unsupported CAR version");
    }
    let Some(CborValue::Array(root_values)) = roots else {
        bail!("CAR header missing roots");
    };
    root_values.into_iter().map(car_cid_link).collect()
}

fn car_cid_link(value: CborValue) -> Result<IpldCid> {
    let CborValue::Tag(42, value) = value else {
        bail!("CAR root must be a CID link");
    };
    let CborValue::Bytes(bytes) = *value else {
        bail!("CAR CID link must contain bytes");
    };
    let raw = bytes.strip_prefix(&[0]).unwrap_or(bytes.as_slice());
    IpldCid::read_bytes(raw).map_err(|e| anyhow!("CAR CID link decode: {e}"))
}

fn write_car_block(out: &mut Vec<u8>, cid: &IpldCid, data: &[u8]) -> Result<()> {
    let cid_bytes = cid.to_bytes();
    write_uvarint(out, (cid_bytes.len() + data.len()) as u64);
    out.extend(cid_bytes);
    out.extend(data);
    Ok(())
}

fn read_car_cid(section: &[u8]) -> Result<(IpldCid, usize)> {
    for len in 1..=section.len() {
        if let Ok(cid) = IpldCid::read_bytes(&section[..len]) {
            return Ok((cid, len));
        }
    }
    bail!("CAR block section does not start with a CID")
}

fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_uvarint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = *data.get(*pos).ok_or_else(|| anyhow!("truncated uvarint"))?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            bail!("uvarint overflow");
        }
    }
}

fn rebase_mfs_path(path: &str, source: &str, dest: &str) -> String {
    if path == source {
        return dest.to_string();
    }
    if source == "/" {
        return format!(
            "{}/{}",
            dest.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
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
            let kind = match tokio::fs::read_to_string(entry.path()).await {
                Ok(value) => PinKind::stored_from_str(&value).unwrap_or(PinKind::Recursive),
                Err(_) => PinKind::Recursive,
            };
            state.pins.write().await.insert(cid, kind);
        }
    }

    load_repo_state(state, repo).await?;

    Ok(())
}

async fn load_repo_state(state: &Arc<State>, repo: &Path) -> Result<()> {
    let path = repo_state_path(repo);
    let data = match tokio::fs::read(&path).await {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("read repo state {path:?}")),
    };
    let manifest: RepoStateManifest =
        serde_json::from_slice(&data).with_context(|| format!("decode repo state {path:?}"))?;

    {
        let mut files = state.files.write().await;
        files.clear();
        for (mfs_path, cid) in manifest.files {
            let cid = cid
                .parse::<IpldCid>()
                .map_err(|err| anyhow!("invalid MFS CID for {mfs_path}: {err}"))?;
            files.insert(mfs_path, cid);
        }
    }
    {
        let mut dirs = state.dirs.write().await;
        dirs.clear();
        dirs.extend(manifest.dirs);
    }
    {
        let mut names = state.names.write().await;
        names.clear();
        for record in manifest.names {
            record
                .value
                .parse::<IpldCid>()
                .map_err(|err| anyhow!("invalid IPNS record CID for {}: {err}", record.name.0))?;
            names.insert(record.name.clone(), record);
        }
    }
    {
        let mut keys = state.keys.write().await;
        keys.clear();
        for key in manifest.keys {
            let name = validate_key_name(key.name.clone())?;
            if key.id.trim().is_empty() {
                bail!("invalid key id for {name}: empty");
            }
            keys.insert(name, key);
        }
    }
    Ok(())
}

async fn persist_repo_state(state: &State) -> Result<()> {
    let Some(repo) = &state.repo_path else {
        return Ok(());
    };
    let files = state
        .files
        .read()
        .await
        .iter()
        .map(|(path, cid)| (path.clone(), cid.to_string()))
        .collect();
    let mut dirs: Vec<_> = state.dirs.read().await.iter().cloned().collect();
    dirs.sort();
    let mut names: Vec<_> = state.names.read().await.values().cloned().collect();
    names.sort_by(|a, b| a.name.0.cmp(&b.name.0));
    let mut keys: Vec<_> = state.keys.read().await.values().cloned().collect();
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    let manifest = RepoStateManifest {
        files,
        dirs,
        names,
        keys,
    };
    let path = repo_state_path(repo);
    let data = serde_json::to_vec_pretty(&manifest)?;
    tokio::fs::write(&path, data)
        .await
        .with_context(|| format!("write repo state {path:?}"))?;
    Ok(())
}

fn validate_key_name(name: String) -> Result<String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        bail!("key name must not be empty");
    }
    if name == "self" {
        bail!("key name is reserved: self");
    }
    Ok(name)
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

async fn persist_pin(state: &State, cid: &IpldCid, kind: PinKind) -> Result<()> {
    let Some(repo) = &state.repo_path else {
        return Ok(());
    };
    let path = pins_dir(repo).join(cid.to_string());
    tokio::fs::write(&path, format!("{}\n", kind.as_str()))
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

fn repo_state_path(repo: &Path) -> PathBuf {
    repo.join("repo-state.json")
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
