//! Public-IPFS-interoperable substrate for kotoba.
//!
//! Provides a lightweight self-owned block store and TCP block exchange behind
//! an IPFS-native CID surface.  CIDs are [`ipld_core::cid::Cid`] values, so
//! sha2-256/raw, sha2-256/dag-cbor, dag-pb, and other normal IPFS block shapes
//! remain addressable without re-keying.

mod cid;
mod ipns;
mod node;

pub use cid::{
    cid_for_bytes, dag_cbor_block, dag_pb_object_block, decode_dag_pb_node,
    decode_unixfs_file_block, decode_unixfs_file_data, is_sha2_256, parse_cid, raw_cid,
    unixfs_chunked_file_blocks, unixfs_file_block, CidError, DagPbLink, DagPbNode, CODEC_DAG_CBOR,
    CODEC_DAG_PB, CODEC_RAW, MH_SHA2_256,
};
pub use ipld_core::cid::Cid as IpldCid;
pub use ipns::{
    InMemoryIpnsRegistry, IpnsName, IpnsRecord, IpnsRegistry, IpnsRegistryError, KuboIpnsRegistry,
    SignedIpnsRegistry,
};
pub use node::{
    BandwidthStats, BitswapStats, BlockPut, BlockStat, DagImport, DagResolve, DagStat, IpfsConfig,
    KotobaIpfsNode, MfsEntry, MfsKind, MfsStat, Multiaddr, NameResolve, NodeId, NodeVersion,
    ObjectGet, ObjectLink, ObjectStat, PathResolve, PeerId, PinKind, PinLsEntry, PinVerify,
    Provider, RepoStat, RepoVerify, RepoVerifyError, SwarmConnect, SwarmPeer,
};
