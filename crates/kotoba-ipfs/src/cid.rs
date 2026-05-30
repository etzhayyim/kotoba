//! IPFS-native CID helpers for kotoba-ipfs.
//!
//! This crate deliberately uses the same CID shape expected by public IPFS
//! tooling: CIDv1 plus a multicodec and sha2-256 multihash.  The codec is
//! caller-selected because raw bytes, dag-cbor, and dag-pb are all valid IPFS
//! blocks.

use ipld_core::cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use serde::Serialize;

pub const CODEC_RAW: u64 = 0x55;
pub const CODEC_DAG_PB: u64 = 0x70;
pub const CODEC_DAG_CBOR: u64 = 0x71;
pub const MH_SHA2_256: u64 = 0x12;

#[derive(Debug, thiserror::Error)]
pub enum CidError {
    #[error("cid parse: {0}")]
    Parse(String),
    #[error("dag-cbor encode: {0}")]
    Cbor(String),
    #[error("unixfs dag-pb decode: {0}")]
    Unixfs(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagPbLink {
    pub name: String,
    pub cid: Cid,
    pub tsize: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagPbNode {
    pub data: Option<Vec<u8>>,
    pub links: Vec<DagPbLink>,
}

/// Build a CIDv1 for an already-encoded IPFS block.
pub fn cid_for_bytes(codec: u64, data: &[u8]) -> Cid {
    Cid::new_v1(codec, Code::Sha2_256.digest(data))
}

/// Build a CIDv1/raw/sha2-256 CID for arbitrary bytes.
pub fn raw_cid(data: &[u8]) -> Cid {
    cid_for_bytes(CODEC_RAW, data)
}

/// Encode a value as dag-cbor and return the matching CIDv1/dag-cbor/sha2-256
/// CID together with the encoded block bytes.
pub fn dag_cbor_block<T: Serialize>(value: &T) -> Result<(Cid, Vec<u8>), CidError> {
    let mut data = Vec::new();
    ciborium::into_writer(value, &mut data).map_err(|e| CidError::Cbor(e.to_string()))?;
    Ok((cid_for_bytes(CODEC_DAG_CBOR, &data), data))
}

/// Encode a Kubo-compatible single-file UnixFS dag-pb block.
///
/// This is the dag-pb shape Kubo emits for a small file when raw leaves are
/// disabled: PBNode.Data contains a UnixFS Data message with Type=File, Data,
/// and filesize.  It intentionally has no links, so it covers the common
/// single-block file case without pulling in a full UnixFS importer.
pub fn unixfs_file_block(data: &[u8]) -> (Cid, Vec<u8>) {
    let mut unixfs = Vec::new();
    write_varint_field(&mut unixfs, 1, 2);
    write_bytes_field(&mut unixfs, 2, data);
    write_varint_field(&mut unixfs, 3, data.len() as u64);

    let mut pb_node = Vec::new();
    write_bytes_field(&mut pb_node, 1, &unixfs);
    (cid_for_bytes(CODEC_DAG_PB, &pb_node), pb_node)
}

/// Encode a Kubo-compatible chunked UnixFS file DAG using CIDv1/raw leaves.
///
/// Returns the dag-pb root block first, followed by `(cid, block)` pairs for
/// every raw leaf.  This mirrors Kubo's common `ipfs add --raw-leaves
/// --cid-version=1 --chunker=size-N` shape closely enough for public IPFS
/// tooling to traverse and `cat` the produced DAG.
pub fn unixfs_chunked_file_blocks(
    data: &[u8],
    chunk_size: usize,
) -> Result<(Cid, Vec<u8>, Vec<(Cid, Vec<u8>)>), CidError> {
    if chunk_size == 0 {
        return Err(CidError::Unixfs(
            "chunk size must be greater than zero".into(),
        ));
    }
    let leaves: Vec<(Cid, Vec<u8>)> = data
        .chunks(chunk_size)
        .map(|chunk| (raw_cid(chunk), chunk.to_vec()))
        .collect();

    let mut unixfs = Vec::new();
    write_varint_field(&mut unixfs, 1, 2);
    write_varint_field(&mut unixfs, 3, data.len() as u64);
    for (_, block) in &leaves {
        write_varint_field(&mut unixfs, 4, block.len() as u64);
    }

    let mut pb_node = Vec::new();
    write_bytes_field(&mut pb_node, 1, &unixfs);
    for (cid, block) in &leaves {
        let mut link = Vec::new();
        write_bytes_field(&mut link, 1, &cid.to_bytes());
        write_varint_field(&mut link, 3, block.len() as u64);
        write_bytes_field(&mut pb_node, 2, &link);
    }

    Ok((cid_for_bytes(CODEC_DAG_PB, &pb_node), pb_node, leaves))
}

/// Encode a generic dag-pb object block.
///
/// This is the block shape behind Kubo's `object/put`: optional PBNode.Data
/// bytes plus zero or more PBLink entries.  The returned CID is
/// CIDv1/dag-pb/sha2-256.
pub fn dag_pb_object_block(data: &[u8], links: &[DagPbLink]) -> (Cid, Vec<u8>) {
    let mut pb_node = Vec::new();
    if !data.is_empty() {
        write_bytes_field(&mut pb_node, 1, data);
    }
    for link in links {
        let mut pb_link = Vec::new();
        write_bytes_field(&mut pb_link, 1, &link.cid.to_bytes());
        if !link.name.is_empty() {
            write_bytes_field(&mut pb_link, 2, link.name.as_bytes());
        }
        if let Some(tsize) = link.tsize {
            write_varint_field(&mut pb_link, 3, tsize);
        }
        write_bytes_field(&mut pb_node, 2, &pb_link);
    }
    (cid_for_bytes(CODEC_DAG_PB, &pb_node), pb_node)
}

/// Encode a Kubo-compatible UnixFS directory dag-pb block.
///
/// PBNode.Data contains a UnixFS Data message with Type=Directory and PBNode
/// links contain the direct children.  This is the common MFS directory root
/// shape exposed by Kubo `files/stat` and `files/ls`.
pub fn unixfs_directory_block(links: &[DagPbLink]) -> (Cid, Vec<u8>) {
    let mut unixfs = Vec::new();
    write_varint_field(&mut unixfs, 1, 1);

    let mut pb_node = Vec::new();
    write_bytes_field(&mut pb_node, 1, &unixfs);
    for link in links {
        let mut pb_link = Vec::new();
        write_bytes_field(&mut pb_link, 1, &link.cid.to_bytes());
        if !link.name.is_empty() {
            write_bytes_field(&mut pb_link, 2, link.name.as_bytes());
        }
        if let Some(tsize) = link.tsize {
            write_varint_field(&mut pb_link, 3, tsize);
        }
        write_bytes_field(&mut pb_node, 2, &pb_link);
    }
    (cid_for_bytes(CODEC_DAG_PB, &pb_node), pb_node)
}

/// Decode the single-file UnixFS dag-pb block shape produced by
/// [`unixfs_file_block`].
pub fn decode_unixfs_file_block(block: &[u8]) -> Result<Vec<u8>, CidError> {
    let node = decode_dag_pb_node(block)?;
    decode_unixfs_file_data(node.data.as_deref().unwrap_or_default())
}

pub fn decode_dag_pb_node(block: &[u8]) -> Result<DagPbNode, CidError> {
    let mut pos = 0;
    let mut unixfs_data = None;
    let mut links = Vec::new();
    while pos < block.len() {
        let (field, wire) = read_key(block, &mut pos)?;
        match (field, wire) {
            (1, 2) => unixfs_data = Some(read_len_bytes(block, &mut pos)?.to_vec()),
            (2, 2) => links.push(decode_dag_pb_link(read_len_bytes(block, &mut pos)?)?),
            (_, 0) => {
                read_varint(block, &mut pos)?;
            }
            (_, 2) => {
                read_len_bytes(block, &mut pos)?;
            }
            _ => {
                return Err(CidError::Unixfs(format!(
                    "unsupported PBNode field {field}/{wire}"
                )))
            }
        }
    }
    Ok(DagPbNode {
        data: unixfs_data,
        links,
    })
}

pub fn decode_unixfs_file_data(unixfs: &[u8]) -> Result<Vec<u8>, CidError> {
    if unixfs.is_empty() {
        return Ok(Vec::new());
    }

    let mut pos = 0;
    let mut typ = None;
    let mut file_data = None;
    let mut filesize = None;
    while pos < unixfs.len() {
        let (field, wire) = read_key(&unixfs, &mut pos)?;
        match (field, wire) {
            (1, 0) => typ = Some(read_varint(&unixfs, &mut pos)?),
            (2, 2) => file_data = Some(read_len_bytes(&unixfs, &mut pos)?.to_vec()),
            (3, 0) => filesize = Some(read_varint(&unixfs, &mut pos)?),
            (_, 0) => {
                read_varint(&unixfs, &mut pos)?;
            }
            (_, 2) => {
                read_len_bytes(&unixfs, &mut pos)?;
            }
            _ => {
                return Err(CidError::Unixfs(format!(
                    "unsupported UnixFS field {field}/{wire}"
                )))
            }
        }
    }
    if typ != Some(2) {
        return Err(CidError::Unixfs("UnixFS block is not a file".into()));
    }
    let data_len = file_data.as_ref().map(Vec::len);
    let file_data = file_data.unwrap_or_default();
    if data_len.is_some() && filesize.is_some_and(|size| size != file_data.len() as u64) {
        return Err(CidError::Unixfs("UnixFS filesize mismatch".into()));
    }
    Ok(file_data)
}

fn decode_dag_pb_link(input: &[u8]) -> Result<DagPbLink, CidError> {
    let mut pos = 0;
    let mut cid = None;
    let mut name = String::new();
    let mut tsize = None;
    while pos < input.len() {
        let (field, wire) = read_key(input, &mut pos)?;
        match (field, wire) {
            (1, 2) => {
                let bytes = read_len_bytes(input, &mut pos)?;
                cid = Some(
                    Cid::read_bytes(bytes)
                        .map_err(|e| CidError::Unixfs(format!("PBLink CID decode: {e}")))?,
                );
            }
            (2, 2) => {
                name = String::from_utf8(read_len_bytes(input, &mut pos)?.to_vec())
                    .map_err(|e| CidError::Unixfs(format!("PBLink name utf8: {e}")))?;
            }
            (3, 0) => tsize = Some(read_varint(input, &mut pos)?),
            (_, 0) => {
                read_varint(input, &mut pos)?;
            }
            (_, 2) => {
                read_len_bytes(input, &mut pos)?;
            }
            _ => {
                return Err(CidError::Unixfs(format!(
                    "unsupported PBLink field {field}/{wire}"
                )))
            }
        }
    }
    let cid = cid.ok_or_else(|| CidError::Unixfs("missing PBLink.Hash".into()))?;
    Ok(DagPbLink { name, cid, tsize })
}

/// Parse any valid IPFS CID string accepted by the upstream CID crate.
pub fn parse_cid(s: &str) -> Result<Cid, CidError> {
    s.parse::<Cid>().map_err(|e| CidError::Parse(e.to_string()))
}

pub fn is_sha2_256(cid: &Cid) -> bool {
    cid.hash().code() == MH_SHA2_256 && cid.hash().size() == 32
}

fn write_key(out: &mut Vec<u8>, field: u64, wire: u64) {
    write_varint(out, (field << 3) | wire);
}

fn write_varint_field(out: &mut Vec<u8>, field: u64, value: u64) {
    write_key(out, field, 0);
    write_varint(out, value);
}

fn write_bytes_field(out: &mut Vec<u8>, field: u64, value: &[u8]) {
    write_key(out, field, 2);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn read_key(input: &[u8], pos: &mut usize) -> Result<(u64, u64), CidError> {
    let key = read_varint(input, pos)?;
    Ok((key >> 3, key & 0x07))
}

fn read_varint(input: &[u8], pos: &mut usize) -> Result<u64, CidError> {
    let mut out = 0u64;
    let mut shift = 0;
    loop {
        let Some(byte) = input.get(*pos).copied() else {
            return Err(CidError::Unixfs("truncated varint".into()));
        };
        *pos += 1;
        out |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(out);
        }
        shift += 7;
        if shift >= 64 {
            return Err(CidError::Unixfs("varint overflow".into()));
        }
    }
}

fn read_len_bytes<'a>(input: &'a [u8], pos: &mut usize) -> Result<&'a [u8], CidError> {
    let len = read_varint(input, pos)? as usize;
    let end = pos.saturating_add(len);
    let Some(bytes) = input.get(*pos..end) else {
        return Err(CidError::Unixfs(
            "length-delimited field exceeds input".into(),
        ));
    };
    *pos = end;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipld_core::cid::Version;

    #[test]
    fn raw_cid_is_ipfs_sha2_256() {
        let cid = raw_cid(b"hello kotoba");
        assert_eq!(cid.version(), Version::V1);
        assert_eq!(cid.codec(), CODEC_RAW);
        assert!(is_sha2_256(&cid));
        assert!(cid.to_string().starts_with("bafkrei"));
    }

    #[test]
    fn raw_cid_matches_kubo_cid_v1_raw_sha2_256_vector() {
        let cid = raw_cid(b"hello");
        assert_eq!(
            cid.to_string(),
            "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq"
        );
        assert_eq!(parse_cid(&cid.to_string()).unwrap(), cid);
    }

    #[test]
    fn unixfs_file_block_matches_kubo_single_file_dag_pb_vector() {
        let (cid, block) = unixfs_file_block(b"hello");
        assert_eq!(cid.codec(), CODEC_DAG_PB);
        assert_eq!(
            cid.to_string(),
            "bafybeid3weurg3gvyoi7nisadzolomlvoxoppe2sesktnpvdve3256n5tq"
        );
        assert_eq!(decode_unixfs_file_block(&block).unwrap(), b"hello");
        assert_eq!(cid, cid_for_bytes(CODEC_DAG_PB, &block));
    }

    #[test]
    fn unixfs_chunked_file_blocks_use_raw_leaves_and_dag_pb_root() {
        let data = b"abcdefghijklmnopqrstuvwxyz";
        let (root, root_block, leaves) = unixfs_chunked_file_blocks(data, 5).unwrap();
        assert_eq!(root.codec(), CODEC_DAG_PB);
        assert_eq!(root, cid_for_bytes(CODEC_DAG_PB, &root_block));
        assert_eq!(leaves.len(), 6);
        assert!(leaves
            .iter()
            .all(|(cid, block)| { cid.codec() == CODEC_RAW && *cid == raw_cid(block) }));

        let root_node = decode_dag_pb_node(&root_block).unwrap();
        assert_eq!(root_node.links.len(), leaves.len());
        assert_eq!(
            root_node
                .links
                .iter()
                .map(|link| link.cid)
                .collect::<Vec<_>>(),
            leaves.iter().map(|(cid, _)| *cid).collect::<Vec<_>>()
        );
    }

    #[test]
    fn dag_pb_object_block_encodes_data_and_links() {
        let child = raw_cid(b"child");
        let links = vec![DagPbLink {
            name: "child.txt".into(),
            cid: child,
            tsize: Some(5),
        }];
        let (cid, block) = dag_pb_object_block(b"metadata", &links);
        assert_eq!(cid.codec(), CODEC_DAG_PB);
        assert_eq!(cid, cid_for_bytes(CODEC_DAG_PB, &block));
        let decoded = decode_dag_pb_node(&block).unwrap();
        assert_eq!(decoded.data.as_deref(), Some(b"metadata".as_slice()));
        assert_eq!(decoded.links, links);
    }

    #[test]
    fn cid_for_bytes_is_codec_sensitive() {
        let data = b"same bytes";
        let raw = cid_for_bytes(CODEC_RAW, data);
        let dag_cbor = cid_for_bytes(CODEC_DAG_CBOR, data);
        assert_ne!(raw, dag_cbor);
        assert_eq!(raw.hash(), dag_cbor.hash());
    }

    #[test]
    fn dag_cbor_block_matches_encoded_bytes() {
        let value = ("kotoba", 42u64);
        let (cid, data) = dag_cbor_block(&value).unwrap();
        assert_eq!(cid, cid_for_bytes(CODEC_DAG_CBOR, &data));
        assert_eq!(cid.codec(), CODEC_DAG_CBOR);
        assert!(is_sha2_256(&cid));
    }

    #[test]
    fn parse_roundtrip() {
        let cid = raw_cid(b"roundtrip");
        let parsed = parse_cid(&cid.to_string()).unwrap();
        assert_eq!(parsed, cid);
    }
}
