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

/// Parse any valid IPFS CID string accepted by the upstream CID crate.
pub fn parse_cid(s: &str) -> Result<Cid, CidError> {
    s.parse::<Cid>().map_err(|e| CidError::Parse(e.to_string()))
}

pub fn is_sha2_256(cid: &Cid) -> bool {
    cid.hash().code() == MH_SHA2_256 && cid.hash().size() == 32
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
