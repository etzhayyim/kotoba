//! AT Protocol Merkle Search Tree (MST) primitives — A2 increment (ADR-2605302300).
//!
//! kotoba origin-PDS path: to emit a faithful `com.atproto.sync.subscribeRepos`
//! kotoba must build an AT-spec MST over its records and reference its root from a
//! signed commit. This module is the **verifiable foundation** of that path.
//!
//! ## In THIS increment (conformance-tested)
//! * [`key_depth`] — the MST layering rule: SHA-256 the key, count leading binary
//!   zeros, divide by two (floor); fanout 4. Tested against the four worked
//!   examples published in the AT Protocol repository spec
//!   (<https://atproto.com/specs/repository>).
//! * [`is_valid_repo_path`] — `<collection>/<rkey>` structure + AT key charset.
//! * [`common_prefix_len`] — shared-prefix compression used by `TreeEntry.p`.
//! * [`MstNode`] / [`TreeEntry`] — the AT node CBOR shape (`l`/`e`/`p`/`k`/`v`/`t`).
//!
//! ## NOT in this increment (gated — ADR-2605302300)
//! Full multi-entry tree assembly, **canonical-CBOR node-CID byte-equality with
//! `@atproto/repo`**, Ed25519-signed commits, and CAR `subscribeRepos` egress are
//! deferred until the atproto-interop-tests vectors are wired in and etzhayyim DID
//! issuance is available. [`MstNode::cid`] produces a structurally correct CIDv1
//! dag-cbor sha2-256 CID, but its byte-for-byte equality with the reference impl is
//! **UNVERIFIED** — do not rely on it for federation yet.

use kotoba_core::cid::KotobaCid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// MST fanout step: leading hash zeros are counted in 2-bit chunks (fanout 4).
pub const FANOUT_BITS: u32 = 2;

/// Compute an MST key's depth/layer per the AT Protocol repository spec:
///
/// > hash the key (a byte array) with SHA-256, with binary output count the number
/// > of leading binary zeros in the hash, and divide by two, rounding down.
///
/// Higher depth → closer to the root (rarer). Most keys are depth 0.
pub fn key_depth(key: &str) -> u32 {
    let hash = Sha256::digest(key.as_bytes());
    let mut zeros = 0u32;
    for &byte in hash.iter() {
        let lz = byte.leading_zeros(); // u8 → 0..=8
        zeros += lz;
        if lz != 8 {
            break; // first non-zero byte ends the leading-zero run
        }
    }
    zeros / FANOUT_BITS
}

/// Length of the shared leading byte prefix of two keys (AT `TreeEntry.p`).
pub fn common_prefix_len(a: &str, b: &str) -> usize {
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .take_while(|(x, y)| x == y)
        .count()
}

/// Validate a repository record path: `<collection>/<rkey>` using the AT key
/// charset (`A-Za-z0-9` plus `/ . - _ ~`), exactly one slash, non-empty segments.
pub fn is_valid_repo_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 256 {
        return false;
    }
    let charset_ok = path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'-' | b'_' | b'~'));
    if !charset_ok {
        return false;
    }
    let mut parts = path.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        // exactly two non-empty segments, no third
        (Some(coll), Some(rkey), None) => !coll.is_empty() && !rkey.is_empty(),
        _ => false,
    }
}

/// One entry in an MST node (AT field names: `p`/`k`/`v`/`t`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TreeEntry {
    /// `p` — count of bytes shared with the previous entry's key (prefix elision).
    pub p: u32,
    /// `k` — key suffix after the shared prefix. (Canonical AT encoding is a CBOR
    /// byte string; conformance encoding is deferred — see module docs.)
    pub k: Vec<u8>,
    /// `v` — CID link to the record value.
    pub v: KotobaCid,
    /// `t` — CID link to the right subtree (keys between this and the next entry).
    pub t: Option<KotobaCid>,
}

/// An MST node (AT field names: `l`/`e`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MstNode {
    /// `l` — left subtree (keys sorting before the first entry).
    pub l: Option<KotobaCid>,
    /// `e` — ordered entries.
    pub e: Vec<TreeEntry>,
}

impl MstNode {
    /// Empty node — `{ l: null, e: [] }`.
    pub fn empty() -> Self {
        MstNode { l: None, e: Vec::new() }
    }

    /// Structurally-correct CIDv1 dag-cbor sha2-256 CID of this node.
    ///
    /// NOTE: byte-equality with `@atproto/repo` (canonical-CBOR key ordering, CID
    /// tag-42 link encoding) is UNVERIFIED pending atproto-interop-tests — see the
    /// module docs. Stable/deterministic for a given node value.
    pub fn cid(&self) -> Result<KotobaCid, String> {
        KotobaCid::from_cbor(self).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four worked depth examples from atproto.com/specs/repository.
    #[test]
    fn key_depth_matches_atproto_spec_vectors() {
        assert_eq!(key_depth("2653ae71"), 0, "spec vector 2653ae71 → depth 0");
        assert_eq!(key_depth("blue"), 1, "spec vector blue → depth 1");
        assert_eq!(
            key_depth("app.bsky.feed.post/454397e440ec"),
            4,
            "spec vector .../454397e440ec → depth 4"
        );
        assert_eq!(
            key_depth("app.bsky.feed.post/9adeb165882c"),
            8,
            "spec vector .../9adeb165882c → depth 8"
        );
    }

    #[test]
    fn key_depth_is_deterministic() {
        assert_eq!(key_depth("app.bsky.feed.post/abc"), key_depth("app.bsky.feed.post/abc"));
    }

    #[test]
    fn common_prefix_len_basics() {
        assert_eq!(common_prefix_len("app.bsky.feed.post/a", "app.bsky.feed.post/b"), 19);
        assert_eq!(common_prefix_len("abc", "abc"), 3);
        assert_eq!(common_prefix_len("abc", "xyz"), 0);
        assert_eq!(common_prefix_len("", "anything"), 0);
    }

    #[test]
    fn repo_path_validation() {
        assert!(is_valid_repo_path("app.bsky.feed.post/3jqfcqzm3fo2j"));
        assert!(is_valid_repo_path("com.example.record/tilde~ok-_"));
        assert!(!is_valid_repo_path("nocollection"), "needs a slash");
        assert!(!is_valid_repo_path("a/b/c"), "exactly one slash");
        assert!(!is_valid_repo_path("/rkey"), "empty collection");
        assert!(!is_valid_repo_path("coll/"), "empty rkey");
        assert!(!is_valid_repo_path("coll/has space"), "space not in charset");
        assert!(!is_valid_repo_path(""), "empty");
    }

    #[test]
    fn empty_node_cid_is_cidv1_dag_cbor_sha2_256_and_stable() {
        let cid = MstNode::empty().cid().expect("empty node serializes");
        // CIDv1 dag-cbor sha2-256 header (0x01 0x71 0x12 0x20).
        assert_eq!(cid.0[0], KotobaCid::CIDV1);
        assert_eq!(cid.0[1], KotobaCid::CODEC_DAG_CBOR);
        assert_eq!(cid.0[2], KotobaCid::MH_SHA2_256);
        assert_eq!(cid.0[3], KotobaCid::DIGEST_LEN_SHA2_256);
        // Deterministic.
        assert_eq!(cid, MstNode::empty().cid().unwrap());
    }

    #[test]
    fn distinct_nodes_have_distinct_cids() {
        let empty = MstNode::empty().cid().unwrap();
        let one = MstNode {
            l: None,
            e: vec![TreeEntry {
                p: 0,
                k: b"app.bsky.feed.post/abc".to_vec(),
                v: KotobaCid::from_bytes(b"record-value"),
                t: None,
            }],
        }
        .cid()
        .unwrap();
        assert_ne!(empty, one);
    }
}
