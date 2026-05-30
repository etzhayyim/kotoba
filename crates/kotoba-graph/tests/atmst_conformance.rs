//! AT MST conformance — integration target (compiles against the public API only,
//! independent of in-crate unit tests). A2 increment, ADR-2605302300.

use kotoba_graph::atmst::{common_prefix_len, is_valid_repo_path, key_depth, MstNode, TreeEntry};
use kotoba_core::cid::KotobaCid;

/// The four worked depth examples published in the AT Protocol repository spec
/// (atproto.com/specs/repository). This is the conformance anchor for the MST
/// layering primitive.
#[test]
fn key_depth_matches_atproto_spec_vectors() {
    assert_eq!(key_depth("2653ae71"), 0);
    assert_eq!(key_depth("blue"), 1);
    assert_eq!(key_depth("app.bsky.feed.post/454397e440ec"), 4);
    assert_eq!(key_depth("app.bsky.feed.post/9adeb165882c"), 8);
}

#[test]
fn common_prefix_len_basics() {
    assert_eq!(
        common_prefix_len("app.bsky.feed.post/a", "app.bsky.feed.post/b"),
        19
    );
    assert_eq!(common_prefix_len("abc", "abc"), 3);
    assert_eq!(common_prefix_len("abc", "xyz"), 0);
}

#[test]
fn repo_path_validation() {
    assert!(is_valid_repo_path("app.bsky.feed.post/3jqfcqzm3fo2j"));
    assert!(is_valid_repo_path("com.example.record/tilde~ok-_"));
    assert!(!is_valid_repo_path("nocollection"));
    assert!(!is_valid_repo_path("a/b/c"));
    assert!(!is_valid_repo_path("/rkey"));
    assert!(!is_valid_repo_path("coll/"));
    assert!(!is_valid_repo_path("coll/has space"));
    assert!(!is_valid_repo_path(""));
}

#[test]
fn empty_node_cid_is_cidv1_dag_cbor_sha2_256_and_stable() {
    let cid = MstNode::empty().cid().expect("empty node serializes");
    assert_eq!(cid.0[0], KotobaCid::CIDV1);
    assert_eq!(cid.0[1], KotobaCid::CODEC_DAG_CBOR);
    assert_eq!(cid.0[2], KotobaCid::MH_SHA2_256);
    assert_eq!(cid.0[3], KotobaCid::DIGEST_LEN_SHA2_256);
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
