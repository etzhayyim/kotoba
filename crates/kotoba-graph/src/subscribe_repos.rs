//! `com.atproto.sync.subscribeRepos` firehose client.
//!
//! Cursor persistence:
//!   The last processed `seq` is checkpointed every `CURSOR_PERSIST_INTERVAL` commits
//!   into the BlockStore under a fixed synthetic CID (`CURSOR_SLOT_CID`).
//!   On startup, if `KOTOBA_SUBSCRIBE_REPOS_CURSOR` is not set, the persisted value is
//!   used automatically to resume from where the previous run left off.
//!
//! Connects to the AT Protocol relay WebSocket, decodes binary CBOR frames,
//! parses inline CAR blocks, writes them to the BlockStore under their original
//! AT CIDs (sha2-256), and asserts a Quad per op into the QuadStore.
//!
//! Wire format (Event Stream Frames):
//!   Binary WebSocket msg = CBOR(header) || CBOR(body)
//!   header = { "op": 1 (msg) | -1 (error), "t": "#commit" | "#identity" | … }
//!   body   = type-specific CBOR map
//!
//! CBOR CIDs: tag 42 with bytes `\x00<raw_cid_bytes>` (multibase identity prefix).
//!
//! CIDv1 sha2-256 dag-cbor (AT Protocol standard) = 36 bytes:
//!   [0x01, 0x71, 0x12, 0x20, ...32 sha2-256 bytes...]
//! KotobaCid uses the same sha2-256 multihash code for IPFS compatibility.
//! We store blocks under their original AT CIDs for round-trip AT compatibility.
//!
//! Env vars:
//!   KOTOBA_SUBSCRIBE_REPOS         — set to any value to enable
//!   KOTOBA_SUBSCRIBE_REPOS_URL     — default: wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos
//!   KOTOBA_SUBSCRIBE_REPOS_CURSOR  — resume from seq number (u64)
//!   KOTOBA_SUBSCRIBE_REPOS_DIDS    — comma-sep DID allowlist (empty = all)

use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Persist cursor every N committed events to avoid excessive BlockStore writes.
const CURSOR_PERSIST_INTERVAL: u64 = 100;

/// Fixed synthetic CID used as the named slot for cursor persistence.
/// Not content-addressed — treated as a mutable named register in BlockStore.
/// Bytes: CIDv1 prefix (4) + ASCII "subscribeRepos/cursor" (21) + padding (11).
const CURSOR_SLOT_CID: KotobaCid = KotobaCid([
    0x01, 0x71, 0x12, 0x20, // CIDv1 dag-cbor sha2-256 prefix
    b's', b'u', b'b', b's', b'c', b'r', b'i', b'b', b'e', b'R', b'e', b'p', b'o', b's', b'/', b'c',
    b'u', b'r', b's', b'o', b'r', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

use bytes::Bytes;
use ciborium::value::Value;
use futures::StreamExt;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, info, warn};

use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use kotoba_kqe::datom::Datom;
use kotoba_kqe::quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject};
use kotoba_kse::Journal;

use crate::atproto::{collection_to_cid, did_to_cid, jetstream_subject_to_topic};
use crate::quad_store::QuadStore;

// ── Cursor persistence helpers ────────────────────────────────────────────

fn load_cursor(store: &dyn BlockStore) -> Option<u64> {
    let bytes = store.get(&CURSOR_SLOT_CID).ok()??;
    if bytes.len() >= 8 {
        Some(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
    } else {
        None
    }
}

fn save_cursor(store: &dyn BlockStore, seq: u64) {
    let bytes = seq.to_le_bytes();
    if let Err(e) = store.put(&CURSOR_SLOT_CID, &bytes) {
        warn!(err = %e, seq, "failed to persist subscribeRepos cursor");
    }
}

// ── Public entry point ────────────────────────────────────────────────────

/// Run the subscribeRepos firehose client loop. Spawn with `tokio::spawn`.
///
/// When `gossip_tx` is `Some`, each asserted quad is also forwarded to the GossipSub
/// swarm actor on the `"quad/assert"` topic so remote peers receive AT Protocol events.
pub async fn run_subscribe_repos(
    journal: Arc<Journal>,
    quad_store: Arc<QuadStore>,
    block_store: Arc<dyn BlockStore + Send + Sync>,
    gossip_tx: Option<tokio::sync::mpsc::Sender<(String, Vec<u8>)>>,
) {
    let base = std::env::var("KOTOBA_SUBSCRIBE_REPOS_URL")
        .unwrap_or_else(|_| "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos".into());

    // Prefer env var cursor → then persisted cursor → then no cursor (full replay)
    let cursor_param = if let Ok(c) = std::env::var("KOTOBA_SUBSCRIBE_REPOS_CURSOR") {
        format!("?cursor={c}")
    } else if let Some(persisted) = load_cursor(&*block_store) {
        info!(
            cursor = persisted,
            "subscribeRepos resuming from persisted cursor"
        );
        format!("?cursor={persisted}")
    } else {
        String::new()
    };

    let url = format!("{base}{cursor_param}");

    let did_filter: Vec<String> = std::env::var("KOTOBA_SUBSCRIBE_REPOS_DIDS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let mut backoff = 1u64;
    let commit_count = Arc::new(AtomicU64::new(0));

    loop {
        info!(%url, "subscribeRepos connecting");

        match connect_async(&url).await {
            Err(e) => warn!(err = %e, backoff, "subscribeRepos connect failed"),
            Ok((mut ws, _)) => {
                info!("subscribeRepos connected");
                backoff = 1;

                while let Some(msg) = ws.next().await {
                    match msg {
                        Ok(Message::Binary(data)) => {
                            let seq = handle_frame(
                                &data,
                                &did_filter,
                                &journal,
                                &quad_store,
                                &block_store,
                                &gossip_tx,
                            )
                            .await;

                            // Persist cursor every CURSOR_PERSIST_INTERVAL commits
                            if let Some(seq) = seq {
                                let n = commit_count.fetch_add(1, Ordering::Relaxed) + 1;
                                if n.is_multiple_of(CURSOR_PERSIST_INTERVAL) {
                                    save_cursor(&*block_store, seq);
                                    debug!(seq, "subscribeRepos cursor persisted");
                                }
                            }
                        }
                        Ok(Message::Close(_)) => {
                            info!("subscribeRepos closed by relay");
                            break;
                        }
                        Err(e) => {
                            warn!(err = %e, "subscribeRepos read error");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

// ── Frame handling ────────────────────────────────────────────────────────

/// Returns the `seq` of the processed commit frame (for cursor tracking), or None.
async fn handle_frame(
    data: &[u8],
    did_filter: &[String],
    journal: &Arc<Journal>,
    quad_store: &Arc<QuadStore>,
    block_store: &Arc<dyn BlockStore + Send + Sync>,
    gossip_tx: &Option<tokio::sync::mpsc::Sender<(String, Vec<u8>)>>,
) -> Option<u64> {
    // Two CBOR values concatenated: header then body
    let mut cur = Cursor::new(data);
    let header: Value = match ciborium::from_reader(&mut cur) {
        Ok(v) => v,
        Err(e) => {
            warn!(err = %e, "bad frame header");
            return None;
        }
    };
    let body: Value = match ciborium::from_reader(&mut cur) {
        Ok(v) => v,
        Err(e) => {
            warn!(err = %e, "bad frame body");
            return None;
        }
    };

    // op=1 → message; op=-1 → error
    let op = cbor_i64(&header, "op").unwrap_or(0);
    if op != 1 {
        return None;
    }

    match cbor_str(&header, "t").as_deref() {
        Some("#commit") => {
            handle_commit(
                body,
                did_filter,
                journal,
                quad_store,
                block_store,
                gossip_tx,
            )
            .await
        }
        Some("#identity") => {
            handle_identity(body, journal, quad_store).await;
            None
        }
        Some("#account") => None,
        other => {
            debug!(t = ?other, "unhandled frame type");
            None
        }
    }
}

/// Returns the `seq` of the processed commit for cursor tracking.
async fn handle_commit(
    body: Value,
    did_filter: &[String],
    journal: &Arc<Journal>,
    quad_store: &Arc<QuadStore>,
    block_store: &Arc<dyn BlockStore + Send + Sync>,
    gossip_tx: &Option<tokio::sync::mpsc::Sender<(String, Vec<u8>)>>,
) -> Option<u64> {
    let repo = match cbor_str(&body, "repo") {
        Some(d) => d,
        None => return None,
    };

    if !did_filter.is_empty() && !did_filter.contains(&repo) {
        return None;
    }

    let seq = cbor_i64(&body, "seq")
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(0);
    let too_big = cbor_bool(&body, "tooBig").unwrap_or(false);

    // Store CAR blocks in BlockStore (skip if tooBig — blocks absent)
    if !too_big {
        if let Some(Value::Bytes(car_bytes)) = cbor_get(&body, "blocks") {
            let blocks = parse_car(car_bytes);
            let stored = blocks.len();
            for (cid_bytes, block_data) in &blocks {
                if cid_bytes.len() == 36 {
                    let mut arr = [0u8; 36];
                    arr.copy_from_slice(cid_bytes);
                    let cid = KotobaCid(arr);
                    // Store under original AT CID (sha2-256) for AT compatibility
                    if let Err(e) = block_store.put(&cid, block_data) {
                        warn!(err = %e, "block store put failed");
                    }
                }
            }
            debug!(repo = %repo, seq, stored, "CAR blocks stored");
        }
    }

    // Build Quads for each op
    let ops = match cbor_get(&body, "ops") {
        Some(Value::Array(arr)) => arr,
        _ => return Some(seq),
    };

    let subject_cid = did_to_cid(&repo);

    for op in ops {
        let action = match cbor_str(op, "action").as_deref() {
            Some("create") | Some("update") => true,
            Some("delete") => false,
            _ => continue,
        };

        let path = match cbor_str(op, "path") {
            Some(p) => p,
            None => continue,
        };

        // path = "collection/rkey"
        let (collection, rkey) = match path.split_once('/') {
            Some(p) => p,
            None => continue,
        };

        let graph_cid = collection_to_cid(collection);
        let topic = jetstream_subject_to_topic(collection);

        let object = if action {
            // Create/update: object is the record CID (tag 42) or Text("delete")
            match cbor_get(op, "cid") {
                Some(v) => {
                    if let Some(arr) = cbor_cid_bytes(v) {
                        QuadObject::Cid(KotobaCid(arr))
                    } else {
                        QuadObject::Text("unknown".into())
                    }
                }
                None => QuadObject::Text("unknown".into()),
            }
        } else {
            QuadObject::Text("delete".into())
        };

        let quad = Quad {
            graph: graph_cid,
            subject: subject_cid.clone(),
            predicate: rkey.to_string(),
            object,
        };

        // Assert into QuadStore as a Datom while preserving the legacy event payload.
        quad_store
            .assert_datom(
                quad.graph.clone(),
                Datom::from_legacy_quad(quad.clone(), true),
            )
            .await;
        let payload = match serde_json::to_vec(&quad) {
            Ok(v) => Bytes::from(v),
            Err(_) => continue,
        };
        // Propagate to GossipSub peers so remote kotoba nodes receive AT Protocol events
        if let Some(tx) = gossip_tx {
            tx.try_send(("quad/assert".to_string(), payload.to_vec()))
                .ok();
        }
        journal.publish(topic, payload).await;
    }

    Some(seq)
}

async fn handle_identity(body: Value, journal: &Arc<Journal>, quad_store: &Arc<QuadStore>) {
    let did = match cbor_str(&body, "did") {
        Some(d) => d,
        None => return,
    };
    let handle = match cbor_str(&body, "handle") {
        Some(h) => h,
        None => return,
    };

    let graph_cid = collection_to_cid("com.atproto.identity.handle");
    let subject_cid = did_to_cid(&did);
    let topic = jetstream_subject_to_topic("com.atproto.identity.handle");

    let quad = Quad {
        graph: graph_cid,
        subject: subject_cid,
        predicate: "handle".into(),
        object: QuadObject::Text(handle.clone()),
    };

    quad_store
        .assert_datom(
            quad.graph.clone(),
            Datom::from_legacy_quad(quad.clone(), true),
        )
        .await;
    let payload = serde_json::to_vec(&quad).unwrap_or_default().into();
    journal.publish(topic, payload).await;

    debug!(did = %did, handle = %handle, "identity asserted");
}

// ── CAR v1 parser (no external crate) ────────────────────────────────────

fn read_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    let mut shift = 0u32;
    for (i, &b) in buf.iter().enumerate().take(10) {
        v |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
        shift += 7;
    }
    None
}

/// Parse a CIDv1 from a byte slice.  Returns (raw_cid_bytes, bytes_consumed).
fn read_cid_v1(buf: &[u8]) -> Option<(&[u8], usize)> {
    let mut pos = 0;
    let (ver, n) = read_uvarint(&buf[pos..])?;
    pos += n;
    if ver != 1 {
        return None;
    }
    let (_, n) = read_uvarint(&buf[pos..])?; // codec
    pos += n;
    let (_, n) = read_uvarint(&buf[pos..])?; // hash function code
    pos += n;
    let (dlen, n) = read_uvarint(&buf[pos..])?; // digest length
    let dlen_usize = usize::try_from(dlen).ok()?;
    pos = pos.checked_add(n)?.checked_add(dlen_usize)?;
    if buf.len() < pos {
        return None;
    }
    Some((&buf[..pos], pos))
}

/// Parse a CAR v1 payload into `(cid_bytes, block_bytes)` pairs.
fn parse_car(data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    let mut pos = 0;

    // Skip CAR header: uvarint(len) + CBOR header map
    let Some((hlen, n)) = read_uvarint(&data[pos..]) else {
        return result;
    };
    let hlen_usize = match usize::try_from(hlen) {
        Ok(v) => v,
        Err(_) => return result,
    };
    pos = match pos.checked_add(n).and_then(|p| p.checked_add(hlen_usize)) {
        Some(p) => p,
        None => return result,
    };

    while pos < data.len() {
        let Some((section_len, n)) = read_uvarint(&data[pos..]) else {
            break;
        };
        pos = match pos.checked_add(n) {
            Some(p) => p,
            None => break,
        };
        if section_len == 0 {
            break;
        }
        let section_len_usize = match usize::try_from(section_len) {
            Ok(v) => v,
            Err(_) => break,
        };
        let section_end = match pos.checked_add(section_len_usize) {
            Some(e) => e,
            None => break,
        };
        if section_end > data.len() {
            break;
        }

        let Some((cid_bytes, cid_len)) = read_cid_v1(&data[pos..section_end]) else {
            break;
        };
        let block = data[pos + cid_len..section_end].to_vec();
        result.push((cid_bytes.to_vec(), block));
        pos = section_end;
    }

    result
}

// ── CBOR helpers ──────────────────────────────────────────────────────────

fn cbor_get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    if let Value::Map(m) = v {
        for (k, val) in m {
            if matches!(k, Value::Text(s) if s == key) {
                return Some(val);
            }
        }
    }
    None
}

fn cbor_str(v: &Value, key: &str) -> Option<String> {
    match cbor_get(v, key)? {
        Value::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn cbor_i64(v: &Value, key: &str) -> Option<i64> {
    match cbor_get(v, key)? {
        Value::Integer(i) => i64::try_from(i128::from(*i)).ok(),
        _ => None,
    }
}

fn cbor_bool(v: &Value, key: &str) -> Option<bool> {
    match cbor_get(v, key)? {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

/// Extract raw CID bytes from a CBOR tag-42 value (`\x00<cid_bytes>`).
fn cbor_cid_bytes(v: &Value) -> Option<[u8; 36]> {
    match v {
        Value::Tag(42, inner) => {
            if let Value::Bytes(b) = inner.as_ref() {
                // Strip leading multibase identity prefix byte 0x00
                let raw = if b.first() == Some(&0) {
                    &b[1..]
                } else {
                    b.as_slice()
                };
                if raw.len() == 36 {
                    let mut arr = [0u8; 36];
                    arr.copy_from_slice(raw);
                    return Some(arr);
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_store::MemoryBlockStore;
    use std::sync::Arc;

    fn mem() -> Arc<MemoryBlockStore> {
        Arc::new(MemoryBlockStore::new())
    }

    #[test]
    fn cursor_slot_cid_has_expected_prefix() {
        assert_eq!(CURSOR_SLOT_CID.0[0], 0x01); // CIDv1
        assert_eq!(CURSOR_SLOT_CID.0[1], 0x71); // dag-cbor
        assert_eq!(CURSOR_SLOT_CID.0[2], 0x12); // sha2-256
        assert_eq!(CURSOR_SLOT_CID.0[3], 0x20); // hash length 32
    }

    #[test]
    fn load_cursor_returns_none_when_empty() {
        let store = mem();
        assert!(load_cursor(&*store).is_none());
    }

    #[test]
    fn save_and_load_cursor_roundtrip() {
        let store = mem();
        save_cursor(&*store, 42_000);
        assert_eq!(load_cursor(&*store), Some(42_000));
    }

    #[test]
    fn save_cursor_overwrites_previous() {
        let store = mem();
        save_cursor(&*store, 1);
        save_cursor(&*store, 9_999);
        assert_eq!(load_cursor(&*store), Some(9_999));
    }

    #[test]
    fn cbor_cid_bytes_extracts_36_byte_payload() {
        let mut cid_bytes = vec![0x00u8]; // identity prefix
        cid_bytes.extend_from_slice(&[0xABu8; 36]);
        let val =
            ciborium::value::Value::Tag(42, Box::new(ciborium::value::Value::Bytes(cid_bytes)));
        let result = cbor_cid_bytes(&val);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), [0xABu8; 36]);
    }

    #[test]
    fn cbor_cid_bytes_rejects_wrong_tag() {
        let val =
            ciborium::value::Value::Tag(0, Box::new(ciborium::value::Value::Bytes(vec![0u8; 37])));
        assert!(cbor_cid_bytes(&val).is_none());
    }

    #[test]
    fn cbor_cid_bytes_rejects_wrong_length() {
        let val =
            ciborium::value::Value::Tag(42, Box::new(ciborium::value::Value::Bytes(vec![0u8; 20])));
        assert!(cbor_cid_bytes(&val).is_none());
    }

    #[test]
    fn parse_car_crafted_overflow_section_len_does_not_panic() {
        // CAR header: varint(0) = 0x00 (zero-length header)
        // Section: varint(u64::MAX) encoded as 9-byte LEB128 + continuation
        // A valid uvarint for u64::MAX is 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0x01
        let mut data = vec![0x00u8]; // header len = 0
                                     // u64::MAX = 0xFFFF_FFFF_FFFF_FFFF — 10-byte LEB128
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
        // Must return empty without panicking
        let result = parse_car(&data);
        assert!(
            result.is_empty(),
            "crafted overflow section_len must yield empty result, not panic"
        );
    }

    #[test]
    fn parse_car_empty_input_returns_empty() {
        assert!(parse_car(&[]).is_empty());
    }

    #[test]
    fn cbor_i64_rejects_value_exceeding_i64_max() {
        use ciborium::value::Value;
        // u64::MAX as CBOR Integer exceeds i64::MAX — must return None, not silently truncate.
        // ciborium::value::Integer implements From<u64>.
        let big = ciborium::value::Integer::from(u64::MAX);
        let map = Value::Map(vec![(Value::Text("seq".into()), Value::Integer(big))]);
        let result = cbor_i64(&map, "seq");
        assert!(
            result.is_none(),
            "cbor_i64 must return None for values > i64::MAX, got: {result:?}"
        );
    }

    #[test]
    fn cbor_i64_accepts_in_range_value() {
        use ciborium::value::Value;
        let map = Value::Map(vec![(
            Value::Text("seq".into()),
            Value::Integer(42i64.into()),
        )]);
        assert_eq!(cbor_i64(&map, "seq"), Some(42i64));
    }

    #[test]
    fn negative_seq_from_firehose_is_rejected_not_wrapped_to_huge_u64() {
        // AT Protocol seq numbers are always non-negative.  A rogue firehose relay
        // could send seq = -1; the old `as u64` cast wraps -1i64 → u64::MAX,
        // corrupting the persisted cursor and breaking subsequent restarts.
        // The fixed path uses `u64::try_from(i64)` which rejects negatives.
        use ciborium::value::Value;
        let negative_seq = ciborium::value::Integer::from(-1i64);
        let map = Value::Map(vec![(
            Value::Text("seq".into()),
            Value::Integer(negative_seq),
        )]);
        // cbor_i64 accepts -1 (in i64 range), but u64::try_from(-1i64) rejects it.
        // The combined pipeline must return 0 (the safe fallback), never u64::MAX.
        let raw = cbor_i64(&map, "seq");
        assert_eq!(
            raw,
            Some(-1i64),
            "cbor_i64 should pass through in-range negatives"
        );
        let seq_u64 = raw.and_then(|v| u64::try_from(v).ok()).unwrap_or(0);
        assert_eq!(
            seq_u64,
            0,
            "negative seq must map to 0, not wrap to {}",
            u64::MAX
        );
    }

    #[test]
    fn read_cid_v1_crafted_overflow_dlen_returns_none() {
        // CIDv1 prefix bytes: version=1, codec=dag-cbor(0x71), hash=sha2-256(0x12), then dlen=u64::MAX
        let mut buf = vec![
            0x01, // version = 1
            0x71, // codec = dag-cbor
            0x12, // hash function = sha2-256
        ];
        // dlen = u64::MAX as LEB128 (10 bytes)
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
        // Must return None without panicking
        assert!(read_cid_v1(&buf).is_none());
    }
}
