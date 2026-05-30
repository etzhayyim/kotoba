//! HTTP egress over the KSE Journal — the "tap" half of the kotoba federation
//! surface (D in the D+E design, 2026-05-30).
//!
//! Two read-only endpoints, both keyed by the Journal's monotonic `seq` (the
//! cursor) so a consumer can resume exactly where it left off:
//!
//!   * `ai.gftd.apps.kotoba.sync.subscribe` — Server-Sent Events live-tail.
//!     Backfills `read_since(cursor+1)` then streams new entries as they are
//!     published.  Each SSE frame carries `id: <seq>`; on reconnect the client
//!     sends the last id back as `?cursor=` (or `Last-Event-ID`) to resume.
//!   * `ai.gftd.apps.kotoba.sync.events` — plain JSON cursor paging / long-poll.
//!     `?cursor=N&limit=K` returns the next batch; usable through any proxy or
//!     CF Worker without WebSocket/SSE support.
//!
//! This is the SAME ordered Journal that the libp2p gossip relay (E,
//! `net_actor`) federates to the mesh — D and E share one cursor, so what you
//! observe over HTTP is exactly what propagates over gossip.
//!
//! NOTE: this is NOT a spec-faithful `com.atproto.sync.subscribeRepos` relay.
//! kotoba has no MST / signed-commit / CAR path (record-log semantics), and the
//! quad projection hashes the repo DID + collection NSID one-way, so faithful
//! AT commits cannot be reconstructed here.  This streams kotoba's own ordered
//! event log under the kotoba NSID — see ADR for the etzhayyim-side AT-MST
//! origination path.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures::stream::{self, Stream};
use serde::{Deserialize, Serialize};

use kotoba_core::cid::KotobaCid;
use kotoba_kse::{Cursor, Journal, JournalEntry};

use crate::graph_auth::{check_read_access, AccessDenied};
use crate::server::KotobaState;

/// SSE live-tail firehose.
pub const NSID_SYNC_SUBSCRIBE: &str = "ai.gftd.apps.kotoba.sync.subscribe";
/// JSON cursor paging / long-poll firehose.
pub const NSID_SYNC_EVENTS: &str = "ai.gftd.apps.kotoba.sync.events";

/// Hard cap on a single paging response so a huge cold backfill can't OOM the node.
const MAX_PAGE_LIMIT: usize = 1000;
const DEFAULT_PAGE_LIMIT: usize = 100;

#[derive(Debug, Deserialize)]
pub struct SubscribeParams {
    /// Resume after this Journal seq (exclusive). Omit = live-only from now.
    pub cursor: Option<u64>,
    /// Only emit entries whose topic starts with this prefix (e.g. `jetstream/`).
    pub topic_prefix: Option<String>,
    /// CACAO delegation chain (base64) — required when the node default
    /// visibility is `private`.
    pub cacao_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EventsParams {
    pub cursor: Option<u64>,
    pub limit: Option<usize>,
    pub topic_prefix: Option<String>,
    pub cacao_b64: Option<String>,
}

/// Read-access gate for the firehose.
///
/// The firehose is a CROSS-graph, whole-Journal stream, so a per-graph
/// credential cannot bound it — we gate at the NODE level on
/// `KOTOBA_DEFAULT_VISIBILITY` (default `private`):
///   * `public`        → open
///   * `authenticated` → any non-empty Bearer token
///   * `private`       → CACAO `datom:read` delegation chain on the operator DID
///
/// Per-entry, per-graph filtering (e.g. a public-only firehose on a private
/// node) is intentionally out of scope here — see the project CLAUDE.md.
async fn gate(
    state: &KotobaState,
    headers: &HeaderMap,
    cacao_b64: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    // Sentinel all-zero CID is never a registered named graph, so
    // `graph_visibility` returns the node default (KOTOBA_DEFAULT_VISIBILITY).
    let visibility = state.graph_visibility(&KotobaCid([0u8; 36])).await;
    check_read_access(
        &visibility,
        headers,
        cacao_b64,
        Some(&state.operator_did),
        Some(&state.nonce_store),
    )
    .map_err(AccessDenied::into_response)
}

/// One firehose event in JSON form. `payload` is decoded as JSON when the
/// Journal payload is valid JSON (the common case — quads/records are JSON),
/// otherwise it is a base64 string of the raw bytes.
#[derive(Debug, Serialize)]
pub struct FirehoseEvent {
    pub seq: u64,
    pub ts: u64,
    pub topic: String,
    pub cid: String,
    pub payload: serde_json::Value,
}

impl FirehoseEvent {
    fn from_entry(e: &JournalEntry) -> Self {
        let payload = match serde_json::from_slice::<serde_json::Value>(&e.payload) {
            Ok(v) => v,
            Err(_) => serde_json::Value::String(B64.encode(&e.payload)),
        };
        FirehoseEvent {
            seq: e.seq,
            ts: e.ts,
            topic: e.topic.clone(),
            cid: e.cid.to_multibase(),
            payload,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct EventsResponse {
    pub events: Vec<FirehoseEvent>,
    /// Seq of the last event in this batch — pass back as `?cursor=` next time.
    pub cursor: u64,
    /// Current head seq of the Journal (so callers know how far behind they are).
    pub current_seq: u64,
    /// `limit` items returned but more are available past `cursor`.
    pub has_more: bool,
}

// ── SSE live-tail ──────────────────────────────────────────────────────────

struct SseState {
    backlog: VecDeque<JournalEntry>,
    live: Cursor,
    last_seq: u64,
    prefix: Option<String>,
}

/// `GET /xrpc/ai.gftd.apps.kotoba.sync.subscribe?cursor=N&topic_prefix=...`
pub async fn subscribe(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(params): Query<SubscribeParams>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    gate(&state, &headers, params.cacao_b64.as_deref()).await?;

    let journal: Arc<Journal> = Arc::clone(&state.journal);

    // Subscribe to the live broadcast FIRST so no entry slips through the gap
    // between reading the backlog and attaching the tail. Overlapping seqs are
    // de-duplicated by `last_seq` below.
    let live = journal.subscribe();
    let baseline = journal.current_seq().await;

    let (backlog, last_seq) = match params.cursor {
        Some(c) => (journal.read_since(c + 1).await, c),
        None => (Vec::new(), baseline),
    };

    let init = SseState {
        backlog: backlog.into(),
        live,
        last_seq,
        prefix: params.topic_prefix,
    };

    let stream = stream::unfold(init, |mut st| async move {
        loop {
            let entry = match st.backlog.pop_front() {
                Some(e) => e,
                None => match st.live.next().await {
                    Some(e) => e,
                    // Broadcast closed or the slow consumer lagged out of the
                    // ring — end the stream; the client resumes via cursor.
                    None => return None,
                },
            };

            if entry.seq <= st.last_seq {
                continue; // already emitted via the backlog/live overlap
            }
            if let Some(p) = &st.prefix {
                if !entry.topic.starts_with(p.as_str()) {
                    st.last_seq = entry.seq;
                    continue;
                }
            }
            st.last_seq = entry.seq;

            let ev = Event::default()
                .id(entry.seq.to_string())
                .event("firehose")
                .json_data(FirehoseEvent::from_entry(&entry))
                .unwrap_or_else(|_| Event::default().comment("payload encode error"));
            return Some((Ok::<_, Infallible>(ev), st));
        }
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

// ── JSON cursor paging / long-poll ───────────────────────────────────────────

/// `GET /xrpc/ai.gftd.apps.kotoba.sync.events?cursor=N&limit=K&topic_prefix=...`
pub async fn events(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Query(params): Query<EventsParams>,
) -> Result<Json<EventsResponse>, (StatusCode, String)> {
    gate(&state, &headers, params.cacao_b64.as_deref()).await?;

    let journal = &state.journal;
    let current_seq = journal.current_seq().await;

    let from = params.cursor.map(|c| c + 1).unwrap_or(1);
    let limit = params.limit.unwrap_or(DEFAULT_PAGE_LIMIT).min(MAX_PAGE_LIMIT);

    let mut entries = journal.read_since(from).await;
    if let Some(prefix) = &params.topic_prefix {
        entries.retain(|e| e.topic.starts_with(prefix.as_str()));
    }

    let has_more = entries.len() > limit;
    entries.truncate(limit);

    let cursor = entries
        .last()
        .map(|e| e.seq)
        .or(params.cursor)
        .unwrap_or(0);

    let events = entries.iter().map(FirehoseEvent::from_entry).collect();

    Ok(Json(EventsResponse {
        events,
        cursor,
        current_seq,
        has_more,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;

    fn entry(seq: u64, topic: &str, payload: &[u8]) -> JournalEntry {
        JournalEntry {
            seq,
            ts: 0,
            topic: topic.to_string(),
            payload: payload.to_vec(),
            cid: KotobaCid::from_bytes(payload),
            prev: None,
        }
    }

    #[test]
    fn from_entry_decodes_json_payload_inline() {
        let e = entry(7, "jetstream/app.bsky.feed.post", br#"{"a":1,"b":"x"}"#);
        let fe = FirehoseEvent::from_entry(&e);
        assert_eq!(fe.seq, 7);
        assert_eq!(fe.topic, "jetstream/app.bsky.feed.post");
        assert_eq!(fe.payload["a"], serde_json::json!(1));
        assert_eq!(fe.payload["b"], serde_json::json!("x"));
    }

    #[test]
    fn from_entry_falls_back_to_base64_for_non_json() {
        let raw = &[0xff, 0x00, 0x10, 0xab];
        let e = entry(3, "blob/raw", raw);
        let fe = FirehoseEvent::from_entry(&e);
        let s = fe.payload.as_str().expect("non-JSON payload must be a base64 string");
        assert_eq!(B64.decode(s).unwrap(), raw);
    }
}
