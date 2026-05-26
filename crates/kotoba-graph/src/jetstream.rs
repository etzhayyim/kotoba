//! Jetstream WebSocket client — subscribes to the AT Protocol Jetstream firehose,
//! converts events to KOTOBA Quads, and publishes them to the local Journal
//! **and** asserts them into the QuadStore (Arrangement + ProllyTree).
//!
//! Jetstream docs: https://github.com/bluesky-social/jetstream
//! Default endpoint: wss://jetstream2.us-east.bsky.network/subscribe
//!
//! Env vars:
//!   KOTOBA_JETSTREAM_URL          — WebSocket URL (default above)
//!   KOTOBA_JETSTREAM_COLLECTIONS  — comma-sep NSIDs to subscribe to (default: all)
//!
//! AT Protocol firehose compatibility notes:
//!   - Jetstream: JSON events (commit/identity/account) — fully supported
//!   - subscribeRepos (CAR binary): not yet implemented (requires CAR parser)
//!   - CID mapping: AT uses sha2-256; KOTOBA remaps to blake3 via at_cid_str_to_kotoba()

use std::sync::Arc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures::StreamExt;
use kotoba_kse::Journal;
use tracing::{info, warn, debug};
use bytes::Bytes;

use crate::atproto::jetstream_event_to_quad;
use crate::quad_store::QuadStore;

/// Run the Jetstream client loop. Intended to be spawned with `tokio::spawn`.
///
/// Each received event is:
/// 1. Published to the KSE Journal (SPO topic) for persistence / gossip
/// 2. Asserted into the QuadStore (Arrangement index + ProllyTree)
///
/// Reconnects with exponential backoff on disconnect.
pub async fn run_jetstream_client(journal: Arc<Journal>, quad_store: Arc<QuadStore>) {
    let base_url = std::env::var("KOTOBA_JETSTREAM_URL")
        .unwrap_or_else(|_| "wss://jetstream2.us-east.bsky.network/subscribe".into());

    let url = build_subscribe_url(&base_url);
    let mut backoff_secs = 1u64;

    loop {
        info!(url = %url, "Jetstream connecting");

        match connect_async(&url).await {
            Err(e) => {
                warn!(err = %e, backoff_secs, "Jetstream connect failed, retrying");
            }
            Ok((mut ws, _)) => {
                info!("Jetstream connected");
                backoff_secs = 1;

                while let Some(msg) = ws.next().await {
                    match msg {
                        Ok(Message::Text(text)) => {
                            let bytes = text.as_bytes();
                            if let Some((topic, quad)) = jetstream_event_to_quad(bytes) {
                                // 1. Persist to Journal (for B2 / gossip)
                                let payload = match serde_json::to_vec(&quad) {
                                    Ok(v) => Bytes::from(v),
                                    Err(e) => {
                                        warn!(err = %e, "failed to serialize quad");
                                        continue;
                                    }
                                };
                                journal.publish(topic, payload).await;

                                // 2. Assert into QuadStore (Arrangement + future ProllyTree commit)
                                quad_store.assert(quad).await;

                                debug!("jetstream quad asserted");
                            }
                        }
                        Ok(Message::Close(_)) => {
                            info!("Jetstream closed by server");
                            break;
                        }
                        Err(e) => {
                            warn!(err = %e, "Jetstream read error");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(60);
    }
}

pub(crate) fn build_subscribe_url(base: &str) -> String {
    let collections_env = std::env::var("KOTOBA_JETSTREAM_COLLECTIONS").unwrap_or_default();
    build_subscribe_url_with(base, &collections_env)
}

fn build_subscribe_url_with(base: &str, collections_csv: &str) -> String {
    let collections: Vec<String> = collections_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if collections.is_empty() {
        return base.to_string();
    }

    let params: Vec<String> = collections
        .iter()
        .map(|c| format!("wantedCollections={c}"))
        .collect();

    format!("{}?{}", base, params.join("&"))
}

#[cfg(test)]
mod tests {
    use super::build_subscribe_url_with;

    #[test]
    fn no_collections_returns_base_url() {
        let url = build_subscribe_url_with("wss://example.com/subscribe", "");
        assert_eq!(url, "wss://example.com/subscribe");
    }

    #[test]
    fn single_collection_appends_param() {
        let url = build_subscribe_url_with("wss://example.com/subscribe", "app.bsky.feed.post");
        assert!(url.contains("wantedCollections=app.bsky.feed.post"), "got: {url}");
    }

    #[test]
    fn multiple_collections_appends_multiple_params() {
        let url = build_subscribe_url_with(
            "wss://example.com/subscribe",
            "app.bsky.feed.post,app.bsky.graph.follow",
        );
        assert!(url.contains("wantedCollections=app.bsky.feed.post"), "got: {url}");
        assert!(url.contains("wantedCollections=app.bsky.graph.follow"), "got: {url}");
    }

    #[test]
    fn whitespace_trimmed_from_collections() {
        let url = build_subscribe_url_with(
            "wss://example.com/subscribe",
            " app.bsky.feed.post , app.bsky.graph.follow ",
        );
        assert!(url.contains("wantedCollections=app.bsky.feed.post"), "got: {url}");
        assert!(!url.contains("wantedCollections= "), "should strip spaces, got: {url}");
    }

    // ── additional build_subscribe_url_with tests ─────────────────────────────

    #[test]
    fn empty_csv_with_whitespace_only_returns_base_url() {
        let url = build_subscribe_url_with("wss://example.com/subscribe", "   ");
        assert_eq!(url, "wss://example.com/subscribe",
            "whitespace-only csv should produce base URL: {url}");
    }

    #[test]
    fn three_collections_appends_three_params() {
        let url = build_subscribe_url_with(
            "wss://example.com/subscribe",
            "app.bsky.feed.post,app.bsky.graph.follow,app.bsky.feed.like",
        );
        assert!(url.contains("wantedCollections=app.bsky.feed.post"), "got: {url}");
        assert!(url.contains("wantedCollections=app.bsky.graph.follow"), "got: {url}");
        assert!(url.contains("wantedCollections=app.bsky.feed.like"), "got: {url}");
    }

    #[test]
    fn base_url_with_no_trailing_slash_is_preserved() {
        let url = build_subscribe_url_with("wss://example.com/subscribe", "");
        assert_eq!(url, "wss://example.com/subscribe");
    }

    #[test]
    fn question_mark_separator_used_before_first_param() {
        let url = build_subscribe_url_with("wss://example.com/sub", "col.one");
        assert!(url.starts_with("wss://example.com/sub?"), "got: {url}");
    }

    #[test]
    fn ampersand_separator_used_between_params() {
        let url = build_subscribe_url_with("wss://example.com/sub", "col.one,col.two");
        // The two params must be separated by '&'
        assert!(url.contains("wantedCollections=col.one&wantedCollections=col.two")
            || url.contains("wantedCollections=col.two&wantedCollections=col.one"),
            "expected & separator between params, got: {url}");
    }

    #[test]
    fn single_collection_no_trailing_ampersand() {
        let url = build_subscribe_url_with("wss://example.com/sub", "col.one");
        assert!(!url.ends_with('&'), "no trailing ampersand expected, got: {url}");
    }

    #[test]
    fn comma_only_csv_returns_base_url() {
        // A CSV that is all separators with no real tokens should behave like empty
        let url = build_subscribe_url_with("wss://example.com/subscribe", ",,,");
        assert_eq!(url, "wss://example.com/subscribe",
            "commas-only csv should produce base URL, got: {url}");
    }
}
