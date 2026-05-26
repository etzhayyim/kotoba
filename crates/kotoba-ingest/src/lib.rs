pub mod cc;
pub mod embed_client;
pub mod gmail;
pub mod ingest;
pub mod ivf;

pub use gmail::GmailClient;
pub use ingest::{EmailIngestor, graph_cid_for};

use std::sync::Arc;
use std::time::Duration;
use kotoba_kse::Vault;
use kotoba_graph::QuadStore;
use kotoba_crypto::AgentCrypto;

/// Long-running polling loop.  Call from a `tokio::spawn`.
///
/// Env vars consumed:
///   KOTOBA_GMAIL_CLIENT_ID / _CLIENT_SECRET / _REFRESH_TOKEN  (required)
///   KOTOBA_GMAIL_OWNER_DID          (default: "did:plc:unknown")
///   KOTOBA_GMAIL_POLL_INTERVAL_SECS (default: 60)
///   KOTOBA_GMAIL_HISTORY_ID         (optional seed; otherwise fetched from profile)
pub async fn gmail_poll_loop(
    crypto:    Arc<dyn AgentCrypto>,
    vault:     Arc<Vault>,
    quad_store: Arc<QuadStore>,
) {
    let owner_did = std::env::var("KOTOBA_GMAIL_OWNER_DID")
        .unwrap_or_else(|_| "did:plc:unknown".to_string());
    let interval_secs: u64 = std::env::var("KOTOBA_GMAIL_POLL_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    let mut client = match GmailClient::from_env() {
        Ok(c)  => c,
        Err(e) => {
            tracing::error!(err = %e, "gmail_poll_loop: missing credentials, aborting");
            return;
        }
    };

    if let Err(e) = client.refresh().await {
        tracing::error!(err = %e, "gmail_poll_loop: initial token refresh failed");
        return;
    }

    // Bootstrap history_id from env or Gmail profile
    let mut history_id: u64 = match std::env::var("KOTOBA_GMAIL_HISTORY_ID")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        Some(id) => id,
        None => match client.profile_history_id().await {
            Ok(id) => {
                tracing::info!(history_id = id, owner_did, "Gmail poll: using profile historyId");
                id
            }
            Err(e) => {
                tracing::error!(err = %e, "gmail_poll_loop: could not fetch profile historyId");
                return;
            }
        },
    };

    let ingestor = EmailIngestor::new(
        crypto,
        vault,
        quad_store,
        owner_did.clone(),
    );

    tracing::info!(owner_did, interval_secs, history_id, "Gmail poll loop started");

    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;

        // Re-auth proactively every tick (tokens expire after 1 hour)
        if let Err(e) = client.refresh().await {
            tracing::warn!(err = %e, "Gmail token refresh failed; will retry next tick");
            continue;
        }

        let (stubs, new_id) = match client.list_history(history_id).await {
            Ok(r)  => r,
            Err(e) => {
                tracing::warn!(err = %e, "Gmail list_history failed");
                continue;
            }
        };
        history_id = new_id;

        for (msg_id, thread_id) in stubs {
            match client.get_raw_message(&msg_id).await {
                Ok((raw, tid)) => {
                    let thread = if tid.is_empty() { &thread_id } else { &tid };
                    if let Err(e) = ingestor.ingest_raw(&raw, thread).await {
                        tracing::warn!(msg_id, err = %e, "ingest_raw failed");
                    }
                }
                Err(e) => tracing::warn!(msg_id, err = %e, "get_raw_message failed"),
            }
        }
    }
}
