//! Gmail REST API client — OAuth2 refresh token flow.
//!
//! Required env vars:
//!   KOTOBA_GMAIL_CLIENT_ID
//!   KOTOBA_GMAIL_CLIENT_SECRET
//!   KOTOBA_GMAIL_REFRESH_TOKEN

use anyhow::{anyhow, Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use serde::Deserialize;

const TOKEN_URL: &str  = "https://oauth2.googleapis.com/token";
const GMAIL_BASE: &str = "https://gmail.googleapis.com/gmail/v1/users/me";

pub struct GmailClient {
    client_id:     String,
    client_secret: String,
    refresh_token: String,
    access_token:  String,
    http:          reqwest::Client,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct MessageStub {
    id:        String,
    #[serde(rename = "threadId")]
    thread_id: String,
}

#[derive(Deserialize)]
struct RawMessageResponse {
    raw:       String,
    #[serde(rename = "threadId")]
    thread_id: String,
}

#[derive(Deserialize)]
struct HistoryResponse {
    history:            Option<Vec<HistoryRecord>>,
    #[serde(rename = "historyId")]
    history_id:         String,
}

#[derive(Deserialize)]
struct HistoryRecord {
    #[serde(rename = "messagesAdded", default)]
    messages_added: Vec<HistoryMessageAdded>,
}

#[derive(Deserialize)]
struct HistoryMessageAdded {
    message: MessageStub,
}

impl GmailClient {
    /// Build from environment variables.
    pub fn from_env() -> Result<Self> {
        let client_id     = std::env::var("KOTOBA_GMAIL_CLIENT_ID")
            .context("KOTOBA_GMAIL_CLIENT_ID not set")?;
        let client_secret = std::env::var("KOTOBA_GMAIL_CLIENT_SECRET")
            .context("KOTOBA_GMAIL_CLIENT_SECRET not set")?;
        let refresh_token = std::env::var("KOTOBA_GMAIL_REFRESH_TOKEN")
            .context("KOTOBA_GMAIL_REFRESH_TOKEN not set")?;
        Ok(Self {
            client_id,
            client_secret,
            refresh_token,
            access_token: String::new(),
            http: reqwest::Client::new(),
        })
    }

    /// Exchange the refresh token for a new access token.
    pub async fn refresh(&mut self) -> Result<()> {
        let resp: TokenResponse = self.http
            .post(TOKEN_URL)
            .form(&[
                ("grant_type",    "refresh_token"),
                ("client_id",     self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("refresh_token", self.refresh_token.as_str()),
            ])
            .send().await?.error_for_status()?.json().await?;
        self.access_token = resp.access_token;
        Ok(())
    }

    /// Fetch the current inbox historyId from the Gmail profile endpoint.
    pub async fn profile_history_id(&mut self) -> Result<u64> {
        let url = format!("{GMAIL_BASE}/profile");
        let resp: serde_json::Value = self.http.get(&url)
            .bearer_auth(&self.access_token)
            .send().await?.error_for_status()?.json().await?;
        resp["historyId"].as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("historyId not found in Gmail profile response"))
    }

    /// Return `(new_stubs, latest_history_id)` since `start_history_id`.
    /// Each stub is `(message_id, thread_id)`.
    pub async fn list_history(
        &mut self,
        start_history_id: u64,
    ) -> Result<(Vec<(String, String)>, u64)> {
        let url = format!("{GMAIL_BASE}/history");
        let resp = self.http.get(&url)
            .bearer_auth(&self.access_token)
            .query(&[
                ("startHistoryId", start_history_id.to_string()),
                ("historyTypes",   "messageAdded".to_string()),
            ])
            .send().await?;

        // 404 means historyId has expired — return empty; caller must full-sync
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            tracing::warn!(start_history_id, "Gmail historyId expired; skipping delta");
            return Ok((vec![], start_history_id));
        }
        let h: HistoryResponse = resp.error_for_status()?.json().await?;
        let new_id = h.history_id.parse::<u64>().unwrap_or(start_history_id);

        let stubs = h.history
            .unwrap_or_default()
            .into_iter()
            .flat_map(|r| r.messages_added)
            .map(|m| (m.message.id, m.message.thread_id))
            .collect();
        Ok((stubs, new_id))
    }

    /// Fetch one message as raw RFC 2822 bytes plus its thread_id.
    pub async fn get_raw_message(&mut self, message_id: &str) -> Result<(Vec<u8>, String)> {
        let url = format!("{GMAIL_BASE}/messages/{message_id}");
        let resp: RawMessageResponse = self.http.get(&url)
            .bearer_auth(&self.access_token)
            .query(&[("format", "raw")])
            .send().await?.error_for_status()?.json().await?;
        let raw = B64URL.decode(&resp.raw)
            .context("base64url decode of Gmail raw message failed")?;
        Ok((raw, resp.thread_id))
    }
}
