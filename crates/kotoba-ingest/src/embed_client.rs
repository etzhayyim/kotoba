//! EmbedClient — async embedding backend trait + implementations.
//!
//! Two concrete clients:
//!   HttpEmbedClient  — HTTP POST to Ollama /api/embeddings or OpenAI-compat /v1/embeddings
//!   Blake3EmbedClient — deterministic pseudo-vector (testing/CI, no HTTP required)
//!
//! Environment variables (for HttpEmbedClient::from_env):
//!   KOTOBA_EMBED_URL    — base URL, e.g. "http://localhost:11434"
//!   KOTOBA_EMBED_MODEL  — model name, e.g. "nomic-embed-text:v1.5"
//!   KOTOBA_EMBED_DIM    — output dimension (default: 768)
//!   KOTOBA_EMBED_BATCH  — texts per HTTP request (default: 64)

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use serde_json::json;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Object-safe async embedding client.
///
/// Implementations return a boxed future so the trait can be used as
/// `dyn EmbedClient` without the `async_trait` crate.
pub trait EmbedClient: Send + Sync {
    fn embed_batch<'a>(
        &'a self,
        texts: &'a [&'a str],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<f32>>>> + Send + 'a>>;

    fn dim(&self) -> usize;
    fn model_id(&self) -> &str;
}

// ---------------------------------------------------------------------------
// HttpEmbedClient
// ---------------------------------------------------------------------------

/// HTTP-backed embedding client.  Tries OpenAI-compat `/v1/embeddings` first;
/// falls back to Ollama `/api/embeddings` on non-2xx.
#[derive(Debug, Clone)]
pub struct HttpEmbedClient {
    base_url:   String,
    model:      String,
    dim:        usize,
    batch_size: usize,
    http:       reqwest::Client,
}

impl HttpEmbedClient {
    /// Construct from explicit parameters.
    pub fn new(base_url: impl Into<String>, model: impl Into<String>, dim: usize, batch_size: usize) -> Self {
        Self {
            base_url:   base_url.into(),
            model:      model.into(),
            dim,
            batch_size,
            http:       reqwest::Client::new(),
        }
    }

    /// Construct from environment variables (with defaults).
    pub fn from_env() -> Result<Self> {
        let base_url   = std::env::var("KOTOBA_EMBED_URL")
            .unwrap_or_else(|_| "http://localhost:11434".to_string());
        let model      = std::env::var("KOTOBA_EMBED_MODEL")
            .unwrap_or_else(|_| "nomic-embed-text:v1.5".to_string());
        let dim: usize = std::env::var("KOTOBA_EMBED_DIM")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(768);
        let batch_size: usize = std::env::var("KOTOBA_EMBED_BATCH")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(64);
        Ok(Self::new(base_url, model, dim, batch_size))
    }

    /// Try OpenAI-compat batch endpoint.  Returns `None` on non-2xx so caller
    /// can fall back.
    async fn try_openai(&self, texts: &[&str]) -> Option<Vec<Vec<f32>>> {
        let url  = format!("{}/v1/embeddings", self.base_url.trim_end_matches('/'));
        let body = json!({ "model": self.model, "input": texts });
        let resp = self.http.post(&url).json(&body).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = resp.json().await.ok()?;
        let data = v.get("data")?.as_array()?;
        let vecs: Vec<Vec<f32>> = data
            .iter()
            .filter_map(|item| {
                let emb = item.get("embedding")?.as_array()?;
                emb.iter().map(|x| x.as_f64().map(|f| f as f32)).collect()
            })
            .collect();
        if vecs.len() == texts.len() { Some(vecs) } else { None }
    }

    /// Ollama single-text endpoint (`/api/embeddings`).
    async fn ollama_single(&self, text: &str) -> Result<Vec<f32>> {
        let url  = format!("{}/api/embeddings", self.base_url.trim_end_matches('/'));
        let body = json!({ "model": self.model, "prompt": text });
        let resp = self.http.post(&url).json(&body).send().await?;
        let v: serde_json::Value = resp.json().await?;
        let emb = v
            .get("embedding")
            .and_then(|e| e.as_array())
            .ok_or_else(|| anyhow::anyhow!("Ollama: missing 'embedding' field in response"))?;
        emb.iter()
            .map(|x| x.as_f64().map(|f| f as f32).ok_or_else(|| anyhow::anyhow!("non-float in embedding")))
            .collect()
    }
}

impl EmbedClient for HttpEmbedClient {
    fn embed_batch<'a>(
        &'a self,
        texts: &'a [&'a str],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<f32>>>> + Send + 'a>> {
        Box::pin(async move {
            let mut all: Vec<Vec<f32>> = Vec::with_capacity(texts.len());

            for chunk in texts.chunks(self.batch_size) {
                // Try OpenAI-compat batch first.
                if let Some(vecs) = self.try_openai(chunk).await {
                    all.extend(vecs);
                    continue;
                }
                // Fall back: Ollama single-text for each item in chunk.
                for text in chunk {
                    let v = self.ollama_single(text).await?;
                    all.push(v);
                }
            }

            Ok(all)
        })
    }

    fn dim(&self) -> usize { self.dim }
    fn model_id(&self) -> &str { &self.model }
}

// ---------------------------------------------------------------------------
// Blake3EmbedClient
// ---------------------------------------------------------------------------

/// Deterministic pseudo-vector client for testing / CI.
/// No HTTP calls; uses blake3 hash of input text.
#[derive(Debug, Clone)]
pub struct Blake3EmbedClient {
    dim: usize,
}

impl Blake3EmbedClient {
    pub fn new(dim: usize) -> Self { Self { dim } }

    fn pseudo_vector(&self, text: &str) -> Vec<f32> {
        let hash       = blake3::hash(text.as_bytes());
        let hash_bytes = hash.as_bytes();
        (0..self.dim)
            .map(|i| (hash_bytes[i % 32] as f32 / 127.5) - 1.0)
            .collect()
    }
}

impl EmbedClient for Blake3EmbedClient {
    fn embed_batch<'a>(
        &'a self,
        texts: &'a [&'a str],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<f32>>>> + Send + 'a>> {
        Box::pin(async move {
            Ok(texts.iter().map(|t| self.pseudo_vector(t)).collect())
        })
    }

    fn dim(&self) -> usize { self.dim }
    fn model_id(&self) -> &str { "blake3-pseudo" }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blake3_correct_dim() {
        let client = Blake3EmbedClient::new(128);
        let results = client.embed_batch(&["hello world"]).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].len(), 128);
    }

    #[tokio::test]
    async fn blake3_deterministic() {
        let client = Blake3EmbedClient::new(64);
        let a = client.embed_batch(&["same text"]).await.unwrap();
        let b = client.embed_batch(&["same text"]).await.unwrap();
        assert_eq!(a, b, "same input must produce same vector");
    }

    #[tokio::test]
    async fn blake3_different_inputs_differ() {
        let client = Blake3EmbedClient::new(64);
        let a = client.embed_batch(&["text A"]).await.unwrap();
        let b = client.embed_batch(&["text B"]).await.unwrap();
        assert_ne!(a, b, "different inputs should produce different vectors");
    }

    #[tokio::test]
    async fn blake3_batch_multiple() {
        let client = Blake3EmbedClient::new(32);
        let texts  = ["one", "two", "three"];
        let results = client.embed_batch(&texts).await.unwrap();
        assert_eq!(results.len(), 3);
        for v in &results {
            assert_eq!(v.len(), 32);
            for &x in v { assert!(x >= -1.0 && x <= 1.0); }
        }
    }

    #[tokio::test]
    async fn blake3_model_id() {
        let client = Blake3EmbedClient::new(8);
        assert_eq!(client.model_id(), "blake3-pseudo");
    }
}
