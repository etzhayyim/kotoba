/// OpenAI-compatible HTTP inference engine.
///
/// Works with any OpenAI-compatible endpoint: Ollama, vLLM, Vultr A16.
///
/// Environment variables:
///   KOTOBA_INFERENCE_URL   — base URL (e.g. http://localhost:11434 for Ollama)
///   KOTOBA_INFERENCE_MODEL — model name (default: gemma2:2b)
///
/// Wire format: POST /v1/chat/completions (OpenAI chat completions API).
///
/// Only compiled when the `http-inference` feature is enabled.
#[cfg(feature = "http-inference")]
mod inner {
    use anyhow::{anyhow, Result};

    /// Synchronous HTTP inference engine backed by reqwest on a dedicated runtime.
    #[derive(Clone)]
    pub struct HttpInferEngine {
        base_url: String,
        model: String,
    }

    impl HttpInferEngine {
        /// Construct from environment variables.
        ///
        /// Requires `KOTOBA_INFERENCE_URL`.
        /// `KOTOBA_INFERENCE_MODEL` defaults to `"gemma4:e4b"`.
        pub fn from_env() -> Result<Self> {
            let base_url = std::env::var("KOTOBA_INFERENCE_URL")
                .map_err(|_| anyhow!("KOTOBA_INFERENCE_URL not set"))?;
            let model = std::env::var("KOTOBA_INFERENCE_MODEL")
                .unwrap_or_else(|_| "gemma4:e4b".to_string());
            Ok(Self {
                base_url: base_url.trim_end_matches('/').to_string(),
                model,
            })
        }

        /// Synchronous generate — drives the HTTP call on a dedicated OS thread
        /// with its own current-thread runtime.
        ///
        /// The WASM host `llm.infer` import is invoked from the runtime context
        /// of whatever thread is executing the guest — which may be a tokio
        /// worker thread (nested `block_on` / nested runtime is illegal) or a
        /// `spawn_blocking` pool thread (`block_in_place` is illegal). A reqwest
        /// client is also bound to the reactor of the runtime that built it, so
        /// reusing a startup-built client here fails with "error sending
        /// request". Spawning a fresh thread + fresh runtime + fresh client
        /// (in `generate_async`) sidesteps all three hazards.
        pub fn generate(&self, prompt: &str, max_tokens: usize) -> Result<String> {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        rt.block_on(self.generate_async(prompt, max_tokens))
                    })
                    .join()
                    .map_err(|_| anyhow!("inference thread panicked"))?
            })
        }

        async fn generate_async(&self, prompt: &str, max_tokens: usize) -> Result<String> {
            // Build the client inside the runtime that drives it (see `generate`).
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()?;
            let url = format!("{}/v1/chat/completions", self.base_url);
            let body = serde_json::json!({
                "model": self.model,
                "messages": [{ "role": "user", "content": prompt }],
                "max_tokens": max_tokens,
                "stream": false,
            });
            let resp = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    anyhow!(
                        "http send to {url} failed (timeout={} connect={} request={} body={}): {e} :: source={:?}",
                        e.is_timeout(),
                        e.is_connect(),
                        e.is_request(),
                        e.is_body(),
                        std::error::Error::source(&e)
                    )
                })?
                .error_for_status()?;

            let json: serde_json::Value = resp.json().await?;
            let text = json["choices"][0]["message"]["content"]
                .as_str()
                .ok_or_else(|| anyhow!("missing choices[0].message.content in response"))?
                .to_string();
            Ok(text)
        }
    }
}

#[cfg(feature = "http-inference")]
pub use inner::HttpInferEngine;
