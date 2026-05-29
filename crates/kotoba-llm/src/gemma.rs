/// Gemma local inference runner via candle-transformers.
///
/// Uses `candle_transformers::models::gemma2` — the Gemma 2 module which covers
/// the GQA + RoPE + SwiGLU architecture family.
///
/// Hardware selection at runtime:
///   - macOS (Apple Silicon): Metal GPU (BF16)
///   - other: CPU (F32)
///
/// Only compiled when the `local-inference` feature is enabled:
///   cargo build -p kotoba-llm --features local-inference
#[cfg(feature = "local-inference")]
mod inner {
    use anyhow::Result;
    use candle_core::{DType, Device, Tensor};
    use candle_nn::VarBuilder;
    use candle_transformers::generation::LogitsProcessor;
    use candle_transformers::models::gemma2::{Config as GemmaConfig, Model as GemmaModel};
    use hf_hub::api::tokio::Api;
    use hf_hub::{Repo, RepoType};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use tokenizers::Tokenizer;

    /// HuggingFace repo for the target model (Gemma 2 2B instruction-tuned, ~5 GB).
    pub const GEMMA_REPO: &str = "google/gemma-2-2b-it";

    /// A loaded Gemma model + tokenizer, ready for synchronous generate() calls.
    ///
    /// Wrap in `Arc<std::sync::Mutex<GemmaRunner>>` when sharing across threads.
    pub struct GemmaRunner {
        pub model: GemmaModel,
        pub tokenizer: Tokenizer,
        pub device: Device,
    }

    impl GemmaRunner {
        /// Download (or load from HuggingFace cache) the model and initialise.
        ///
        /// On macOS selects Metal GPU 0 (BF16); falls back to CPU (F32).
        /// On other platforms uses CPU (F32).
        pub async fn load() -> Result<Self> {
            let device = Self::select_device();
            let dtype = if matches!(device, Device::Metal(_)) {
                DType::BF16
            } else {
                DType::F32
            };

            tracing::info!(
                device = ?device,
                dtype  = ?dtype,
                repo   = GEMMA_REPO,
                "GemmaRunner: loading model"
            );

            let api = Api::new()?;
            let repo = api.repo(Repo::new(GEMMA_REPO.to_string(), RepoType::Model));

            let config_path = repo.get("config.json").await?;
            let tokenizer_path = repo.get("tokenizer.json").await?;

            let model_paths: Vec<PathBuf> = if let Ok(p) = repo.get("model.safetensors").await {
                vec![p]
            } else {
                let index_path = repo.get("model.safetensors.index.json").await?;
                let index_text = std::fs::read_to_string(&index_path)?;
                let index: serde_json::Value = serde_json::from_str(&index_text)?;
                let mut files: HashSet<String> = HashSet::new();
                if let Some(wm) = index.get("weight_map").and_then(|v| v.as_object()) {
                    for v in wm.values() {
                        if let Some(s) = v.as_str() {
                            files.insert(s.to_string());
                        }
                    }
                }
                let mut paths = Vec::new();
                for f in files {
                    paths.push(repo.get(&f).await?);
                }
                paths.sort();
                paths
            };

            let config: GemmaConfig =
                serde_json::from_str(&std::fs::read_to_string(&config_path)?)?;
            let tokenizer = Tokenizer::from_file(&tokenizer_path)
                .map_err(|e| anyhow::anyhow!("tokenizer load error: {e}"))?;

            // Safety: mmap is read-only; all data is already on disk before this call.
            let vb = unsafe { VarBuilder::from_mmaped_safetensors(&model_paths, dtype, &device)? };

            let model = GemmaModel::new(/* use_flash_attn */ false, &config, vb)?;

            Ok(Self {
                model,
                tokenizer,
                device,
            })
        }

        /// Run text generation synchronously.
        pub fn generate(&mut self, prompt: &str, max_new_tokens: usize) -> anyhow::Result<String> {
            let max_new_tokens = max_new_tokens.max(1);

            let encoding = self
                .tokenizer
                .encode(prompt, true)
                .map_err(|e| anyhow::anyhow!("tokenizer encode error: {e}"))?;
            let mut tokens: Vec<u32> = encoding.get_ids().to_vec();

            let eos_token = self
                .tokenizer
                .token_to_id("<eos>")
                .or_else(|| self.tokenizer.token_to_id("</s>"))
                .or_else(|| self.tokenizer.token_to_id("<end_of_turn>"))
                .unwrap_or(1);

            let mut logits_processor = LogitsProcessor::new(42, Some(0.7), Some(0.9));
            let mut generated: Vec<u32> = Vec::new();

            self.model.clear_kv_cache();

            for idx in 0..max_new_tokens {
                let (input_slice, seqlen_offset) = if idx == 0 {
                    (tokens.as_slice(), 0usize)
                } else {
                    let last = &tokens[tokens.len() - 1..];
                    (last, tokens.len() - 1)
                };

                let input = Tensor::new(input_slice, &self.device)?.unsqueeze(0)?;
                let logits = self.model.forward(&input, seqlen_offset)?;
                let logits = logits.squeeze(0)?;
                let seq_len = logits.dim(0)?;
                let last_logits = logits.get(seq_len - 1)?;

                let next_token = logits_processor.sample(&last_logits)?;

                if next_token == eos_token {
                    break;
                }
                tokens.push(next_token);
                generated.push(next_token);
            }

            let text = self
                .tokenizer
                .decode(&generated, true)
                .map_err(|e| anyhow::anyhow!("tokenizer decode error: {e}"))?;
            Ok(text)
        }

        fn select_device() -> Device {
            #[cfg(target_os = "macos")]
            {
                match Device::new_metal(0) {
                    Ok(d) => {
                        tracing::info!("GemmaRunner: Metal GPU selected");
                        return d;
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, "Metal unavailable, falling back to CPU");
                    }
                }
            }
            Device::Cpu
        }
    }
}

#[cfg(feature = "local-inference")]
pub use inner::{GemmaRunner, GEMMA_REPO};
