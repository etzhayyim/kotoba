/// WebGPU training backend (feature = "webgpu-train").
///
/// Architecture (ADR-2605250004, amended ADR-2605250005):
///   Vault FP8 bytes ──dequantize──▶ f32 GPU buffer
///   GPU (WGSL): MATMUL → CE_LOSS → MATMUL_AT → ADAMW
///   f32 result ──quantize──▶ FP8 bytes ──Vault.put──▶ new WeightRef
///
/// Scope: embedding table + LM head (2-layer fine-tuning).
/// wgpu = "24" (aligned with kami-engine).
use std::sync::Arc;

use bytes::Bytes;
use kotoba_core::cid::KotobaCid;
use kotoba_kse::vault::Vault;
use kotoba_kqe::delta::Delta;

use crate::gpu_common::{
    dequantize_fp8_e4m3, quantize_f32_to_fp8_e4m3,
    cpu_matmul, f32_slice_to_bytes, bytes_to_f32_slice,
    MATMUL_WGSL,
};
use crate::train::{AdamMoments, GradientRef, OptimizerStep, TrainBatch};
use crate::weight::{WeightKind, WeightRef};

// ── Additional WGSL shaders (training-only) ───────────────────────────────────

/// Backward pass: G[n,k] = A^T[n,m] × delta[m,k]  (weight gradient)
const MATMUL_AT_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read>       a     : array<f32>;
@group(0) @binding(1) var<storage, read>       delta : array<f32>;
@group(0) @binding(2) var<storage, read_write> g     : array<f32>;
@group(0) @binding(3) var<uniform>             dims  : vec3<u32>; // m, n, k

@compute @workgroup_size(16, 16)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.x;
    let col = gid.y;
    let m = dims.x; let n = dims.y; let k = dims.z;
    if (row >= n || col >= k) { return; }
    var acc = 0.0f;
    for (var i = 0u; i < m; i++) {
        acc += a[i * n + row] * delta[i * k + col];
    }
    g[row * k + col] = acc;
}
"#;

/// Quality-weighted cross-entropy loss + logit gradient.
const CE_LOSS_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read>       logits  : array<f32>;
@group(0) @binding(1) var<storage, read>       labels  : array<u32>;
@group(0) @binding(2) var<storage, read_write> grad    : array<f32>;
@group(0) @binding(3) var<uniform>             params  : vec3<f32>; // seq_len, vocab_size, quality

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let t       = gid.x;
    let seq_len = u32(params.x);
    let vocab   = u32(params.y);
    let quality = params.z;
    if (t >= seq_len) { return; }

    var max_v = logits[t * vocab];
    for (var v = 1u; v < vocab; v++) {
        max_v = max(max_v, logits[t * vocab + v]);
    }
    var sum_exp = 0.0f;
    for (var v = 0u; v < vocab; v++) {
        sum_exp += exp(logits[t * vocab + v] - max_v);
    }
    let log_sum = log(sum_exp);

    let label = labels[t];
    let scale = quality / f32(seq_len);
    for (var v = 0u; v < vocab; v++) {
        let softmax_v = exp(logits[t * vocab + v] - max_v - log_sum);
        let indicator = select(0.0f, 1.0f, v == label);
        grad[t * vocab + v] = (softmax_v - indicator) * scale;
    }
}
"#;

/// AdamW optimizer: in-place weight update.
const ADAMW_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read_write> w  : array<f32>;
@group(0) @binding(1) var<storage, read>       g  : array<f32>;
@group(0) @binding(2) var<storage, read_write> m1 : array<f32>;
@group(0) @binding(3) var<storage, read_write> m2 : array<f32>;
@group(0) @binding(4) var<uniform>             hp : array<f32, 7>; // lr,b1,b2,eps,wd,step,n

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    let n = u32(hp[6]);
    if (i >= n) { return; }

    let lr = hp[0]; let b1 = hp[1]; let b2 = hp[2];
    let eps = hp[3]; let wd = hp[4]; let t = hp[5];

    let gi  = g[i];
    let m1i = b1 * m1[i] + (1.0f - b1) * gi;
    let m2i = b2 * m2[i] + (1.0f - b2) * gi * gi;
    m1[i] = m1i;
    m2[i] = m2i;

    let m1_hat = m1i / (1.0f - pow(b1, t));
    let m2_hat = m2i / (1.0f - pow(b2, t));
    w[i] = w[i] * (1.0f - lr * wd) - lr * m1_hat / (sqrt(m2_hat) + eps);
}
"#;

// ── AdamConfig ────────────────────────────────────────────────────────────────

/// AdamW hyperparameters.
#[derive(Debug, Clone)]
pub struct AdamConfig {
    pub lr:           f32,
    pub beta1:        f32,
    pub beta2:        f32,
    pub eps:          f32,
    pub weight_decay: f32,
}

impl Default for AdamConfig {
    fn default() -> Self {
        Self { lr: 1e-4, beta1: 0.9, beta2: 0.999, eps: 1e-8, weight_decay: 0.01 }
    }
}

/// Result of one training step.
#[derive(Debug)]
pub struct TrainStepResult {
    /// Atomic Delta pairs for each updated weight: [retract_old, assert_new]
    pub weight_deltas:  Vec<[Delta; 2]>,
    /// Moment retract/assert quads for each weight: [retract_m1, retract_m2, assert_m1, assert_m2]
    pub moment_deltas:  Vec<[Delta; 4]>,
    /// Gradient retract deltas (apply after weight_deltas to clean up ephemeral grads)
    pub grad_retracts:  Vec<Delta>,
}

/// WebGPU-backed fine-tuner for embedding + LM head (2-layer scope).
pub struct WebGpuTrainer {
    pub vault:  Arc<Vault>,
    pub config: AdamConfig,
    pub step:   u64,
}

impl WebGpuTrainer {
    pub fn new(vault: Arc<Vault>, config: AdamConfig) -> Self {
        Self { vault, config, step: 0 }
    }

    /// Execute one fine-tuning step (CPU emulation of WGSL logic; no wgpu device needed).
    pub async fn train_step(
        &mut self,
        model_cid:    KotobaCid,
        graph_cid:    KotobaCid,
        embed_ref:    &WeightRef,
        lmhead_ref:   &WeightRef,
        embed_m:      Option<&AdamMoments>,
        lmhead_m:     Option<&AdamMoments>,
        batch:        &TrainBatch,
        vocab_size:   u32,
        hidden_dim:   u32,
    ) -> anyhow::Result<TrainStepResult> {
        self.step += 1;
        let t = self.step as f32;

        let embed_bytes  = self.vault.get(&embed_ref.blob_cid).await
            .ok_or_else(|| anyhow::anyhow!("embed weight not found in Vault"))?;
        let lmhead_bytes = self.vault.get(&lmhead_ref.blob_cid).await
            .ok_or_else(|| anyhow::anyhow!("lmhead weight not found in Vault"))?;

        let mut embed_f32  = dequantize_fp8_e4m3(&embed_bytes);
        let mut lmhead_f32 = dequantize_fp8_e4m3(&lmhead_bytes);

        let seq_len = batch.input_tokens.len();
        let v       = vocab_size as usize;
        let h       = hidden_dim as usize;

        let (mut embed_m1, mut embed_m2)   = load_or_init_moments(&self.vault, embed_m,  embed_f32.len()).await;
        let (mut lmhead_m1, mut lmhead_m2) = load_or_init_moments(&self.vault, lmhead_m, lmhead_f32.len()).await;

        // Forward: embed lookup
        let mut hidden = vec![0.0f32; seq_len * h];
        for (ti, &tok) in batch.input_tokens.iter().enumerate() {
            let row = (tok as usize).min(v - 1);
            hidden[ti * h..ti * h + h].copy_from_slice(&embed_f32[row * h..(row + 1) * h]);
        }

        // Forward: LM head
        let mut logits = vec![0.0f32; seq_len * v];
        cpu_matmul(&hidden, &lmhead_f32, &mut logits, seq_len, h, v);

        // CE loss gradient
        let mut logit_grad = vec![0.0f32; seq_len * v];
        cpu_ce_loss_grad(&logits, &batch.target_tokens, &mut logit_grad, batch.quality, v);

        // Backward: LM head gradient
        let mut grad_lmhead = vec![0.0f32; h * v];
        cpu_matmul_at(&hidden, &logit_grad, &mut grad_lmhead, seq_len, h, v);

        // Backward: embed gradient
        let mut grad_embed = vec![0.0f32; v * h];
        {
            let mut lmhead_t = vec![0.0f32; v * h];
            for i in 0..h { for j in 0..v { lmhead_t[j * h + i] = lmhead_f32[i * v + j]; } }
            let mut delta_hidden = vec![0.0f32; seq_len * h];
            cpu_matmul(&logit_grad, &lmhead_t, &mut delta_hidden, seq_len, v, h);
            for (ti, &tok) in batch.input_tokens.iter().enumerate() {
                let row = (tok as usize).min(v - 1);
                for j in 0..h { grad_embed[row * h + j] += delta_hidden[ti * h + j]; }
            }
        }

        // AdamW update
        let cfg = &self.config;
        adamw_step(&mut embed_f32,  &grad_embed,  &mut embed_m1,  &mut embed_m2,  cfg, t);
        adamw_step(&mut lmhead_f32, &grad_lmhead, &mut lmhead_m1, &mut lmhead_m2, cfg, t);

        // Quantize → Vault
        let new_embed_bytes  = Bytes::from(quantize_f32_to_fp8_e4m3(&embed_f32));
        let new_lmhead_bytes = Bytes::from(quantize_f32_to_fp8_e4m3(&lmhead_f32));
        let new_embed_blob   = self.vault.put(new_embed_bytes).await;
        let new_lmhead_blob  = self.vault.put(new_lmhead_bytes).await;

        let new_em1_blob = self.vault.put(Bytes::from(f32_slice_to_bytes(&embed_m1))).await;
        let new_em2_blob = self.vault.put(Bytes::from(f32_slice_to_bytes(&embed_m2))).await;
        let new_lm1_blob = self.vault.put(Bytes::from(f32_slice_to_bytes(&lmhead_m1))).await;
        let new_lm2_blob = self.vault.put(Bytes::from(f32_slice_to_bytes(&lmhead_m2))).await;

        // Build Delta payloads
        let embed_step = OptimizerStep {
            model_cid:      model_cid.clone(),
            kind:           WeightKind::Embed,
            old_weight_cid: embed_ref.blob_cid.clone(),
            new_weight_cid: new_embed_blob.cid.clone(),
            shape:          embed_ref.shape.clone(),
            step:           self.step,
        };
        let lmhead_step = OptimizerStep {
            model_cid:      model_cid.clone(),
            kind:           WeightKind::LmHead,
            old_weight_cid: lmhead_ref.blob_cid.clone(),
            new_weight_cid: new_lmhead_blob.cid.clone(),
            shape:          lmhead_ref.shape.clone(),
            step:           self.step,
        };

        let embed_grad_ref = GradientRef {
            model_cid: model_cid.clone(),
            kind:      WeightKind::Embed,
            step:      self.step,
            blob_cid:  new_embed_blob.cid.clone(),
            shape:     embed_ref.shape.clone(),
        };
        let lmhead_grad_ref = GradientRef {
            model_cid: model_cid.clone(),
            kind:      WeightKind::LmHead,
            step:      self.step,
            blob_cid:  new_lmhead_blob.cid.clone(),
            shape:     lmhead_ref.shape.clone(),
        };

        let new_embed_moments = AdamMoments {
            model_cid: model_cid.clone(),
            kind:      WeightKind::Embed,
            m1_cid:    new_em1_blob.cid,
            m2_cid:    new_em2_blob.cid,
            shape:     embed_ref.shape.clone(),
        };
        let new_lmhead_moments = AdamMoments {
            model_cid: model_cid.clone(),
            kind:      WeightKind::LmHead,
            m1_cid:    new_lm1_blob.cid,
            m2_cid:    new_lm2_blob.cid,
            shape:     lmhead_ref.shape.clone(),
        };

        let embed_moment_deltas  = moment_swap_deltas(embed_m,  &new_embed_moments,  graph_cid.clone());
        let lmhead_moment_deltas = moment_swap_deltas(lmhead_m, &new_lmhead_moments, graph_cid.clone());

        Ok(TrainStepResult {
            weight_deltas: vec![
                embed_step.weight_deltas(graph_cid.clone()),
                lmhead_step.weight_deltas(graph_cid.clone()),
            ],
            moment_deltas: vec![embed_moment_deltas, lmhead_moment_deltas],
            grad_retracts: vec![
                embed_grad_ref.to_retract_delta(graph_cid.clone()),
                lmhead_grad_ref.to_retract_delta(graph_cid),
            ],
        })
    }
}

// ── CPU kernels ───────────────────────────────────────────────────────────────

fn cpu_matmul_at(a: &[f32], delta: &[f32], g: &mut [f32], m: usize, n: usize, k: usize) {
    for row in 0..n {
        for col in 0..k {
            let mut acc = 0.0f32;
            for i in 0..m { acc += a[i * n + row] * delta[i * k + col]; }
            g[row * k + col] = acc;
        }
    }
}

fn cpu_ce_loss_grad(logits: &[f32], labels: &[u32], grad: &mut [f32], quality: f32, vocab: usize) {
    let seq_len = labels.len();
    let scale   = quality / seq_len as f32;
    for t in 0..seq_len {
        let base  = t * vocab;
        let slice = &logits[base..base + vocab];
        let max_v = slice.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let sum_e: f32 = slice.iter().map(|&x| (x - max_v).exp()).sum();
        let label = labels[t] as usize;
        for v in 0..vocab {
            let sm = ((logits[base + v] - max_v).exp()) / sum_e;
            grad[base + v] = (sm - if v == label { 1.0 } else { 0.0 }) * scale;
        }
    }
}

fn adamw_step(w: &mut [f32], g: &[f32], m1: &mut [f32], m2: &mut [f32], cfg: &AdamConfig, t: f32) {
    let (b1, b2) = (cfg.beta1, cfg.beta2);
    let bias1 = 1.0 - b1.powf(t);
    let bias2 = 1.0 - b2.powf(t);
    for i in 0..w.len() {
        m1[i] = b1 * m1[i] + (1.0 - b1) * g[i];
        m2[i] = b2 * m2[i] + (1.0 - b2) * g[i] * g[i];
        let m1h = m1[i] / bias1;
        let m2h = m2[i] / bias2;
        w[i] = w[i] * (1.0 - cfg.lr * cfg.weight_decay) - cfg.lr * m1h / (m2h.sqrt() + cfg.eps);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn load_or_init_moments(vault: &Vault, moments: Option<&AdamMoments>, n: usize) -> (Vec<f32>, Vec<f32>) {
    if let Some(m) = moments {
        let m1_bytes = vault.get(&m.m1_cid).await;
        let m2_bytes = vault.get(&m.m2_cid).await;
        if let (Some(b1), Some(b2)) = (m1_bytes, m2_bytes) {
            return (bytes_to_f32_slice(&b1), bytes_to_f32_slice(&b2));
        }
    }
    (vec![0.0f32; n], vec![0.0f32; n])
}

fn moment_swap_deltas(old: Option<&AdamMoments>, new_m: &AdamMoments, graph_cid: KotobaCid) -> [Delta; 4] {
    let retracts: [Delta; 2] = if let Some(old_m) = old {
        old_m.to_retract_deltas(graph_cid.clone())
    } else {
        new_m.to_retract_deltas(graph_cid.clone())
    };
    let asserts = new_m.to_assert_deltas(graph_cid);
    [retracts[0].clone(), retracts[1].clone(), asserts[0].clone(), asserts[1].clone()]
}

/// Returns all WGSL source strings for training pipeline.
pub fn wgsl_shaders() -> [(&'static str, &'static str); 4] {
    [
        ("matmul",    MATMUL_WGSL),
        ("matmul_at", MATMUL_AT_WGSL),
        ("ce_loss",   CE_LOSS_WGSL),
        ("adamw",     ADAMW_WGSL),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ce_loss_grad_sums_to_zero_for_uniform_logits() {
        let vocab   = 4usize;
        let seq_len = 2usize;
        let logits  = vec![0.0f32; seq_len * vocab];
        let labels  = vec![0u32, 1u32];
        let mut grad = vec![0.0f32; seq_len * vocab];
        cpu_ce_loss_grad(&logits, &labels, &mut grad, 1.0, vocab);
        for t in 0..seq_len {
            let s: f32 = grad[t * vocab..t * vocab + vocab].iter().sum();
            assert!((s).abs() < 1e-6, "grad sum for token {t} = {s}");
        }
    }

    #[test]
    fn adamw_step_decreases_weight() {
        let mut w  = vec![1.0f32];
        let g      = vec![1.0f32];
        let mut m1 = vec![0.0f32];
        let mut m2 = vec![0.0f32];
        let cfg    = AdamConfig::default();
        adamw_step(&mut w, &g, &mut m1, &mut m2, &cfg, 1.0);
        assert!(w[0] < 1.0, "weight should decrease: {}", w[0]);
    }

    #[test]
    fn matmul_at_transpose() {
        // A^T × delta: A=[1,2;3,4] (2×2), delta=[1,0;0,1] (identity) → A^T=[1,3;2,4]
        let a     = vec![1.0f32, 2.0, 3.0, 4.0]; // 2×2
        let delta = vec![1.0f32, 0.0, 0.0, 1.0]; // 2×2 identity
        let mut g = vec![0.0f32; 4];
        cpu_matmul_at(&a, &delta, &mut g, 2, 2, 2);
        assert_eq!(g, vec![1.0, 3.0, 2.0, 4.0]);
    }

    #[test]
    fn adam_config_default_fields() {
        let cfg = AdamConfig::default();
        assert!((cfg.lr           - 1e-4).abs() < 1e-10);
        assert!((cfg.beta1        - 0.9 ).abs() < 1e-10);
        assert!((cfg.beta2        - 0.999).abs() < 1e-10);
        assert!((cfg.eps          - 1e-8).abs() < 1e-15);
        assert!((cfg.weight_decay - 0.01).abs() < 1e-10);
    }

    #[test]
    fn adam_config_clone_is_equal() {
        let cfg   = AdamConfig::default();
        let cfg2  = cfg.clone();
        // No PartialEq on AdamConfig — compare fields manually
        assert!((cfg.lr - cfg2.lr).abs() < 1e-15);
        assert!((cfg.beta1 - cfg2.beta1).abs() < 1e-15);
        assert!((cfg.beta2 - cfg2.beta2).abs() < 1e-15);
    }

    #[test]
    fn adam_config_debug_contains_lr() {
        let cfg = AdamConfig::default();
        let s   = format!("{:?}", cfg);
        assert!(s.contains("lr"), "Debug output must mention 'lr': {s}");
    }

    #[test]
    fn wgsl_shaders_returns_four_entries() {
        let shaders = wgsl_shaders();
        assert_eq!(shaders.len(), 4);
    }

    #[test]
    fn wgsl_shaders_has_expected_names() {
        let shaders = wgsl_shaders();
        let names: Vec<&str> = shaders.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["matmul", "matmul_at", "ce_loss", "adamw"]);
    }

    #[test]
    fn wgsl_shaders_source_non_empty() {
        for (name, src) in wgsl_shaders() {
            assert!(!src.is_empty(), "shader '{name}' must have non-empty WGSL source");
            assert!(src.contains("@compute"), "shader '{name}' must contain @compute");
        }
    }

    #[test]
    fn ce_loss_grad_correct_label_gets_negative_gradient() {
        // For a single token with one-hot label=0, the gradient at position 0
        // should be (softmax_0 - 1) * scale < 0.
        let vocab   = 3usize;
        let logits  = vec![2.0f32, 0.0, 0.0]; // label 0 has highest logit
        let labels  = vec![0u32];
        let mut grad = vec![0.0f32; vocab];
        cpu_ce_loss_grad(&logits, &labels, &mut grad, 1.0, vocab);
        assert!(grad[0] < 0.0, "gradient at correct label should be negative: {}", grad[0]);
        assert!(grad[1] > 0.0, "gradient at incorrect label should be positive: {}", grad[1]);
    }

    #[test]
    fn adamw_zero_gradient_applies_weight_decay_only() {
        let mut w  = vec![1.0f32];
        let g      = vec![0.0f32]; // zero gradient
        let mut m1 = vec![0.0f32];
        let mut m2 = vec![0.0f32];
        let cfg    = AdamConfig::default();
        adamw_step(&mut w, &g, &mut m1, &mut m2, &cfg, 1.0);
        // With zero gradient, weight decay only: w ≈ w*(1 - lr*wd) = 1*(1 - 1e-4*0.01) ≈ 0.999999
        assert!(w[0] < 1.0, "weight decay must reduce weight even with zero gradient: {}", w[0]);
        assert!(w[0] > 0.999, "weight decay alone should not reduce too much: {}", w[0]);
    }
}
