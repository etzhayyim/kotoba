/// WebGPU Transformer inference backend (feature = "webgpu-infer").
///
/// Supports Gemma 4 E2B / E4B (configurable via WebGpuInferConfig).
/// dtype boundary: Vault FP8 → dequantize → f32 buffers.
/// KV cache: in-memory f32, session-scoped, not persisted (ADR-2605250005).
///
/// Predicate scheme (ADR-2605250005):
///   weight/embed / weight/lm_head / weight/norm/final
///   weight/block/{N}/attn/{q,k,v,o}
///   weight/block/{N}/ffn/{gate,up,down}
///   weight/block/{N}/norm/{attn,ffn}
use crate::gpu_common::{dequantize_fp8_e4m3, MATMUL_WGSL};

// ── WGSL shaders (inference-only) ─────────────────────────────────────────────

/// RMSNorm: y[i] = x[i] / sqrt(mean(x^2) + eps) * w[i]
/// Bindings: 0=x(in, H), 1=w(weight, H), 2=y(out, H), 3=params(H, eps)
const RMS_NORM_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read>       x      : array<f32>;
@group(0) @binding(1) var<storage, read>       w      : array<f32>;
@group(0) @binding(2) var<storage, read_write> y      : array<f32>;
@group(0) @binding(3) var<uniform>             params : vec2<f32>; // dim_f32, eps

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i   = gid.x;
    let dim = u32(params.x);
    let eps = params.y;
    if (i >= dim) { return; }

    var sum_sq = 0.0f;
    for (var j = 0u; j < dim; j++) { sum_sq += x[j] * x[j]; }
    let rms = sqrt(sum_sq / f32(dim) + eps);
    y[i] = x[i] / rms * w[i];
}
"#;

/// Rotary Position Embedding applied to Q or K: rotate pairs (i, i+head_dim/2).
/// theta_i = rope_theta^(-2i/head_dim).
/// Bindings: 0=qk(inout, n_heads×head_dim), 1=params(n_heads, head_dim, pos, rope_theta)
const ROPE_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read_write> qk     : array<f32>;
@group(0) @binding(1) var<uniform>             params : vec4<f32>; // n_heads, head_dim, pos, rope_theta

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let idx      = gid.x;
    let n_heads  = u32(params.x);
    let head_dim = u32(params.y);
    let pos      = params.z;
    let theta    = params.w;

    let half_hd  = head_dim / 2u;
    let total    = n_heads * half_hd;
    if (idx >= total) { return; }

    let h = idx / half_hd;
    let i = idx % half_hd;

    let angle    = pos / pow(theta, 2.0f * f32(i) / f32(head_dim));
    let cos_a    = cos(angle);
    let sin_a    = sin(angle);

    let base     = h * head_dim + i;
    let base2    = base + half_hd;

    let x0 = qk[base];
    let x1 = qk[base2];
    qk[base]  = x0 * cos_a - x1 * sin_a;
    qk[base2] = x0 * sin_a + x1 * cos_a;
}
"#;

/// Grouped Query Attention (single query position).
/// Q: [n_heads × head_dim], K/V cache: [seq_len × n_kv_heads × head_dim]
/// Bindings: 0=Q, 1=K_cache, 2=V_cache, 3=out[n_heads×head_dim],
///           4=params(n_heads, n_kv_heads, head_dim, seq_len)
const ATTENTION_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read>       q      : array<f32>;
@group(0) @binding(1) var<storage, read>       k_cache: array<f32>;
@group(0) @binding(2) var<storage, read>       v_cache: array<f32>;
@group(0) @binding(3) var<storage, read_write> out_buf: array<f32>;
@group(0) @binding(4) var<uniform>             params : vec4<f32>; // n_heads, n_kv_heads, head_dim, seq_len

@compute @workgroup_size(16, 16)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let h        = gid.x;
    let d        = gid.y;
    let n_heads  = u32(params.x);
    let n_kv     = u32(params.y);
    let head_dim = u32(params.z);
    let seq_len  = u32(params.w);
    if (h >= n_heads || d >= head_dim) { return; }

    let kv_h    = h * n_kv / n_heads; // GQA: map query head to kv head
    let scale   = 1.0f / sqrt(f32(head_dim));

    // Compute attention scores for each past position
    var scores  = array<f32, 4096>(); // max_seq_len — compile-time limit
    var max_s   = -1e38f;
    for (var s = 0u; s < seq_len; s++) {
        var dot = 0.0f;
        for (var i = 0u; i < head_dim; i++) {
            dot += q[h * head_dim + i] * k_cache[(s * n_kv + kv_h) * head_dim + i];
        }
        scores[s] = dot * scale;
        if (scores[s] > max_s) { max_s = scores[s]; }
    }

    // Softmax
    var sum_exp = 0.0f;
    for (var s = 0u; s < seq_len; s++) {
        scores[s] = exp(scores[s] - max_s);
        sum_exp  += scores[s];
    }

    // Weighted sum of V
    var acc = 0.0f;
    for (var s = 0u; s < seq_len; s++) {
        let w = scores[s] / sum_exp;
        acc  += w * v_cache[(s * n_kv + kv_h) * head_dim + d];
    }
    out_buf[h * head_dim + d] = acc;
}
"#;

/// SwiGLU FFN: out = down(silu(gate(x)) * up(x))
/// Bindings: 0=x[H], 1=gate_w[ffn×H], 2=up_w[ffn×H], 3=down_w[H×ffn],
///           4=tmp_gate[ffn], 5=tmp_up[ffn], 6=out[H], 7=params(H, ffn_dim)
const SWIGLU_FFN_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read>       x        : array<f32>;
@group(0) @binding(1) var<storage, read>       gate_w   : array<f32>;
@group(0) @binding(2) var<storage, read>       up_w     : array<f32>;
@group(0) @binding(3) var<storage, read>       down_w   : array<f32>;
@group(0) @binding(4) var<storage, read_write> tmp_gate : array<f32>;
@group(0) @binding(5) var<storage, read_write> tmp_up   : array<f32>;
@group(0) @binding(6) var<storage, read_write> out_buf  : array<f32>;
@group(0) @binding(7) var<uniform>             params   : vec2<f32>; // hidden_dim, ffn_dim

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i       = gid.x;
    let hidden  = u32(params.x);
    let ffn_dim = u32(params.y);

    if (i < ffn_dim) {
        // gate projection + SiLU
        var g = 0.0f;
        var u = 0.0f;
        for (var j = 0u; j < hidden; j++) {
            g += gate_w[i * hidden + j] * x[j];
            u += up_w[i * hidden + j] * x[j];
        }
        let silu_g = g / (1.0f + exp(-g)); // SiLU(x) = x * sigmoid(x)
        tmp_gate[i] = silu_g * u;
    }
    workgroupBarrier();

    if (i < hidden) {
        var acc = 0.0f;
        for (var j = 0u; j < ffn_dim; j++) {
            acc += down_w[i * ffn_dim + j] * tmp_gate[j];
        }
        out_buf[i] = acc;
    }
}
"#;

/// Greedy argmax sampling: returns index of max logit.
/// Bindings: 0=logits[vocab], 1=out_token[1], 2=params(vocab_size)
const SAMPLE_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read>       logits    : array<f32>;
@group(0) @binding(1) var<storage, read_write> out_token : array<u32>;
@group(0) @binding(2) var<uniform>             params    : vec2<f32>; // vocab_size, unused

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    // Single-thread reduction (workgroup 0, thread 0)
    if (gid.x != 0u) { return; }
    let vocab = u32(params.x);
    var best_val = logits[0];
    var best_idx = 0u;
    for (var i = 1u; i < vocab; i++) {
        if (logits[i] > best_val) { best_val = logits[i]; best_idx = i; }
    }
    out_token[0] = best_idx;
}
"#;

// ── Config ────────────────────────────────────────────────────────────────────

/// Transformer architecture configuration.
#[derive(Debug, Clone)]
pub struct WebGpuInferConfig {
    pub n_layers: u32,
    pub hidden_dim: u32,
    pub n_heads: u32,
    pub n_kv_heads: u32,
    pub head_dim: u32,
    pub ffn_dim: u32,
    pub vocab_size: u32,
    pub rope_theta: f32,
    pub max_seq_len: u32,
}

impl WebGpuInferConfig {
    /// Representative values for Gemma 4 E2B.
    pub fn gemma4_e2b() -> Self {
        Self {
            n_layers: 26,
            hidden_dim: 2048,
            n_heads: 8,
            n_kv_heads: 4,
            head_dim: 256,
            ffn_dim: 16384,
            vocab_size: 262144,
            rope_theta: 1_000_000.0,
            max_seq_len: 2048,
        }
    }

    /// Representative values for Gemma 4 E4B.
    pub fn gemma4_e4b() -> Self {
        Self {
            n_layers: 34,
            hidden_dim: 2560,
            n_heads: 16,
            n_kv_heads: 8,
            head_dim: 160,
            ffn_dim: 20480,
            vocab_size: 262144,
            rope_theta: 1_000_000.0,
            max_seq_len: 2048,
        }
    }
}

// ── Weight containers ─────────────────────────────────────────────────────────

/// Weights for one Transformer block (all f32, dequantized from FP8).
pub struct LayerWeights {
    pub attn_q: Vec<f32>,    // [n_heads*head_dim × hidden]
    pub attn_k: Vec<f32>,    // [n_kv_heads*head_dim × hidden]
    pub attn_v: Vec<f32>,    // [n_kv_heads*head_dim × hidden]
    pub attn_o: Vec<f32>,    // [hidden × n_heads*head_dim]
    pub ffn_gate: Vec<f32>,  // [ffn_dim × hidden]
    pub ffn_up: Vec<f32>,    // [ffn_dim × hidden]
    pub ffn_down: Vec<f32>,  // [hidden × ffn_dim]
    pub norm_attn: Vec<f32>, // [hidden]
    pub norm_ffn: Vec<f32>,  // [hidden]
}

/// All f32 weights for a Transformer model (dequantized from Vault FP8).
pub struct TransformerWeights {
    pub embed: Vec<f32>, // [vocab × hidden]
    pub layers: Vec<LayerWeights>,
    pub final_norm: Vec<f32>, // [hidden]
    pub lm_head: Vec<f32>,    // [hidden × vocab]
}

impl TransformerWeights {
    /// Create from raw f32 vecs (test / dev path).
    pub fn from_vecs(
        embed: Vec<f32>,
        layers: Vec<LayerWeights>,
        final_norm: Vec<f32>,
        lm_head: Vec<f32>,
    ) -> Self {
        Self {
            embed,
            layers,
            final_norm,
            lm_head,
        }
    }

    /// Load from Vault blobs (FP8 → f32 dequantize).
    pub async fn load_from_vault(
        vault: &kotoba_kse::vault::Vault,
        blobs: &TransformerBlobRefs,
    ) -> anyhow::Result<Self> {
        let load_cid = async |cid: kotoba_core::cid::KotobaCid| -> anyhow::Result<Vec<f32>> {
            let bytes = vault
                .get(&cid)
                .await
                .ok_or_else(|| anyhow::anyhow!("blob not found: {:?}", cid))?;
            Ok(dequantize_fp8_e4m3(&bytes))
        };

        let embed = load_cid(blobs.embed.clone()).await?;
        let final_norm = load_cid(blobs.final_norm.clone()).await?;
        let lm_head = load_cid(blobs.lm_head.clone()).await?;

        let mut layers = Vec::with_capacity(blobs.layers.len());
        for lb in &blobs.layers {
            layers.push(LayerWeights {
                attn_q: load_cid(lb.attn_q.clone()).await?,
                attn_k: load_cid(lb.attn_k.clone()).await?,
                attn_v: load_cid(lb.attn_v.clone()).await?,
                attn_o: load_cid(lb.attn_o.clone()).await?,
                ffn_gate: load_cid(lb.ffn_gate.clone()).await?,
                ffn_up: load_cid(lb.ffn_up.clone()).await?,
                ffn_down: load_cid(lb.ffn_down.clone()).await?,
                norm_attn: load_cid(lb.norm_attn.clone()).await?,
                norm_ffn: load_cid(lb.norm_ffn.clone()).await?,
            });
        }
        Ok(Self {
            embed,
            layers,
            final_norm,
            lm_head,
        })
    }
}

/// CID references for loading TransformerWeights from Vault.
pub struct LayerBlobRefs {
    pub attn_q: kotoba_core::cid::KotobaCid,
    pub attn_k: kotoba_core::cid::KotobaCid,
    pub attn_v: kotoba_core::cid::KotobaCid,
    pub attn_o: kotoba_core::cid::KotobaCid,
    pub ffn_gate: kotoba_core::cid::KotobaCid,
    pub ffn_up: kotoba_core::cid::KotobaCid,
    pub ffn_down: kotoba_core::cid::KotobaCid,
    pub norm_attn: kotoba_core::cid::KotobaCid,
    pub norm_ffn: kotoba_core::cid::KotobaCid,
}

pub struct TransformerBlobRefs {
    pub embed: kotoba_core::cid::KotobaCid,
    pub layers: Vec<LayerBlobRefs>,
    pub final_norm: kotoba_core::cid::KotobaCid,
    pub lm_head: kotoba_core::cid::KotobaCid,
}

// ── Inference session ─────────────────────────────────────────────────────────

/// Autoregressive inference session with KV cache.
///
/// KV cache layout per layer: `[seq_pos × n_kv_heads × head_dim]` (f32).
/// Cache grows one position at a time; errors on `seq_pos >= max_seq_len`.
pub struct WebGpuInferSession {
    pub config: WebGpuInferConfig,
    weights: TransformerWeights,
    /// k_cache[layer] = Vec<f32> growing as [s × n_kv_heads × head_dim]
    k_cache: Vec<Vec<f32>>,
    /// v_cache[layer] = Vec<f32> growing as [s × n_kv_heads × head_dim]
    v_cache: Vec<Vec<f32>>,
    seq_pos: usize,
}

impl WebGpuInferSession {
    pub fn new(config: WebGpuInferConfig, weights: TransformerWeights) -> Self {
        let n_layers = config.n_layers as usize;
        Self {
            k_cache: vec![Vec::new(); n_layers],
            v_cache: vec![Vec::new(); n_layers],
            seq_pos: 0,
            config,
            weights,
        }
    }

    /// Generate up to `max_new_tokens` tokens given `input_tokens` prompt.
    ///
    /// Returns the generated token IDs (not including input_tokens).
    pub fn generate(
        &mut self,
        input_tokens: &[u32],
        max_new_tokens: usize,
    ) -> anyhow::Result<Vec<u32>> {
        let mut output = Vec::with_capacity(max_new_tokens);

        // Prefill: process each prompt token, discard all but last logits
        for &tok in input_tokens {
            self.forward_one(tok)?;
        }

        // Sample the first output token from the last prefill position
        if !input_tokens.is_empty() {
            let next = self.sample_last()?;
            output.push(next);
            // Continuation: feed generated token back
            for _ in 1..max_new_tokens {
                let last = *output.last().unwrap();
                self.forward_one(last)?;
                let next = self.sample_last()?;
                output.push(next);
            }
        }

        Ok(output)
    }

    fn forward_one(&mut self, token: u32) -> anyhow::Result<()> {
        let cfg = &self.config;
        if self.seq_pos >= cfg.max_seq_len as usize {
            return Err(anyhow::anyhow!(
                "seq_pos {} exceeds max_seq_len {}",
                self.seq_pos,
                cfg.max_seq_len
            ));
        }

        let h = cfg.hidden_dim as usize;
        let nh = cfg.n_heads as usize;
        let nkv = cfg.n_kv_heads as usize;
        let hd = cfg.head_dim as usize;
        let v = cfg.vocab_size as usize;

        // Embed lookup
        let tok_row = (token as usize).min(v - 1);
        let mut hidden: Vec<f32> = self.weights.embed[tok_row * h..(tok_row + 1) * h].to_vec();

        for layer_idx in 0..self.config.n_layers as usize {
            let lw = &self.weights.layers[layer_idx];

            // Pre-attn RMSNorm
            let normed = cpu_rms_norm(&hidden, &lw.norm_attn, 1e-6);

            // Q, K, V projections: [n_?_heads × head_dim] = proj [n*hd × H] × normed [H]
            let q = cpu_matvec(&lw.attn_q, &normed, nh * hd, h);
            let k = cpu_matvec(&lw.attn_k, &normed, nkv * hd, h);
            let v_vec = cpu_matvec(&lw.attn_v, &normed, nkv * hd, h);

            // RoPE
            let q_rope = cpu_rope(&q, self.seq_pos, nh, hd, cfg.rope_theta);
            let k_rope = cpu_rope(&k, self.seq_pos, nkv, hd, cfg.rope_theta);

            // Append K, V to cache
            self.k_cache[layer_idx].extend_from_slice(&k_rope);
            self.v_cache[layer_idx].extend_from_slice(&v_vec);

            let seq_so_far = self.seq_pos + 1;

            // GQA attention
            let attn_out = cpu_gqa_attention(
                &q_rope,
                &self.k_cache[layer_idx],
                &self.v_cache[layer_idx],
                nh,
                nkv,
                hd,
                seq_so_far,
            );

            // O projection: [H × nh*hd] × attn_out[nh*hd]
            let attn_proj = cpu_matvec(&lw.attn_o, &attn_out, h, nh * hd);

            // Residual
            for i in 0..h {
                hidden[i] += attn_proj[i];
            }

            // Pre-FFN RMSNorm
            let normed_ffn = cpu_rms_norm(&hidden, &lw.norm_ffn, 1e-6);

            // SwiGLU FFN
            let ffn_dim = cfg.ffn_dim as usize;
            let ffn_out = cpu_swiglu(
                &normed_ffn,
                &lw.ffn_gate,
                &lw.ffn_up,
                &lw.ffn_down,
                h,
                ffn_dim,
            );

            // Residual
            for i in 0..h {
                hidden[i] += ffn_out[i];
            }
        }

        // Final norm + store as "last_hidden" for sampling
        let final_hidden = cpu_rms_norm(&hidden, &self.weights.final_norm, 1e-6);

        // Compute logits and store in session state
        let logits = cpu_matvec_t(&self.weights.lm_head, &final_hidden, v, h);
        // Store logits in a scratch field — embed last `vocab_size` floats in kv_cache[0] for now
        // (simpler than a separate field; generation loop calls sample_last immediately after)
        self.k_cache.push(logits); // temporary scratch — popped in sample_last

        self.seq_pos += 1;
        Ok(())
    }

    fn sample_last(&mut self) -> anyhow::Result<u32> {
        let logits = self
            .k_cache
            .pop()
            .ok_or_else(|| anyhow::anyhow!("no logits in scratch"))?;
        Ok(cpu_argmax(&logits))
    }
}

// ── CPU kernels (mirror WGSL, used in tests and fallback) ────────────────────

pub(crate) fn cpu_rms_norm(x: &[f32], w: &[f32], eps: f32) -> Vec<f32> {
    let sum_sq: f32 = x.iter().map(|&v| v * v).sum();
    let rms = (sum_sq / x.len() as f32 + eps).sqrt();
    x.iter()
        .zip(w.iter())
        .map(|(&xi, &wi)| xi / rms * wi)
        .collect()
}

/// Matrix-vector product: out[m] = A[m×n] × x[n]
pub(crate) fn cpu_matvec(a: &[f32], x: &[f32], m: usize, n: usize) -> Vec<f32> {
    (0..m)
        .map(|i| (0..n).map(|j| a[i * n + j] * x[j]).sum())
        .collect()
}

/// Transposed matrix-vector: out[m] = A^T[n×m-as-A[m×n]] × x[n]  → treats A as [n×m]
/// Used for lm_head: A is [hidden × vocab] stored as [H × V], we want [V] output from x[H].
fn cpu_matvec_t(a: &[f32], x: &[f32], m: usize, n: usize) -> Vec<f32> {
    // A stored as [n × m], we want A^T × x = [m] output
    // out[j] = sum_i A[i*m + j] * x[i]
    let mut out = vec![0.0f32; m];
    for i in 0..n {
        for j in 0..m {
            out[j] += a[i * m + j] * x[i];
        }
    }
    out
}

pub(crate) fn cpu_rope(
    x: &[f32],
    pos: usize,
    n_heads: usize,
    head_dim: usize,
    theta: f32,
) -> Vec<f32> {
    let mut out = x.to_vec();
    let half = head_dim / 2;
    for h in 0..n_heads {
        for i in 0..half {
            let angle = pos as f32 / theta.powf(2.0 * i as f32 / head_dim as f32);
            let (sin_a, cos_a) = angle.sin_cos();
            let base = h * head_dim + i;
            let base2 = base + half;
            let x0 = out[base];
            let x1 = out[base2];
            out[base] = x0 * cos_a - x1 * sin_a;
            out[base2] = x0 * sin_a + x1 * cos_a;
        }
    }
    out
}

/// GQA scaled dot-product attention for a single query position.
///
/// q: [n_heads × head_dim]
/// k_cache / v_cache: [seq_len × n_kv_heads × head_dim]
/// returns: [n_heads × head_dim]
pub(crate) fn cpu_gqa_attention(
    q: &[f32],
    k_cache: &[f32],
    v_cache: &[f32],
    n_heads: usize,
    n_kv: usize,
    hd: usize,
    seq_len: usize,
) -> Vec<f32> {
    let scale = 1.0 / (hd as f32).sqrt();
    let group_size = n_heads / n_kv;
    let mut out = vec![0.0f32; n_heads * hd];

    for h in 0..n_heads {
        let kv_h = h / group_size;
        let mut scores: Vec<f32> = (0..seq_len)
            .map(|s| {
                let q_off = h * hd;
                let k_off = (s * n_kv + kv_h) * hd;
                let dot: f32 = (0..hd).map(|d| q[q_off + d] * k_cache[k_off + d]).sum();
                dot * scale
            })
            .collect();

        // Softmax
        let max_s = scores.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let sum_e: f32 = scores.iter().map(|&s| (s - max_s).exp()).sum();
        for s in scores.iter_mut() {
            *s = (*s - max_s).exp() / sum_e;
        }

        // Weighted sum of V
        let out_off = h * hd;
        for s in 0..seq_len {
            let v_off = (s * n_kv + kv_h) * hd;
            let w = scores[s];
            for d in 0..hd {
                out[out_off + d] += w * v_cache[v_off + d];
            }
        }
    }
    out
}

pub(crate) fn cpu_swiglu(
    x: &[f32],
    gate_w: &[f32],
    up_w: &[f32],
    down_w: &[f32],
    hidden: usize,
    ffn_dim: usize,
) -> Vec<f32> {
    // gate and up projections
    let gate: Vec<f32> = (0..ffn_dim)
        .map(|i| {
            let g: f32 = (0..hidden).map(|j| gate_w[i * hidden + j] * x[j]).sum();
            let u: f32 = (0..hidden).map(|j| up_w[i * hidden + j] * x[j]).sum();
            let silu_g = g / (1.0 + (-g).exp()); // SiLU
            silu_g * u
        })
        .collect();

    // down projection
    (0..hidden)
        .map(|i| {
            (0..ffn_dim)
                .map(|j| down_w[i * ffn_dim + j] * gate[j])
                .sum()
        })
        .collect()
}

pub(crate) fn cpu_argmax(logits: &[f32]) -> u32 {
    let mut best_val = logits[0];
    let mut best_idx = 0u32;
    for (i, &v) in logits.iter().enumerate().skip(1) {
        if v > best_val {
            best_val = v;
            best_idx = i as u32;
        }
    }
    best_idx
}

/// Returns all WGSL source strings for inference pipeline.
pub fn wgsl_shaders() -> [(&'static str, &'static str); 6] {
    [
        ("matmul", MATMUL_WGSL),
        ("rms_norm", RMS_NORM_WGSL),
        ("rope", ROPE_WGSL),
        ("attention", ATTENTION_WGSL),
        ("swiglu_ffn", SWIGLU_FFN_WGSL),
        ("sample", SAMPLE_WGSL),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_config() -> WebGpuInferConfig {
        WebGpuInferConfig {
            n_layers: 2,
            hidden_dim: 8,
            n_heads: 2,
            n_kv_heads: 1,
            head_dim: 4,
            ffn_dim: 16,
            vocab_size: 16,
            rope_theta: 10_000.0,
            max_seq_len: 64,
        }
    }

    fn tiny_layer(h: usize, nh: usize, nkv: usize, hd: usize, ffn: usize) -> LayerWeights {
        LayerWeights {
            attn_q: vec![0.0; nh * hd * h],
            attn_k: vec![0.0; nkv * hd * h],
            attn_v: vec![0.0; nkv * hd * h],
            attn_o: vec![0.0; h * nh * hd],
            ffn_gate: vec![0.0; ffn * h],
            ffn_up: vec![0.0; ffn * h],
            ffn_down: vec![0.0; h * ffn],
            norm_attn: vec![1.0; h],
            norm_ffn: vec![1.0; h],
        }
    }

    fn tiny_weights(cfg: &WebGpuInferConfig) -> TransformerWeights {
        let h = cfg.hidden_dim as usize;
        let nh = cfg.n_heads as usize;
        let nkv = cfg.n_kv_heads as usize;
        let hd = cfg.head_dim as usize;
        let ffn = cfg.ffn_dim as usize;
        let v = cfg.vocab_size as usize;
        let layers = (0..cfg.n_layers as usize)
            .map(|_| tiny_layer(h, nh, nkv, hd, ffn))
            .collect();
        TransformerWeights {
            embed: vec![0.1; v * h],
            layers,
            final_norm: vec![1.0; h],
            lm_head: vec![0.0; h * v],
        }
    }

    #[test]
    fn rms_norm_unit_weight_is_normalized() {
        let x = vec![3.0f32, 4.0];
        let w = vec![1.0, 1.0];
        let y = cpu_rms_norm(&x, &w, 1e-6);
        let rms = ((3.0f32 * 3.0 + 4.0 * 4.0) / 2.0 + 1e-6).sqrt();
        assert!((y[0] - 3.0 / rms).abs() < 1e-5);
        assert!((y[1] - 4.0 / rms).abs() < 1e-5);
    }

    #[test]
    fn rope_zero_position_identity() {
        // At pos=0 all angles are 0 → cos=1, sin=0 → no rotation
        let x = vec![1.0f32, 2.0, 3.0, 4.0]; // 1 head × head_dim=4
        let y = cpu_rope(&x, 0, 1, 4, 10_000.0);
        assert!((y[0] - x[0]).abs() < 1e-5);
        assert!((y[1] - x[1]).abs() < 1e-5);
    }

    #[test]
    fn gqa_attention_uniform_scores_averages_v() {
        // If Q=0 → all scores equal → output = mean of V rows
        let n_heads = 2usize;
        let n_kv = 1usize;
        let hd = 2usize;
        let seq_len = 3usize;

        let q = vec![0.0f32; n_heads * hd];
        let k_cache = vec![1.0f32; seq_len * n_kv * hd];
        // V rows: [1,2], [3,4], [5,6]
        let v_cache = vec![1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0];

        let out = cpu_gqa_attention(&q, &k_cache, &v_cache, n_heads, n_kv, hd, seq_len);
        // Each head uses kv_head=0; uniform softmax → mean of rows
        assert!((out[0] - 3.0).abs() < 1e-4, "out[0]={}", out[0]); // mean of 1,3,5
        assert!((out[1] - 4.0).abs() < 1e-4, "out[1]={}", out[1]); // mean of 2,4,6
    }

    #[test]
    fn argmax_returns_max_index() {
        let logits = vec![0.1f32, 5.0, 2.3, 0.7];
        assert_eq!(cpu_argmax(&logits), 1);
    }

    #[test]
    fn session_generate_zero_weights_returns_token_zero() {
        let cfg = tiny_config();
        let weights = tiny_weights(&cfg);
        let mut session = WebGpuInferSession::new(cfg, weights);
        let tokens = session.generate(&[0u32], 2).unwrap();
        assert_eq!(tokens.len(), 2);
        // zero weights → uniform logits → argmax = 0
        assert_eq!(tokens[0], 0);
        assert_eq!(tokens[1], 0);
    }

    #[test]
    fn config_gemma4_e2b_shape() {
        let cfg = WebGpuInferConfig::gemma4_e2b();
        assert_eq!(cfg.n_layers, 26);
        assert_eq!(cfg.hidden_dim, 2048);
        assert!(
            cfg.n_heads % cfg.n_kv_heads == 0,
            "GQA: n_heads must be divisible by n_kv_heads"
        );
    }

    #[test]
    fn config_gemma4_e4b_shape() {
        let cfg = WebGpuInferConfig::gemma4_e4b();
        assert_eq!(cfg.n_layers, 34);
        assert!(cfg.n_heads % cfg.n_kv_heads == 0);
    }

    #[test]
    fn cpu_matvec_identity_matrix() {
        // 2×2 identity
        let a = vec![1.0f32, 0.0, 0.0, 1.0];
        let x = vec![3.0f32, 7.0];
        let out = cpu_matvec(&a, &x, 2, 2);
        assert!((out[0] - 3.0).abs() < 1e-6);
        assert!((out[1] - 7.0).abs() < 1e-6);
    }

    #[test]
    fn cpu_matvec_zero_input_gives_zero_output() {
        let a = vec![1.0f32, 2.0, 3.0, 4.0];
        let x = vec![0.0f32, 0.0];
        let out = cpu_matvec(&a, &x, 2, 2);
        assert!((out[0]).abs() < 1e-6);
        assert!((out[1]).abs() < 1e-6);
    }

    #[test]
    fn cpu_argmax_single_element() {
        let logits = vec![42.0f32];
        assert_eq!(cpu_argmax(&logits), 0);
    }

    #[test]
    fn cpu_argmax_last_element_is_max() {
        let logits = vec![0.1f32, 0.2, 0.3, 99.0];
        assert_eq!(cpu_argmax(&logits), 3);
    }

    #[test]
    fn cpu_rope_nonzero_pos_rotates() {
        // At pos=1 the first pair should be rotated — not identical to input
        let x = vec![1.0f32, 0.0, 0.0, 1.0]; // 1 head × head_dim=4
        let y = cpu_rope(&x, 1, 1, 4, 10_000.0);
        // The output should differ from input (rotation applied)
        let changed = x.iter().zip(y.iter()).any(|(a, b)| (a - b).abs() > 1e-6);
        assert!(changed, "cpu_rope at pos>0 must rotate the vector");
    }

    #[test]
    fn cpu_swiglu_zero_input_gives_zero_output() {
        let x = vec![0.0f32; 4];
        let gate_w = vec![1.0f32; 2 * 4]; // ffn_dim=2, hidden=4
        let up_w = vec![1.0f32; 2 * 4];
        let down_w = vec![1.0f32; 4 * 2];
        let out = cpu_swiglu(&x, &gate_w, &up_w, &down_w, 4, 2);
        for &v in &out {
            assert!(v.abs() < 1e-6, "zero input → zero output, got {v}");
        }
    }

    #[test]
    fn wgsl_shaders_returns_six_entries() {
        let shaders = wgsl_shaders();
        assert_eq!(shaders.len(), 6);
    }

    #[test]
    fn wgsl_shaders_names_are_unique() {
        let shaders = wgsl_shaders();
        let names: std::collections::HashSet<&str> = shaders.iter().map(|(n, _)| *n).collect();
        assert_eq!(names.len(), 6, "all shader names must be unique");
    }

    #[test]
    fn webgpu_infer_config_clone() {
        let orig = WebGpuInferConfig::gemma4_e2b();
        let cloned = orig.clone();
        assert_eq!(cloned.n_layers, orig.n_layers);
        assert_eq!(cloned.hidden_dim, orig.hidden_dim);
        assert_eq!(cloned.vocab_size, orig.vocab_size);
    }
}
