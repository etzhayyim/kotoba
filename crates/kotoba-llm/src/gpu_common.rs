/// Shared GPU utilities: FP8 codec, MATMUL WGSL, CPU matmul helper.
///
/// Used by both `train_gpu` (feature=webgpu-train) and `infer_gpu` (feature=webgpu-infer).
/// No feature gate — always compiled.

// ── WGSL shared shaders ───────────────────────────────────────────────────────

/// Matrix multiply: C[m,k] = A[m,n] × B[n,k]
/// Bindings: 0=A, 1=B, 2=C(out), 3=dims(m,n,k)
pub const MATMUL_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read>       a    : array<f32>;
@group(0) @binding(1) var<storage, read>       b    : array<f32>;
@group(0) @binding(2) var<storage, read_write> c    : array<f32>;
@group(0) @binding(3) var<uniform>             dims : vec3<u32>; // m, n, k

@compute @workgroup_size(16, 16)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.x;
    let col = gid.y;
    let m = dims.x; let n = dims.y; let k = dims.z;
    if (row >= m || col >= k) { return; }
    var acc = 0.0f;
    for (var i = 0u; i < n; i++) {
        acc += a[row * n + i] * b[i * k + col];
    }
    c[row * k + col] = acc;
}
"#;

// ── FP8 E4M3FN codec (CPU-side) ───────────────────────────────────────────────

/// Dequantize FP8 E4M3FN bytes → f32 vec.
///
/// E4M3FN: sign=1 / exp=4 (bias 7) / mantissa=3 bits.
/// NaN sentinel: exp=0x0F AND man=0x07 only (S_1111_111).
pub fn dequantize_fp8_e4m3(bytes: &[u8]) -> Vec<f32> {
    bytes.iter().map(|&b| {
        let sign     = if b & 0x80 != 0 { -1.0f32 } else { 1.0f32 };
        let exp_bits = (b >> 3) & 0x0F;
        let man_bits = b & 0x07;
        if exp_bits == 0x0F && man_bits == 0x07 {
            f32::NAN
        } else if exp_bits == 0 {
            // subnormal: sign × 2^(1−7) × (man/8) = sign × man / 64
            sign * (man_bits as f32) / 64.0
        } else {
            let exp  = exp_bits as i32 - 7;
            let mant = 1.0 + (man_bits as f32) / 8.0;
            sign * mant * (2.0f32).powi(exp)
        }
    }).collect()
}

/// Quantize f32 vec → FP8 E4M3FN bytes (saturate to ±448).
///
/// E4M3FN max normal = 2^(15−7) × (1 + 6/8) = 256 × 1.75 = 448.
pub fn quantize_f32_to_fp8_e4m3(vals: &[f32]) -> Vec<u8> {
    vals.iter().map(|&v| {
        if v.is_nan() {
            return 0x7F;
        }
        let sign: u8 = if v < 0.0 { 0x80 } else { 0x00 };
        let av       = v.abs().min(448.0);
        if av == 0.0 { return sign; }
        let exp        = av.log2().floor() as i32;
        let exp_biased = (exp + 7).clamp(0, 15) as u8;
        let mant_f     = av / (2.0f32).powi(exp) - 1.0;
        let man_bits   = (mant_f * 8.0).round() as u8 & 0x07;
        // Avoid NaN sentinel (exp=15, man=7)
        if exp_biased == 15 && man_bits == 7 {
            return sign | (15 << 3) | 6; // clamp to 448
        }
        sign | (exp_biased << 3) | man_bits
    }).collect()
}

// ── CPU kernels ───────────────────────────────────────────────────────────────

/// C[m,k] = A[m,n] × B[n,k]
pub fn cpu_matmul(a: &[f32], b: &[f32], c: &mut [f32], m: usize, n: usize, k: usize) {
    for row in 0..m {
        for col in 0..k {
            let mut acc = 0.0f32;
            for i in 0..n {
                acc += a[row * n + i] * b[i * k + col];
            }
            c[row * k + col] = acc;
        }
    }
}

// ── Byte helpers ──────────────────────────────────────────────────────────────

pub fn f32_slice_to_bytes(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|f| f.to_le_bytes()).collect()
}

pub fn bytes_to_f32_slice(b: &[u8]) -> Vec<f32> {
    b.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fp8_roundtrip_common() {
        let vals: Vec<f32> = vec![0.0, 1.0, -1.0, 2.0, -0.5, 0.25, 448.0, -448.0];
        let enc = quantize_f32_to_fp8_e4m3(&vals);
        let dec = dequantize_fp8_e4m3(&enc);
        for (orig, &d) in vals.iter().zip(dec.iter()) {
            let rel = (orig - d).abs() / orig.abs().max(1e-6);
            assert!(rel < 0.15, "fp8 roundtrip: {orig} → {d} (rel={rel:.3})");
        }
    }

    #[test]
    fn matmul_identity_common() {
        let a = vec![1.0f32, 0.0, 0.0, 1.0];
        let b = vec![1.0f32, 2.0, 3.0, 4.0];
        let mut c = vec![0.0f32; 4];
        cpu_matmul(&a, &b, &mut c, 2, 2, 2);
        assert_eq!(c, vec![1.0, 2.0, 3.0, 4.0]);
    }
}
