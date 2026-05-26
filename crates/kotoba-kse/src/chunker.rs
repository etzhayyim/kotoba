//! File-type–aware chunking strategies for blob storage.
//!
//! Three strategies are supported:
//! - `FixedLen(n)` — fixed-size slices (video/audio/opaque binary).
//! - `ContentDefined` — gear-hash CDC, ~256 KB avg (text/JSON/CBOR/code).
//! - `CodecAware` — CBOR top-level item boundaries (dag-cbor/cbor).
//!
//! Blobs smaller than `SINGLE_THRESHOLD` are never split regardless of strategy.

use bytes::Bytes;

/// Blobs below this size are always returned as a single chunk.
const SINGLE_THRESHOLD: usize = 128 * 1024; // 128 KB

/// Default fixed-length chunk size for binary/AV content.
pub const FIXED_CHUNK_BYTES: usize = 512 * 1024; // 512 KB

/// CDC target: average ~256 KB, min 128 KB, max 1 MB.
const CDC_AVG_BITS: u32  = 18;  // 2^18 = 256 KB avg boundary probability
const CDC_MIN_BYTES: usize = 128 * 1024;
const CDC_MAX_BYTES: usize = 1024 * 1024;

/// Gear-hash lookup table (pseudo-random u64 per byte value, seeded deterministically).
static GEAR: std::sync::OnceLock<[u64; 256]> = std::sync::OnceLock::new();

fn gear_table() -> &'static [u64; 256] {
    GEAR.get_or_init(|| {
        // Deterministic fill via xorshift64 seeded with 0xdeadbeefcafe1234.
        let mut state: u64 = 0xdead_beef_cafe_1234;
        let mut table = [0u64; 256];
        for slot in &mut table {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *slot = state;
        }
        table
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkStrategy {
    Single,
    FixedLen(usize),
    ContentDefined,
    CodecAware,
}

/// Choose a chunking strategy from a MIME type and data length.
pub fn strategy_for(mime: &str, size: usize) -> ChunkStrategy {
    if size < SINGLE_THRESHOLD {
        return ChunkStrategy::Single;
    }
    match mime {
        // AV / opaque binary → fixed-length for predictable random access
        m if m.starts_with("video/")
            || m.starts_with("audio/")
            || m == "application/octet-stream"
            || m == "application/zip"
            || m == "application/x-tar"
            || m == "application/x-zstd"
            || m == "application/x-lz4"
            || m == "image/jpeg"
            || m == "image/png"
            || m == "image/webp" => ChunkStrategy::FixedLen(FIXED_CHUNK_BYTES),

        // CBOR / dag-cbor → split on top-level CBOR item boundaries
        "application/vnd.ipld.dag-cbor"
        | "application/cbor"
        | "application/x-cbor" => ChunkStrategy::CodecAware,

        // Everything else (text, JSON, HTML, code, …) → CDC
        _ => ChunkStrategy::ContentDefined,
    }
}

/// Split `data` into `Bytes` chunks according to `strategy`.
pub fn split(data: &[u8], strategy: &ChunkStrategy) -> Vec<Bytes> {
    match strategy {
        ChunkStrategy::Single => vec![Bytes::copy_from_slice(data)],
        ChunkStrategy::FixedLen(n) => fixed_chunks(data, *n),
        ChunkStrategy::ContentDefined => cdc_chunks(data),
        ChunkStrategy::CodecAware => cbor_chunks(data),
    }
}

fn fixed_chunks(data: &[u8], chunk_size: usize) -> Vec<Bytes> {
    data.chunks(chunk_size)
        .map(Bytes::copy_from_slice)
        .collect()
}

/// Gear-hash CDC.  Emits a boundary when the low `CDC_AVG_BITS` bits of the
/// rolling hash are all zero, subject to min/max window constraints.
fn cdc_chunks(data: &[u8]) -> Vec<Bytes> {
    let table = gear_table();
    let mask: u64 = (1u64 << CDC_AVG_BITS) - 1;
    let mut chunks = Vec::new();
    let mut start = 0usize;
    let mut hash: u64 = 0;

    for (i, &byte) in data.iter().enumerate() {
        hash = (hash << 1).wrapping_add(table[byte as usize]);
        let window = i - start + 1;
        if window >= CDC_MIN_BYTES && (hash & mask == 0 || window >= CDC_MAX_BYTES) {
            chunks.push(Bytes::copy_from_slice(&data[start..=i]));
            start = i + 1;
            hash = 0;
        }
    }
    if start < data.len() {
        chunks.push(Bytes::copy_from_slice(&data[start..]));
    }
    chunks
}

/// Split on CBOR top-level item boundaries.
/// Walks the CBOR stream; each complete top-level item becomes one chunk.
/// Falls back to CDC if the data is not valid CBOR.
fn cbor_chunks(data: &[u8]) -> Vec<Bytes> {
    let mut chunks = Vec::new();
    let mut pos = 0usize;

    while pos < data.len() {
        match cbor_item_len(data, pos) {
            Some(len) if len > 0 => {
                chunks.push(Bytes::copy_from_slice(&data[pos..pos + len]));
                pos += len;
            }
            _ => return cdc_chunks(data), // malformed CBOR → fall back to CDC
        }
    }

    if chunks.is_empty() {
        vec![Bytes::copy_from_slice(data)]
    } else {
        chunks
    }
}

/// Return the byte-length of the next top-level CBOR item starting at `pos`,
/// or `None` if the data is truncated or malformed.
fn cbor_item_len(data: &[u8], pos: usize) -> Option<usize> {
    let &first = data.get(pos)?;
    let major = first >> 5;
    let info  = first & 0x1f;

    // Decode the "additional info" (argument) and its size in bytes.
    let (arg, arg_bytes): (u64, usize) = match info {
        0..=23 => (info as u64, 0),
        24 => (*data.get(pos + 1)? as u64, 1),
        25 => {
            let hi = *data.get(pos + 1)? as u64;
            let lo = *data.get(pos + 2)? as u64;
            (hi << 8 | lo, 2)
        }
        26 => {
            let b = data.get(pos + 1..pos + 5)?;
            (u32::from_be_bytes(b.try_into().ok()?) as u64, 4)
        }
        27 => {
            let b = data.get(pos + 1..pos + 9)?;
            (u64::from_be_bytes(b.try_into().ok()?), 8)
        }
        31 => (0, 0), // indefinite-length marker
        _  => return None,
    };
    let header = 1 + arg_bytes;

    let total = match major {
        0 | 1 | 7 => header,                              // uint, nint, simple/float
        2 | 3 => {                                         // bstr, tstr
            if info == 31 {
                // indefinite-length: scan for 0xff break
                let mut p = pos + header;
                loop {
                    if *data.get(p)? == 0xff { break p - pos + 2; }
                    let chunk_len = cbor_item_len(data, p)?;
                    p += chunk_len;
                }
            } else {
                header + arg as usize
            }
        }
        4 => {
            // array
            if info == 31 {
                let mut p = pos + header;
                let mut n = 0u64;
                while *data.get(p)? != 0xff { let l = cbor_item_len(data, p)?; p += l; n += 1; if n > 1_000_000 { return None; } }
                p - pos + 1
            } else {
                let mut p = pos + header;
                for _ in 0..arg { p += cbor_item_len(data, p)?; }
                p - pos
            }
        }
        5 => {
            // map (2×arg items)
            if info == 31 {
                let mut p = pos + header;
                let mut n = 0u64;
                while *data.get(p)? != 0xff { let l = cbor_item_len(data, p)?; p += l; n += 1; if n > 2_000_000 { return None; } }
                p - pos + 1
            } else {
                let mut p = pos + header;
                for _ in 0..arg * 2 { p += cbor_item_len(data, p)?; }
                p - pos
            }
        }
        6 => {
            // tag — one tagged item follows
            let inner = cbor_item_len(data, pos + header)?;
            header + inner
        }
        _ => return None,
    };

    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_below_threshold() {
        let data = vec![0u8; 64 * 1024];
        let chunks = split(&data, &strategy_for("text/plain", data.len()));
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), data.len());
    }

    #[test]
    fn fixed_len_video() {
        let data = vec![0xABu8; 1_100_000];
        let strat = strategy_for("video/mp4", data.len());
        assert_eq!(strat, ChunkStrategy::FixedLen(FIXED_CHUNK_BYTES));
        let chunks = split(&data, &strat);
        assert_eq!(chunks.len(), 3); // 512K + 512K + 76K
        assert_eq!(chunks[0].len(), FIXED_CHUNK_BYTES);
        assert_eq!(chunks[2].len(), 1_100_000 - 2 * FIXED_CHUNK_BYTES);
    }

    #[test]
    fn cdc_produces_multiple_chunks_for_large_text() {
        // 2 MB of pseudo-random-ish bytes to exercise CDC boundaries
        let mut data = Vec::with_capacity(2 * 1024 * 1024);
        let mut v: u8 = 0;
        for _ in 0..data.capacity() { v = v.wrapping_mul(6).wrapping_add(1); data.push(v); }
        let strat = strategy_for("text/plain", data.len());
        assert_eq!(strat, ChunkStrategy::ContentDefined);
        let chunks = split(&data, &strat);
        assert!(chunks.len() > 1, "expected multiple CDC chunks, got {}", chunks.len());
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, data.len());
    }

    #[test]
    fn cbor_chunk_roundtrip() {
        // Encode 3 CBOR unsigned integers as separate top-level items.
        let mut buf = Vec::new();
        ciborium::into_writer(&42u64, &mut buf).unwrap();
        ciborium::into_writer(&99u64, &mut buf).unwrap();
        ciborium::into_writer(&255u64, &mut buf).unwrap();
        // Repeat to exceed SINGLE_THRESHOLD
        let repeated: Vec<u8> = buf.iter().cycle().take(SINGLE_THRESHOLD + buf.len()).cloned().collect();
        let strat = strategy_for("application/cbor", repeated.len());
        assert_eq!(strat, ChunkStrategy::CodecAware);
        let chunks = split(&repeated, &strat);
        assert!(chunks.len() > 1);
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, repeated.len());
    }

    #[test]
    fn strategy_dispatch() {
        let big = 1_000_000;
        assert_eq!(strategy_for("video/mp4",  big), ChunkStrategy::FixedLen(FIXED_CHUNK_BYTES));
        assert_eq!(strategy_for("audio/mpeg", big), ChunkStrategy::FixedLen(FIXED_CHUNK_BYTES));
        assert_eq!(strategy_for("image/jpeg", big), ChunkStrategy::FixedLen(FIXED_CHUNK_BYTES));
        assert_eq!(strategy_for("text/plain", big), ChunkStrategy::ContentDefined);
        assert_eq!(strategy_for("application/json", big), ChunkStrategy::ContentDefined);
        assert_eq!(strategy_for("application/cbor", big), ChunkStrategy::CodecAware);
        assert_eq!(strategy_for("application/vnd.ipld.dag-cbor", big), ChunkStrategy::CodecAware);
    }
}
