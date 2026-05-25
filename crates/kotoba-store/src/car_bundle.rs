/// CAR (Content Addressable aRchive) bundle — Hummock-style SST analogue.
///
/// Packs all ProllyTree blocks from a single commit into one flat file so they can
/// be uploaded to S3/B2 with a **single PUT** instead of ~15K individual PUTs.
///
/// # Format (kotoba-car v1)
///
/// ```text
/// ┌─────────────────────────────────────── HEADER (72 bytes) ──┐
/// │ magic[4]  "KCAR"                                           │
/// │ version[4] = 1u32 LE                                       │
/// │ block_count[8]  u64 LE                                     │
/// │ index_offset[8] u64 LE  (byte offset of index section)     │
/// │ root_cid[36]    commit root CID (for IPFS pinning)         │
/// │ _reserved[12]   zeroed                                     │
/// └────────────────────────────────────────────────────────────┘
/// ┌─────────────────────────── BLOCKS section ─────────────────┐
/// │ block_0_data ... block_N_data  (variable, concatenated)    │
/// └────────────────────────────────────────────────────────────┘
/// ┌─────────────────────────── INDEX section ──────────────────┐
/// │ For each block i: cid[36] + data_offset[8] + data_len[4]  │
/// │ Entry size = 48 bytes, total = block_count × 48            │
/// └────────────────────────────────────────────────────────────┘
/// ```
///
/// Random-access read: fetch index → range GET `data_offset..data_offset+data_len`.
/// Sequential scan: read blocks section start→index_offset.
///
/// The in-memory [`CarBlockIndex`] maps `KotobaCid → (car_key, data_offset, data_len)`.
use std::collections::HashMap;
use bytes::Bytes;
use anyhow::{bail, Result};
use kotoba_core::cid::KotobaCid;

const MAGIC: &[u8; 4]  = b"KCAR";
const VERSION: u32      = 1;
const HEADER_LEN: usize = 72;
const INDEX_ENTRY: usize = 48; // 36 (cid) + 8 (offset) + 4 (len)

// ─── CarBundleWriter ─────────────────────────────────────────────────────────

/// Accumulates blocks in memory and serializes to a single CAR byte buffer.
///
/// Usage:
/// ```ignore
/// let mut w = CarBundleWriter::new(commit_root_cid);
/// for (cid, data) in blocks { w.append(&cid, &data); }
/// let (car_bytes, index) = w.finish();
/// ```
pub struct CarBundleWriter {
    root_cid:    KotobaCid,
    blocks_buf:  Vec<u8>,                          // raw block bytes, concatenated
    offsets:     Vec<(KotobaCid, u64, u32)>,       // (cid, data_offset, data_len)
}

impl CarBundleWriter {
    pub fn new(root_cid: KotobaCid) -> Self {
        Self {
            root_cid,
            blocks_buf: Vec::new(),
            offsets:    Vec::new(),
        }
    }

    /// Append one block. Returns the byte offset within the blocks section.
    pub fn append(&mut self, cid: &KotobaCid, data: &[u8]) -> u64 {
        let data_offset = self.blocks_buf.len() as u64;
        self.blocks_buf.extend_from_slice(data);
        self.offsets.push((cid.clone(), data_offset, data.len() as u32));
        data_offset
    }

    pub fn block_count(&self) -> usize { self.offsets.len() }
    pub fn blocks_bytes(&self) -> usize { self.blocks_buf.len() }

    /// Serialize to a flat CAR byte buffer and return the per-block index.
    /// The returned index offsets are relative to the start of the CAR file
    /// (i.e. `HEADER_LEN + data_offset`).
    pub fn finish(self) -> (Vec<u8>, Vec<(KotobaCid, u64, u32)>) {
        let block_count   = self.offsets.len() as u64;
        let blocks_size   = self.blocks_buf.len();
        let index_offset  = HEADER_LEN + blocks_size;
        let total_size    = index_offset + self.offsets.len() * INDEX_ENTRY;

        let mut buf = Vec::with_capacity(total_size);

        // ── Header ──────────────────────────────────────────────────────────
        buf.extend_from_slice(MAGIC);                              // [0..4]
        buf.extend_from_slice(&VERSION.to_le_bytes());             // [4..8]
        buf.extend_from_slice(&block_count.to_le_bytes());         // [8..16]
        buf.extend_from_slice(&(index_offset as u64).to_le_bytes()); // [16..24]
        buf.extend_from_slice(&self.root_cid.0);                   // [24..60]
        buf.extend_from_slice(&[0u8; 12]);                         // [60..72] reserved

        debug_assert_eq!(buf.len(), HEADER_LEN);

        // ── Blocks ──────────────────────────────────────────────────────────
        buf.extend_from_slice(&self.blocks_buf);

        // ── Index ───────────────────────────────────────────────────────────
        // Offsets in index are file-absolute (header + block section + data_offset).
        let header_and_blocks = HEADER_LEN as u64;
        let mut abs_offsets = Vec::with_capacity(self.offsets.len());
        for (cid, rel_off, len) in &self.offsets {
            let abs_off = header_and_blocks + rel_off;
            buf.extend_from_slice(&cid.0);                         // 36 bytes
            buf.extend_from_slice(&abs_off.to_le_bytes());         // 8 bytes
            buf.extend_from_slice(&len.to_le_bytes());             // 4 bytes
            abs_offsets.push((cid.clone(), abs_off, *len));
        }

        debug_assert_eq!(buf.len(), total_size);
        (buf, abs_offsets)
    }
}

// ─── CAR parsing ─────────────────────────────────────────────────────────────

/// Parse the index section from a complete CAR byte buffer.
/// Returns `(root_cid, Vec<(cid, abs_offset, data_len)>)`.
pub fn parse_index(car: &[u8]) -> Result<(KotobaCid, Vec<(KotobaCid, u64, u32)>)> {
    if car.len() < HEADER_LEN {
        bail!("car too short: {} bytes", car.len());
    }
    if &car[0..4] != MAGIC {
        bail!("invalid car magic");
    }
    let version = u32::from_le_bytes(car[4..8].try_into().unwrap());
    if version != 1 {
        bail!("unsupported car version {version}");
    }
    let block_count  = u64::from_le_bytes(car[8..16].try_into().unwrap()) as usize;
    let index_offset = u64::from_le_bytes(car[16..24].try_into().unwrap()) as usize;

    let mut root = [0u8; 36];
    root.copy_from_slice(&car[24..60]);
    let root_cid = KotobaCid(root);

    if car.len() < index_offset + block_count * INDEX_ENTRY {
        bail!("car truncated: index section incomplete");
    }

    let mut entries = Vec::with_capacity(block_count);
    let mut pos = index_offset;
    for _ in 0..block_count {
        let mut cid_bytes = [0u8; 36];
        cid_bytes.copy_from_slice(&car[pos..pos + 36]);
        let abs_off = u64::from_le_bytes(car[pos+36..pos+44].try_into().unwrap());
        let data_len = u32::from_le_bytes(car[pos+44..pos+48].try_into().unwrap());
        entries.push((KotobaCid(cid_bytes), abs_off, data_len));
        pos += INDEX_ENTRY;
    }

    Ok((root_cid, entries))
}

/// Extract a single block from a CAR byte buffer using a pre-parsed index entry.
pub fn extract_block(car: &[u8], abs_offset: u64, data_len: u32) -> Result<Bytes> {
    let start = abs_offset as usize;
    let end   = start + data_len as usize;
    if end > car.len() {
        bail!("block out of range: car {} bytes, want [{start}..{end}]", car.len());
    }
    Ok(Bytes::copy_from_slice(&car[start..end]))
}

// ─── CarBlockIndex ────────────────────────────────────────────────────────────

/// In-memory index: maps CID → (car_key, abs_offset, data_len).
/// `car_key` is the S3/B2 object key for the CAR file (= commit CID multibase).
///
/// In production this would be backed by sled for persistence across restarts.
#[derive(Default)]
pub struct CarBlockIndex {
    entries: HashMap<KotobaCid, (String, u64, u32)>,
}

impl CarBlockIndex {
    pub fn new() -> Self { Self::default() }

    /// Insert all entries from a freshly written CAR file.
    pub fn insert_car(
        &mut self,
        car_key: &str,
        index: &[(KotobaCid, u64, u32)],
    ) {
        for (cid, off, len) in index {
            self.entries.insert(cid.clone(), (car_key.to_string(), *off, *len));
        }
    }

    /// Look up a CID. Returns `(car_key, abs_offset, data_len)` if present.
    pub fn get(&self, cid: &KotobaCid) -> Option<(&str, u64, u32)> {
        self.entries.get(cid).map(|(k, o, l)| (k.as_str(), *o, *l))
    }

    pub fn len(&self)     -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_cid(n: u64) -> KotobaCid { KotobaCid::from_bytes(&n.to_le_bytes()) }
    fn fake_data(n: u64, size: usize) -> Vec<u8> {
        (0..size).map(|i| ((n + i as u64) & 0xff) as u8).collect()
    }

    #[test]
    fn roundtrip_small() {
        let root = fake_cid(0);
        let mut w = CarBundleWriter::new(root.clone());
        for i in 1u64..=5 {
            w.append(&fake_cid(i), &fake_data(i, 128));
        }
        let (car, idx) = w.finish();

        let (parsed_root, parsed_idx) = parse_index(&car).unwrap();
        assert_eq!(parsed_root, root);
        assert_eq!(parsed_idx.len(), 5);

        for (i, (cid, off, len)) in parsed_idx.iter().enumerate() {
            assert_eq!(*cid, fake_cid(i as u64 + 1));
            assert_eq!(*len, 128);
            let block = extract_block(&car, *off, *len).unwrap();
            assert_eq!(block.as_ref(), fake_data(i as u64 + 1, 128).as_slice());
            // Also verify against pre-computed index
            assert_eq!(idx[i].1, *off);
        }
    }

    #[test]
    fn block_index_insert_and_lookup() {
        let root = fake_cid(0);
        let mut w = CarBundleWriter::new(root);
        for i in 0u64..10 { w.append(&fake_cid(i), &fake_data(i, 64)); }
        let (_, idx) = w.finish();

        let mut index = CarBlockIndex::new();
        index.insert_car("commit-abc123", &idx);
        assert_eq!(index.len(), 10);

        let (key, off, len) = index.get(&fake_cid(5)).unwrap();
        assert_eq!(key, "commit-abc123");
        assert!(off >= HEADER_LEN as u64);
        assert_eq!(len, 64);
    }

    #[test]
    fn header_is_exactly_72_bytes() {
        let mut w = CarBundleWriter::new(fake_cid(0));
        w.append(&fake_cid(1), b"x");
        let (car, _) = w.finish();
        // First block should be at HEADER_LEN offset
        assert_eq!(&car[HEADER_LEN..HEADER_LEN + 1], b"x");
    }
}
