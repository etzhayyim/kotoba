//! Common Crawl parquet ingestor.
//!
//! Two ingestors:
//!   CcPageIngestor  — reads parquet-rs-v2 pages files → Page quads
//!   CcChunkIngestor — reads parquet-wet-v1 wet_chunks → Chunk + Embed quads + IVF
//!
//! Named graphs (KotobaCid by content):
//!   cc_pages_graph()  → "cc:2026-12:pages"
//!   cc_chunks_graph() → "cc:2026-12:chunks"
//!
//! Predicate namespace: `cc/*` (see ADR-2605250006).

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use kotoba_core::cid::KotobaCid;
use kotoba_graph::quad_store::QuadStore;
use kotoba_kqe::quad::{Quad, QuadObject};
use tracing::{debug, info};

use crate::embed_client::EmbedClient;
use crate::ivf::IvfIndex;

// ── Named graph CIDs ─────────────────────────────────────────────────────────

pub fn cc_pages_graph() -> KotobaCid {
    KotobaCid::from_bytes(b"cc:2026-12:pages")
}

pub fn cc_chunks_graph() -> KotobaCid {
    KotobaCid::from_bytes(b"cc:2026-12:chunks")
}

pub fn cc_links_graph() -> KotobaCid {
    KotobaCid::from_bytes(b"cc:2026-12:links")
}

// ── Helper: build subject CID from vertex_id string ──────────────────────────

fn subject_from_vertex(vertex_id: &str) -> KotobaCid {
    KotobaCid::from_bytes(vertex_id.as_bytes())
}

fn subject_from_chunk(page_rkey: &str, chunk_index: i64) -> KotobaCid {
    KotobaCid::from_bytes(format!("{}:c{}", page_rkey, chunk_index).as_bytes())
}

// ── Quad constructors ─────────────────────────────────────────────────────────

fn text_quad(graph: &KotobaCid, subject: &KotobaCid, predicate: &str, value: &str) -> Quad {
    Quad {
        graph:     graph.clone(),
        subject:   subject.clone(),
        predicate: predicate.to_string(),
        object:    QuadObject::Text(value.to_string()),
    }
}

fn int_quad(graph: &KotobaCid, subject: &KotobaCid, predicate: &str, value: i64) -> Quad {
    Quad {
        graph:     graph.clone(),
        subject:   subject.clone(),
        predicate: predicate.to_string(),
        object:    QuadObject::Integer(value),
    }
}

fn cid_quad(graph: &KotobaCid, subject: &KotobaCid, predicate: &str, target: &KotobaCid) -> Quad {
    Quad {
        graph:     graph.clone(),
        subject:   subject.clone(),
        predicate: predicate.to_string(),
        object:    QuadObject::Cid(target.clone()),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CcPageIngestor
// ═══════════════════════════════════════════════════════════════════════════════

/// Reads `batch_XXXXXX_pages.parquet` files from `parquet-rs-v2/` and writes
/// Page quads into the `cc:2026-12:pages` named graph.
pub struct CcPageIngestor {
    pub quad_store: Arc<QuadStore>,
    pub graph_cid:  KotobaCid,
    /// Quads accumulated before each QuadStore commit.
    pub batch_size: usize,
}

impl CcPageIngestor {
    pub fn new(quad_store: Arc<QuadStore>) -> Self {
        Self {
            quad_store,
            graph_cid:  cc_pages_graph(),
            batch_size: 50_000,
        }
    }

    pub fn with_batch(mut self, n: usize) -> Self {
        self.batch_size = n;
        self
    }

    /// Ingest all `*_pages.parquet` files in `parquet_dir`.
    /// Returns (files_processed, total_quads).
    pub async fn ingest_dir(
        &self,
        parquet_dir: &Path,
        max_batches: Option<usize>,
    ) -> Result<(usize, u64)> {
        let mut files: Vec<_> = std::fs::read_dir(parquet_dir)
            .with_context(|| format!("read_dir {}", parquet_dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with("_pages.parquet"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();

        if let Some(max) = max_batches {
            files.truncate(max);
        }

        let total_files = files.len();
        info!(total_files, "CcPageIngestor: starting dir scan");

        let mut total_quads = 0u64;
        let mut seq: u64 = 0;
        let mut pending: Vec<Quad> = Vec::with_capacity(self.batch_size);

        for path in &files {
            let quads = self
                .read_page_file(path)
                .with_context(|| format!("read_page_file {}", path.display()))?;

            for q in quads {
                pending.push(q);
                if pending.len() >= self.batch_size {
                    seq += 1;
                    total_quads += pending.len() as u64;
                    self.flush_commit(&mut pending, seq).await?;
                }
            }
        }

        // Final flush
        if !pending.is_empty() {
            seq += 1;
            total_quads += pending.len() as u64;
            self.flush_commit(&mut pending, seq).await?;
        }

        info!(total_files, total_quads, "CcPageIngestor: done");
        Ok((total_files, total_quads))
    }

    async fn flush_commit(&self, pending: &mut Vec<Quad>, seq: u64) -> Result<()> {
        self.quad_store.assert_batch_silent(std::mem::take(pending)).await;
        self.quad_store
            .commit("did:web:kotoba.gftd.ai", self.graph_cid.clone(), seq)
            .await?;
        self.quad_store.reset_arrangement(&self.graph_cid).await;
        Ok(())
    }

    /// Read a single pages parquet file → Vec<Quad>.
    pub fn read_page_file(&self, path: &Path) -> Result<Vec<Quad>> {
        use arrow::array::{Array, Int64Array, StringArray};
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        use std::fs::File;

        let file    = File::open(path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let reader  = builder.build()?;
        let graph   = &self.graph_cid;
        let mut out: Vec<Quad> = Vec::new();

        for batch_result in reader {
            let batch = batch_result?;
            let ncols = batch.schema().fields().len();
            let nrows = batch.num_rows();

            // Column helpers — gracefully handle missing columns
            macro_rules! col_str {
                ($name:expr) => {
                    batch.schema().index_of($name).ok().and_then(|i| {
                        batch.column(i).as_any().downcast_ref::<StringArray>()
                    })
                };
            }
            macro_rules! col_i64 {
                ($name:expr) => {
                    batch.schema().index_of($name).ok().and_then(|i| {
                        batch.column(i).as_any().downcast_ref::<Int64Array>()
                    })
                };
            }

            let vertex_id_col  = col_str!("vertex_id");
            let url_col        = col_str!("url");
            let domain_col     = col_str!("domain");
            let title_col      = col_str!("title");
            let desc_col       = col_str!("description");
            let lang_col       = col_str!("language");
            let crawl_col      = col_str!("crawl");
            let crawled_at_col = col_str!("crawled_at");
            let hash_col       = col_str!("content_hash");
            let owner_did_col  = col_str!("owner_did");
            let status_col     = col_str!("status_code");
            let outlink_col    = col_i64!("outlink_count");

            let _ = ncols; // suppress unused warning

            for row in 0..nrows {
                let vid = vertex_id_col
                    .and_then(|c| if c.is_null(row) { None } else { Some(c.value(row)) })
                    .unwrap_or("");
                if vid.is_empty() {
                    continue;
                }
                let subj = subject_from_vertex(vid);

                macro_rules! push_str {
                    ($col:expr, $pred:expr) => {
                        if let Some(col) = $col {
                            if !col.is_null(row) {
                                let v = col.value(row);
                                if !v.is_empty() {
                                    out.push(text_quad(graph, &subj, $pred, v));
                                }
                            }
                        }
                    };
                }

                push_str!(url_col,        "cc/url");
                push_str!(domain_col,     "cc/domain");
                push_str!(title_col,      "cc/title");
                push_str!(desc_col,       "cc/description");
                push_str!(lang_col,       "cc/lang");
                push_str!(crawl_col,      "cc/crawl");
                push_str!(crawled_at_col, "cc/crawled_at");
                push_str!(hash_col,       "cc/content_hash");
                push_str!(owner_did_col,  "cc/owner_did");
                push_str!(status_col,     "cc/status");

                if let Some(col) = outlink_col {
                    if !col.is_null(row) {
                        out.push(int_quad(graph, &subj, "cc/outlink_count", col.value(row)));
                    }
                }
            }
        }

        debug!(path = %path.display(), quads = out.len(), "read_page_file done");
        Ok(out)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CcChunkIngestor
// ═══════════════════════════════════════════════════════════════════════════════

/// Reads `*_wet_chunks.parquet` files and writes:
///   1. Text chunk quads (`cc/chunk/*`)
///   2. Embedding quads (`cc/embed/{model_id}`) via EmbedClient
///   3. IVF centroid quads + cluster assignment (`cc/ivf/*`)
pub struct CcChunkIngestor {
    pub quad_store:   Arc<QuadStore>,
    pub embed_client: Arc<dyn EmbedClient>,
    pub graph_cid:    KotobaCid,
    pub batch_size:   usize,
    pub k_centroids:  usize,
    pub ivf_max_iter: usize,
}

impl CcChunkIngestor {
    pub fn new(
        quad_store:   Arc<QuadStore>,
        embed_client: Arc<dyn EmbedClient>,
    ) -> Self {
        Self {
            quad_store,
            embed_client,
            graph_cid:   cc_chunks_graph(),
            batch_size:  50_000,
            k_centroids: 140,
            ivf_max_iter: 20,
        }
    }

    pub fn with_k(mut self, k: usize) -> Self { self.k_centroids = k; self }
    pub fn with_batch(mut self, n: usize) -> Self { self.batch_size = n; self }

    /// Ingest all `*_wet_chunks.parquet` files in `parquet_dir`.
    /// Returns (chunks_ingested, embeddings_computed).
    pub async fn ingest_dir(
        &self,
        parquet_dir: &Path,
        max_files: Option<usize>,
    ) -> Result<(u64, u64)> {
        let mut files: Vec<_> = std::fs::read_dir(parquet_dir)
            .with_context(|| format!("read_dir {}", parquet_dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with("_wet_chunks.parquet"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        if let Some(max) = max_files {
            files.truncate(max);
        }

        let mut total_chunks = 0u64;
        let mut total_embeds = 0u64;

        for path in &files {
            let (c, e) = self.ingest_file(path).await?;
            total_chunks += c;
            total_embeds += e;
        }

        info!(total_chunks, total_embeds, "CcChunkIngestor: done");
        Ok((total_chunks, total_embeds))
    }

    /// Ingest a single wet_chunks parquet file.
    pub async fn ingest_file(&self, path: &Path) -> Result<(u64, u64)> {
        let rows = self.read_chunk_file(path)?;
        if rows.is_empty() {
            return Ok((0, 0));
        }

        let model_id  = self.embed_client.model_id().to_string();
        let graph     = &self.graph_cid;
        let n         = rows.len();

        // ── Step 1: write chunk metadata quads ───────────────────────────────
        let mut chunk_quads: Vec<Quad> = Vec::with_capacity(n * 8);
        for row in &rows {
            let subj     = subject_from_chunk(&row.page_rkey, row.chunk_index);
            let page_cid = subject_from_vertex(&row.page_rkey);

            chunk_quads.push(cid_quad(graph, &subj, "cc/chunk/page", &page_cid));
            chunk_quads.push(int_quad(graph, &subj, "cc/chunk/index", row.chunk_index));
            chunk_quads.push(int_quad(graph, &subj, "cc/chunk/total", row.total_chunks));
            chunk_quads.push(int_quad(graph, &subj, "cc/chunk/tokens", row.token_count));
            if !row.markdown.is_empty() {
                chunk_quads.push(text_quad(graph, &subj, "cc/chunk/text", &row.markdown));
            }
            if !row.language.is_empty() {
                chunk_quads.push(text_quad(graph, &subj, "cc/chunk/lang", &row.language));
            }
            if !row.url.is_empty() {
                chunk_quads.push(text_quad(graph, &subj, "cc/chunk/url", &row.url));
            }
            if !row.domain.is_empty() {
                chunk_quads.push(text_quad(graph, &subj, "cc/chunk/domain", &row.domain));
            }
        }

        self.quad_store.assert_batch_silent(chunk_quads).await;

        // ── Step 2: embed text chunks ─────────────────────────────────────────
        const EMBED_BATCH: usize = 64;
        let texts: Vec<&str> = rows.iter().map(|r| r.markdown.as_str()).collect();
        let mut all_embeddings: Vec<(KotobaCid, Vec<f32>)> = Vec::with_capacity(n);
        let mut embed_count = 0u64;

        for chunk_texts in texts.chunks(EMBED_BATCH) {
            let vecs = self.embed_client.embed_batch(chunk_texts).await?;
            let base  = embed_count as usize;
            for (i, vec) in vecs.into_iter().enumerate() {
                let row  = &rows[base + i];
                let subj = subject_from_chunk(&row.page_rkey, row.chunk_index);
                let pred = format!("cc/embed/{}", model_id);

                // dim ≤ 1024: inline VectorF32, else TensorCid
                let object = if vec.len() <= 1024 {
                    QuadObject::VectorF32(vec.clone())
                } else {
                    let raw: Vec<u8> = vec.iter().flat_map(|f| f.to_le_bytes()).collect();
                    let tcid = KotobaCid::from_bytes(&raw);
                    QuadObject::TensorCid {
                        cid:   tcid,
                        shape: vec![vec.len() as u32],
                        dtype: kotoba_kqe::quad::TensorDtype::F32,
                    }
                };

                // Pre-compute L2 norm for fast cosine
                let norm = vec.iter().map(|x| x * x).sum::<f32>().sqrt();

                self.quad_store.assert(Quad {
                    graph:     graph.clone(),
                    subject:   subj.clone(),
                    predicate: pred,
                    object,
                }).await;
                self.quad_store.assert(Quad {
                    graph:     graph.clone(),
                    subject:   subj.clone(),
                    predicate: "cc/embed_norm".to_string(),
                    object:    QuadObject::Float(norm as f64),
                }).await;

                all_embeddings.push((subj, vec));
                embed_count += 1;
            }
        }

        // ── Step 3: build IVF index ───────────────────────────────────────────
        let k = self.k_centroids.min(all_embeddings.len());
        if k > 0 {
            let t0 = std::time::Instant::now();
            let ivf = IvfIndex::build(&all_embeddings, k, &model_id, self.ivf_max_iter);
            info!(k, n, elapsed_ms = t0.elapsed().as_millis(), "IVF build done");

            // Write cluster assignments
            let mut assign_quads: Vec<Quad> = Vec::with_capacity(n);
            let mut member_counts = vec![0usize; k];
            for (subj, vec) in &all_embeddings {
                let (centroid_id, _dist) = ivf.assign(vec);
                member_counts[centroid_id] += 1;
                assign_quads.push(int_quad(graph, subj, "cc/ivf/cluster", centroid_id as i64));
            }
            self.quad_store.assert_batch_silent(assign_quads).await;

            // Write centroid quads
            let centroid_quads = ivf.to_quads(graph, &member_counts);
            self.quad_store.assert_batch_silent(centroid_quads).await;
        }

        // ── Step 4: final commit ──────────────────────────────────────────────
        let commit_seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.quad_store
            .commit("did:web:kotoba.gftd.ai", graph.clone(), commit_seq)
            .await?;
        self.quad_store.reset_arrangement(graph).await;

        info!(
            path = %path.display(),
            chunks = n,
            embeddings = embed_count,
            "CcChunkIngestor: file done"
        );
        Ok((n as u64, embed_count))
    }

    fn read_chunk_file(&self, path: &Path) -> Result<Vec<ChunkRow>> {
        use arrow::array::{Array, Float32Array, Int64Array, ListArray, StringArray};
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        use std::fs::File;

        let file    = File::open(path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let reader  = builder.build()?;
        let mut out: Vec<ChunkRow> = Vec::new();

        for batch_result in reader {
            let batch = batch_result?;
            let nrows = batch.num_rows();

            macro_rules! col_str {
                ($name:expr) => {
                    batch.schema().index_of($name).ok().and_then(|i| {
                        batch.column(i).as_any().downcast_ref::<StringArray>()
                    })
                };
            }
            macro_rules! col_i64 {
                ($name:expr) => {
                    batch.schema().index_of($name).ok().and_then(|i| {
                        batch.column(i).as_any().downcast_ref::<Int64Array>()
                    })
                };
            }

            let page_rkey_col    = col_str!("page_rkey");
            let url_col          = col_str!("url");
            let domain_col       = col_str!("domain");
            let markdown_col     = col_str!("markdown");
            let language_col     = col_str!("language");
            let chunk_index_col  = col_i64!("chunk_index");
            let total_chunks_col = col_i64!("total_chunks");
            let token_count_col  = col_i64!("token_count");

            // Pre-existing embeddings (if any) — list<float>
            let embedding_col = batch.schema().index_of("embedding").ok().and_then(|i| {
                batch.column(i).as_any().downcast_ref::<ListArray>()
            });

            for row in 0..nrows {
                let page_rkey = page_rkey_col
                    .and_then(|c| if c.is_null(row) { None } else { Some(c.value(row).to_string()) })
                    .unwrap_or_default();
                if page_rkey.is_empty() {
                    continue;
                }

                // If embedding is already present in parquet, use it (skip HTTP embed)
                let precomputed_embedding: Option<Vec<f32>> =
                    embedding_col.and_then(|col| {
                        if col.is_null(row) {
                            return None;
                        }
                        let list_val = col.value(row);
                        list_val
                            .as_any()
                            .downcast_ref::<Float32Array>()
                            .map(|arr| (0..arr.len()).map(|i| arr.value(i)).collect())
                    });

                out.push(ChunkRow {
                    page_rkey,
                    url:           url_col.and_then(|c| if c.is_null(row) { None } else { Some(c.value(row).to_string()) }).unwrap_or_default(),
                    domain:        domain_col.and_then(|c| if c.is_null(row) { None } else { Some(c.value(row).to_string()) }).unwrap_or_default(),
                    markdown:      markdown_col.and_then(|c| if c.is_null(row) { None } else { Some(c.value(row).to_string()) }).unwrap_or_default(),
                    language:      language_col.and_then(|c| if c.is_null(row) { None } else { Some(c.value(row).to_string()) }).unwrap_or_default(),
                    chunk_index:   chunk_index_col.and_then(|c| if c.is_null(row) { None } else { Some(c.value(row)) }).unwrap_or(0),
                    total_chunks:  total_chunks_col.and_then(|c| if c.is_null(row) { None } else { Some(c.value(row)) }).unwrap_or(1),
                    token_count:   token_count_col.and_then(|c| if c.is_null(row) { None } else { Some(c.value(row)) }).unwrap_or(0),
                    precomputed_embedding,
                });
            }
        }

        debug!(path = %path.display(), rows = out.len(), "read_chunk_file done");
        Ok(out)
    }
}

// ── Internal row types ────────────────────────────────────────────────────────

struct ChunkRow {
    page_rkey:              String,
    url:                    String,
    domain:                 String,
    markdown:               String,
    language:               String,
    chunk_index:            i64,
    total_chunks:           i64,
    token_count:            i64,
    #[allow(dead_code)]
    precomputed_embedding:  Option<Vec<f32>>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// IngestStatus — snapshot of ingest progress
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct IngestStatus {
    pub pages_files:     u64,
    pub pages_quads:     u64,
    pub chunks_total:    u64,
    pub chunks_embedded: u64,
    pub ivf_k:           usize,
    pub ivf_built:       bool,
    pub pages_graph_cid: String,
    pub chunks_graph_cid: String,
}

impl IngestStatus {
    pub fn new() -> Self {
        Self {
            pages_graph_cid:  cc_pages_graph().to_multibase(),
            chunks_graph_cid: cc_chunks_graph().to_multibase(),
            ..Default::default()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Unit tests (no network, no parquet files required)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_kse::Journal;
    use kotoba_store::MemoryBlockStore;
    use std::sync::Arc;

    fn make_store() -> Arc<QuadStore> {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new())
            as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
        Arc::new(QuadStore::new(journal, block_store))
    }

    #[test]
    fn named_graph_cids_are_distinct() {
        let pages  = cc_pages_graph();
        let chunks = cc_chunks_graph();
        let links  = cc_links_graph();
        assert_ne!(pages,  chunks);
        assert_ne!(pages,  links);
        assert_ne!(chunks, links);
    }

    #[test]
    fn subject_from_chunk_encodes_index() {
        let a = subject_from_chunk("page-abc", 0);
        let b = subject_from_chunk("page-abc", 1);
        let c = subject_from_chunk("page-abc", 0);
        assert_ne!(a, b, "different indices → different CIDs");
        assert_eq!(a, c, "same input → same CID");
    }

    #[tokio::test]
    async fn page_ingestor_constructs() {
        let qs  = make_store();
        let ing = CcPageIngestor::new(qs).with_batch(1000);
        assert_eq!(ing.batch_size, 1000);
        assert_eq!(ing.graph_cid, cc_pages_graph());
    }

    #[tokio::test]
    async fn chunk_ingestor_constructs_with_blake3() {
        use crate::embed_client::Blake3EmbedClient;
        let qs    = make_store();
        let embed = Arc::new(Blake3EmbedClient::new(128));
        let ing   = CcChunkIngestor::new(qs, embed).with_k(10);
        assert_eq!(ing.k_centroids, 10);
        assert_eq!(ing.graph_cid, cc_chunks_graph());
    }

    #[test]
    fn ingest_status_new_has_graph_cids() {
        let status = IngestStatus::new();
        assert!(!status.pages_graph_cid.is_empty(),  "pages_graph_cid must be set");
        assert!(!status.chunks_graph_cid.is_empty(), "chunks_graph_cid must be set");
        assert_ne!(status.pages_graph_cid, status.chunks_graph_cid,
            "pages and chunks graph CIDs must differ");
    }

    #[test]
    fn ingest_status_default_counters_are_zero() {
        let status = IngestStatus::default();
        assert_eq!(status.pages_files,     0);
        assert_eq!(status.pages_quads,     0);
        assert_eq!(status.chunks_total,    0);
        assert_eq!(status.chunks_embedded, 0);
        assert_eq!(status.ivf_k,           0);
        assert!(!status.ivf_built);
    }

    #[test]
    fn ingest_status_clone_equals_original() {
        let s1 = IngestStatus::new();
        let s2 = s1.clone();
        assert_eq!(s1.pages_graph_cid,  s2.pages_graph_cid);
        assert_eq!(s1.chunks_graph_cid, s2.chunks_graph_cid);
    }

    #[test]
    fn subject_from_vertex_same_input_same_cid() {
        let a = subject_from_vertex("vertex-001");
        let b = subject_from_vertex("vertex-001");
        assert_eq!(a, b);
    }

    #[test]
    fn subject_from_vertex_different_input_different_cid() {
        let a = subject_from_vertex("vertex-001");
        let b = subject_from_vertex("vertex-002");
        assert_ne!(a, b);
    }

    #[test]
    fn text_quad_predicate_and_object() {
        let graph = cc_pages_graph();
        let subj  = subject_from_vertex("page-xyz");
        let q     = text_quad(&graph, &subj, "cc/url", "https://example.com");
        assert_eq!(q.predicate, "cc/url");
        assert_eq!(q.graph,   graph);
        assert_eq!(q.subject, subj);
        match q.object {
            QuadObject::Text(v) => assert_eq!(v, "https://example.com"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    #[test]
    fn int_quad_predicate_and_object() {
        let graph = cc_pages_graph();
        let subj  = subject_from_vertex("page-xyz");
        let q     = int_quad(&graph, &subj, "cc/outlink_count", 42);
        assert_eq!(q.predicate, "cc/outlink_count");
        match q.object {
            QuadObject::Integer(v) => assert_eq!(v, 42),
            other => panic!("expected Integer, got {other:?}"),
        }
    }

    #[test]
    fn cid_quad_predicate_and_object() {
        let graph   = cc_chunks_graph();
        let subj    = subject_from_chunk("page-rkey", 0);
        let target  = subject_from_vertex("page-rkey");
        let q       = cid_quad(&graph, &subj, "cc/chunk/page", &target);
        assert_eq!(q.predicate, "cc/chunk/page");
        match q.object {
            QuadObject::Cid(c) => assert_eq!(c, target),
            other => panic!("expected Cid, got {other:?}"),
        }
    }

    #[test]
    fn page_ingestor_with_batch_updates_size() {
        let qs  = make_store();
        let ing = CcPageIngestor::new(qs).with_batch(99);
        assert_eq!(ing.batch_size, 99);
    }

    #[tokio::test]
    async fn chunk_ingestor_with_batch_updates_size() {
        use crate::embed_client::Blake3EmbedClient;
        let qs    = make_store();
        let embed = Arc::new(Blake3EmbedClient::new(64));
        let ing   = CcChunkIngestor::new(qs, embed).with_batch(200);
        assert_eq!(ing.batch_size, 200);
    }
}
