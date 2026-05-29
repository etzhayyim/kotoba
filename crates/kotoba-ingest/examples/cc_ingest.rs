//! Common Crawl parquet → Kotoba QuadStore ingest CLI.
//!
//! Usage:
//!   cargo run --release --example cc_ingest -p kotoba-ingest -- \
//!     --dir /Volumes/251220/CC/2603 \
//!     --mode chunks \
//!     --max-files 5
//!
//! Env vars:
//!   KOTOBA_EMBED_URL   — OpenAI-compat embedding endpoint (default: Blake3 test embedder)
//!   KOTOBA_EMBED_MODEL — model name (default: nomic-embed-text)
//!   KOTOBA_EMBED_DIM   — embedding dimension (default: 768)
//!   KOTOBA_EMBED_BATCH — batch size for embed API (default: 64)

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use kotoba_graph::QuadStore;
use kotoba_kse::Journal;
use kotoba_store::MemoryBlockStore;

use kotoba_ingest::cc::{CcChunkIngestor, CcPageIngestor};
use kotoba_ingest::embed_client::{Blake3EmbedClient, EmbedClient, HttpEmbedClient};

fn parse_args() -> (PathBuf, String, Option<usize>) {
    let args: Vec<String> = std::env::args().collect();
    let mut dir = PathBuf::from(".");
    let mut mode = "chunks".to_string();
    let mut max_files = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => {
                i += 1;
                dir = PathBuf::from(&args[i]);
            }
            "--mode" => {
                i += 1;
                mode = args[i].clone();
            }
            "--max-files" => {
                i += 1;
                max_files = args[i].parse().ok();
            }
            _ => {}
        }
        i += 1;
    }
    (dir, mode, max_files)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let (dir, mode, max_files) = parse_args();

    // In-memory store for this example (swap for SledBlockStore for persistence)
    let block_store = Arc::new(MemoryBlockStore::default());
    let journal = Arc::new(Journal::new());
    let quad_store = Arc::new(QuadStore::new(journal, block_store));

    let embed_client: Arc<dyn EmbedClient> = match HttpEmbedClient::from_env() {
        Ok(c) => {
            tracing::info!(
                model = c.model_id(),
                dim = c.dim(),
                "Using HTTP embed client"
            );
            Arc::new(c)
        }
        Err(_) => {
            tracing::info!("KOTOBA_EMBED_URL not set; using Blake3 test embedder (dim=384)");
            Arc::new(Blake3EmbedClient::new(384))
        }
    };

    let start = std::time::Instant::now();

    if mode == "pages" || mode == "both" {
        tracing::info!(?dir, "Starting CC pages ingest");
        let ingestor = CcPageIngestor::new(Arc::clone(&quad_store));
        let (files, quads) = ingestor.ingest_dir(&dir, max_files).await?;
        tracing::info!(
            files,
            quads,
            elapsed_s = start.elapsed().as_secs_f32(),
            "CC pages ingest complete"
        );
    }

    if mode == "chunks" || mode == "both" {
        tracing::info!(?dir, "Starting CC chunks ingest");
        let ingestor = CcChunkIngestor::new(Arc::clone(&quad_store), Arc::clone(&embed_client));
        let (chunks, embeddings) = ingestor.ingest_dir(&dir, max_files).await?;
        tracing::info!(
            chunks,
            embeddings,
            elapsed_s = start.elapsed().as_secs_f32(),
            "CC chunks ingest complete"
        );
    }

    tracing::info!(total_elapsed_s = start.elapsed().as_secs_f32(), "Done");
    Ok(())
}
