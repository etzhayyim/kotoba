//! kotoba CLI — serve, block, quad, health subcommands.
//!
//! Configuration via env vars (same as the server):
//!   KOTOBA_URL   — server base URL for client subcommands (default: http://localhost:8080)
//!   KOTOBA_TOKEN — Bearer token for authenticated requests (block put, quad put/retract)
//!
//! Server env vars (serve subcommand):
//!   KOTOBA_PORT, KOTOBA_NO_SWARM, KOTOBA_IPFS_ENDPOINT, etc.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

// ── NSIDs (mirror kotoba-server::xrpc constants) ─────────────────────────────
const NSID_BLOCK_PUT:   &str = "ai.gftd.apps.kotoba.block.put";
const NSID_BLOCK_GET:   &str = "ai.gftd.apps.kotoba.block.get";
const NSID_QUAD_CREATE: &str = "ai.gftd.apps.kotoba.quad.create";
const NSID_QUAD_RETRACT:&str = "ai.gftd.apps.kotoba.quad.retract";
const NSID_GRAPH_QUERY: &str = "ai.gftd.apps.kotoba.graph.query";

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "kotoba", about = "Kotoba knowledge-graph node CLI", version)]
struct Cli {
    /// Server base URL (overrides KOTOBA_URL)
    #[arg(long, env = "KOTOBA_URL", global = true, default_value = "http://localhost:8080")]
    url: String,

    /// Bearer token for authenticated requests (overrides KOTOBA_TOKEN)
    #[arg(long, env = "KOTOBA_TOKEN", global = true)]
    token: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the kotoba server
    Serve,

    /// Raw block operations
    #[command(subcommand)]
    Block(BlockCmd),

    /// Named-graph quad operations
    #[command(subcommand)]
    Quad(QuadCmd),

    /// SPARQL or Cypher query over the running server's KG endpoint.
    /// Goes to POST /xrpc/ai.gftd.apps.yata.kg.query — which evaluates over
    /// IPFS-backed cold storage (DistributedBlockStore / Kubo HTTP).
    Sparql {
        /// SPARQL query string (max 64 KiB).
        query: String,
        /// Maximum results (1–10000, default 1000)
        #[arg(long, default_value = "1000")]
        limit: usize,
        /// CACAO chain (base64 DAG-CBOR) for private graphs
        #[arg(long, env = "KOTOBA_CACAO_B64")]
        cacao: Option<String>,
    },

    /// Cypher MATCH/RETURN over the running server (same endpoint, lang=cypher).
    Cypher {
        query: String,
        #[arg(long, default_value = "1000")]
        limit: usize,
        #[arg(long, env = "KOTOBA_CACAO_B64")]
        cacao: Option<String>,
    },

    /// Ping the server's /health endpoint
    Health,
}

#[derive(Subcommand)]
enum BlockCmd {
    /// Store bytes and return the CID.
    /// Provide data inline as hex, or use --file to read from disk.
    Put {
        /// Hex-encoded bytes (mutually exclusive with --file)
        data_hex: Option<String>,
        /// Path to file to read (mutually exclusive with inline hex)
        #[arg(long, short)]
        file: Option<std::path::PathBuf>,
    },
    /// Retrieve a block by CID (multibase)
    Get {
        cid: String,
        /// Write raw bytes to this path instead of printing base64
        #[arg(long, short)]
        out: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum QuadCmd {
    /// Assert a quad: <graph-cid> <subject> <predicate> <object>
    Put {
        graph:     String,
        subject:   String,
        predicate: String,
        object:    String,
    },
    /// Retract a quad: <graph-cid> <subject> <predicate> <object>
    Retract {
        graph:     String,
        subject:   String,
        predicate: String,
        object:    String,
    },
    /// SPO pattern query over a named graph
    Query {
        /// Named graph CID (multibase)
        #[arg(long)]
        graph: String,
        /// Subject filter (multibase CID or raw string)
        #[arg(long, short)]
        subject: Option<String>,
        /// Predicate filter (exact string)
        #[arg(long, short)]
        predicate: Option<String>,
        /// Maximum results (1–1000, default 100)
        #[arg(long, default_value = "100")]
        limit: u64,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Serve => {
            // Re-init logging at INFO for serve mode unless RUST_LOG is set
            kotoba_server::run().await?;
        }

        Cmd::Sparql { query, limit, cacao } => {
            run_kg_query(&cli.url, &cli.token, "sparql", &query, limit, cacao).await?;
        }

        Cmd::Cypher { query, limit, cacao } => {
            run_kg_query(&cli.url, &cli.token, "cypher", &query, limit, cacao).await?;
        }

        Cmd::Health => {
            let url = format!("{}/health", cli.url.trim_end_matches('/'));
            let resp = reqwest::get(&url).await.context("GET /health failed")?;
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            println!("{status}  {body}");
            if !status.is_success() {
                std::process::exit(1);
            }
        }

        Cmd::Block(block_cmd) => {
            let client = build_client(&cli.token)?;
            match block_cmd {
                BlockCmd::Put { data_hex, file } => {
                    let bytes = match (data_hex, file) {
                        (Some(hex), None) => hex::decode(hex.trim())
                            .context("invalid hex data")?,
                        (None, Some(path)) => std::fs::read(&path)
                            .with_context(|| format!("reading {}", path.display()))?,
                        (Some(_), Some(_)) => anyhow::bail!("specify data_hex OR --file, not both"),
                        (None, None) => {
                            // Read stdin
                            use std::io::Read;
                            let mut buf = Vec::new();
                            std::io::stdin().read_to_end(&mut buf)?;
                            buf
                        }
                    };

                    let data_b64 = B64.encode(&bytes);
                    let url = format!(
                        "{}/xrpc/{}",
                        cli.url.trim_end_matches('/'),
                        NSID_BLOCK_PUT
                    );
                    let resp = client
                        .post(&url)
                        .json(&serde_json::json!({ "data_b64": data_b64 }))
                        .send()
                        .await
                        .context("POST block.put failed")?;
                    check_status(&resp)?;
                    let json: serde_json::Value = resp.json().await?;
                    println!("{}", json["cid"].as_str().unwrap_or("(no cid)"));
                }

                BlockCmd::Get { cid, out } => {
                    let url = format!(
                        "{}/xrpc/{}?cid={}",
                        cli.url.trim_end_matches('/'),
                        NSID_BLOCK_GET,
                        urlencoding::encode(&cid)
                    );
                    let resp = client.get(&url).send().await.context("GET block.get failed")?;
                    check_status(&resp)?;
                    let json: serde_json::Value = resp.json().await?;
                    let data_b64 = json["data_b64"].as_str().unwrap_or("");
                    let bytes = B64.decode(data_b64).context("invalid base64 in response")?;

                    if let Some(path) = out {
                        std::fs::write(&path, &bytes)
                            .with_context(|| format!("writing {}", path.display()))?;
                        eprintln!("wrote {} bytes to {}", bytes.len(), path.display());
                    } else {
                        print!("{}", B64.encode(&bytes));
                    }
                }
            }
        }

        Cmd::Quad(quad_cmd) => {
            let client = build_client(&cli.token)?;
            match quad_cmd {
                QuadCmd::Put { graph, subject, predicate, object } => {
                    let url = format!(
                        "{}/xrpc/{}",
                        cli.url.trim_end_matches('/'),
                        NSID_QUAD_CREATE
                    );
                    let resp = client
                        .post(&url)
                        .json(&serde_json::json!({
                            "graph":     graph,
                            "subject":   subject,
                            "predicate": predicate,
                            "object":    object,
                        }))
                        .send()
                        .await
                        .context("POST quad.create failed")?;
                    check_status(&resp)?;
                    let json: serde_json::Value = resp.json().await?;
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }

                QuadCmd::Retract { graph, subject, predicate, object } => {
                    let url = format!(
                        "{}/xrpc/{}",
                        cli.url.trim_end_matches('/'),
                        NSID_QUAD_RETRACT
                    );
                    let resp = client
                        .post(&url)
                        .json(&serde_json::json!({
                            "graph":     graph,
                            "subject":   subject,
                            "predicate": predicate,
                            "object":    object,
                        }))
                        .send()
                        .await
                        .context("POST quad.retract failed")?;
                    check_status(&resp)?;
                    let json: serde_json::Value = resp.json().await?;
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }

                QuadCmd::Query { graph, subject, predicate, limit } => {
                    let mut url = format!(
                        "{}/xrpc/{}?graph={}&limit={}",
                        cli.url.trim_end_matches('/'),
                        NSID_GRAPH_QUERY,
                        urlencoding::encode(&graph),
                        limit,
                    );
                    if let Some(s) = &subject {
                        url.push_str(&format!("&subject={}", urlencoding::encode(s)));
                    }
                    if let Some(p) = &predicate {
                        url.push_str(&format!("&predicate={}", urlencoding::encode(p)));
                    }
                    let resp = client.get(&url).send().await.context("GET graph.query failed")?;
                    check_status(&resp)?;
                    let json: serde_json::Value = resp.json().await?;
                    println!("{}", serde_json::to_string_pretty(&json)?);
                }
            }
        }
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_client(token: &Option<String>) -> Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(tok) = token {
        let val = reqwest::header::HeaderValue::from_str(&format!("Bearer {tok}"))
            .context("invalid token value")?;
        headers.insert(reqwest::header::AUTHORIZATION, val);
    }
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .context("building HTTP client")
}

fn check_status(resp: &reqwest::Response) -> Result<()> {
    let status = resp.status();
    if !status.is_success() {
        anyhow::bail!("server returned {status}");
    }
    Ok(())
}

/// POST a SPARQL/Cypher query to the running server's
/// `/xrpc/ai.gftd.apps.yata.kg.query` endpoint.  The server evaluates over
/// IPFS-backed cold storage (Kubo HTTP via KOTOBA_IPFS_ENDPOINT or a
/// DistributedBlockStore multi-peer setup).
async fn run_kg_query(
    base_url: &str,
    token:    &Option<String>,
    lang:     &str,
    query:    &str,
    limit:    usize,
    cacao:    Option<String>,
) -> Result<()> {
    let url = format!("{}/xrpc/ai.gftd.apps.yata.kg.query", base_url.trim_end_matches('/'));
    let client = build_client(token)?;
    let body = serde_json::json!({
        "lang":     lang,
        "query":    query,
        "limit":    limit,
        "cacaoB64": cacao,
    });
    let resp = client.post(&url).json(&body).send().await
        .context("POST kg.query failed")?;
    check_status(&resp)?;
    let v: serde_json::Value = resp.json().await.context("decode kg.query JSON")?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}
