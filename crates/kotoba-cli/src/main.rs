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

    /// SPARQL query (SELECT / DESCRIBE / CONSTRUCT / ASK) over the running
    /// server's direct-SPARQL endpoint.  Auto-detects the form from the
    /// query.  Goes to POST /xrpc/ai.gftd.apps.kotoba.graph.sparql which
    /// runs over IPFS-backed cold storage (DistributedBlockStore / Kubo HTTP).
    Sparql {
        /// SPARQL query string (max 64 KiB).
        query: String,
        /// Maximum quads returned (default 10000)
        #[arg(long, default_value = "10000")]
        limit: usize,
        /// CACAO chain (base64 DAG-CBOR) for private graphs
        #[arg(long, env = "KOTOBA_CACAO_B64")]
        cacao: Option<String>,
        /// Target named graph CID (multibase). Defaults to the kg-graph.
        #[arg(long)]
        graph: Option<String>,
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

    /// Initialise device-local identity (Ed25519 + X25519 + DID) and persist to
    /// macOS Keychain (or ~/.gftd/kotoba.env on Linux/other).  Subsequent
    /// `kotoba serve` invocations will load these automatically and the DID
    /// remains stable across restarts.
    Init {
        /// Overwrite any existing device-local identity.
        #[arg(long)]
        force: bool,
        /// Print the resulting DID + hex material to stdout.
        #[arg(long)]
        show: bool,
    },

    /// Print the local deployment-config summary (env-driven): identity
    /// source, IPFS endpoint, peer list, default visibility, hot-cache size.
    Whoami,

    /// End-to-end smoke: ingest a sample entity via kg.ingest, then run
    /// SELECT / ASK / DESCRIBE / CONSTRUCT through the direct-SPARQL endpoint.
    /// Useful for verifying that `kotoba serve` is wired up against the
    /// expected IPFS + CACAO + graph stack.
    Demo {
        /// Bearer token used for the Authenticated tier (kg graph default).
        /// If absent, falls back to `KOTOBA_TOKEN` or "demo-token".
        #[arg(long, env = "KOTOBA_DEMO_TOKEN")]
        token: Option<String>,
    },

    /// HTTP-level loadtest for the direct-SPARQL endpoint.  Issues `iters`
    /// sequential POSTs of the same query and reports p50 / p95 / p99 / mean
    /// in milliseconds.  Use after `kotoba demo` has seeded a quad so the
    /// query has non-empty results.
    Bench {
        /// SPARQL query to repeat.
        #[arg(default_value = r#"SELECT * WHERE { ?s <kg/claim/role> ?o }"#)]
        query: String,
        /// Number of sequential iterations (default 100).
        #[arg(long, default_value = "100")]
        iters: usize,
        /// Bearer token (defaults to a fresh JWT-shaped demo token).
        #[arg(long, env = "KOTOBA_DEMO_TOKEN")]
        token: Option<String>,
    },
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

        Cmd::Sparql { query, limit, cacao, graph } => {
            run_sparql(&cli.url, &cli.token, &query, limit, cacao, graph).await?;
        }

        Cmd::Cypher { query, limit, cacao } => {
            run_kg_query(&cli.url, &cli.token, "cypher", &query, limit, cacao).await?;
        }

        Cmd::Init { force, show } => {
            // Refuse to overwrite an existing identity unless --force.
            if !force {
                if let Some(existing) = kotoba_kse::AgentIdentity::from_keychain() {
                    anyhow::bail!(
                        "device-local identity already exists (DID={}). \
                         Use --force to overwrite.",
                        existing.did
                    );
                }
            }
            let id = kotoba_kse::AgentIdentity::generate_persistent();
            id.persist_to_keychain().context("persisting identity")?;
            println!("Persisted identity to macOS Keychain (or ~/.gftd/kotoba.env).");
            println!("DID: {}", id.did);
            if show {
                println!("KOTOBA_AGENT_ED25519_HEX={}", hex::encode(id.signing_key.to_bytes()));
                println!("KOTOBA_AGENT_X25519_HEX={}",  hex::encode(id.dh_secret.to_bytes()));
                println!("KOTOBA_AGENT_DID={}",         id.did);
            }
        }

        Cmd::Demo { token } => {
            let tok = token
                .or_else(|| cli.token.clone())
                .unwrap_or_else(|| "demo-token".into());
            run_demo(&cli.url, &tok).await?;
        }

        Cmd::Bench { query, iters, token } => {
            let tok = token
                .or_else(|| cli.token.clone())
                .unwrap_or_else(|| "demo-token".into());
            run_bench(&cli.url, &tok, &query, iters).await?;
        }

        Cmd::Whoami => {
            // Resolve identity (keychain → env → ephemeral)
            let id = kotoba_kse::AgentIdentity::from_env();
            let source = if id.ephemeral { "ephemeral (no keychain, no env)" }
                else if kotoba_kse::AgentIdentity::from_keychain().is_some() { "keychain" }
                else { "env" };
            let ipfs_off = std::env::var("KOTOBA_IPFS")
                .map(|v| v.eq_ignore_ascii_case("off") || v == "0" || v.eq_ignore_ascii_case("false"))
                .unwrap_or(false);
            let ipfs_endpoint = std::env::var("KOTOBA_IPFS_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:5001 (default)".into());
            let peers = std::env::var("KOTOBA_PEERS").unwrap_or_default();
            let default_vis = std::env::var("KOTOBA_DEFAULT_VISIBILITY")
                .unwrap_or_else(|_| "private (default)".into());
            let hot_mib = std::env::var("KOTOBA_HOT_CACHE_BYTES")
                .or_else(|_| std::env::var("KOTOBA_STORAGE_BUDGET_BYTES"))
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .map(|b| b / (1024 * 1024))
                .unwrap_or(256);
            println!("identity source       : {source}");
            println!("DID                   : {}", id.did);
            println!("ephemeral             : {}", id.ephemeral);
            println!("IPFS cold tier        : {}", if ipfs_off { "OFF (KOTOBA_IPFS=off)" } else { "ON" });
            println!("KOTOBA_IPFS_ENDPOINT  : {ipfs_endpoint}");
            println!("KOTOBA_PEERS          : {}",
                if peers.trim().is_empty() { "(none — single-node)".into() }
                else { peers.split_whitespace().collect::<Vec<_>>().join(", ") });
            println!("default visibility    : {default_vis}");
            println!("hot cache             : {hot_mib} MiB");
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

/// Build a non-expiring JWT-shaped token. The kotoba server's Authenticated
/// tier accepts any Bearer token whose `exp` claim is in the future — it does
/// NOT verify the signature (the upstream PDS / edge BFF is the trust
/// boundary).  This lets the demo run without an external identity service.
fn demo_token() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let header  = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        br#"{"sub":"did:key:zKotobaDemo","exp":9999999999}"#
    );
    format!("{header}.{payload}.demosig")
}

/// Sequential SPARQL loadtest.  Issues `iters` POSTs of the same query and
/// prints p50/p95/p99/mean in milliseconds plus the response count.
async fn run_bench(base_url: &str, token_in: &str, query: &str, iters: usize) -> Result<()> {
    use std::time::{Duration, Instant};

    let base   = base_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let token: String = if token_in.contains('.') {
        token_in.to_string()
    } else {
        demo_token()
    };

    println!("→ benchmarking {iters} iterations of:");
    println!("    {query}");

    let url = format!("{base}/xrpc/ai.gftd.apps.kotoba.graph.sparql");
    let body = serde_json::json!({ "query": query, "limit": 10_000 });

    let mut samples: Vec<Duration> = Vec::with_capacity(iters);
    let mut last_count: u64 = 0;
    for _ in 0..iters {
        let t0 = Instant::now();
        let resp = client.post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .json(&body)
            .send().await.context("bench POST")?;
        check_status(&resp)?;
        let v: serde_json::Value = resp.json().await.context("bench JSON")?;
        samples.push(t0.elapsed());
        last_count = v["count"].as_u64().unwrap_or(0);
    }
    samples.sort_unstable();

    let pct = |q: f64| -> u128 {
        let idx = ((samples.len() as f64 * q) as usize).min(samples.len() - 1);
        samples[idx].as_micros()
    };
    let mean: u128 =
        (samples.iter().map(|d| d.as_micros()).sum::<u128>()) / (samples.len() as u128);

    println!("\nresults (sequential, single client):");
    println!("  count per query : {last_count}");
    println!("  p50             : {:.2} ms", pct(0.50) as f64 / 1000.0);
    println!("  p95             : {:.2} ms", pct(0.95) as f64 / 1000.0);
    println!("  p99             : {:.2} ms", pct(0.99) as f64 / 1000.0);
    println!("  mean            : {:.2} ms", mean   as f64 / 1000.0);
    println!("  total           : {:.2} s",  samples.iter().sum::<Duration>().as_secs_f64());
    Ok(())
}

/// End-to-end smoke: ingest a sample entity then run all four SPARQL forms.
async fn run_demo(base_url: &str, token_in: &str) -> Result<()> {
    let base   = base_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    // If the caller passed a placeholder lacking JWT shape, upgrade to a
    // proper JWT-shaped token so the Bearer-auth gate accepts us.
    let token: String = if token_in.contains('.') {
        token_in.to_string()
    } else {
        demo_token()
    };
    let token = &token;

    let bearer = |req: reqwest::RequestBuilder| {
        req.header("Authorization", format!("Bearer {token}"))
    };

    // 1. ingest
    println!("→ ingest sample entity (kg.ingest)");
    let ingest_body = serde_json::json!({
        "id":         "kotoba-demo-001",
        "type":       "Person",
        "labelEn":    "Demo Subject",
        "confidence": "0.95",
        "license":    "CC0-1.0",
        "sourceId":   "kotoba-demo",
        "claims": [
            { "pred": "role",       "value": "admin" },
            { "pred": "occupation", "value": "engineer" }
        ],
        "relations": []
    });
    let resp = bearer(client.post(format!("{base}/xrpc/ai.gftd.apps.yata.kg.ingest"))
        .json(&ingest_body))
        .send().await.context("kg.ingest POST")?;
    check_status(&resp)?;
    let put: serde_json::Value = resp.json().await.context("ingest JSON")?;
    let subj_cid = put["subjectCid"].as_str()
        .ok_or_else(|| anyhow::anyhow!("ingest response missing subjectCid: {put}"))?
        .to_string();
    println!("  ingested subjectCid: {subj_cid}");

    // 2. SELECT
    println!("→ SELECT * WHERE {{ ?s <kg/claim/role> ?o }}");
    let sel = sparql_req(&client, base, token.as_str(),
        r#"SELECT * WHERE { ?s <kg/claim/role> ?o }"#).await?;
    println!("  count={} (≥1 expected)", sel["count"]);

    // 3. ASK true
    println!("→ ASK {{ ?s <kg/claim/role> \"admin\" }}");
    let ask = sparql_req(&client, base, token.as_str(),
        r#"ASK { ?s <kg/claim/role> "admin" }"#).await?;
    println!("  result={}", ask["result"]);

    // 4. DESCRIBE the subject
    println!("→ DESCRIBE <cid:{subj_cid}>");
    let descr = sparql_req(&client, base, token.as_str(),
        &format!("DESCRIBE <cid:{subj_cid}>")).await?;
    println!("  count={} quads about the subject", descr["count"]);

    // 5. CONSTRUCT
    println!("→ CONSTRUCT {{ ?s <admin> \"yes\" }} WHERE {{ ?s <kg/claim/role> \"admin\" }}");
    let con = sparql_req(&client, base, token.as_str(),
        r#"CONSTRUCT { ?s <admin> "yes" } WHERE { ?s <kg/claim/role> "admin" }"#).await?;
    println!("  count={} constructed quads", con["count"]);

    println!("\n✓ demo complete — all four SPARQL forms executed against IPFS-backed cold path");
    Ok(())
}

async fn sparql_req(client: &reqwest::Client, base: &str, token: &str, query: &str)
    -> Result<serde_json::Value>
{
    let resp = client.post(format!("{base}/xrpc/ai.gftd.apps.kotoba.graph.sparql"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({ "query": query, "limit": 1000 }))
        .send().await.context("kg.sparql POST")?;
    check_status(&resp)?;
    resp.json().await.context("sparql JSON")
}

/// POST a SPARQL query (any form) to the direct-SPARQL endpoint.
async fn run_sparql(
    base_url: &str,
    token:    &Option<String>,
    query:    &str,
    limit:    usize,
    cacao:    Option<String>,
    graph:    Option<String>,
) -> Result<()> {
    let url = format!("{}/xrpc/ai.gftd.apps.kotoba.graph.sparql",
        base_url.trim_end_matches('/'));
    let client = build_client(token)?;
    let body = serde_json::json!({
        "query":    query,
        "limit":    limit,
        "cacaoB64": cacao,
        "graph":    graph,
    });
    let resp = client.post(&url).json(&body).send().await
        .context("POST kotoba.graph.sparql failed")?;
    check_status(&resp)?;
    let v: serde_json::Value = resp.json().await
        .context("decode kotoba.graph.sparql JSON")?;
    println!("{}", serde_json::to_string_pretty(&v)?);
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
