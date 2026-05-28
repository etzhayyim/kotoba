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
        /// DESCRIBE only: traverse N hops along QuadObject::Cid edges from
        /// matched seeds (multi-pop subgraph expansion).  Capped at 16 server-side.
        #[arg(long, default_value = "0")]
        max_hops: usize,
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

    /// Check whether `etzhayyim/kotoba` main branch is newer than this
    /// binary's build commit.  Hits GitHub's REST API once and caches the
    /// result for 24 h in `~/.gftd/kotoba-update.json`.
    UpdateCheck {
        /// Re-fetch even if the cache is fresh.
        #[arg(long)]
        force: bool,
    },

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

    /// Derive a `did:key:z…` from a 32-byte hex Ed25519 seed.  Useful for
    /// pre-computing the DID a `kotoba serve` will boot with when
    /// KOTOBA_AGENT_ED25519_HEX is set to the same seed.
    DidDerive {
        /// 64 hex chars (32-byte seed).
        seed: String,
    },

    /// Build a real-signed CACAO authorising `quad:read` (or another cap) on a
    /// graph CID, signed by the supplied Ed25519 seed.  Output is DAG-CBOR
    /// base64-standard — paste into `cacaoB64` field of the SPARQL request.
    CacaoSign {
        /// 32-byte hex Ed25519 seed of the signer.
        seed: String,
        /// Graph CID multibase to scope the CACAO to.
        #[arg(long)]
        graph: String,
        /// Capability granted (e.g. `quad:read`, `quad:write`).
        #[arg(long, default_value = "quad:read")]
        capability: String,
        /// Audience.  Defaults to the issuer DID (the server enforces
        /// aud == operator_did on Private graphs).
        #[arg(long)]
        aud: Option<String>,
        /// CACAO nonce (anti-replay).  Default `kotoba-cli-nonce`.
        #[arg(long, default_value = "kotoba-cli-nonce")]
        nonce: String,
        /// If true, prefix the graph as `private/<did>` (matches the server's
        /// Private-visibility check).  When the server runs with
        /// KOTOBA_DEFAULT_VISIBILITY=private this is required.
        #[arg(long)]
        private: bool,
    },

    /// HTTP-level loadtest for the direct-SPARQL endpoint.  Issues `iters`
    /// POSTs of the same query (sequential or concurrent) and reports
    /// p50/p95/p99/mean in milliseconds plus aggregate QPS.
    Bench {
        /// SPARQL query to repeat.
        #[arg(default_value = r#"SELECT * WHERE { ?s <kg/claim/role> ?o }"#)]
        query: String,
        /// Total iterations (default 100).
        #[arg(long, default_value = "100")]
        iters: usize,
        /// Concurrent in-flight clients (default 1 = sequential).
        #[arg(long, short = 'c', default_value = "1")]
        concurrency: usize,
        /// Bearer token (defaults to a fresh JWT-shaped demo token).
        #[arg(long, env = "KOTOBA_DEMO_TOKEN")]
        token: Option<String>,
        /// CACAO chain (DAG-CBOR base64).  When set, every request includes
        /// `cacaoB64` — required for Private-visibility graphs.  Note: CAIP-74
        /// anti-replay nonce is single-use, so this works for one request only.
        /// Use `--cacao-seed` instead for sustained CACAO loadtests.
        #[arg(long, env = "KOTOBA_CACAO_B64")]
        cacao: Option<String>,
        /// 32-byte hex Ed25519 seed — when set, a fresh CACAO is signed for
        /// each request with a unique nonce.  Required for any sustained
        /// (`--iters > 1`) CACAO-gated bench.
        #[arg(long)]
        cacao_seed: Option<String>,
        /// Graph scope baked into the per-request CACAO.  With
        /// `--cacao-private` the scope is rewritten to `private/<did>` to
        /// match the server's Private-visibility check.
        #[arg(long, default_value = "foo")]
        cacao_graph: String,
        /// Treat the graph as Private (rewrite scope to `private/<did>`).
        #[arg(long)]
        cacao_private: bool,
        /// DESCRIBE only: N-hop multi-pop subgraph expansion depth.
        #[arg(long, default_value = "0")]
        max_hops: usize,
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
            // Fire-and-forget update-check before booting the server.  Cached
            // 24 h to avoid hitting GitHub on every restart.  Result is printed
            // to stderr so it doesn't interfere with structured logging.
            if let Some(msg) = check_for_update(false).await {
                eprintln!("{msg}");
            }
            kotoba_server::run().await?;
        }

        Cmd::Sparql { query, limit, cacao, graph, max_hops } => {
            run_sparql(&cli.url, &cli.token, &query, limit, cacao, graph, max_hops).await?;
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

        Cmd::DidDerive { seed } => {
            use ed25519_dalek::SigningKey;
            let bytes = hex::decode(seed.trim())
                .context("seed must be hex")?;
            if bytes.len() != 32 {
                anyhow::bail!("seed must decode to exactly 32 bytes, got {}", bytes.len());
            }
            let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes);
            let sk  = SigningKey::from_bytes(&arr);
            let did = kotoba_auth::did_key::ed25519_pubkey_to_did_key(
                sk.verifying_key().as_bytes()
            );
            println!("{did}");
        }

        Cmd::CacaoSign { seed, graph, capability, aud, nonce, private } => {
            use base64::{Engine, engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD}};
            use ed25519_dalek::{Signer, SigningKey};
            use kotoba_auth::did_key::ed25519_pubkey_to_did_key;
            use kotoba_auth::{Cacao, CacaoHeader, CacaoPayload, CacaoSig};

            let bytes = hex::decode(seed.trim()).context("seed must be hex")?;
            if bytes.len() != 32 {
                anyhow::bail!("seed must decode to exactly 32 bytes");
            }
            let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes);
            let sk  = SigningKey::from_bytes(&arr);
            let did = ed25519_pubkey_to_did_key(sk.verifying_key().as_bytes());

            // The Private-visibility check uses the synthetic graph scope
            // "private/<owner_did>" rather than the raw CID multibase, so the
            // CACAO must carry that scope to be accepted by the server.
            let graph_scope = if private {
                format!("private/{did}")
            } else {
                graph
            };

            let aud_resolved = aud.unwrap_or_else(|| did.clone());
            let mut cacao = Cacao {
                h: CacaoHeader { t: "caip122".into() },
                p: CacaoPayload {
                    iss:       did.clone(),
                    aud:       aud_resolved,
                    issued_at: "2026-05-26T00:00:00Z".into(),
                    expiry:    Some("2099-01-01T00:00:00Z".into()),
                    nonce,
                    domain:    "kotoba.cli".into(),
                    statement: None,
                    version:   "1".into(),
                    resources: vec![
                        format!("kotoba://graph/{graph_scope}"),
                        format!("kotoba://can/{capability}"),
                    ],
                },
                s: CacaoSig { t: "EdDSA".into(), s: String::new() },
            };
            let msg = cacao.siwe_message();
            let sig: ed25519_dalek::Signature = sk.sign(msg.as_bytes());
            cacao.s.s = URL_SAFE_NO_PAD.encode(sig.to_bytes());

            let mut cbor = Vec::new();
            ciborium::into_writer(&cacao, &mut cbor).context("cbor encode")?;
            println!("{}", B64.encode(&cbor));
        }

        Cmd::Bench { query, iters, concurrency, token, cacao, cacao_seed, cacao_graph, cacao_private, max_hops } => {
            let tok = token
                .or_else(|| cli.token.clone())
                .unwrap_or_else(|| "demo-token".into());
            run_bench(&cli.url, &tok, &query, iters, concurrency,
                cacao, cacao_seed, cacao_graph, cacao_private, max_hops).await?;
        }

        Cmd::UpdateCheck { force } => {
            let local_sha = BUILD_COMMIT;
            println!("local build commit : {local_sha}");
            match check_for_update(force).await {
                Some(msg) => println!("{msg}"),
                None      => println!("you are up to date."),
            }
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

/// A signer that produces a fresh DAG-CBOR base64 CACAO with a caller-chosen
/// nonce on every call.  Used by `kotoba bench --cacao-seed` to sustain a
/// CACAO-gated loadtest beyond iter 1 (CAIP-74 nonce is single-use).
struct CacaoSigner {
    sk:          ed25519_dalek::SigningKey,
    did:         String,
    graph_scope: String,
}

impl CacaoSigner {
    fn from_seed_hex(seed: &str, graph: &str, private: bool) -> Result<Self> {
        use ed25519_dalek::SigningKey;
        let bytes = hex::decode(seed.trim()).context("cacao seed must be hex")?;
        if bytes.len() != 32 {
            anyhow::bail!("cacao seed must decode to 32 bytes");
        }
        let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes);
        let sk  = SigningKey::from_bytes(&arr);
        let did = kotoba_auth::did_key::ed25519_pubkey_to_did_key(
            sk.verifying_key().as_bytes()
        );
        let graph_scope = if private {
            format!("private/{did}")
        } else {
            graph.to_string()
        };
        Ok(Self { sk, did, graph_scope })
    }

    fn sign_with_nonce(&self, nonce: &str) -> String {
        use base64::{Engine, engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD}};
        use ed25519_dalek::Signer;
        use kotoba_auth::{Cacao, CacaoHeader, CacaoPayload, CacaoSig};
        let mut cacao = Cacao {
            h: CacaoHeader { t: "caip122".into() },
            p: CacaoPayload {
                iss:       self.did.clone(),
                aud:       self.did.clone(),
                issued_at: "2026-05-26T00:00:00Z".into(),
                expiry:    Some("2099-01-01T00:00:00Z".into()),
                nonce:     nonce.to_string(),
                domain:    "kotoba.bench".into(),
                statement: None,
                version:   "1".into(),
                resources: vec![
                    format!("kotoba://graph/{}", self.graph_scope),
                    "kotoba://can/quad:read".into(),
                ],
            },
            s: CacaoSig { t: "EdDSA".into(), s: String::new() },
        };
        let msg = cacao.siwe_message();
        let sig: ed25519_dalek::Signature = self.sk.sign(msg.as_bytes());
        cacao.s.s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let mut cbor = Vec::new();
        ciborium::into_writer(&cacao, &mut cbor).expect("cbor encode");
        B64.encode(&cbor)
    }
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

/// HTTP SPARQL loadtest.  Issues `iters` POSTs of the same query with up to
/// `concurrency` in-flight clients; prints latency percentiles + aggregate QPS.
#[allow(clippy::too_many_arguments)]
async fn run_bench(
    base_url:      &str,
    token_in:      &str,
    query:         &str,
    iters:         usize,
    concurrency:   usize,
    cacao:         Option<String>,
    cacao_seed:    Option<String>,
    cacao_graph:   String,
    cacao_private: bool,
    max_hops:      usize,
) -> Result<()> {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let base   = base_url.trim_end_matches('/');
    let client = reqwest::Client::new();
    let token: String = if token_in.contains('.') {
        token_in.to_string()
    } else {
        demo_token()
    };

    // Resolve the CACAO signer (when --cacao-seed given) so each worker can
    // forge a fresh CACAO with unique nonce per request — the only way to
    // sustain a CACAO-gated bench past iter 1.
    let signer: Option<CacaoSigner> = if let Some(seed) = &cacao_seed {
        Some(CacaoSigner::from_seed_hex(seed, &cacao_graph, cacao_private)?)
    } else { None };

    let concurrency = concurrency.max(1);
    let mode = match (&cacao, &signer) {
        (_,        Some(_)) => "CACAO-gated (fresh CACAO per request)",
        (Some(_), _       ) => "CACAO-gated (single CACAO — likely 1 request only)",
        (None,    None    ) => "unauthed",
    };
    println!("→ benchmarking {iters} iters × concurrency {concurrency} ({mode}):");
    println!("    {query}");

    let url = Arc::new(format!("{base}/xrpc/ai.gftd.apps.kotoba.graph.sparql"));
    let token = Arc::new(token);
    let cacao_static = Arc::new(cacao);
    let signer = Arc::new(signer);
    let query  = Arc::new(query.to_string());

    let wall_start = Instant::now();

    // Per-run nonce salt — ensures CACAO nonces from this bench run do not
    // collide with nonces from prior bench runs (the server's NonceStore
    // persists across requests but inside one server process).
    let run_salt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();

    // Spawn `concurrency` workers; each consumes from a shared atomic counter
    // until `iters` requests have been dispatched.
    use std::sync::atomic::{AtomicUsize, Ordering};
    let next = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::with_capacity(concurrency);

    for worker_id in 0..concurrency {
        let client = client.clone();
        let url    = Arc::clone(&url);
        let token  = Arc::clone(&token);
        let next   = Arc::clone(&next);
        let cacao_static = Arc::clone(&cacao_static);
        let signer = Arc::clone(&signer);
        let query  = Arc::clone(&query);
        handles.push(tokio::spawn(async move {
            let mut local: Vec<Duration> = Vec::new();
            let mut last_count: u64 = 0;
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= iters { break; }
                // Per-request CACAO when --cacao-seed is set.  Nonce must be
                // unique across requests so the server's NonceStore admits it.
                let cacao_field: Option<String> = match (&*signer, cacao_static.as_ref()) {
                    (Some(s), _)    => Some(s.sign_with_nonce(
                        &format!("kb-{run_salt}-{worker_id}-{i}"))),
                    (None, Some(c)) => Some(c.clone()),
                    (None, None)    => None,
                };
                let body = serde_json::json!({
                    "query":    &*query,
                    "limit":    100_000,
                    "cacaoB64": cacao_field,
                    "maxHops":  max_hops,
                });
                let t0 = Instant::now();
                let resp = match client.post(url.as_str())
                    .header("Authorization", format!("Bearer {token}"))
                    .json(&body)
                    .send().await {
                    Ok(r)  => r,
                    Err(_) => continue,
                };
                if !resp.status().is_success() { continue; }
                let v: serde_json::Value = match resp.json().await {
                    Ok(v)  => v,
                    Err(_) => continue,
                };
                local.push(t0.elapsed());
                last_count = v["count"].as_u64().unwrap_or(0);
            }
            (local, last_count)
        }));
    }

    let mut samples:    Vec<Duration> = Vec::with_capacity(iters);
    let mut last_count: u64           = 0;
    for h in handles {
        let (mut local, n) = h.await.context("bench worker join")?;
        samples.append(&mut local);
        if n > 0 { last_count = n; }
    }
    let wall = wall_start.elapsed();
    if samples.is_empty() {
        anyhow::bail!("no successful samples — server may be unreachable");
    }
    samples.sort_unstable();

    let pct = |q: f64| -> u128 {
        let idx = ((samples.len() as f64 * q) as usize).min(samples.len() - 1);
        samples[idx].as_micros()
    };
    let mean: u128 =
        (samples.iter().map(|d| d.as_micros()).sum::<u128>()) / (samples.len() as u128);
    let qps = samples.len() as f64 / wall.as_secs_f64();

    println!("\nresults (concurrency = {concurrency}):");
    println!("  count per query : {last_count}");
    println!("  successful      : {} / {iters}", samples.len());
    println!("  p50             : {:.2} ms", pct(0.50) as f64 / 1000.0);
    println!("  p95             : {:.2} ms", pct(0.95) as f64 / 1000.0);
    println!("  p99             : {:.2} ms", pct(0.99) as f64 / 1000.0);
    println!("  mean            : {:.2} ms", mean       as f64 / 1000.0);
    println!("  wall            : {:.2} s",  wall.as_secs_f64());
    println!("  qps             : {:.1} req/s", qps);
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
    let resp = bearer(client.post(format!("{base}/xrpc/ai.gftd.apps.kotobase.kg.ingest"))
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
    max_hops: usize,
) -> Result<()> {
    let url = format!("{}/xrpc/ai.gftd.apps.kotoba.graph.sparql",
        base_url.trim_end_matches('/'));
    let client = build_client(token)?;
    let body = serde_json::json!({
        "query":    query,
        "limit":    limit,
        "cacaoB64": cacao,
        "graph":    graph,
        "maxHops":  max_hops,
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
/// `/xrpc/ai.gftd.apps.kotobase.kg.query` endpoint.  The server evaluates over
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
    let url = format!("{}/xrpc/ai.gftd.apps.kotobase.kg.query", base_url.trim_end_matches('/'));
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

// ── Update check (etzhayyim/kotoba) ───────────────────────────────────────────

/// Short SHA baked at build time by `build.rs`.  "unknown" outside a git tree
/// or when the build script did not run (e.g. cargo install from a tarball).
const BUILD_COMMIT: &str = match option_env!("KOTOBA_BUILD_COMMIT") {
    Some(s) => s,
    None    => "unknown",
};

const UPDATE_CACHE_TTL_SECS: u64 = 24 * 3600;
const UPDATE_CHECK_URL: &str =
    "https://api.github.com/repos/etzhayyim/kotoba/commits/main";

#[derive(serde::Serialize, serde::Deserialize)]
struct UpdateCache {
    checked_at: u64,    // unix seconds
    upstream_sha: String,
}

fn update_cache_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(std::path::PathBuf::from(home).join(".gftd").join("kotoba-update.json"))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_update_cache() -> Option<UpdateCache> {
    let path = update_cache_path()?;
    let raw  = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_update_cache(c: &UpdateCache) -> Result<()> {
    let path = update_cache_path().ok_or_else(|| anyhow::anyhow!("no HOME"))?;
    if let Some(p) = path.parent() { std::fs::create_dir_all(p)?; }
    std::fs::write(&path, serde_json::to_vec(c)?)?;
    Ok(())
}

/// Return a short notice string when an upstream update is available.
/// `None` means up-to-date, no network failure, or fresh-enough cache that
/// matches the local commit.  Stays silent on any failure so the user is
/// never blocked by a flaky network.
async fn check_for_update(force: bool) -> Option<String> {
    if BUILD_COMMIT == "unknown" { return None; }

    if !force {
        if let Some(c) = read_update_cache() {
            if now_secs().saturating_sub(c.checked_at) < UPDATE_CACHE_TTL_SECS {
                return notify(&c.upstream_sha);
            }
        }
    }

    // One-shot GitHub fetch.  Short timeout so this never blocks startup.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build().ok()?;
    let resp = client.get(UPDATE_CHECK_URL)
        .header("User-Agent", format!("kotoba-cli/{BUILD_COMMIT}"))
        .header("Accept",     "application/vnd.github+json")
        .send().await.ok()?;
    if !resp.status().is_success() { return None; }
    let body: serde_json::Value = resp.json().await.ok()?;
    let upstream_full = body.get("sha")?.as_str()?.to_string();
    let upstream_sha  = upstream_full.chars().take(12).collect::<String>();

    let _ = write_update_cache(&UpdateCache {
        checked_at: now_secs(),
        upstream_sha: upstream_sha.clone(),
    });

    notify(&upstream_sha)
}

fn notify(upstream_sha: &str) -> Option<String> {
    if upstream_sha == BUILD_COMMIT { return None; }
    Some(format!(
        "→ kotoba update available: upstream {upstream} ≠ local {local}\n  \
         brew upgrade etzhayyim/kotoba/kotoba   # or `brew reinstall --HEAD`\n  \
         see  https://github.com/etzhayyim/kotoba/commits/main",
        upstream = upstream_sha,
        local    = BUILD_COMMIT,
    ))
}
