//! gftdcojp: Chargespot BMA — kotoba-server ingest client
//!
//! Generates an ephemeral Ed25519 keypair, builds a self-signed CACAO with
//! `quad:write` capability, and ingests all Chargespot BMA Quads into a
//! running kotoba-server via:
//!   - XRPC  POST /xrpc/ai.gftd.apps.kotoba.quad.create   (one per Quad)
//!   - XRPC  POST /xrpc/ai.gftd.apps.kotoba.commit.store  (once at end)
//!   - MCP   POST /mcp  kotoba_graph_query                 (verify round-trip)
//!
//! Usage:
//!   KOTOBA_SERVER=http://localhost:8080 cargo run -p gftdcojp-chargespot-ingest

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use kotoba_auth::{did_key::ed25519_pubkey_to_did_key, Cacao, CacaoHeader, CacaoPayload, CacaoSig};
use kotoba_core::cid::KotobaCid;
use kotoba_kqe::{
    delta::Delta,
    quad::{Quad, QuadObject},
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

// ── Graph identifier ──────────────────────────────────────────────────────────
const GRAPH_ID: &str = "gftdcojp:bma:chargespot:v1";

// ── Quad data (same as gftdcojp-chargespot-bma example) ──────────────────────

const COMPETITORS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "energy-monster",
        "cn",
        "怪兽充電 (Energy Monster)",
        "dominant",
        "NASDAQ上場(EM)、国内最大手",
    ),
    (
        "meituan-charge",
        "cn",
        "美団充電 (Meituan)",
        "dominant",
        "怪兽買収後に国内最大規模",
    ),
    (
        "zhuman-tech",
        "cn",
        "竹芒科技",
        "active",
        "街電＋搜電合併、数億台規模",
    ),
    ("xiaodian", "cn", "小電科技", "active", "SoftBank等出資あり"),
    ("laidian", "cn", "来電科技", "active", "大型キオスク特化"),
    (
        "chargespot",
        "jp",
        "Chargespot (INFORICH)",
        "dominant",
        "国内一強、IIJ系",
    ),
    ("batt-kr", "kr", "Batt", "active", "韓国主要プレイヤー"),
    (
        "kakao-charge",
        "kr",
        "KakaoMobility系",
        "active",
        "プラットフォーム統合型",
    ),
    (
        "charge-plus-sg",
        "sea",
        "Charge+ (Singapore)",
        "struggling",
        "観光地中心、採算不安定",
    ),
    (
        "magicpower-th",
        "sea",
        "MagicPower (Thailand)",
        "struggling",
        "低返却率問題",
    ),
    (
        "chargeitspot",
        "us",
        "ChargeItSpot",
        "struggling",
        "医療・商業施設特化",
    ),
    (
        "veloxity",
        "us",
        "Veloxity",
        "struggling",
        "イベント会場中心",
    ),
    (
        "brightbox",
        "us",
        "Brightbox",
        "active",
        "B2B向けロッカー型",
    ),
    ("incharge", "us", "InCharge", "struggling", "小規模展開"),
    (
        "charge-anywhere",
        "eu",
        "Charge Anywhere",
        "struggling",
        "欧州各国展開、収益低",
    ),
    (
        "locker-eu",
        "eu",
        "Locker (various)",
        "struggling",
        "分散的、スケール未達",
    ),
];

const REGIONS: &[(&str, &str, i64, i64, i64)] = &[
    ("cn", "中国", 5, 5, 80),
    ("jp", "日本", 1, 4, 8),
    ("kr", "韓国", 2, 3, 3),
    ("sea", "東南アジア", 3, 2, 4),
    ("us", "北米", 4, 2, 3),
    ("eu", "欧州", 2, 1, 2),
];

const STRUGGLE_FACTORS: &[(&str, &str, &str, i64)] = &[
    (
        "f1",
        "user_behavior",
        "車移動中心・スマホ依存度低・自分でバッテリーを持つ文化 (欧米)",
        5,
    ),
    (
        "f2",
        "unit_economics",
        "観光地特化=季節変動大・キオスク設置コスト固定・回転率低で採算未達",
        5,
    ),
    (
        "f3",
        "venue_negotiation",
        "商業施設との設置交渉コスト高・リベニューシェア構造が複雑 (欧米)",
        4,
    ),
    (
        "f4",
        "payment_friction",
        "クレカ登録・アプリDLの離脱率高・デポジット取得コスト (欧米・東南アジア)",
        4,
    ),
    (
        "f5",
        "theft_return",
        "返却率低・デポジット回収の法的コスト高 (欧米・東南アジア一部)",
        3,
    ),
];

const SUCCESS_CONDITIONS: &[(&str, &str, &str)] = &[
    ("sc1", "高密度な徒歩生活圏 (通勤・街ブラ文化)", "cn,jp,kr"),
    ("sc2", "QRコード決済・デポジット即取得の普及", "cn,jp,kr"),
    ("sc3", "日常動線 (コンビニ・飲食店) への設置", "cn,jp"),
    ("sc4", "返却文化・低盗難率", "cn,jp,kr"),
    (
        "sc5",
        "スマホ依存度が高い (決済・交通・地図が全てスマホ)",
        "cn,jp,kr",
    ),
];

// ── Quad builder (identical to bma example) ──────────────────────────────────

fn cid(s: &str) -> KotobaCid {
    KotobaCid::from_bytes(s.as_bytes())
}
fn graph_cid_val() -> KotobaCid {
    cid(GRAPH_ID)
}

fn quad(subject: &str, predicate: &str, object: QuadObject) -> Quad {
    Quad {
        graph: graph_cid_val(),
        subject: cid(subject),
        predicate: predicate.to_string(),
        object,
    }
}

fn build_facts() -> Vec<Delta> {
    let mut d = Vec::new();
    d.push(Delta::assert(quad(
        "gftdcojp:bma:chargespot",
        "bma/namespace",
        QuadObject::Text("gftdcojp".into()),
    )));
    d.push(Delta::assert(quad(
        "gftdcojp:bma:chargespot",
        "bma/subject",
        QuadObject::Text("モバイルバッテリーシェアリング競合分析".into()),
    )));
    d.push(Delta::assert(quad(
        "gftdcojp:bma:chargespot",
        "bma/model_type",
        QuadObject::Text("mobile-battery-sharing".into()),
    )));
    d.push(Delta::assert(quad(
        "gftdcojp:bma:chargespot",
        "bma/date",
        QuadObject::Text("2026-05-27".into()),
    )));
    d.push(Delta::assert(quad(
        "gftdcojp:bma:chargespot",
        "bma/version",
        QuadObject::Text("v1".into()),
    )));
    for (id, region, name, status, notes) in COMPETITORS {
        let cid_str = format!("gftdcojp:bma:chargespot:competitor:{id}");
        d.push(Delta::assert(quad(
            "gftdcojp:bma:chargespot",
            "bma/competitor",
            QuadObject::Cid(cid(&cid_str)),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "competitor/region",
            QuadObject::Text(region.to_string()),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "competitor/name",
            QuadObject::Text(name.to_string()),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "competitor/status",
            QuadObject::Text(status.to_string()),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "competitor/notes",
            QuadObject::Text(notes.to_string()),
        )));
    }
    for (rid, name, count, maturity, share_pct) in REGIONS {
        let cid_str = format!("gftdcojp:bma:chargespot:region:{rid}");
        d.push(Delta::assert(quad(
            "gftdcojp:bma:chargespot",
            "bma/region",
            QuadObject::Cid(cid(&cid_str)),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "region/code",
            QuadObject::Text(rid.to_string()),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "region/name",
            QuadObject::Text(name.to_string()),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "region/competitor_count",
            QuadObject::Integer(*count),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "region/maturity",
            QuadObject::Integer(*maturity),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "region/market_share_pct",
            QuadObject::Integer(*share_pct),
        )));
    }
    for (fid, category, desc, severity) in STRUGGLE_FACTORS {
        let cid_str = format!("gftdcojp:bma:chargespot:factor:{fid}");
        d.push(Delta::assert(quad(
            "gftdcojp:bma:chargespot",
            "bma/struggle_factor",
            QuadObject::Cid(cid(&cid_str)),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "factor/category",
            QuadObject::Text(category.to_string()),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "factor/description",
            QuadObject::Text(desc.to_string()),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "factor/severity",
            QuadObject::Integer(*severity),
        )));
    }
    for (scid, desc, regions) in SUCCESS_CONDITIONS {
        let cid_str = format!("gftdcojp:bma:chargespot:success:{scid}");
        d.push(Delta::assert(quad(
            "gftdcojp:bma:chargespot",
            "bma/success_condition",
            QuadObject::Cid(cid(&cid_str)),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "condition/description",
            QuadObject::Text(desc.to_string()),
        )));
        d.push(Delta::assert(quad(
            &cid_str,
            "condition/present_in",
            QuadObject::Text(regions.to_string()),
        )));
    }
    d
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

/// Ephemeral Ed25519 identity for this ingest run.
struct IngestIdentity {
    signing_key: SigningKey,
    did: String,
}

impl IngestIdentity {
    fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let did = ed25519_pubkey_to_did_key(signing_key.verifying_key().as_bytes());
        Self { signing_key, did }
    }

    /// Build a self-signed CACAO granting `quad:write` on all graphs.
    /// Signed with EdDSA (Ed25519) over the SIWE plaintext.
    fn make_cacao(&self, server_url: &str) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = now + 3600; // 1 hour

        let fmt = |secs: u64| -> String {
            // YYYY-MM-DDTHH:MM:SSZ
            let s = secs;
            let sec = s % 60;
            let s = s / 60;
            let min = s % 60;
            let s = s / 60;
            let hour = s % 24;
            let days = s / 24;
            // days since 1970-01-01
            let (y, mo, d) = days_to_ymd(days);
            format!("{y:04}-{mo:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
        };

        let payload = CacaoPayload {
            iss: self.did.clone(),
            aud: server_url.to_string(),
            issued_at: fmt(now),
            expiry: Some(fmt(exp)),
            nonce: format!("{:016x}", now),
            domain: "localhost".to_string(),
            statement: Some("kotoba ingest: gftdcojp BMA chargespot".to_string()),
            version: "1".to_string(),
            resources: vec!["kotoba://can/quad:write".to_string()],
        };

        let cacao = Cacao {
            h: CacaoHeader {
                t: "eip4361".to_string(),
            },
            p: payload,
            s: CacaoSig {
                t: String::new(),
                s: String::new(),
            }, // filled below
        };

        // Sign the SIWE message with Ed25519
        let msg = cacao.siwe_message();
        let sig: ed25519_dalek::Signature = self.signing_key.sign(msg.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        let signed = Cacao {
            s: CacaoSig {
                t: "EdDSA".to_string(),
                s: sig_b64,
            },
            ..cacao
        };

        // Serialize to DAG-CBOR → standard base64
        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&signed, &mut cbor_bytes).context("CACAO DAG-CBOR serialize")?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&cbor_bytes))
    }

    /// Build a minimal JWT for MCP `tools/call` auth.
    /// kotoba-server only checks `exp` — no signature verification.
    fn make_jwt(&self) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(format!(r#"{{"sub":"{}","exp":{}}}"#, self.did, exp));
        let sig_input = format!("{header}.{payload}");
        let sig_bytes: ed25519_dalek::Signature = self.signing_key.sign(sig_input.as_bytes());
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes.to_bytes());
        format!("{header}.{payload}.{sig}")
    }
}

// ── Quad → string object representation ──────────────────────────────────────

fn object_to_string(obj: &QuadObject) -> String {
    match obj {
        QuadObject::Text(t) => t.clone(),
        QuadObject::Integer(i) => i.to_string(),
        QuadObject::Float(f) => f.to_string(),
        QuadObject::Bool(b) => b.to_string(),
        QuadObject::Cid(c) => multibase::encode(multibase::Base::Base32Lower, &c.0),
        _ => "<binary>".to_string(),
    }
}

// ── Date math (no external dep) ──────────────────────────────────────────────

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    loop {
        let dy = if is_leap(y) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let months = [
        31u64,
        if is_leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mo = 1u64;
    for &dm in &months {
        if days < dm {
            break;
        }
        days -= dm;
        mo += 1;
    }
    (y, mo, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── MCP JSON-RPC helper ───────────────────────────────────────────────────────

async fn mcp_call(
    client: &reqwest::Client,
    url: &str,
    jwt: &str,
    id: u64,
    tool: &str,
    args: Value,
) -> Result<Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": tool, "arguments": args }
    });
    let resp = client
        .post(url)
        .bearer_auth(jwt)
        .json(&body)
        .send()
        .await
        .context("MCP POST")?;
    let status = resp.status();
    let val: Value = resp.json().await.context("MCP response parse")?;
    if !status.is_success() {
        anyhow::bail!("MCP {tool} HTTP {status}: {val}");
    }
    if let Some(err) = val.get("error") {
        anyhow::bail!("MCP {tool} error: {err}");
    }
    Ok(val)
}

// ── XRPC helpers ─────────────────────────────────────────────────────────────

async fn xrpc_quad_create(
    client: &reqwest::Client,
    base: &str,
    graph: &str,
    subject: &str,
    predicate: &str,
    object: &str,
    cacao_b64: &str,
) -> Result<()> {
    let url = format!("{base}/xrpc/ai.gftd.apps.kotoba.quad.create");
    let body = json!({
        "graph":     graph,
        "subject":   subject,
        "predicate": predicate,
        "object":    object,
        "cacao_b64": cacao_b64,
    });
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("quad.create POST")?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("quad.create HTTP {status}: {text}");
    }
    Ok(())
}

async fn xrpc_commit(
    client: &reqwest::Client,
    base: &str,
    graph: &str,
    author: &str,
    cacao_b64: &str,
) -> Result<String> {
    let url = format!("{base}/xrpc/ai.gftd.apps.kotoba.commit.store");
    let body = json!({
        "graph":     graph,
        "author":    author,
        "seq":       0,
        "cacao_b64": cacao_b64,
    });
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("commit.store POST")?;
    let status = resp.status();
    let val: Value = resp.json().await.context("commit.store response parse")?;
    if !status.is_success() {
        anyhow::bail!("commit.store HTTP {status}: {val}");
    }
    Ok(val["cid"].as_str().unwrap_or("").to_string())
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let server = std::env::var("KOTOBA_SERVER").unwrap_or_else(|_| "http://localhost:8080".into());
    let mcp_url = format!("{server}/mcp");

    println!("kotoba-server : {server}");

    // 1. Generate ephemeral Ed25519 identity
    let identity = IngestIdentity::generate();
    println!("ingest DID    : {}", identity.did);

    let cacao_b64 = identity.make_cacao(&server)?;
    let jwt = identity.make_jwt();

    let client = reqwest::Client::new();

    // 2. Build Quads
    let facts = build_facts();
    let assert_quads: Vec<&Quad> = facts
        .iter()
        .filter(|d| d.is_assert())
        .map(|d| &d.quad)
        .collect();
    println!("quads to ingest: {}", assert_quads.len());

    // 3. Ingest each Quad via XRPC quad.create
    let graph_mb = multibase::encode(multibase::Base::Base32Lower, &graph_cid_val().0);
    let mut ok = 0usize;
    for q in &assert_quads {
        let subj_mb = multibase::encode(multibase::Base::Base32Lower, &q.subject.0);
        let obj_str = object_to_string(&q.object);
        xrpc_quad_create(
            &client,
            &server,
            &graph_mb,
            &subj_mb,
            &q.predicate,
            &obj_str,
            &cacao_b64,
        )
        .await?;
        ok += 1;
        if ok % 20 == 0 {
            println!("  … {ok}/{} quads ingested", assert_quads.len());
        }
    }
    println!("✓ {} quads ingested", ok);

    // 4. Commit → triggers ProllyTree build + kotobase IPFS pin (fire-and-forget)
    let commit_cid = xrpc_commit(&client, &server, &graph_mb, &identity.did, &cacao_b64).await?;
    println!("✓ committed  cid={commit_cid}");
    println!(
        "  → kotobase pin queued (fire-and-forget to kotobase.gftd.ai if KOTOBA_PIN_TOKEN set)"
    );

    // 5. Verify via MCP kotoba_graph_query
    println!("\nverifying via MCP kotoba_graph_query …");
    let query_result = mcp_call(
        &client,
        &mcp_url,
        &jwt,
        1,
        "kotoba_graph_query",
        json!({ "graph": graph_mb, "predicate": "bma/namespace", "limit": 5 }),
    )
    .await?;
    println!(
        "MCP query result: {}",
        serde_json::to_string_pretty(&query_result)?
    );

    println!("\n✓ Done. Knowledge is now in kotoba-server QuadStore.");
    println!("  graph_cid (multibase): {graph_mb}");
    println!("  commit_cid:            {commit_cid}");
    println!("\nAgent query example (MCP kotoba_graph_query):");
    println!("  graph:     \"{graph_mb}\"");
    println!("  predicate: \"competitor/status\"");
    println!("  object:    \"dominant\"");

    Ok(())
}
