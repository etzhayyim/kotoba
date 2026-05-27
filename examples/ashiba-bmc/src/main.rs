//! ashiba.gftd.ai Lean BMC — kotoba Quad storage + Datalog coverage scoring
//!
//! This example encodes the ashiba Lean BMC as kotoba Quads, then runs
//! a DatalogProgram to compute coverage % and per-block maturity scores.
//!
//! Data source: `60-apps/ai-gftd-project-jp-ashiba/docs/bmc/ashiba-lean-bmc-v18.toml`
//! Rules source: `60-apps/ai-gftd-project-jp-ashiba/docs/bmc/coverage.dl`

use anyhow::Result;
use kotoba_core::cid::KotobaCid;
use kotoba_kqe::{
    datalog::{Atom, BodyLiteral, DatalogProgram, DatalogRule, Term},
    delta::Delta,
    quad::{Quad, QuadObject},
};
use kotoba_store::MemoryBlockStore;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Lean BMC blocks (Lean Canvas hybrid, 9 blocks)
// ─────────────────────────────────────────────────────────────────────────────

const BMC_BLOCKS: &[(&str, i64)] = &[
    ("problem",           5),
    ("customer_segments", 4),
    ("uvp",               4),
    ("solution",          4),
    ("channels",          5),
    ("revenue",           5),
    ("cost_structure",    5),
    ("key_metrics",       4),
    ("unfair_advantage",  4),
];

// ─────────────────────────────────────────────────────────────────────────────
// Lean hypotheses: (entry_id, block, hypothesis_text, validated)
// ─────────────────────────────────────────────────────────────────────────────

const HYPOTHESES: &[(&str, &str, &str, bool)] = &[
    // problem (5/5)
    ("p_domestic",         "problem",           "国内ペイン普遍的 (stable)", true),
    ("p_apac",             "problem",           "APAC (韓国+台湾+タイ+ベトナム) 同一ペイン構造 (stable)", true),
    ("p_india_survey",     "problem",           "インド (ムンバイ・デリー) 建設業者でも同一ペイン — 8社ヒアリング 2028-Q1 実施", false),
    // customer_segments (4/5)
    ("cs_korea_stable",    "customer_segments", "韓国 101社 active stable (iter-17 確認)", true),
    ("cs_enterprise5",     "customer_segments", "国内 Enterprise 5社 stable", true),
    ("cs_taiwan_30",       "customer_segments", "台湾 30社 active 2028-Q1 (LOI 15社 → 成約 30社)", false),
    ("cs_thailand_5",      "customer_segments", "タイ 5社 pilot 2028-Q1 (BDC LOI 後 Thana Construction 主導)", false),
    ("cs_india_explore",   "customer_segments", "インド 建設業者 5社 ヒアリング設計完了 — ペイン確認後 2029 パイロット", false),
    // uvp (4/5)
    ("uvp_v3_multilingual","uvp",               "v3 AI 多言語 (日韓繁中) 88%+ stable", true),
    ("uvp_jis_mandatory",  "uvp",               "JIS A 8951:2026 義務化 仕様権保有 stable", true),
    ("uvp_v4_audit",       "uvp",               "v4 AI 動画施工 audit → 安全スコア自動発行 = 保険料 連動 UVP (2028-Q1 GA)", false),
    ("uvp_v4_insurance_poc","uvp",              "損保 2社 との v4 AI 安全スコア × 保険料割引 PoC 合意 (2028-Q1)", false),
    // solution (4/5)
    ("sol_v3_global",      "solution",          "v3 AI 多言語 本番 stable (日韓繁中)", true),
    ("sol_taiwan_stable",  "solution",          "台湾版 API stable — 15社 LOI 全稼働", true),
    ("sol_v4_ga",          "solution",          "v4 AI GA 本番 deploy 2028-Q1 (infra 完了済み → 本番リリース)", false),
    ("sol_thailand_api",   "solution",          "タイ版 API (タイ語 UI / THB 決済 / タイ建設法令対応) 2028-Q2 beta", false),
    // channels (5/5)
    ("ch_korea_stable",    "channels",          "韓国 チャネル stable (101社 active、月 +8社 pace 継続)", true),
    ("ch_seo_stable",      "channels",          "SEO organic 3,520/月 stable (コンテンツ 月 40本 継続)", true),
    ("ch_taiwan_bizdev",   "channels",          "台湾 BizDev パートナー stable (15社 LOI 稼働、30社 拡大中)", true),
    ("ch_thailand_bdc",    "channels",          "タイ BDC LOI stable (Thana Construction Group 経由 pilot 準備中)", true),
    ("ch_india_explore",   "channels",          "インド チャネル設計 — JETRO + 建設協会 India office ネットワーク", false),
    // revenue (5/5)
    ("r_gmv_122m",         "revenue",           "GMV ¥122M/月 stable (iter-17 確認)", true),
    ("r_ebitda_154",       "revenue",           "EBITDA margin 15.4% stable (iter-17 確認)", true),
    ("r_gmv_135m",         "revenue",           "GMV ¥135M/月 (2028-Q2) — 台湾 30社 + タイ + v4 AI upsell 寄与", false),
    ("r_v4_upsell",        "revenue",           "v4 AI upsell: 動画 audit オプション ¥50K/月/社 → 100社 × ¥50K = ¥5M/月 (2028-Q3)", false),
    // cost_structure (5/5)
    ("cs_ebitda_model",    "cost_structure",    "OPEX ¥6.18M stable — margin 15% 維持しながら v4 + SEA 投資", true),
    ("cs_taiwan_sea_agent","cost_structure",    "台湾 + タイ 代理店モデル stable (¥330K/月合計)", true),
    ("cs_team_43",         "cost_structure",    "43名体制 stable — v4 AI 3名 + SEA BizDev 2名 稼働中", true),
    ("cs_india_budget",    "cost_structure",    "インド探索予算 ¥300K (JETRO 委託) — 2028-Q1 単発コスト", true),
    // key_metrics (4/5)
    ("km_nrr_135",         "key_metrics",       "NRR 135% stable (iter-17 確認)", true),
    ("km_d365_342",        "key_metrics",       "D365 34.2% stable (iter-17 確認)", true),
    ("km_ebitda_154",      "key_metrics",       "EBITDA 15.4% stable (iter-17 確認)", true),
    ("km_intl_20pct",      "key_metrics",       "海外 GMV 比率 20%+ (2028-Q2) — 台湾 30社 + タイ + v4 upsell 寄与", false),
    ("km_nrr_140",         "key_metrics",       "NRR 140% (2028-Q2) — v4 AI upsell + 台湾 拡大 寄与", false),
    // unfair_advantage (4/5)
    ("ua_jis_mandatory",   "unfair_advantage",  "JIS 義務化 仕様権保有 stable", true),
    ("ua_did_6200",        "unfair_advantage",  "DID 6,200件+ stable (相関 0.85)", true),
    ("ua_v3_patent",       "unfair_advantage",  "v3 AI 特許 出願完了 stable (日本+韓国+PCT)", true),
    ("ua_v4_patent",       "unfair_advantage",  "v4 AI 動画施工 audit 特許出願 (日本+韓国+PCT) 2028-Q1-15 出願予定", false),
    ("ua_india_network",   "unfair_advantage",  "インド 建設業者ネットワーク独占契約 — 中長期 Moat (2029)", false),
];

// ─────────────────────────────────────────────────────────────────────────────
// CID helper
// ─────────────────────────────────────────────────────────────────────────────

fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

fn graph_cid() -> KotobaCid { cid("bmc:ashiba:v18") }

fn quad(subject: &str, predicate: &str, object: QuadObject) -> Quad {
    Quad { graph: graph_cid(), subject: cid(subject), predicate: predicate.to_string(), object }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build BMC fact deltas
// ─────────────────────────────────────────────────────────────────────────────

fn build_bmc_facts() -> Vec<Delta> {
    let mut deltas = Vec::new();

    deltas.push(Delta::assert(quad(
        "bmc:ashiba", "bmc/version", QuadObject::Text("v18".into()),
    )));
    deltas.push(Delta::assert(quad(
        "bmc:ashiba", "bmc/product", QuadObject::Text("ashiba.gftd.ai".into()),
    )));
    deltas.push(Delta::assert(quad(
        "bmc:ashiba", "bmc/model", QuadObject::Text("lean-canvas-hybrid".into()),
    )));

    for (block_name, maturity) in BMC_BLOCKS {
        let block_id = format!("bmc:ashiba:block:{block_name}");

        deltas.push(Delta::assert(quad(
            "bmc:ashiba", "bmc/block", QuadObject::Cid(cid(&block_id)),
        )));
        deltas.push(Delta::assert(quad(
            &block_id, "bmc/block_name", QuadObject::Text(block_name.to_string()),
        )));
        deltas.push(Delta::assert(quad(
            &block_id, "bmc/maturity", QuadObject::Integer(*maturity),
        )));

        let entry_id = format!("bmc:ashiba:entry:{block_name}:default");
        deltas.push(Delta::assert(quad(
            &entry_id, "entry/block", QuadObject::Cid(cid(&block_id)),
        )));
    }

    for (entry_id, block_name, hypothesis, validated) in HYPOTHESES {
        let full_entry_id = format!("bmc:ashiba:entry:{block_name}:{entry_id}");
        let block_id = format!("bmc:ashiba:block:{block_name}");

        deltas.push(Delta::assert(quad(
            &full_entry_id, "entry/block", QuadObject::Cid(cid(&block_id)),
        )));
        deltas.push(Delta::assert(quad(
            &full_entry_id, "bmc/hypothesis", QuadObject::Text(hypothesis.to_string()),
        )));
        deltas.push(Delta::assert(quad(
            &full_entry_id, "bmc/validated", QuadObject::Bool(*validated),
        )));
    }

    deltas
}

// ─────────────────────────────────────────────────────────────────────────────
// Build coverage / maturity Datalog program
// ─────────────────────────────────────────────────────────────────────────────

fn build_coverage_program() -> DatalogProgram {
    let mut prog = DatalogProgram::new();

    prog.add_rule(DatalogRule {
        head: Atom {
            relation: "covered".into(),
            args: vec![Term::Variable("Block".into()), Term::Variable("Block".into())],
        },
        body: vec![BodyLiteral::Positive(Atom {
            relation: "entry/block".into(),
            args: vec![Term::Variable("Entry".into()), Term::Variable("Block".into())],
        })],
    });

    prog.add_rule(DatalogRule {
        head: Atom {
            relation: "at_risk".into(),
            args: vec![Term::Variable("Entry".into()), Term::Variable("Entry".into())],
        },
        body: vec![
            BodyLiteral::Positive(Atom {
                relation: "bmc/hypothesis".into(),
                args: vec![Term::Variable("Entry".into()), Term::Variable("_H".into())],
            }),
            BodyLiteral::Positive(Atom {
                relation: "bmc/validated".into(),
                args: vec![
                    Term::Variable("Entry".into()),
                    Term::Constant(cid_label_for_bool(false)),
                ],
            }),
        ],
    });

    prog
}

fn cid_label_for_bool(b: bool) -> String {
    if b { "true".into() } else { "false".into() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Score report
// ─────────────────────────────────────────────────────────────────────────────

fn print_score_report(derived_covered: usize, derived_at_risk: usize) {
    let total = BMC_BLOCKS.len();
    let coverage_pct = (derived_covered * 100) / total;
    let maturity_sum: i64 = BMC_BLOCKS.iter().map(|(_, m)| m).sum();
    let maturity_avg = maturity_sum as f64 / total as f64;

    let mut below_target: Vec<&str> = Vec::new();
    for (block, maturity) in BMC_BLOCKS {
        if *maturity < 3 { below_target.push(block); }
    }

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     ashiba.gftd.ai Lean BMC — kotoba Scoring Report      ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Iteration : 18 (2026-05-27) [Deep Global Phase Month 1] ║");
    println!("║  Model     : Lean Canvas Hybrid (9 blocks)               ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Coverage  : {derived_covered}/{total} blocks = {coverage_pct}%                       ║");
    println!("║  Maturity  : {maturity_avg:.1} / 5.0 (avg)                          ║");
    println!("║  At-Risk   : {derived_at_risk} unvalidated hypotheses                ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Per-Block Maturity                                       ║");
    for (block, m) in BMC_BLOCKS {
        let bar = "█".repeat(*m as usize);
        let gap = "░".repeat((5 - m) as usize);
        let flag = if *m < 3 { " ← next" } else { "       " };
        println!("║  {block:<22} [{bar}{gap}] {m}/5{flag}║");
    }
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Blocks below target (< 3): (none)                       ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Riskiest Assumptions (2028-Q1 critical)                 ║");
    println!("║    1. v4 GA 本番 deploy 2028-Q1 — QA 品質ゲート          ║");
    println!("║    2. 台湾 30社 2028-Q1 — LOI 15社 → +15社 成約          ║");
    println!("║    3. 損保 PoC 合意 2028-Q1 — 規制・認定の壁             ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  GMV ¥122M stable / EBITDA 15.4% / NRR 135% / DID 6,200+║");
    println!("║  次: v4 GA + 台湾 30社 + タイ pilot + インド調査         ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Deep Global Phase — Month 1 (prior: ★★ Q4 Validated)   ║");
    println!("║    · v4 GA 本番 deploy (2028-Q1) [未]                    ║");
    println!("║    · 損保 PoC 合意 (2028-Q1) [未]                        ║");
    println!("║    · 台湾 30社 active (2028-Q1) [未]                     ║");
    println!("║    · タイ 5社 pilot (2028-Q1) [未]                       ║");
    println!("║    · v4 特許出願 (2028-Q1) [未]                          ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let _store = Arc::new(MemoryBlockStore::new());

    let facts = build_bmc_facts();
    println!("Loaded {} BMC fact deltas into kotoba Quad store", facts.len());

    let prog = build_coverage_program();
    let derived = prog.evaluate_delta(&facts);

    let covered_blocks: std::collections::HashSet<_> = derived.iter()
        .filter(|d| d.quad.predicate == "covered" && d.is_assert())
        .map(|d| d.quad.subject.clone())
        .collect();

    let at_risk_entries: std::collections::HashSet<_> = derived.iter()
        .filter(|d| d.quad.predicate == "at_risk" && d.is_assert())
        .map(|d| d.quad.subject.clone())
        .collect();

    println!("Datalog derived {} facts total", derived.len());
    println!("  covered blocks : {}", covered_blocks.len());
    println!("  at-risk entries: {}", at_risk_entries.len());

    println!();
    print_score_report(covered_blocks.len(), at_risk_entries.len());

    Ok(())
}
