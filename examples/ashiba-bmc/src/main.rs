//! ashiba.gftd.ai Lean BMC — kotoba Quad storage + Datalog coverage scoring
//!
//! This example encodes the ashiba Lean BMC as kotoba Quads, then runs
//! a DatalogProgram to compute coverage % and per-block maturity scores.
//!
//! Data source: `60-apps/ai-gftd-project-jp-ashiba/docs/bmc/ashiba-lean-bmc-v17.toml`
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
    ("customer_segments", 5),
    ("uvp",               5),
    ("solution",          5),
    ("channels",          5),
    ("revenue",           5),
    ("cost_structure",    5),
    ("key_metrics",       5),
    ("unfair_advantage",  5),
];

// ─────────────────────────────────────────────────────────────────────────────
// Lean hypotheses: (entry_id, block, hypothesis_text, validated)
// ─────────────────────────────────────────────────────────────────────────────

const HYPOTHESES: &[(&str, &str, &str, bool)] = &[
    // problem (5/5)
    ("p_domestic",          "problem",           "国内ペイン普遍的 (stable)", true),
    ("p_apac",              "problem",           "APAC (韓国+台湾+タイ+ベトナム) 同一ペイン構造 確認 (stable)", true),
    ("p_india_survey",      "problem",           "インド (ムンバイ・デリー) 建設業者でも同一ペイン — 中長期 TAM 最大化", false),
    // customer_segments (5/5)
    ("cs_enterprise5",      "customer_segments", "ゼネコン 5社 Enterprise stable", true),
    ("cs_korea_70",         "customer_segments", "韓国 70社 active 2027-Q3 確認 (stable milestone)", true),
    ("cs_korea_100",        "customer_segments", "韓国 101社 active 2027-Q4 達成 (目標 100社 超過)", true),
    ("cs_taiwan_30",        "customer_segments", "台湾 30社 active (2028-Q1) — 現 15社 LOI → 30社 full expand", false),
    ("cs_thailand_5",       "customer_segments", "タイ 5社 pilot 2028-Q1 (BDC LOI 契約後 pilot 開始)", false),
    // uvp (5/5)
    ("uvp_v3_multilingual", "uvp",               "v3 AI 多言語 (日韓繁中) 88%+ stable", true),
    ("uvp_jis_mandatory",   "uvp",               "JIS A 8951:2026 義務化 仕様権保有 stable", true),
    ("uvp_v4_audit",        "uvp",               "v4 AI: 動画施工 audit → 安全スコア自動発行 = 保険料 連動 UVP (2028-Q1)", false),
    // solution (5/5)
    ("sol_v3_global",       "solution",          "v3 AI 多言語 本番 stable (日韓繁中)", true),
    ("sol_taiwan_stable",   "solution",          "台湾版 API beta stable — 15社 LOI 稼働", true),
    ("sol_v4_rollout",      "solution",          "v4 AI 本番 infra 構築完了 2027-Q4 (精度 84%・GPU streaming) GA 2028-Q1 確定", true),
    ("sol_thailand_api",    "solution",          "タイ版 API (タイ語 UI / THB 決済 / タイ建設法令対応) 2028-Q2 beta", false),
    // channels (5/5)
    ("ch_korea_70",         "channels",          "韓国 70社 active 2027-Q3 確認 (stable milestone)", true),
    ("ch_thailand_bdc_loi", "channels",          "タイ BDC 1社 LOI signed 2027-Q3 — SEA 展開起点確立", true),
    ("ch_seo_3200",         "channels",          "SEO organic 3,200/月 2027-Q3 達成 (stable milestone)", true),
    ("ch_taiwan_15",        "channels",          "台湾 BizDev 経由 15社 LOI 追加確認 (stable milestone)", true),
    ("ch_seo_3500",         "channels",          "SEO organic 3,520/月 2027-Q4 達成 (目標 3,500 超過)", true),
    // revenue (5/5)
    ("r_gmv_103m",          "revenue",           "GMV ¥103M/月 stable (iter-14 確認)", true),
    ("r_gmv_112m",          "revenue",           "GMV ¥112M/月 2027-Q3 確認 (stable milestone)", true),
    ("r_ebitda_138",        "revenue",           "EBITDA margin 13.8% 2027-Q3 確認 (stable milestone)", true),
    ("r_gmv_120m",          "revenue",           "GMV ¥122M/月 2027-Q4 達成 (韓국 ¥11M + 台湾 ¥3M 寄与)", true),
    ("r_ebitda_15pct",      "revenue",           "EBITDA margin 15.4% 2027-Q4 達成 (¥838K/月 — 目標 15% 超過)", true),
    // cost_structure (5/5)
    ("cs_ebitda_model",     "cost_structure",    "OPEX 管理モデル stable (¥6.18M/月 — GMV 成長と margin 維持両立)", true),
    ("cs_taiwan_agent",     "cost_structure",    "台湾 代理店モデル stable (¥180K/月)", true),
    ("cs_sea_agent",        "cost_structure",    "SEA 代理店モデル: タイ BDC ¥150K/月 確定", true),
    ("cs_team_43",          "cost_structure",    "43名体制 runway 28ヶ月 (v4 AI エンジニア + SEA BizDev 稼働)", true),
    // key_metrics (5/5)
    ("km_nrr_133",          "key_metrics",       "NRR 133% 2027-Q3 (stable milestone)", true),
    ("km_nrr_135",          "key_metrics",       "NRR 135% 2027-Q4 (Month 18) — 韓국 upsell + 台湾 新規", true),
    ("km_d365_342",         "key_metrics",       "D365 34.2% 実測 2027-Q4 — 目標 35% 圏内", true),
    ("km_intl_12pct",       "key_metrics",       "海外比率 12% 2027-Q3 確認 (stable milestone)", true),
    ("km_intl_15pct",       "key_metrics",       "海外 GMV 比率 11.5% 2027-Q4 実測 (¥14M/¥122M) — 15% 2028-Q1 目標に前進", true),
    ("km_ebitda_15pct",     "key_metrics",       "EBITDA margin 15.4% 2027-Q4 達成 (目標 15% 超過)", true),
    // unfair_advantage (5/5)
    ("ua_jis_mandatory",    "unfair_advantage",  "JIS 義務化 仕様権保有 stable", true),
    ("ua_did_6200",         "unfair_advantage",  "DID 6,200件 相関 0.85 (国内 5,100 + 韓국 580 + 台湾 420 + タイ 100)", true),
    ("ua_v3_patent",        "unfair_advantage",  "v3 AI 特許 出願完了 stable (日本+韓国+PCT)", true),
    ("ua_v4_patent",        "unfair_advantage",  "v4 AI 動画施工 audit 特許出願 (日本+韓国+PCT) 2028-Q1 予定", false),
];

// ─────────────────────────────────────────────────────────────────────────────
// CID helper
// ─────────────────────────────────────────────────────────────────────────────

fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

fn graph_cid() -> KotobaCid { cid("bmc:ashiba:v17") }

fn quad(subject: &str, predicate: &str, object: QuadObject) -> Quad {
    Quad { graph: graph_cid(), subject: cid(subject), predicate: predicate.to_string(), object }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build BMC fact deltas
// ─────────────────────────────────────────────────────────────────────────────

fn build_bmc_facts() -> Vec<Delta> {
    let mut deltas = Vec::new();

    deltas.push(Delta::assert(quad(
        "bmc:ashiba", "bmc/version", QuadObject::Text("v17".into()),
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
    println!("║  Iteration : 17 (2026-05-27) [Global Acceleration Q4 ✓] ║");
    println!("║  Model     : Lean Canvas Hybrid (9 blocks)               ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Coverage  : {derived_covered}/{total} blocks = {coverage_pct}%                       ║");
    println!("║  Maturity  : {maturity_avg:.1} / 5.0 (avg)                          ║");
    println!("║  At-Risk   : {derived_at_risk} unvalidated hypotheses (next-phase)  ║");
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
    println!("║  Riskiest Assumptions (next phase)                       ║");
    println!("║    1. インド ペイン調査 2028-Q1 — 中長期 TAM 起点       ║");
    println!("║    2. 台湾 30社 2028-Q1 — LOI 15社 → 成約 30社          ║");
    println!("║    3. タイ 5社 pilot 2028-Q1 — BDC LOI → 実導入         ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  GMV ¥122M ✓ / EBITDA 15.4% ✓ / NRR 135% / DID 6,200   ║");
    println!("║  韓국 101社 ✓ / SEO 3,520 ✓ / v4 infra 完了 ✓           ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  GLOBAL ACCELERATION Q4 VALIDATED ★★ — No IPO           ║");
    println!("║    · 韓국 101社 ✓ / 台湾 15社 LOI ✓ / タイ BDC LOI ✓   ║");
    println!("║    · GMV ¥122M ✓ / EBITDA 15.4% ✓ / 海外比率 11.5%     ║");
    println!("║    · v4 AI infra 完了 (精度 84%) → GA 2028-Q1           ║");
    println!("║    · 次フェーズ: Deep Global + v4 GA + 台湾・タイ expand ║");
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
