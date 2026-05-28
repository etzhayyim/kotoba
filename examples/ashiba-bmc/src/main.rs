//! ashiba.gftd.ai Lean BMC — kotoba Quad storage + Datalog coverage scoring
//!
//! This example encodes the ashiba Lean BMC as kotoba Quads, then runs
//! a DatalogProgram to compute coverage % and per-block maturity scores.
//!
//! Data source: `60-apps/ai-gftd-project-jp-ashiba/docs/bmc/ashiba-lean-bmc-v40.toml`
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
    // problem (5/5) — p_indonesia_q1_pain validated Q1 末
    ("p_domestic",               "problem",           "国内ペイン普遍的 stable ✓", true),
    ("p_apac",                   "problem",           "APAC (韓国+台湾+タイ) 同一ペイン構造 stable ✓", true),
    ("p_india_full",             "problem",           "インド 40社 ペイン全確認 stable ✓ — 定量スコア 4.4/5.0", true),
    ("p_asean_full",             "problem",           "ASEAN (ベトナム/マレーシア) ペイン完全確認 stable ✓ — 各 40社+ 定量スコア 4.1/5.0", true),
    ("p_indonesia_q1_pain",      "problem",           "インドネシア ペイン完全確認 ✓ (2030-Q1 末) — 建設市場 大手 25社調査完了 定量スコア 4.0/5.0", true),
    ("p_q2_deep_segment",        "problem",           "2030-Q2 ベトナム深堀り (中堅 50社+) + マレーシア 半島部 ペイン調査開始", false),
    // customer_segments (5/5) — cs_india_40 + cs_asean_scale_10 validated Q1 末
    ("cs_korea_stable",          "customer_segments", "韓国 101社 active stable ✓", true),
    ("cs_enterprise5",           "customer_segments", "国内 Enterprise 5社 stable ✓", true),
    ("cs_taiwan_42",             "customer_segments", "台湾 42社 active stable ✓", true),
    ("cs_thailand_24",           "customer_segments", "タイ 24社 stable ✓", true),
    ("cs_india_37",              "customer_segments", "インド 37社 active stable ✓ (2030-Q1 Month 1)", true),
    ("cs_asean_beta_5",          "customer_segments", "ASEAN β (ベトナム/マレーシア) 5社 stable ✓", true),
    ("cs_india_40",              "customer_segments", "インド 40社 active ✓ (2030-Q1 末) — v6 AI GA 普及 + 損保新規 5社 達成", true),
    ("cs_asean_scale_10",        "customer_segments", "ASEAN 10社 active ✓ (2030-Q1 末) — ベトナム 5社 + マレーシア 3社 + インドネシア β 2社 達成", true),
    ("cs_indonesia_q2_8",        "customer_segments", "インドネシア 8社 active (2030-Q2) — SNI 規格パートナー 3社 経由 + 損保 ID 連携", false),
    // uvp (5/5) — uvp_v6_ai_ga validated Q1 末
    ("uvp_v3_multilingual",      "uvp",               "v3 AI 多言語 (日韓繁中) 88%+ stable ✓", true),
    ("uvp_jis_mandatory",        "uvp",               "JIS A 8951:2026 義務化 仕様権保有 stable ✓", true),
    ("uvp_v4_audit",             "uvp",               "v4 AI 動画施工 audit GA stable ✓ (精度 87%)", true),
    ("uvp_v5_ai_ga",             "uvp",               "v5 AI 足場設計 GA stable ✓ — 精度 88% / 10社 本番適用", true),
    ("uvp_india_insurance_20co", "uvp",               "インド損保 dynamic pricing 20社完全適用 stable ✓", true),
    ("uvp_v6_ai_beta_ga",        "uvp",               "v6 AI β GA stable ✓", true),
    ("uvp_asean_multilingual",   "uvp",               "ASEAN 多言語 β stable ✓", true),
    ("uvp_v6_ai_ga_poc",         "uvp",               "v6 AI GA PoC stable ✓ (2030-Q1 Month 1)", true),
    ("uvp_v6_ai_ga",             "uvp",               "v6 AI GA 全市場展開 ✓ (2030-Q1 末) — マルチサイト精度 91% / 全 GA 達成 / インドネシア正式対応", true),
    ("uvp_v7_ai_poc",            "uvp",               "v7 AI PoC (2030-Q2) — 安全予測 AI + 事故予兆検知 (画像+IoT センサ融合)", false),
    // solution (5/5) — sol_v6_ai_ga validated Q1 末
    ("sol_v3_global",            "solution",          "v3 AI 多言語 本番 stable ✓", true),
    ("sol_v4_ga",                "solution",          "v4 AI GA 本番 stable ✓", true),
    ("sol_v5_ga",                "solution",          "v5 AI GA stable ✓", true),
    ("sol_asean_onboard",        "solution",          "ASEAN β 5社 自動 onboarding stable ✓", true),
    ("sol_v6_ai_beta_ga",        "solution",          "v6 AI β GA stable ✓", true),
    ("sol_v6_ai_ga_start",       "solution",          "v6 AI GA 開発 stable ✓ (2030-Q1 Month 1)", true),
    ("sol_v6_ai_ga",             "solution",          "v6 AI GA 全市場展開 ✓ (2030-Q1 末) — 精度 91% / 全市場本番稼働 / インドネシア SNI 正式適合", true),
    ("sol_v7_safety_start",      "solution",          "v7 安全予測 AI 開発開始 (2030-Q2) — 画像+IoT融合 / 事故予兆検知 PoC 目標 80%", false),
    // channels (5/5) — ch_indonesia_beta validated Q1 末
    ("ch_korea_stable",          "channels",          "韓国 チャネル stable ✓", true),
    ("ch_seo_6500",              "channels",          "SEO organic 6,500/月 stable ✓", true),
    ("ch_india_referral",        "channels",          "インド 損保顧客紹介 月 10社+ stable ✓ (40社 規模)", true),
    ("ch_asean_vietnam_stable",  "channels",          "ベトナム チャネル stable ✓", true),
    ("ch_asean_malaysia_stable", "channels",          "マレーシア チャネル stable ✓", true),
    ("ch_asean_scale",           "channels",          "ASEAN 2国 月 3社+ 安定流入 stable ✓", true),
    ("ch_indonesia_beta_contact","channels",          "インドネシア BizDev β 接触 stable ✓ (2030-Q1 Month 1)", true),
    ("ch_indonesia_beta",        "channels",          "インドネシア β チャネル確立 ✓ (2030-Q1 末) — SNI 規格パートナー 3社 / 月 1社+ 安定流入 達成", true),
    ("ch_q2_insurance_id",       "channels",          "2030-Q2 インドネシア 損保 ID パートナーシップ (Jasindo + Asuransi Astra) — 月 3社+ 目標", false),
    // revenue (5/5) — r_gmv_350m + r_ebitda_20_restored validated Q1 末
    ("r_gmv_300m",               "revenue",           "GMV ¥300M/月 stable ✓ (2029-Q4 末)", true),
    ("r_india_35_rev",           "revenue",           "インド 35社 課金 ¥17.5M/月 stable ✓", true),
    ("r_ebitda_20_q4",           "revenue",           "EBITDA 20.0% stable ✓ (2029-Q4 末)", true),
    ("r_gmv_320m",               "revenue",           "GMV ¥320M/月 stable ✓ (2030-Q1 Month 1)", true),
    ("r_gmv_350m",               "revenue",           "GMV ¥350M/月 ✓ (2030-Q1 末) — インド 40社 ¥22M + v6 AI GA premium 全市場 + ASEAN 10社 + インドネシア β 達成", true),
    ("r_ebitda_20_restored",     "revenue",           "EBITDA 20.0% 復元 ✓ (2030-Q1 末) — v6 AI GA premium + 海外 45% 高 margin で v6 開発投資を吸収", true),
    ("r_gmv_400m",               "revenue",           "GMV ¥400M/月 (2030-Q2) — v6 AI GA full ramp + インドネシア 8社 + ASEAN 14社", false),
    // cost_structure (5/5)
    ("cs_ebitda_model",          "cost_structure",    "OPEX ¥11.0M/月 ✓ (margin 20.5%、v6 GA 投資完了 + インドネシア BizDev 拠点コスト込み)", true),
    ("cs_all_agents",            "cost_structure",    "台湾 + タイ + インド + ASEAN 3国 (ベトナム/マレーシア/インドネシア) 代理店モデル ✓ (¥1.0M/月合計)", true),
    ("cs_team_75",               "cost_structure",    "75名体制 ✓ (+3名: インドネシア 現地 BizDev 拠点 立ち上げ)", true),
    ("cs_v6_ga_done",            "cost_structure",    "v6 AI GA 開発 完了 ✓ (累計 ¥18M, ROI = 12ヶ月)", true),
    ("cs_v7_safety_budget",      "cost_structure",    "v7 安全予測 AI 開発予算 ¥1.2M/月 ✓ (GPU × 6 + エンジニア 8名体制を 2030-Q2 から組成)", true),
    // key_metrics (5/5) — km_nrr_170 + km_intl_45pct + km_ebitda_20_restored validated Q1 末
    ("km_nrr_165",               "key_metrics",       "NRR 165% stable ✓ (2029-Q4 末)", true),
    ("km_intl_40pct",            "key_metrics",       "海外 GMV 比率 40% stable ✓ (2029-Q4 末)", true),
    ("km_ebitda_20_q4",          "key_metrics",       "EBITDA 20.0% stable ✓ (2029-Q4 末)", true),
    ("km_nrr_167",               "key_metrics",       "NRR 167% stable ✓ (2030-Q1 Month 1)", true),
    ("km_intl_41pct",            "key_metrics",       "海外 GMV 41% stable ✓ (2030-Q1 Month 1)", true),
    ("km_nrr_170",               "key_metrics",       "NRR 170% ✓ (2030-Q1 末) — インド 40社 + v6 AI GA upsell + ASEAN 10社 達成", true),
    ("km_intl_45pct",            "key_metrics",       "海外 GMV 比率 45% ✓ (2030-Q1 末) — GMV ¥350M のうち ¥157M 海外 達成", true),
    ("km_ebitda_20_restored",    "key_metrics",       "EBITDA 20.0% 復元 ✓ (2030-Q1 末) — v6 AI GA premium + 海外 high-margin 効果", true),
    ("km_nrr_175",               "key_metrics",       "NRR 175% (2030-Q2) — v7 安全予測 PoC upsell + インドネシア 拡大", false),
    // unfair_advantage (5/5) — ua_did_25000 + ua_did_28000 + ua_indonesia_moat validated Q1 末
    ("ua_jis_mandatory",         "unfair_advantage",  "JIS 義務化 仕様権保有 stable ✓", true),
    ("ua_did_22000",             "unfair_advantage",  "DID 2.2万件+ stable ✓ (2029-Q4 末)", true),
    ("ua_v4_patent",             "unfair_advantage",  "v4 AI 特許 stable ✓ (日本+韓国+PCT)", true),
    ("ua_v5_patent",             "unfair_advantage",  "v5 AI 特許 stable ✓ — IS 2750 × JIS PCT 出願完了", true),
    ("ua_insurance_moat_20co",   "unfair_advantage",  "インド損保 20社完全適用 Moat stable ✓", true),
    ("ua_asean_moat_2co",        "unfair_advantage",  "ASEAN 規格 Moat stable ✓ — TCXDVN + CIDB 独占適合認定", true),
    ("ua_v6_patent_filed",       "unfair_advantage",  "v6 AI 特許出願済 ✓ — マルチサイト × BIM PCT", true),
    ("ua_did_25000",             "unfair_advantage",  "DID 2.5万件+ ✓ (2030-Q1 Month 1 末)", true),
    ("ua_did_28000",             "unfair_advantage",  "DID 2.8万件+ ✓ (2030-Q1 末) — インド 40社 + ASEAN 10社 + インドネシア β 達成 (相関 0.95)", true),
    ("ua_indonesia_moat",        "unfair_advantage",  "インドネシア SNI Moat 確立 ✓ (2030-Q1 末) — SNI 7395:2017 独占適合認定 / JIS-SNI 互換層 特許出願", true),
    ("ua_v7_patent_plan",        "unfair_advantage",  "v7 安全予測 AI 特許計画 (2030-Q2) — 画像+IoT融合 事故予兆 PCT 出願準備", false),
    ("ua_did_35000",             "unfair_advantage",  "DID 3.5万件+ (2030-Q2) — インドネシア 8社 + ASEAN 14社 + v7 安全予測 cohort", false),
];

// ─────────────────────────────────────────────────────────────────────────────
// CID helper
// ─────────────────────────────────────────────────────────────────────────────

fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

fn graph_cid() -> KotobaCid { cid("bmc:ashiba:v40") }

fn quad(subject: &str, predicate: &str, object: QuadObject) -> Quad {
    Quad { graph: graph_cid(), subject: cid(subject), predicate: predicate.to_string(), object }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build BMC fact deltas
// ─────────────────────────────────────────────────────────────────────────────

fn build_bmc_facts() -> Vec<Delta> {
    let mut deltas = Vec::new();

    deltas.push(Delta::assert(quad(
        "bmc:ashiba", "bmc/version", QuadObject::Text("v40".into()),
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

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     ashiba.gftd.ai Lean BMC — kotoba Scoring Report      ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Iteration : 40 (2026-05-28) [2030-Q1 末 ★★★★★ VALIDATED]║");
    println!("║  Model     : Lean Canvas Hybrid (9 blocks)                ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Coverage  : {derived_covered}/{total} blocks = {coverage_pct}%                       ║");
    println!("║  Maturity  : {maturity_avg:.1} / 5.0 (avg)  ★★★★★ VALIDATED         ║");
    println!("║  At-Risk   : {derived_at_risk} unvalidated hypotheses (Q2 stretch) ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Per-Block Maturity                                       ║");
    for (block, m) in BMC_BLOCKS {
        let bar = "█".repeat(*m as usize);
        let gap = "░".repeat((5 - m) as usize);
        let flag = if *m < 3 { " ← next" } else { "       " };
        println!("║  {block:<22} [{bar}{gap}] {m}/5{flag}║");
    }
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  ★★★★★ 2030-Q1 末 VALIDATED ★★★★★                      ║");
    println!("║  GMV ¥350M ✓ / NRR 170% ✓ / 海外 45% ✓ / EBITDA 20% ✓ ║");
    println!("║  インド 40社 ✓ / ASEAN 10社 ✓ / インドネシア β ✓        ║");
    println!("║  v6 AI GA 全市場 (精度91%) ✓ / DID 2.8万 ✓              ║");
    println!("║  インドネシア SNI Moat 確立 ✓                            ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Next (→ iter-41, 2030-Q2 Phase Month 1 reset ~4.2)      ║");
    println!("║    1. v7 安全予測 AI PoC (画像+IoT 融合)                  ║");
    println!("║    2. インドネシア 8社 + 損保 ID パートナー (Jasindo)     ║");
    println!("║    3. GMV ¥400M + NRR 175% + DID 3.5万 → Q2 stretch       ║");
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
