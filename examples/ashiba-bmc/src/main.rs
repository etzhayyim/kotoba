//! ashiba.gftd.ai Lean BMC — kotoba Quad storage + Datalog coverage scoring
//!
//! This example encodes the ashiba Lean BMC as kotoba Quads, then runs
//! a DatalogProgram to compute coverage % and per-block maturity scores.
//!
//! Data source: `60-apps/ai-gftd-project-jp-ashiba/docs/bmc/ashiba-lean-bmc-v38.toml`
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
    ("channels",          4),
    ("revenue",           4),
    ("cost_structure",    5),
    ("key_metrics",       4),
    ("unfair_advantage",  4),
];

// ─────────────────────────────────────────────────────────────────────────────
// Lean hypotheses: (entry_id, block, hypothesis_text, validated)
// ─────────────────────────────────────────────────────────────────────────────

const HYPOTHESES: &[(&str, &str, &str, bool)] = &[
    // problem (5/5)
    ("p_domestic",               "problem",           "国内ペイン普遍的 stable ✓", true),
    ("p_apac",                   "problem",           "APAC (韓国+台湾+タイ) 同一ペイン構造 stable ✓", true),
    ("p_india_full",             "problem",           "インド 35社 ペイン全確認 stable ✓ — 定量スコア 4.3/5.0", true),
    ("p_asean_full",             "problem",           "ASEAN (ベトナム/マレーシア) ペイン完全確認 stable ✓ — 各 30社+ 定量スコア 4.0/5.0", true),
    ("p_indonesia_q1_pain",      "problem",           "インドネシア ペイン調査 (2030-Q1) — 建設市場 大手 20社 スクリーニング開始", false),
    // customer_segments (4/5)
    ("cs_korea_stable",          "customer_segments", "韓国 101社 active stable ✓", true),
    ("cs_enterprise5",           "customer_segments", "国内 Enterprise 5社 stable ✓", true),
    ("cs_taiwan_42",             "customer_segments", "台湾 42社 active stable ✓", true),
    ("cs_thailand_24",           "customer_segments", "タイ 24社 stable ✓", true),
    ("cs_india_35",              "customer_segments", "インド 35社 active stable ✓ (2029-Q4 末)", true),
    ("cs_asean_beta_5",          "customer_segments", "ASEAN β (ベトナム/マレーシア) 5社 stable ✓ (2029-Q4 末)", true),
    ("cs_india_37",              "customer_segments", "インド 37社 active (2030-Q1 Month 1) — 損保紹介 2社 追加 / v6 AI GA 早期採用", false),
    ("cs_india_40",              "customer_segments", "インド 40社 active (2030-Q1) — v6 AI GA 普及 + 損保新規 5社", false),
    ("cs_asean_scale_10",        "customer_segments", "ASEAN 10社 active (2030-Q1) — ベトナム 5社 + マレーシア 3社 + インドネシア β 2社", false),
    // uvp (4/5)
    ("uvp_v3_multilingual",      "uvp",               "v3 AI 多言語 (日韓繁中) 88%+ stable ✓", true),
    ("uvp_jis_mandatory",        "uvp",               "JIS A 8951:2026 義務化 仕様権保有 stable ✓", true),
    ("uvp_v4_audit",             "uvp",               "v4 AI 動画施工 audit GA stable ✓ (精度 87%)", true),
    ("uvp_v5_ai_ga",             "uvp",               "v5 AI 足場設計 GA stable ✓ — 精度 88% / 10社 本番適用", true),
    ("uvp_india_insurance_20co", "uvp",               "インド損保 dynamic pricing 20社完全適用 stable ✓", true),
    ("uvp_v6_ai_beta_ga",        "uvp",               "v6 AI β GA stable ✓ (2029-Q4 末) — 精度 85% / 5社 / BIM 連携", true),
    ("uvp_asean_multilingual",   "uvp",               "ASEAN 多言語 β stable ✓ (2029-Q4 末) — ベトナム語/マレー語対応", true),
    ("uvp_v6_ai_ga_poc",         "uvp",               "v6 AI GA PoC (2030-Q1 Month 1) — マルチサイト精度 87% / 3社 先行テスト", false),
    ("uvp_v6_ai_ga",             "uvp",               "v6 AI GA 全市場展開 (2030-Q1) — マルチサイト精度 90%+ / インドネシア対応", false),
    // solution (4/5)
    ("sol_v3_global",            "solution",          "v3 AI 多言語 本番 stable ✓", true),
    ("sol_v4_ga",                "solution",          "v4 AI GA 本番 stable ✓ (SLA 99.9%)", true),
    ("sol_v5_ga",                "solution",          "v5 AI GA stable ✓ — 精度 88% / 10社 / SLA 99.5%", true),
    ("sol_asean_onboard",        "solution",          "ASEAN β 5社 自動 onboarding stable ✓ (2029-Q4 末)", true),
    ("sol_v6_ai_beta_ga",        "solution",          "v6 AI β GA stable ✓ (2029-Q4 末) — マルチサイト 85%+ / 5社 本番稼働", true),
    ("sol_v6_ai_ga_start",       "solution",          "v6 AI GA 開発開始 (2030-Q1 Month 1) — インドネシア SNI 規格対応 + 精度 87% PoC", false),
    ("sol_v6_ai_ga",             "solution",          "v6 AI GA (2030-Q1) — 精度 90%+ / 全市場展開 / インドネシア対応", false),
    // channels (4/5)
    ("ch_korea_stable",          "channels",          "韓国 チャネル stable ✓", true),
    ("ch_seo_6500",              "channels",          "SEO organic 6,500/月 stable ✓", true),
    ("ch_india_referral",        "channels",          "インド 損保顧客紹介 月 8社+ stable ✓ (35社 規模)", true),
    ("ch_asean_vietnam_stable",  "channels",          "ベトナム チャネル stable ✓ (2029-Q4 末)", true),
    ("ch_asean_malaysia_stable", "channels",          "マレーシア チャネル stable ✓ (2029-Q4 末)", true),
    ("ch_asean_scale",           "channels",          "ASEAN 2国 月 3社+ 安定流入 stable ✓ (2029-Q4 末)", true),
    ("ch_indonesia_beta_contact","channels",          "インドネシア BizDev β 接触 (2030-Q1 Month 1) — SNI 規格パートナー 2社 初回 MTG 完了", false),
    ("ch_indonesia_beta",        "channels",          "インドネシア β チャネル確立 (2030-Q1) — SNI パートナー 月 1社+ 流入", false),
    // revenue (4/5)
    ("r_gmv_300m",               "revenue",           "GMV ¥300M/月 stable ✓ (2029-Q4 末)", true),
    ("r_india_35_rev",           "revenue",           "インド 35社 課金 ¥17.5M/月 stable ✓ (2029-Q4 末)", true),
    ("r_ebitda_20",              "revenue",           "EBITDA 20.0% stable ✓ (2029-Q4 末)", true),
    ("r_gmv_320m",               "revenue",           "GMV ¥320M/月 (2030-Q1 Month 1) — インド 37社 + v6 AI GA PoC 3社 premium", false),
    ("r_gmv_350m",               "revenue",           "GMV ¥350M/月 (2030-Q1) — インド 40社 + v6 AI GA + ASEAN 10社 + インドネシア β", false),
    // cost_structure (5/5)
    ("cs_ebitda_model",          "cost_structure",    "OPEX ¥10.5M/月 ✓ (margin 19%+ 維持、v6 GA 開発 + インドネシア β 探索費込み)", true),
    ("cs_all_agents",            "cost_structure",    "台湾 + タイ + インド + ASEAN 2国 代理店モデル stable ✓ (¥900K/月合計)", true),
    ("cs_team_72",               "cost_structure",    "72名体制 ✓ (+2名 インドネシア BizDev + v6 GA エンジニア 2名追加)", true),
    ("cs_v6_ga_dev",             "cost_structure",    "v6 AI GA 開発コスト ¥900K/月 ✓ (GPU × 4 + エンジニア 6名体制)", true),
    // key_metrics (4/5)
    ("km_nrr_165",               "key_metrics",       "NRR 165% stable ✓ (2029-Q4 末)", true),
    ("km_intl_40pct",            "key_metrics",       "海外 GMV 比率 40% stable ✓ (2029-Q4 末)", true),
    ("km_ebitda_20",             "key_metrics",       "EBITDA 20.0% stable ✓ (2029-Q4 末)", true),
    ("km_nrr_167",               "key_metrics",       "NRR 167% (2030-Q1 Month 1) — インド 37社 + v6 AI GA PoC upsell", false),
    ("km_nrr_170",               "key_metrics",       "NRR 170% (2030-Q1) — インド 40社 + v6 AI GA upsell + ASEAN 10社", false),
    ("km_intl_45pct",            "key_metrics",       "海外 GMV 比率 45% (2030-Q1) — インド 40社 + ASEAN 10社 + インドネシア β", false),
    // unfair_advantage (4/5)
    ("ua_jis_mandatory",         "unfair_advantage",  "JIS 義務化 仕様権保有 stable ✓", true),
    ("ua_did_22000",             "unfair_advantage",  "DID 2.2万件+ stable ✓ (2029-Q4 末)", true),
    ("ua_v4_patent",             "unfair_advantage",  "v4 AI 特許 stable ✓ (日本+韓国+PCT)", true),
    ("ua_v5_patent",             "unfair_advantage",  "v5 AI 特許 stable ✓ — IS 2750 × JIS PCT 出願完了", true),
    ("ua_insurance_moat_20co",   "unfair_advantage",  "インド損保 20社完全適用 Moat stable ✓", true),
    ("ua_asean_moat_2co",        "unfair_advantage",  "ASEAN 規格 Moat stable ✓ (2029-Q4 末) — TCXDVN + CIDB 独占適合認定", true),
    ("ua_v6_patent_filed",       "unfair_advantage",  "v6 AI 特許出願済 ✓ (2029-Q4 末) — マルチサイト × BIM PCT", true),
    ("ua_did_25000",             "unfair_advantage",  "DID 2.5万件+ (2030-Q1 Month 1) — インド 37社 + ASEAN 拡張 (相関 0.95)", false),
    ("ua_did_28000",             "unfair_advantage",  "DID 2.8万件+ (2030-Q1) — インド 40社 + ASEAN 10社 + インドネシア β (相関 0.95)", false),
];

// ─────────────────────────────────────────────────────────────────────────────
// CID helper
// ─────────────────────────────────────────────────────────────────────────────

fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

fn graph_cid() -> KotobaCid { cid("bmc:ashiba:v38") }

fn quad(subject: &str, predicate: &str, object: QuadObject) -> Quad {
    Quad { graph: graph_cid(), subject: cid(subject), predicate: predicate.to_string(), object }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build BMC fact deltas
// ─────────────────────────────────────────────────────────────────────────────

fn build_bmc_facts() -> Vec<Delta> {
    let mut deltas = Vec::new();

    deltas.push(Delta::assert(quad(
        "bmc:ashiba", "bmc/version", QuadObject::Text("v38".into()),
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
    println!("║  Iteration : 38 (2026-05-28) [India Scale 2030-Q1 Month 1]║");
    println!("║  Model     : Lean Canvas Hybrid (9 blocks)                ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Coverage  : {derived_covered}/{total} blocks = {coverage_pct}%                       ║");
    println!("║  Maturity  : {maturity_avg:.1} / 5.0 (avg)  2030-Q1 Phase Month 1  ║");
    println!("║  At-Risk   : {derived_at_risk} unvalidated hypotheses              ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Per-Block Maturity                                       ║");
    for (block, m) in BMC_BLOCKS {
        let bar = "█".repeat(*m as usize);
        let gap = "░".repeat((5 - m) as usize);
        let flag = if *m < 5 { " ← next" } else { "       " };
        println!("║  {block:<22} [{bar}{gap}] {m}/5{flag}║");
    }
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Blocks below 5/5: cs / uvp / sol / ch / rev / km / ua   ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  2030-Q1 Month 1 Targets (→ iter-39)                      ║");
    println!("║    1. インド 37社 → cs Month 1 進捗確認                  ║");
    println!("║    2. v6 AI GA PoC 精度 87% → uvp/sol 進捗               ║");
    println!("║    3. インドネシア BizDev 初回 MTG → ch 開始              ║");
    println!("║    4. GMV ¥320M + NRR 167% → rev/km Month 1              ║");
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
