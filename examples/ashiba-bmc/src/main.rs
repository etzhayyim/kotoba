//! ashiba.gftd.ai Lean BMC — kotoba Quad storage + Datalog coverage scoring
//!
//! This example encodes the ashiba Lean BMC as kotoba Quads, then runs
//! a DatalogProgram to compute coverage % and per-block maturity scores.
//!
//! Data source: `60-apps/ai-gftd-project-jp-ashiba/docs/bmc/ashiba-lean-bmc-v30.toml`
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
    ("uvp",               4),
    ("solution",          5),
    ("channels",          5),
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
    ("p_india_full_8",           "problem",           "インド 8社全員ヒアリング完了 ✓ + 定量スコア 4.4/5.0", true),
    ("p_india_pilot_poc",        "problem",           "インド pilot 2社 現場 PoC 完了 ✓ — ペイン深度 4.5/5.0 + IS 2750 適合性 確認", true),
    ("p_india_scale_pain",       "problem",           "インド 10社 ヒアリング拡張 ✓ — CII 認定 8社 ペイン定量スコア 4.3/5.0 (2029-Q2-10)", true),
    // customer_segments (5/5)
    ("cs_korea_stable",          "customer_segments", "韓国 101社 active stable ✓", true),
    ("cs_enterprise5",           "customer_segments", "国内 Enterprise 5社 stable ✓", true),
    ("cs_taiwan_37",             "customer_segments", "台湾 37社 active ✓", true),
    ("cs_thailand_20",           "customer_segments", "タイ 20社 ✓ (+1社 Q2 新規 API 申請)", true),
    ("cs_india_pilot_ga",        "customer_segments", "インド pilot 2社 正式課金 stable ✓", true),
    ("cs_india_10",              "customer_segments", "インド 10社 onboard ✓ — CII 紹介 8社 + BizDev 追加 2社 (2029-Q2-15)", true),
    ("cs_india_20",              "customer_segments", "インド 20社 active (2029-Q2 末) — CII 追加紹介 10社 + 自己申請 API 利用", false),
    // uvp (4/5)
    ("uvp_v3_multilingual",      "uvp",               "v3 AI 多言語 (日韓繁中) 88%+ stable ✓", true),
    ("uvp_jis_mandatory",        "uvp",               "JIS A 8951:2026 義務化 仕様権保有 stable ✓", true),
    ("uvp_v4_audit",             "uvp",               "v4 AI 動画施工 audit GA stable ✓ (精度 87%)", true),
    ("uvp_insurance_2co",        "uvp",               "東京海上日動 + 損保ジャパン exclusive Moat stable ✓", true),
    ("uvp_v4_upsell_70",         "uvp",               "v4 upsell 70社 stable ✓ × ¥50K = ¥3.5M/月", true),
    ("uvp_india_is2750",         "uvp",               "インド版 UVP stable ✓ — IS 2750 + ヒンディー語 UI", true),
    ("uvp_india_insurance",      "uvp",               "インド損保連携 UVP stable ✓ (LIC/NIA PoC 稼働中)", true),
    ("uvp_india_insurance_pricing","uvp",             "インド損保本格連携 — 保険スコア連動 dynamic pricing + 10社 適用 (2029-Q2 末)", false),
    // solution (5/5)
    ("sol_v3_global",            "solution",          "v3 AI 多言語 本番 stable ✓", true),
    ("sol_v4_ga",                "solution",          "v4 AI GA 本番 stable ✓ (SLA 99.9%)", true),
    ("sol_v4_upsell_70",         "solution",          "v4 upsell 70社 stable ✓ × ¥50K = ¥3.5M/月", true),
    ("sol_thailand_api",         "solution",          "タイ版 API stable ✓ (20社 active)", true),
    ("sol_india_pilot_ga",       "solution",          "インド版 pilot GA stable ✓ (SLA 99.5%+ / 正式課金中)", true),
    ("sol_india_scale_infra",    "solution",          "インド 20社向け multi-tenant スケールインフラ ✓ — IS 2750 対応 SLA 99.5%+ / auto onboard (2029-Q2-15)", true),
    ("sol_india_scale_30",       "solution",          "インド 30社向け自動 onboarding パイプライン全自動化 (2029-Q2 末) — CII API 連携完全自動", false),
    // channels (5/5)
    ("ch_korea_stable",          "channels",          "韓国 チャネル stable ✓", true),
    ("ch_seo_5000",              "channels",          "SEO organic 5,000/月 ✓", true),
    ("ch_taiwan_stable",         "channels",          "台湾 BizDev stable ✓ (37社 active)", true),
    ("ch_thailand_api_eff",      "channels",          "タイ API 自己申請チャネル stable ✓ (20社 active)", true),
    ("ch_india_3co",             "channels",          "インド BizDev 3社体制 stable ✓", true),
    ("ch_india_gov_channel",     "channels",          "インド 建設省 / CII 経由 認定チャネル stable ✓", true),
    ("ch_india_gov_10plus",      "channels",          "インド 建設省/CII チャネル 10社+ 紹介パイプライン稼働 ✓ (2029-Q2-20)", true),
    ("ch_india_self_apply",      "channels",          "インド IS 2750 認定企業 自己申請 API チャネル (2029-Q2 末) — 月10社+ 申請", false),
    // revenue (4/5)
    ("r_gmv_160m",               "revenue",           "GMV ¥160M/月 stable ✓", true),
    ("r_ebitda_172",             "revenue",           "EBITDA 17.5% ✓ (インド 10社 高 margin 寄与)", true),
    ("r_v4_upsell_350m",         "revenue",           "v4 upsell 70社 × ¥50K = ¥3.5M/月 stable ✓", true),
    ("r_india_rev_15m",          "revenue",           "インド 正式課金 ¥1.5M/月 stable ✓ (pilot 2社)", true),
    ("r_gmv_175m",               "revenue",           "GMV ¥175M/月 ✓ — インド 10社 + タイ 20社 + v4 75社 寄与 (2029-Q2-20)", true),
    ("r_india_10_rev",           "revenue",           "インド 10社 課金 ¥5M/月 ✓ (¥500K/社 × 10社、2029-Q2-20)", true),
    ("r_gmv_200m",               "revenue",           "GMV ¥200M/月 (2029-Q2 末) — インド 20社 + CII 自己申請チャネル 本格化", false),
    // cost_structure (5/5)
    ("cs_ebitda_model",          "cost_structure",    "OPEX ¥7.8M/月 ✓ (margin 17.5%+ 維持、インド 10社スケール + v4 75社 込み)", true),
    ("cs_all_agents",            "cost_structure",    "台湾 + タイ + インド 3社 代理店モデル stable ✓ (¥600K/月合計)", true),
    ("cs_team_55",               "cost_structure",    "55名体制 ✓ (インド拡大 BizDev/CS 5名追加済)", true),
    ("cs_india_scale_ops",       "cost_structure",    "インド 10社 スケール運用コスト ¥480K/月 ✓ (予算 ¥600K 以内)", true),
    ("cs_v4_scale_infra",        "cost_structure",    "v4 upsell 75社向け追加インフラコスト ¥340K/月 ✓", true),
    // key_metrics (4/5)
    ("km_nrr_150",               "key_metrics",       "NRR 150% stable ✓", true),
    ("km_d365_370",              "key_metrics",       "D365 37.0% ✓ (インド 10社 + タイ 20社 継続率向上)", true),
    ("km_ebitda_175",            "key_metrics",       "EBITDA 17.5% ✓ (インド 10社 高 margin + v4 75社 寄与)", true),
    ("km_intl_27pct",            "key_metrics",       "海外 GMV 比率 27% ✓ — インド 10社 + タイ 20社 + 台湾 37社 (2029-Q2-20)", true),
    ("km_nrr_155",               "key_metrics",       "NRR 155% (2029-Q2 末) — インド 20社 本格課金 + v4 75社 継続率 99.5%+", false),
    ("km_intl_30pct",            "key_metrics",       "海外 GMV 比率 30% (2029-Q2 末) — インド 20社 + タイ 20社 + 台湾 38社", false),
    // unfair_advantage (4/5)
    ("ua_jis_mandatory",         "unfair_advantage",  "JIS 義務化 仕様権保有 stable ✓", true),
    ("ua_did_10000",             "unfair_advantage",  "DID 1万件+ stable ✓", true),
    ("ua_did_12000",             "unfair_advantage",  "DID 1.2万件+ ✓ — インド 10社 本番登録 + タイ 20社 + 台湾 37社 (2029-Q2-20、相関 0.92)", true),
    ("ua_v3_patent",             "unfair_advantage",  "v3 AI 特許 stable ✓ (日本+韓国+PCT)", true),
    ("ua_v4_patent",             "unfair_advantage",  "v4 AI 動画施工 audit 特許 stable ✓ (日本+韓国+PCT)", true),
    ("ua_insurance_moat_2",      "unfair_advantage",  "東京海上日動 + 損保ジャパン exclusive Moat stable ✓", true),
    ("ua_india_moat_3co",        "unfair_advantage",  "インド Moat 3社独占 stable ✓ + CII 認定 10社パイプライン独占チャネル", true),
    ("ua_india_is2750",          "unfair_advantage",  "インド IS 2750 仕様権申請 stable ✓", true),
    ("ua_india_insurance_poc",   "unfair_advantage",  "インド損保 PoC stable ✓ (LIC / New India Assurance 稼働中)", true),
    ("ua_india_insurance_scale", "unfair_advantage",  "インド損保 本格連携 — 保険スコア連動 pricing + 10社 適用 (2029-Q2 末)", false),
    ("ua_did_15000",             "unfair_advantage",  "DID 1.5万件+ (2029-Q2 末) — インド 20社 本番登録 + タイ 20社 + 台湾 38社 (相関 0.93)", false),
];

// ─────────────────────────────────────────────────────────────────────────────
// CID helper
// ─────────────────────────────────────────────────────────────────────────────

fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

fn graph_cid() -> KotobaCid { cid("bmc:ashiba:v30") }

fn quad(subject: &str, predicate: &str, object: QuadObject) -> Quad {
    Quad { graph: graph_cid(), subject: cid(subject), predicate: predicate.to_string(), object }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build BMC fact deltas
// ─────────────────────────────────────────────────────────────────────────────

fn build_bmc_facts() -> Vec<Delta> {
    let mut deltas = Vec::new();

    deltas.push(Delta::assert(quad(
        "bmc:ashiba", "bmc/version", QuadObject::Text("v30".into()),
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
    println!("║  Iteration : 30 (2026-05-28) [India Scale 2029-Q2 Phase Month 2]║");
    println!("║  Model     : Lean Canvas Hybrid (9 blocks)                ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Coverage  : {derived_covered}/{total} blocks = {coverage_pct}%                       ║");
    println!("║  Maturity  : {maturity_avg:.1} / 5.0 (avg)                          ║");
    println!("║  At-Risk   : {derived_at_risk} unvalidated hypotheses               ║");
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
    println!("║  Priority (2029-Q2 末 → iter-31)                         ║");
    println!("║    1. インド 20社 + 損保 dynamic pricing → uvp/ua 5/5  ║");
    println!("║    2. GMV ¥200M + NRR 155% + 海外 30% → rev/km 5/5    ║");
    println!("║    3. DID 1.5万件+ → ua 5/5                             ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  GMV ¥175M ✓ / NRR 150% ✓ / 海外 27% ✓ / DID 1.2万 ✓ ║");
    println!("║  (prior: ★★★★★ 2029-Q1 末 VALIDATED)                   ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  India Scale 2029-Q2 Phase Month 2                       ║");
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
