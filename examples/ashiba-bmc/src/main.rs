//! ashiba.gftd.ai Lean BMC — kotoba Quad storage + Datalog coverage scoring
//!
//! Data source: `60-apps/ai-gftd-project-jp-ashiba/docs/bmc/ashiba-lean-bmc-v41.toml`
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

const HYPOTHESES: &[(&str, &str, &str, bool)] = &[
    // problem (5/5) + Q2 invisible-demand 衛星検出仮説
    ("p_domestic",               "problem",           "国内ペイン普遍的 stable ✓", true),
    ("p_apac",                   "problem",           "APAC 同一ペイン構造 stable ✓", true),
    ("p_india_full",             "problem",           "インド 40社 ペイン全確認 stable ✓", true),
    ("p_asean_full",             "problem",           "ASEAN ペイン完全確認 stable ✓", true),
    ("p_indonesia_full",         "problem",           "インドネシア ペイン完全確認 stable ✓", true),
    ("p_q2_invisible_demand",    "problem",           "見えない需要ペイン (Q2) — 衛星画像で 30-60日 リードタイム短縮可能", false),
    ("p_q2_deep_segment",        "problem",           "Q2 ベトナム中堅 + マレーシア半島部 ペイン調査", false),
    // customer_segments (4/5)
    ("cs_korea_stable",          "customer_segments", "韓国 101社 active stable ✓", true),
    ("cs_enterprise5",           "customer_segments", "国内 Enterprise 5社 stable ✓", true),
    ("cs_taiwan_42",             "customer_segments", "台湾 42社 active stable ✓", true),
    ("cs_thailand_24",           "customer_segments", "タイ 24社 stable ✓", true),
    ("cs_india_40",              "customer_segments", "インド 40社 active stable ✓", true),
    ("cs_asean_scale_10",        "customer_segments", "ASEAN 10社 stable ✓", true),
    ("cs_q2_outbound_japan_8",   "customer_segments", "国内 衛星 outbound 流入 8社 (Q2 Month 1) — 100現場 pilot から conv 8% 想定", false),
    ("cs_indonesia_q2_4",        "customer_segments", "インドネシア 4社 active (Q2 Month 1) — SNI + Jasindo trial", false),
    ("cs_indonesia_q2_8",        "customer_segments", "インドネシア 8社 active (Q2 末)", false),
    ("cs_asean_q2_14",           "customer_segments", "ASEAN 14社 active (Q2 末)", false),
    // uvp (4/5) — satellite outbound + EVO-X2 + v7 が Q2 中核
    ("uvp_v3_multilingual",      "uvp",               "v3 AI 多言語 88%+ stable ✓", true),
    ("uvp_jis_mandatory",        "uvp",               "JIS A 8951:2026 義務化 stable ✓", true),
    ("uvp_v4_audit",             "uvp",               "v4 AI 動画施工 audit GA stable ✓", true),
    ("uvp_v5_ai_ga",             "uvp",               "v5 AI 足場設計 GA stable ✓", true),
    ("uvp_india_insurance_20co", "uvp",               "インド損保 20社完全適用 stable ✓", true),
    ("uvp_v6_ai_ga",             "uvp",               "v6 AI GA 全市場 stable ✓ (精度 91%)", true),
    ("uvp_asean_multilingual",   "uvp",               "ASEAN 多言語 stable ✓", true),
    ("uvp_satellite_detection_poc", "uvp",            "衛星画像 工事現場検出 PoC (Q2 Month 1) — Sentinel-2 + Planet Labs / U-Net + temporal stack on Gad EVO-X2 / baseline 70%", false),
    ("uvp_satellite_outbound_match","uvp",            "衛星 outbound マッチング (Q2 末) — 検出現場 → 施主 reverse → mailer.gftd.ai 経由 AI メール → 業者マッチング, conv 8%+", false),
    ("uvp_satellite_detection_ga","uvp",              "衛星画像検出 GA (Q2 末) — 月次再検出 精度 85% / 月 500 lead", false),
    ("uvp_v7_ai_poc_start",      "uvp",               "v7 安全予測 AI PoC 開始 (Q2 Month 1) — 画像+IoT融合 baseline 65% on EVO-X2", false),
    ("uvp_v7_ai_poc",            "uvp",               "v7 PoC 完了 (Q2 末) — 精度 80% / 5社", false),
    // solution (4/5)
    ("sol_v3_global",            "solution",          "v3 AI 多言語 本番 stable ✓", true),
    ("sol_v4_ga",                "solution",          "v4 AI GA 本番 stable ✓", true),
    ("sol_v5_ga",                "solution",          "v5 AI GA stable ✓", true),
    ("sol_asean_onboard",        "solution",          "ASEAN β 自動 onboarding stable ✓", true),
    ("sol_v6_ai_ga",             "solution",          "v6 AI GA 全市場 stable ✓ (精度 91%, SLA 99.5%)", true),
    ("sol_evo_x2_procure",       "solution",          "Gad EVO-X2 (GMKtec) 調達 (Q2 Month 1) — AMD Ryzen AI Max+ 395 / 128GB unified / Radeon 8060S iGPU 40CU / 50 TOPS NPU / ROCm 6.2 + ONNX Runtime", false),
    ("sol_satellite_ingest",     "solution",          "衛星画像 ingestion (Q2 Month 1) — Sentinel-2 + Planet Labs → kotoba Vault CAR bundle / 国内 36ヶ月 7.2TB", false),
    ("sol_construction_detection_ml", "solution",     "工事現場検出 ML (Q2 Month 1) — U-Net + temporal stack on EVO-X2 local (320ms/画像) / baseline 70%", false),
    ("sol_owner_resolve",        "solution",          "施主 reverse-lookup (Q2 Month 1) — 国土地理院 + 法務局 + 建確 統合 / 識別率 75%+", false),
    ("sol_mailer_outbound",      "solution",          "AI 営業メール送受信 (Q2 Month 1) — mailer.gftd.ai (Resend 送信 + CF Email Routing 受信) + Murakumo LLM + 業者 3社マッチング + 返信自動分類", false),
    ("sol_satellite_pipeline_ga","solution",          "衛星駆動 outbound pipeline GA (Q2 末) — 月次再検出 → reverse → mailer → match SLA 99%", false),
    ("sol_v7_safety_start",      "solution",          "v7 開発開始 (Q2 Month 1) — EVO-X2 画像+IoT融合 PoC アーキ baseline 65%", false),
    ("sol_iot_sensor_layer",     "solution",          "IoT センサ統合 PoC (Q2 Month 1) — LoRaWAN + 加速度 + 風速 / 5現場テスト", false),
    ("sol_v7_safety_poc",        "solution",          "v7 PoC 完了 (Q2 末) — 80% / 5社", false),
    // channels (4/5)
    ("ch_korea_stable",          "channels",          "韓国 stable ✓", true),
    ("ch_seo_6500",              "channels",          "SEO organic 6,500/月 stable ✓", true),
    ("ch_india_referral",        "channels",          "インド 損保紹介 月 10社+ stable ✓", true),
    ("ch_asean_vietnam_stable",  "channels",          "ベトナム stable ✓", true),
    ("ch_asean_malaysia_stable", "channels",          "マレーシア stable ✓", true),
    ("ch_indonesia_beta",        "channels",          "インドネシア β stable ✓", true),
    ("ch_q2_outbound_pilot",     "channels",          "衛星 outbound 営業 pilot (Q2 Month 1) — 国内 100現場 → mailer.gftd.ai 経由 300+メール → 30日 conv 計測", false),
    ("ch_q2_jasindo_mou",        "channels",          "Jasindo MoU 締結 (Q2 Month 1) — 損保 ID trial", false),
    ("ch_q2_outbound_ga",        "channels",          "衛星 outbound GA (Q2 末) — 月 500 lead → conv 8%+ → 月 40社新規", false),
    ("ch_q2_insurance_id",       "channels",          "損保 ID パートナー (Q2 末) — Jasindo + Asuransi Astra", false),
    // revenue (4/5)
    ("r_gmv_350m",               "revenue",           "GMV ¥350M/月 stable ✓", true),
    ("r_ebitda_20_restored",     "revenue",           "EBITDA 20.0% stable ✓", true),
    ("r_india_40_rev",           "revenue",           "インド 40社 ¥22M/月 stable ✓", true),
    ("r_gmv_370m",               "revenue",           "GMV ¥370M/月 (Q2 Month 1) — インドネシア 4社 + outbound 8社 + v7 premium", false),
    ("r_outbound_cac_payback",   "revenue",           "Outbound CAC ¥35K/社 (Q2 Month 1) — EVO-X2 marginal ≒ 0、Planet $5K / 8社 + ETL = ¥30K / payback 1.2M", false),
    ("r_gmv_400m",               "revenue",           "GMV ¥400M/月 (Q2 末)", false),
    // cost_structure (5/5) — EVO-X2 + 衛星 + mailer 全 cost validated as procurement plan
    ("cs_ebitda_model",          "cost_structure",    "OPEX ¥11.8M/月 ✓ (margin 19.5%、EVO-X2 local 推論で cloud GPU ¥200K カット)", true),
    ("cs_all_agents",            "cost_structure",    "代理店 stable ✓ (¥1.0M/月合計)", true),
    ("cs_team_78",               "cost_structure",    "78名体制 ✓", true),
    ("cs_v7_dev",                "cost_structure",    "v7 開発 ¥1.0M/月 ✓ (EVO-X2 ¥0 cloud + 8名 + IoT ¥400K)", true),
    ("cs_indonesia_office",      "cost_structure",    "インドネシア BizDev 拠点 ¥350K/月 ✓", true),
    ("cs_evo_x2_capex",          "cost_structure",    "EVO-X2 capex ¥350K (one-shot) ✓ — Ryzen AI Max+ 395 / 24M償却 ¥14.6K + 電気 ¥3K = ¥18K/月", true),
    ("cs_satellite_pipeline",    "cost_structure",    "衛星 pipeline ¥600K/月 ✓ (Sentinel-2 無料 + Planet $5K + EVO-X2 ¥18K + ETL ¥80K) — 予算 ¥800K → ¥600K", true),
    ("cs_mailer_resend",         "cost_structure",    "mailer.gftd.ai 送受信 ¥30K/月 ✓ (Resend $50 + CF Email Routing 無料 + email-relay + Murakumo token)", true),
    // key_metrics (4/5)
    ("km_nrr_170",               "key_metrics",       "NRR 170% stable ✓", true),
    ("km_intl_45pct",            "key_metrics",       "海外 GMV 45% stable ✓", true),
    ("km_ebitda_20",             "key_metrics",       "EBITDA 20.0% stable ✓", true),
    ("km_nrr_172",               "key_metrics",       "NRR 172% (Q2 Month 1) — インドネシア + outbound + v7 trial upsell", false),
    ("km_outbound_conv_8",       "key_metrics",       "Outbound conv 8.0% (Q2 Month 1) — 100現場 / 300+メール / 8社成約 / CAC ¥35K / payback 1.2M", false),
    ("km_intl_46pct",            "key_metrics",       "海外 GMV 46% (Q2 Month 1)", false),
    ("km_nrr_175",               "key_metrics",       "NRR 175% (Q2 末)", false),
    ("km_intl_48pct",            "key_metrics",       "海外 GMV 48% (Q2 末)", false),
    // unfair_advantage (4/5)
    ("ua_jis_mandatory",         "unfair_advantage",  "JIS 義務化 仕様権保有 stable ✓", true),
    ("ua_did_28000",             "unfair_advantage",  "DID 2.8万件+ stable ✓", true),
    ("ua_v4_patent",             "unfair_advantage",  "v4 AI 特許 stable ✓", true),
    ("ua_v5_patent",             "unfair_advantage",  "v5 AI 特許 stable ✓", true),
    ("ua_insurance_moat_20co",   "unfair_advantage",  "インド損保 Moat stable ✓", true),
    ("ua_asean_moat_2co",        "unfair_advantage",  "ASEAN 規格 Moat stable ✓", true),
    ("ua_v6_patent_filed",       "unfair_advantage",  "v6 AI 特許出願済 stable ✓", true),
    ("ua_indonesia_moat",        "unfair_advantage",  "インドネシア SNI Moat stable ✓", true),
    ("ua_did_30000",             "unfair_advantage",  "DID 3.0万件+ (Q2 Month 1)", false),
    ("ua_satellite_demand_dataset","unfair_advantage", "衛星 dataset Moat (Q2 Month 1) — Sentinel-2 36ヶ月 7.2TB + DID 相関 5,000現場 / EVO-X2 再学習サイクル 4時間", false),
    ("ua_local_inference_moat",  "unfair_advantage",  "Local inference Moat (Q2 Month 1) — EVO-X2 で衛星 ML を VPC 外不要 / competitor cloud GPU より marginal 1/10 + leak ゼロ", false),
    ("ua_v7_patent_draft",       "unfair_advantage",  "v7 特許 draft (Q2 Month 1) — 画像+IoT融合 事故予兆 PCT 準備", false),
    ("ua_v7_patent_filed",       "unfair_advantage",  "v7 特許 PCT 出願完了 (Q2 末)", false),
    ("ua_satellite_outbound_patent","unfair_advantage","衛星 outbound 特許 (Q2 末) — 衛星 × DID × mailer AI メール method PCT", false),
    ("ua_did_35000",             "unfair_advantage",  "DID 3.5万件+ (Q2 末)", false),
    ("ua_jasindo_moat",          "unfair_advantage",  "Jasindo パートナーシップ Moat (Q2 末)", false),
];

fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }
fn graph_cid() -> KotobaCid { cid("bmc:ashiba:v41") }
fn quad(subject: &str, predicate: &str, object: QuadObject) -> Quad {
    Quad { graph: graph_cid(), subject: cid(subject), predicate: predicate.to_string(), object }
}

fn build_bmc_facts() -> Vec<Delta> {
    let mut deltas = Vec::new();
    deltas.push(Delta::assert(quad("bmc:ashiba", "bmc/version", QuadObject::Text("v41".into()))));
    deltas.push(Delta::assert(quad("bmc:ashiba", "bmc/product", QuadObject::Text("ashiba.gftd.ai".into()))));
    deltas.push(Delta::assert(quad("bmc:ashiba", "bmc/model", QuadObject::Text("lean-canvas-hybrid".into()))));

    for (block_name, maturity) in BMC_BLOCKS {
        let block_id = format!("bmc:ashiba:block:{block_name}");
        deltas.push(Delta::assert(quad("bmc:ashiba", "bmc/block", QuadObject::Cid(cid(&block_id)))));
        deltas.push(Delta::assert(quad(&block_id, "bmc/block_name", QuadObject::Text(block_name.to_string()))));
        deltas.push(Delta::assert(quad(&block_id, "bmc/maturity", QuadObject::Integer(*maturity))));
        let entry_id = format!("bmc:ashiba:entry:{block_name}:default");
        deltas.push(Delta::assert(quad(&entry_id, "entry/block", QuadObject::Cid(cid(&block_id)))));
    }

    for (entry_id, block_name, hypothesis, validated) in HYPOTHESES {
        let full_entry_id = format!("bmc:ashiba:entry:{block_name}:{entry_id}");
        let block_id = format!("bmc:ashiba:block:{block_name}");
        deltas.push(Delta::assert(quad(&full_entry_id, "entry/block", QuadObject::Cid(cid(&block_id)))));
        deltas.push(Delta::assert(quad(&full_entry_id, "bmc/hypothesis", QuadObject::Text(hypothesis.to_string()))));
        deltas.push(Delta::assert(quad(&full_entry_id, "bmc/validated", QuadObject::Bool(*validated))));
    }
    deltas
}

fn build_coverage_program() -> DatalogProgram {
    let mut prog = DatalogProgram::new();
    prog.add_rule(DatalogRule {
        head: Atom { relation: "covered".into(), args: vec![Term::Variable("Block".into()), Term::Variable("Block".into())] },
        body: vec![BodyLiteral::Positive(Atom { relation: "entry/block".into(), args: vec![Term::Variable("Entry".into()), Term::Variable("Block".into())] })],
    });
    prog.add_rule(DatalogRule {
        head: Atom { relation: "at_risk".into(), args: vec![Term::Variable("Entry".into()), Term::Variable("Entry".into())] },
        body: vec![
            BodyLiteral::Positive(Atom { relation: "bmc/hypothesis".into(), args: vec![Term::Variable("Entry".into()), Term::Variable("_H".into())] }),
            BodyLiteral::Positive(Atom { relation: "bmc/validated".into(), args: vec![Term::Variable("Entry".into()), Term::Constant(cid_label_for_bool(false))] }),
        ],
    });
    prog
}

fn cid_label_for_bool(b: bool) -> String { if b { "true".into() } else { "false".into() } }

fn print_score_report(derived_covered: usize, derived_at_risk: usize) {
    let total = BMC_BLOCKS.len();
    let coverage_pct = (derived_covered * 100) / total;
    let maturity_sum: i64 = BMC_BLOCKS.iter().map(|(_, m)| m).sum();
    let maturity_avg = maturity_sum as f64 / total as f64;

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     ashiba.gftd.ai Lean BMC — kotoba Scoring Report      ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Iteration : 41 (2026-05-28) [Q2 Phase Month 1 reset]     ║");
    println!("║  Model     : Lean Canvas Hybrid (9 blocks)                ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Coverage  : {derived_covered}/{total} blocks = {coverage_pct}%                       ║");
    println!("║  Maturity  : {maturity_avg:.1} / 5.0 (avg)  Q2 Month 1 start ║");
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
    println!("║  Q2 中核戦略 (3 ユーザー確定ディレクティブ統合)            ║");
    println!("║  1. 衛星画像 outbound matching (Sentinel-2 + Planet Labs) ║");
    println!("║  2. Gad EVO-X2 (Ryzen AI Max+ 395) local 推論              ║");
    println!("║  3. mailer.gftd.ai (Resend + CF Email Routing)            ║");
    println!("║  + v7 安全予測 AI / Jasindo / インドネシア 8社            ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Next (→ iter-42, Q2 Month 1 進捗 → ~4.9)                 ║");
    println!("║    1. EVO-X2 調達 + 衛星 PoC 70% + mailer 送受信稼働       ║");
    println!("║    2. outbound pilot conv 8% + Jasindo MoU + 4社流入       ║");
    println!("║    3. GMV ¥370M + NRR 172% + DID 3.0万 + v7 特許 draft    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}

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
        .map(|d| d.quad.subject.clone()).collect();
    let at_risk_entries: std::collections::HashSet<_> = derived.iter()
        .filter(|d| d.quad.predicate == "at_risk" && d.is_assert())
        .map(|d| d.quad.subject.clone()).collect();
    println!("Datalog derived {} facts total", derived.len());
    println!("  covered blocks : {}", covered_blocks.len());
    println!("  at-risk entries: {}", at_risk_entries.len());
    println!();
    print_score_report(covered_blocks.len(), at_risk_entries.len());
    Ok(())
}
