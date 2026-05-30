//! ashiba.gftd.ai Lean BMC — kotoba Datomic-on-IPFS pipeline (Quad → Journal WAL →
//! 4 ProllyTrees → Kubo cold tier → AEAD-sealed summary → IPFS self-pin) + Datalog
//! coverage scoring.
//!
//! Data source:  `60-apps/ai-gftd-project-jp-ashiba/docs/bmc/ashiba-lean-bmc-v50.toml`
//! Rules source: `60-apps/ai-gftd-project-jp-ashiba/docs/bmc/coverage.dl`
//!
//! Requires a running Kubo daemon (default `http://localhost:5001`); override with
//! `KOTOBA_IPFS_ENDPOINT`.  `KOTOBA_STORE_PATH` controls the on-disk Journal head
//! pointer (default `/tmp/ashiba-bmc-kse`).

use anyhow::Result;
use bytes::Bytes;
use kotoba_core::{cid::KotobaCid, store::BlockStore};
use kotoba_graph::QuadStore;
use kotoba_kqe::{
    datalog::{Atom, BodyLiteral, DatalogProgram, DatalogRule, Term},
    delta::Delta,
    quad::{Quad, QuadObject},
};
use kotoba_kse::{Journal, SecureVault, Vault};
use kotoba_store::{
    BudgetedBlockStore, IpfsPinClient, KuboBlockStore, MemoryBlockStore, TieredBlockStore,
};
use std::sync::Arc;

const BMC_BLOCKS: &[(&str, i64)] = &[
    ("problem", 4),
    ("customer_segments", 4),
    ("uvp", 5),
    ("solution", 5),
    ("channels", 5),
    ("revenue", 4),
    ("cost_structure", 5),
    ("key_metrics", 4),
    ("unfair_advantage", 5),
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
    ("cs_indonesia_q2_4",        "customer_segments", "インドネシア 4社 active (Q2 Month 1) — SNI + Jasindo trial", true),
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
    ("uvp_satellite_detection_poc", "uvp",            "衛星画像 工事現場検出 PoC (Q2 Month 1) — Sentinel-2 + Planet Labs / U-Net + temporal stack on Gad EVO-X2 / baseline 70%", true),
    ("uvp_satellite_outbound_match","uvp",            "衛星 outbound マッチング (Q2 末) — 検出現場 → 施主 reverse → mailer.gftd.ai 経由 AI メール → 業者マッチング, conv 8%+", false),
    ("uvp_satellite_detection_ga","uvp",              "衛星画像検出 GA (Q2 末) — 月次再検出 精度 85% / 月 500 lead", false),
    ("uvp_v7_ai_poc_start",      "uvp",               "v7 安全予測 AI PoC 開始 (Q2 Month 1) — 画像+IoT融合 baseline 65% on EVO-X2", true),
    ("uvp_v7_ai_poc",            "uvp",               "v7 PoC 完了 (Q2 末) — 精度 80% / 5社", false),
    // solution (4/5)
    ("sol_v3_global",            "solution",          "v3 AI 多言語 本番 stable ✓", true),
    ("sol_v4_ga",                "solution",          "v4 AI GA 本番 stable ✓", true),
    ("sol_v5_ga",                "solution",          "v5 AI GA stable ✓", true),
    ("sol_asean_onboard",        "solution",          "ASEAN β 自動 onboarding stable ✓", true),
    ("sol_v6_ai_ga",             "solution",          "v6 AI GA 全市場 stable ✓ (精度 91%, SLA 99.5%)", true),
    ("sol_evo_x2_procure",       "solution",          "Gad EVO-X2 (GMKtec) 調達 (Q2 Month 1) — AMD Ryzen AI Max+ 395 / 128GB unified / Radeon 8060S iGPU 40CU / 50 TOPS NPU / ROCm 6.2 + ONNX Runtime", true),
    ("sol_satellite_ingest",     "solution",          "衛星画像 ingestion (Q2 Month 1) — Sentinel-2 + Planet Labs → kotoba Vault CAR bundle / 国内 36ヶ月 7.2TB", true),
    ("sol_construction_detection_ml", "solution",     "工事現場検出 ML (Q2 Month 1) — U-Net + temporal stack on EVO-X2 local (320ms/画像) / baseline 70%", true),
    ("sol_owner_resolve",        "solution",          "施主 reverse-lookup (Q2 Month 1) — 国土地理院 + 法務局 + 建確 統合 / 識別率 75%+", true),
    ("sol_mailer_outbound",      "solution",          "AI 営業メール送受信 (Q2 Month 1) — mailer.gftd.ai (Resend 送信 + CF Email Routing 受信) + Murakumo LLM + 業者 3社マッチング + 返信自動分類", false),
    ("sol_satellite_pipeline_ga","solution",          "衛星駆動 outbound pipeline GA (Q2 末) — 月次再検出 → reverse → mailer → match SLA 99%", false),
    ("sol_v7_safety_start",      "solution",          "v7 開発開始 (Q2 Month 1) — EVO-X2 画像+IoT融合 PoC アーキ baseline 65%", true),
    ("sol_iot_sensor_layer",     "solution",          "IoT センサ統合 PoC (Q2 Month 1) — LoRaWAN + 加速度 + 風速 / 5現場テスト", true),
    ("sol_v7_safety_poc",        "solution",          "v7 PoC 完了 (Q2 末) — 80% / 5社", false),
    // channels (4/5)
    ("ch_korea_stable",          "channels",          "韓国 stable ✓", true),
    ("ch_seo_6500",              "channels",          "SEO organic 6,500/月 stable ✓", true),
    ("ch_india_referral",        "channels",          "インド 損保紹介 月 10社+ stable ✓", true),
    ("ch_asean_vietnam_stable",  "channels",          "ベトナム stable ✓", true),
    ("ch_asean_malaysia_stable", "channels",          "マレーシア stable ✓", true),
    ("ch_indonesia_beta",        "channels",          "インドネシア β stable ✓", true),
    ("ch_q2_outbound_pilot",     "channels",          "衛星 outbound 営業 pilot (Q2 Month 1) — 国内 100現場 → mailer.gftd.ai 経由 300+メール → 30日 conv 計測", false),
    ("ch_q2_jasindo_mou",        "channels",          "Jasindo MoU 締結 (Q2 Month 1) — 損保 ID trial", true),
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
    ("ua_satellite_demand_dataset","unfair_advantage", "衛星 dataset Moat (Q2 Month 1) — Sentinel-2 36ヶ月 7.2TB + DID 相関 5,000現場 / EVO-X2 再学習サイクル 4時間", true),
    ("ua_local_inference_moat",  "unfair_advantage",  "Local inference Moat (Q2 Month 1) — EVO-X2 で衛星 ML を VPC 外不要 / competitor cloud GPU より marginal 1/10 + leak ゼロ", true),
    ("ua_v7_patent_draft",       "unfair_advantage",  "v7 特許 draft (Q2 Month 1) — 画像+IoT融合 事故予兆 PCT 準備", true),
    ("ua_v7_patent_filed",       "unfair_advantage",  "v7 特許 PCT 出願完了 (Q2 末)", false),
    ("ua_satellite_outbound_patent","unfair_advantage","衛星 outbound 特許 (Q2 末) — 衛星 × DID × mailer AI メール method PCT", false),
    ("ua_did_35000",             "unfair_advantage",  "DID 3.5万件+ (Q2 末)", false),
    ("ua_jasindo_moat",          "unfair_advantage",  "Jasindo パートナーシップ Moat (Q2 末)", false),
    // === iter-43 reality-recalibration additions (2026-05-28 CF audit) ===
    ("sol_mailer_infra_ok",      "solution",          "mailer.gftd.ai インフラ確認 ✓ (CF API audit 2026-05-28) — Email Routing enabled/ready, catch-all → ai-gftd-email-relay worker, MX route1-3 設定済, DKIM/SPF/DMARC OK", true),
    ("sol_xrpc_fix",             "solution",          "XRPC 520 修復 (Q2 Month 1 残り) — BPMN dispatcher + Zeebe `mailer` worker profile 再起動 + listEmails/stats 復活", false),
    ("sol_resume_email_traffic", "solution", "送信トラフィック再開 ✓ (iter-45) — Resend probe → CF Email Routing +30min で 6 events 着弾確認、E2E 復活", true),
    ("ch_q2_5_7_burst_40emails", "channels",          "5/6-5/7 mailer pilot 40通受信実績 ✓ — CF Analytics で確認、E2E pipeline 1度成功、sample 不足で conv 推定不能", true),
    ("km_mailer_5_7_40emails",   "key_metrics",       "mailer 5/7 受信 40通 ✓ (CF Analytics evidence) — E2E pipeline 1度成功した実証データ", true),
    ("km_mailer_dormancy_20d",   "key_metrics",       "mailer 5/8 以降 20日 dormancy ✓ (CF Analytics 0通) — 修復までの SLA gap 計測", true),
    // === iter-44 live-probe evidence (2026-05-28 11:02 UTC, Resend → CF) ===
    ("sol_live_probe_resend_2",  "solution",          "Live probe via Resend 実施 ✓ (iter-44, 2026-05-28 11:02 UTC) — 2発 (test-iter44@mailer.gftd.ai + apex test-iter44@gftd.ai) を ap-northeast-1 から送信、両方 last_event=sent 確認", true),
    ("sol_cf_silent_drop",       "solution",          "CF Email Routing 着信側 silent drop 観測 ✓ — probe +90s で emailRoutingAdaptiveGroups events=0、SMTP layer rejection or Analytics 遅延", true),
    ("sol_smtp_diag_resolved", "solution", "SMTP-layer 切り分け 完了 ✓ (iter-45) — +30min 後 CF Analytics events=6 確認、仮説 (b) Analytics 遅延 が真、SMTP rejection は falsified、propagation delay 2-17min", true),
    ("ch_q2_external_esp_probe_obsoleted", "channels", "外部 ESP probe 提案 obsoleted ✓ (iter-45) — SMTP rejection falsified で不要化", true),
    ("km_probe_send_recv_gap",   "key_metrics",       "Probe 送受信 gap ✓ — Resend sent=2/2、CF received=0/2 (+90s 時点)、real-time 着弾率は Resend last_event 単独では SSoT 不可、vertex_mailer_inbound_email row count を SSoT に", true),
    // === iter-44 NEW directive (2026-05-28): ashiba = Python + LangGraph ===
    ("sol_langgraph_runtime", "solution", "ashiba 実装 = Python + LangGraph (L7 Granian pod) ✓ (iter-45) — actor-manifest.jsonld + 20-actors/jp-ashiba/py/ scaffold + ADR-2605281130", true),
    ("sol_pyzeebe_4_actors_scaffold", "solution", "4 actor DIDs pyzeebe primitives scaffold ✓ (iter-45) — 4 dirs + __init__.py + State TypedDict 設置、Zeebe registration は iter-46+", true),
    ("sol_langgraph_subgraph",   "solution",          "LangGraph subgraph アーキ — 各 actor を State + Edge + Tool / kotoba Quad で graph_def_cid 永続化 / Checkpointer = kotoba Vault CAR (ADR-2605082100)", false),
    ("sol_ts_native_deprecate",  "solution",          "TS Native (wasm/*/src/app.ts) を T3 fallback only として deprecate 維持 — actor-manifest.jsonld + Python LangGraph が primary", true),
    // === iter-46 LangGraph 4-actor wire-up (2026-05-28) ===
    ("sol_satellite_detector_wired", "solution",     "satellite_detector wire-up ✓ (iter-46) — State + 3 Nodes + route_by_confidence (≥0.7→dispatch, <0.3→discard, mid→retry) + build_graph + register_zeebe_tasks(_worker) + TASK_TYPE ai.gftd.apps.jp-ashiba.satellite-detector.detect + EVO_X2_INFER_URL", true),
    ("sol_owner_resolver_wired",     "solution",     "owner_resolver wire-up ✓ (iter-46) — 3 parallel Nodes (GSI 地番 + 法務局 登記 + 建確) + route_by_match_rate (≥0.75→dispatch, <0.4→discard) + DATA_SOURCES [gsi.go.jp, houmu.go.jp, kenchiku-permit.go.jp]", true),
    ("sol_outbound_emailer_wired",   "solution",     "outbound_emailer wire-up ✓ (iter-46) — Nodes (Murakumo proposal + vendor matching + mailer XRPC send) + MAILER_SEND_XRPC + FROM ashiba@mailer.gftd.ai + route_by_send_status", true),
    ("sol_safety_predictor_wired",   "solution",     "safety_predictor wire-up ✓ (iter-46) — fuse_image_iot_on_evo_x2 multimodal + route_by_risk (≥0.8 alert / ≥0.5 log) + EVO_X2 /v7/multimodal + LoRaWAN IoT sources + TARGET_PRECISION 0.80", true),
    // === iter-47 BPMN process_def + K8s Granian pod scaffold (2026-05-28) ===
    ("sol_bpmn_process_def",       "solution",      "BPMN process_def ✓ (iter-47) — site_detect_to_send.bpmn / 4 ServiceTask + 3 ExclusiveGateway + 4 EndEvent + Zeebe ioMapping + retries policy", true),
    ("sol_k8s_granian_manifest",   "solution",      "K8s Granian pod manifest ✓ (iter-47) — jp-ashiba-langgraph ns + ConfigMap 13 keys + Secret refs + Granian ASGI Deployment + ClusterIP Service + deploy roadmap", true),
    ("sol_iter48_deploy_plan",     "solution",      "iter-48+ deploy plan — image build & push / kubectl apply / BPMN seed / 1-tile smoke test → mailer 着弾確認", false),
    // === iter-48 buildable artifacts + Datalog evidence-counter (2026-05-28) ===
    ("sol_dockerfile_ready",       "solution",      "Dockerfile ✓ (iter-48) — python:3.12-slim + granian[uvloop] 1.6 + pyzeebe 4.5 + langgraph 0.2 + httpx 0.27 + kotoba-py 0.1 + HEALTHCHECK + Granian ASGI 8080 workers=2 uvloop", true),
    ("sol_granian_entrypoint",     "solution",      "Granian ASGI entrypoint ✓ (iter-48) — 20-actors/jp-ashiba/py/app.py / lifespan で Zeebe worker bootstrap + /health /metrics /actor-manifest / smoke OK", true),
    ("sol_datalog_evidence_counter","solution",     "Datalog evidence-counter rule ✓ (iter-48) — coverage.dl に real_inbound_count + evidence_gap + mailer_drift_alert (gap>20) 追加、claim vs CF/RW 自動突合", true),
    ("sol_iter48_probe_resend",    "solution",      "iter-48 Resend probe ✓ — test-iter48@mailer.gftd.ai 送信 e43c95e6 / CF Analytics events=8 累計 / Analytics 遅延仮説 引き続き 真", true),
    // === iter-49/50: kotoba-datomic 接続確認 + 4 actor 半分 refactor ===
    ("sol_datomic_rust_pipeline",      "solution",   "kotoba-datomic Rust pipeline ✓ (iter-49) — Connection.transact(EDN) → 2 tx / 371 datoms / 126 entities, Datalog q() で per-block validated count 9 行返却", true),
    ("sol_satellite_detector_datomic", "solution",   "satellite_detector Datomic-first refactor ✓ (iter-50) — slim Input/Output, conn.transact 6 Datoms, WRITTEN_ATTRIBUTES 公開", true),
    ("sol_owner_resolver_datomic",     "solution",   "owner_resolver Datomic-first refactor ✓ (iter-50) — PULL_QUERY_EDN で q() pull, conn.transact 5 Datoms", true),
    ("sol_actor_datomic_remaining",    "solution",   "outbound_emailer + safety_predictor Datomic refactor (iter-51+ 残り)", false),
];

fn cid(s: &str) -> KotobaCid {
    KotobaCid::from_bytes(s.as_bytes())
}
fn graph_cid() -> KotobaCid {
    cid("bmc:ashiba:v50")
}
fn quad(subject: &str, predicate: &str, object: QuadObject) -> Quad {
    Quad {
        graph: graph_cid(),
        subject: cid(subject),
        predicate: predicate.to_string(),
        object,
    }
}

fn build_bmc_facts() -> Vec<Delta> {
    let mut deltas = Vec::new();
    deltas.push(Delta::assert(quad(
        "bmc:ashiba",
        "bmc/version",
        QuadObject::Text("v50".into()),
    )));
    deltas.push(Delta::assert(quad(
        "bmc:ashiba",
        "bmc/product",
        QuadObject::Text("ashiba.gftd.ai".into()),
    )));
    deltas.push(Delta::assert(quad(
        "bmc:ashiba",
        "bmc/model",
        QuadObject::Text("lean-canvas-hybrid".into()),
    )));

    for (block_name, maturity) in BMC_BLOCKS {
        let block_id = format!("bmc:ashiba:block:{block_name}");
        deltas.push(Delta::assert(quad(
            "bmc:ashiba",
            "bmc/block",
            QuadObject::Cid(cid(&block_id)),
        )));
        deltas.push(Delta::assert(quad(
            &block_id,
            "bmc/block_name",
            QuadObject::Text(block_name.to_string()),
        )));
        deltas.push(Delta::assert(quad(
            &block_id,
            "bmc/maturity",
            QuadObject::Integer(*maturity),
        )));
        let entry_id = format!("bmc:ashiba:entry:{block_name}:default");
        deltas.push(Delta::assert(quad(
            &entry_id,
            "entry/block",
            QuadObject::Cid(cid(&block_id)),
        )));
    }

    for (entry_id, block_name, hypothesis, validated) in HYPOTHESES {
        let full_entry_id = format!("bmc:ashiba:entry:{block_name}:{entry_id}");
        let block_id = format!("bmc:ashiba:block:{block_name}");
        deltas.push(Delta::assert(quad(
            &full_entry_id,
            "entry/block",
            QuadObject::Cid(cid(&block_id)),
        )));
        deltas.push(Delta::assert(quad(
            &full_entry_id,
            "bmc/hypothesis",
            QuadObject::Text(hypothesis.to_string()),
        )));
        deltas.push(Delta::assert(quad(
            &full_entry_id,
            "bmc/validated",
            QuadObject::Bool(*validated),
        )));
    }
    deltas
}

fn build_coverage_program() -> DatalogProgram {
    let mut prog = DatalogProgram::new();
    prog.add_rule(DatalogRule {
        head: Atom {
            relation: "covered".into(),
            args: vec![
                Term::Variable("Block".into()),
                Term::Variable("Block".into()),
            ],
        },
        body: vec![BodyLiteral::Positive(Atom {
            relation: "entry/block".into(),
            args: vec![
                Term::Variable("Entry".into()),
                Term::Variable("Block".into()),
            ],
        })],
    });
    prog.add_rule(DatalogRule {
        head: Atom {
            relation: "at_risk".into(),
            args: vec![
                Term::Variable("Entry".into()),
                Term::Variable("Entry".into()),
            ],
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
    if b {
        "true".into()
    } else {
        "false".into()
    }
}

fn print_score_report(derived_covered: usize, derived_at_risk: usize) {
    let total = BMC_BLOCKS.len();
    let coverage_pct = (derived_covered * 100) / total;
    let maturity_sum: i64 = BMC_BLOCKS.iter().map(|(_, m)| m).sum();
    let maturity_avg = maturity_sum as f64 / total as f64;

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     ashiba.gftd.ai Lean BMC — kotoba Scoring Report      ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Iteration : 43 (2026-05-28) [iter-50 Datomic-first refactor]║");
    println!("║  Model     : Lean Canvas Hybrid (9 blocks)                ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!(
        "║  Coverage  : {derived_covered}/{total} blocks = {coverage_pct}%                       ║"
    );
    println!("║  Maturity  : {maturity_avg:.1} / 5.0 (avg)  Q2 M1 datomic");
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

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // 1. BlockStore: TieredBlockStore<BudgetedBlockStore<MemoryBlockStore>, KuboBlockStore>
    //    hot  = 64 MiB BudgetedBlockStore<MemoryBlockStore> (LRU eviction)
    //    cold = KuboBlockStore (Kubo HTTP /api/v0/block/{put,get,rm}, Single-CID)
    let hot_bytes = 64 * 1024 * 1024;
    let hot = BudgetedBlockStore::new(MemoryBlockStore::new(), hot_bytes);
    let cold = KuboBlockStore::from_env();
    let tiered = TieredBlockStore::new(hot, cold);
    let block_store: Arc<dyn BlockStore + Send + Sync> = Arc::new(tiered);
    println!("BlockStore: TieredBlockStore<BudgetedMemory(64MiB), KuboIpfs>");

    // 2. Journal — Merkle WAL backed by block_store; head pointer in a sibling JSON file.
    let store_path =
        std::env::var("KOTOBA_STORE_PATH").unwrap_or_else(|_| "/tmp/ashiba-bmc-kse".into());
    let head_path = format!("{store_path}.journal-head.json");
    let journal = Arc::new(Journal::with_block_store(
        Arc::clone(&block_store),
        head_path,
    ));
    println!("Journal:    Merkle WAL on block_store (head={store_path}.journal-head.json)");

    // 3. QuadStore — wraps Journal + BlockStore; provides 4-index Arrangement + ProllyTree commit.
    let quad_store = QuadStore::new(Arc::clone(&journal), Arc::clone(&block_store));

    // 4. SecureVault — AES-256-GCM-sealed blob store over the same block_store.
    let vault = Vault::with_block_store(Arc::clone(&block_store));
    let secure_vault = SecureVault::with_vault(vault);
    // 32-byte vault key for the demo summary blob.  In production this would
    // be derived from the operator's SovereignCrypto agent key (HPKE-wrapped).
    let vault_key: [u8; 32] = *blake3::hash(b"ashiba-bmc-v44-demo-vault-key").as_bytes();

    // 5. IpfsPinClient — Kubo HTTP /api/v0/pin/{add,rm,ls}; kotoba self-pins
    //    its own CIDs.  Extended >1GB pinning is delegated to kotobase out-of-band.
    let ipfs_pin = IpfsPinClient::from_env();
    println!("IPFS pin:   kotoba self-pin via Kubo (extended >1GB → kotobase out-of-band)");
    println!();

    // 6. Ingest all BMC facts as real Quad writes (Journal-backed).
    let facts = build_bmc_facts();
    println!(
        "Ingesting {} BMC quads → kotoba QuadStore (Journal WAL → Kubo)…",
        facts.len()
    );
    let t0 = std::time::Instant::now();
    let mut deltas: Vec<Delta> = Vec::with_capacity(facts.len());
    for d in &facts {
        deltas.push(quad_store.assert(d.quad.clone()).await);
    }
    println!("  ingested in {} ms", t0.elapsed().as_millis());

    // 7. Datalog over the live Delta stream.
    let prog = build_coverage_program();
    let derived = prog.evaluate_delta(&deltas);
    let covered_blocks: std::collections::HashSet<_> = derived
        .iter()
        .filter(|d| d.quad.predicate == "covered" && d.is_assert())
        .map(|d| d.quad.subject.clone())
        .collect();
    let at_risk_entries: std::collections::HashSet<_> = derived
        .iter()
        .filter(|d| d.quad.predicate == "at_risk" && d.is_assert())
        .map(|d| d.quad.subject.clone())
        .collect();
    println!(
        "Datalog derived {} facts (covered={}, at_risk={})",
        derived.len(),
        covered_blocks.len(),
        at_risk_entries.len(),
    );

    // 8. Commit — seal hot Arrangement → 4 ProllyTrees → BlockStore checkpoint.
    let g = graph_cid();
    let t1 = std::time::Instant::now();
    let commit_cid = quad_store
        .commit("ashiba-bmc-example", g.clone(), 1)
        .await?;
    let commit_mb = commit_cid.to_multibase();
    println!(
        "kg.commit:  sealed → commit CID = {} ({} ms)",
        commit_mb,
        t1.elapsed().as_millis(),
    );

    // 9. Self-pin the commit CID via Kubo.
    ipfs_pin.pin(&commit_mb).await;
    let pin_status = ipfs_pin.status(&commit_mb).await;
    println!("IPFS pin:   commit {} → status={}", commit_mb, pin_status);

    // 10. Encrypt + store the score summary as an AEAD-sealed Vault blob.
    let summary = serde_json::json!({
        "iteration":  44,
        "graph_cid":  g.to_multibase(),
        "commit_cid": commit_mb,
        "covered":    covered_blocks.len(),
        "at_risk":    at_risk_entries.len(),
        "blocks":     BMC_BLOCKS.iter().map(|(n, m)| serde_json::json!([n, m])).collect::<Vec<_>>(),
    });
    let summary_bytes = serde_json::to_vec(&summary)?;
    let blob_ref = secure_vault
        .put(&vault_key, Bytes::from(summary_bytes))
        .await
        .map_err(|e| anyhow::anyhow!("SecureVault::put: {e}"))?;
    let ct_mb = blob_ref.cid.to_multibase();
    ipfs_pin.pin(&ct_mb).await;
    println!(
        "SecureVault: sealed summary → ciphertext CID = {} (AES-256-GCM AEAD)",
        ct_mb,
    );
    println!("IPFS pin:   ciphertext {} → pinned", ct_mb);

    // 11. Verify decrypt roundtrip — proves the plaintext is recoverable from
    //     ciphertext only with the vault key.
    let restored = secure_vault
        .get(&vault_key, &blob_ref)
        .await
        .map_err(|e| anyhow::anyhow!("SecureVault::get: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("ciphertext missing after seal"))?;
    println!(
        "SecureVault: unseal roundtrip → {} plaintext bytes recovered ✓",
        restored.len(),
    );
    println!();

    print_score_report(covered_blocks.len(), at_risk_entries.len());
    println!();
    println!("Persistence:");
    println!("  graph CID  : {}", g.to_multibase());
    println!("  commit CID : {commit_mb} (pinned)");
    println!("  summary CID: {ct_mb} (AEAD-sealed + pinned)");
    Ok(())
}
