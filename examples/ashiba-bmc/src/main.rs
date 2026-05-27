//! ashiba.gftd.ai Lean BMC — kotoba Quad storage + Datalog coverage scoring
//!
//! This example encodes the ashiba Lean BMC as kotoba Quads, then runs
//! a DatalogProgram to compute coverage % and per-block maturity scores.
//!
//! Data source: `60-apps/ai-gftd-project-jp-ashiba/docs/bmc/ashiba-lean-bmc-v1.toml`
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
    ("problem",           2),
    ("customer_segments", 2),
    ("uvp",               2),
    ("solution",          2),
    ("channels",          2),
    ("revenue",           3),
    ("cost_structure",    2),
    ("key_metrics",       3),
    ("unfair_advantage",  1),
];

// ─────────────────────────────────────────────────────────────────────────────
// Lean hypotheses: (entry_id, block, hypothesis_text, validated)
// ─────────────────────────────────────────────────────────────────────────────

const HYPOTHESES: &[(&str, &str, &str, bool)] = &[
    ("p1", "problem", "工務店の60%以上が足場確保に3日以上かけている", false),
    ("p2", "problem", "中小足場業者の遊休在庫率は30%超", false),
    ("p3", "problem", "工務店の80%は相見積もりを3社以上から取れていない", false),
    ("cs1_cold_start", "customer_segments", "供給側50社pre-commitmentでコールドスタート解消", false),
    ("uvp1", "uvp", "「5分で足場を見つける」コピーCTR > 5%", false),
    ("r1", "revenue", "6% take rateで双方継続利用", false),
    ("ua1", "unfair_advantage", "安全チェック自動化が競合との差別化になる", false),
];

// ─────────────────────────────────────────────────────────────────────────────
// CID helper
// ─────────────────────────────────────────────────────────────────────────────

fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

fn graph_cid() -> KotobaCid { cid("bmc:ashiba:v1") }

fn quad(subject: &str, predicate: &str, object: QuadObject) -> Quad {
    Quad { graph: graph_cid(), subject: cid(subject), predicate: predicate.to_string(), object }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build BMC fact deltas
// ─────────────────────────────────────────────────────────────────────────────

fn build_bmc_facts() -> Vec<Delta> {
    let mut deltas = Vec::new();

    // bmc root
    deltas.push(Delta::assert(quad(
        "bmc:ashiba", "bmc/version", QuadObject::Text("v1".into()),
    )));
    deltas.push(Delta::assert(quad(
        "bmc:ashiba", "bmc/product", QuadObject::Text("ashiba.gftd.ai".into()),
    )));
    deltas.push(Delta::assert(quad(
        "bmc:ashiba", "bmc/model", QuadObject::Text("lean-canvas-hybrid".into()),
    )));

    // blocks: bmc/block(bmc_cid, block_name_cid) + bmc/maturity(block_cid, int)
    for (block_name, maturity) in BMC_BLOCKS {
        let block_id = format!("bmc:ashiba:block:{block_name}");

        // bmc/block relation: bmc_root → block_cid (using object as text label)
        deltas.push(Delta::assert(quad(
            "bmc:ashiba",
            "bmc/block",
            QuadObject::Cid(cid(&block_id)),
        )));

        // bmc/block_name: block_cid → name text
        deltas.push(Delta::assert(quad(
            &block_id,
            "bmc/block_name",
            QuadObject::Text(block_name.to_string()),
        )));

        // bmc/maturity: block_cid → integer
        deltas.push(Delta::assert(quad(
            &block_id,
            "bmc/maturity",
            QuadObject::Integer(*maturity),
        )));

        // each block has at least one entry (coverage = all 9 filled)
        let entry_id = format!("bmc:ashiba:entry:{block_name}:default");
        deltas.push(Delta::assert(quad(
            &entry_id,
            "entry/block",
            QuadObject::Cid(cid(&block_id)),
        )));
    }

    // hypotheses
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

// ─────────────────────────────────────────────────────────────────────────────
// Build coverage / maturity Datalog program
// ─────────────────────────────────────────────────────────────────────────────
//
// Datalog atoms are binary: (subject_cid, object_cid).
// We use kotoba-kqe's string-keyed relations where the predicate is the
// relation name, and subject/object are CIDs derived from the quad.
//
// Rules implemented:
//   covered(Block) :- entry/block(_, Block).
//   at_risk(Entry) :- bmc/hypothesis(Entry, _), bmc/validated(Entry, false).
//   below_target(Block) :- bmc/maturity(Block, M), M < 3.

fn build_coverage_program() -> DatalogProgram {
    let mut prog = DatalogProgram::new();

    // covered(Block) :- entry/block(Entry, Block).
    // i.e., for all (Entry, Block) in entry/block relation → assert covered(Block)
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

    // at_risk(Entry) :- bmc/hypothesis(Entry, Hyp), bmc/validated(Entry, False)
    // (simplified: if entry has a hypothesis quad, it's at risk until validated=true)
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
    // QuadObject::Bool serializes to cid_of_str("true"/"false") in evaluate_delta
    if b { "true".into() } else { "false".into() }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring: compute directly from BMC_BLOCKS (no Datalog needed for integers)
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
    println!("║  Iteration : 1  (2026-05-27)                             ║");
    println!("║  Model     : Lean Canvas Hybrid (9 blocks)               ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Coverage  : {derived_covered}/{total} blocks = {coverage_pct}%                       ║");
    println!("║  Maturity  : {maturity_avg:.1} / 5.0 (avg)                          ║");
    println!("║  At-Risk   : {derived_at_risk} unvalidated hypotheses                 ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Per-Block Maturity                                       ║");
    for (block, m) in BMC_BLOCKS {
        let bar = "█".repeat(*m as usize);
        let gap = "░".repeat((5 - m) as usize);
        let flag = if *m < 3 { " ← next" } else { "       " };
        println!("║  {block:<22} [{bar}{gap}] {m}/5{flag}║");
    }
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Blocks below target (< 3):                              ║");
    for b in &below_target {
        println!("║    · {b:<52}║");
    }
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Riskiest Assumptions (prioritised)                      ║");
    println!("║    1. 供給側コールドスタート (pre-commitment 50社)        ║");
    println!("║    2. 問題の深刻度 (3日超調達率 > 60%)                   ║");
    println!("║    3. Take rate 受容性 (6% @ both sides)                 ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║  Next Iteration (iter-2) Goals: maturity → 3.0           ║");
    println!("║    · 供給側 20社インタビュー → 遊休在庫率データ          ║");
    println!("║    · 需要側 20社インタビュー → 調達リードタイム          ║");
    println!("║    · LP 3パターン A/Bテスト → UVP バリデーション         ║");
    println!("║    · 仮設工業会 勉強会登壇申込                           ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let _store = Arc::new(MemoryBlockStore::new());

    // 1. Build fact deltas from BMC data
    let facts = build_bmc_facts();
    println!("Loaded {} BMC fact deltas into kotoba Quad store", facts.len());

    // 2. Build and run Datalog coverage program
    let prog = build_coverage_program();
    let derived = prog.evaluate_delta(&facts);

    // 3. Count derived facts
    let covered_count = derived.iter()
        .filter(|d| d.quad.predicate == "covered" && d.is_assert())
        .count();
    // Deduplicate by subject CID (one block may derive covered multiple times)
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

    // 4. Print scored report
    println!();
    print_score_report(covered_blocks.len(), at_risk_entries.len());

    Ok(())
}
