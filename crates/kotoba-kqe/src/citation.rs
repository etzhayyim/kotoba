//! CitationLedger — tracks how often each Datom is referenced
//! during Datalog evaluation and computes royalty distributions in mKOTO.
//!
//! Usage:
//! ```ignore
//! let mut ledger = CitationLedger::new();
//! ledger.cite(&datom_key);         // called by the Datalog engine for each join hit
//! let epoch_royalties = ledger.flush_epoch(total_pool_mkoto);
//! ```

use crate::datom::{Datom, Value};
use crate::quad::LegacyQuad as Quad;
use kotoba_core::cid::KotobaCid;
use std::collections::HashMap;

/// Micro-KOTO token unit (1 KOTO = 1_000_000 mKOTO)
pub type Mkoto = u64;

/// 1 KOTO in mKOTO
pub const MKOTO_PER_KOTO: Mkoto = 1_000_000;

/// Opaque key that uniquely identifies a Datom for citation tracking.
/// Derived from the exact Datom `(E, A, V, T, Added)` tuple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DatomKey(pub [u8; 36]);

impl DatomKey {
    /// Derive a DatomKey from the exact Datom `(E, A, V, T, Added)` tuple.
    pub fn from_datom(datom: &Datom) -> Self {
        let mut buf = Vec::with_capacity(96 + datom.a.len());
        buf.extend_from_slice(&datom.e.0);
        buf.extend_from_slice(datom.a.as_bytes());
        buf.push(0xff);
        buf.extend_from_slice(&serde_json::to_vec(&datom.v).unwrap_or_default());
        buf.push(0xff);
        buf.extend_from_slice(&datom.tx.0);
        buf.push(u8::from(datom.op));
        let cid = KotobaCid::from_bytes(&buf);
        DatomKey(cid.0)
    }

    /// Derive a DatomKey from a legacy Quad boundary.
    pub fn from_quad(quad: &Quad) -> Self {
        Self::from_datom(&Datom::from_legacy_quad(quad.clone(), true))
    }

    /// Derive a DatomKey directly from a CID (e.g., for object references).
    pub fn from_cid(cid: &KotobaCid) -> Self {
        DatomKey(cid.0)
    }
}

/// Royalty record for a single Datom within an epoch.
#[derive(Debug, Clone)]
pub struct RoyaltyEntry {
    pub datom_key: DatomKey,
    /// Number of times this Datom was cited in the epoch.
    pub citation_count: u64,
    /// Computed royalty in mKOTO.
    pub royalty_mkoto: Mkoto,
    /// PageRank-style citation weight ∈ [0.0, 1.0].
    pub weight: f64,
}

/// Tracks citations across a single epoch and computes royalties.
///
/// An "epoch" is a bounded evaluation window (e.g., one Datalog query batch
/// or a fixed wall-clock interval). Call `flush_epoch()` to reset and emit
/// the ledger datoms for that epoch.
pub struct CitationLedger {
    /// Accumulated citation counts for the current epoch.
    counts: HashMap<DatomKey, u64>,
    /// Epoch sequence number (monotonically increasing).
    epoch: u64,
}

impl CitationLedger {
    /// Create a new empty ledger at epoch 0.
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            epoch: 0,
        }
    }

    /// Record one citation of a Datom identified by `key`.
    /// Called by the Datalog engine each time a datom is used in a join.
    pub fn cite(&mut self, key: &DatomKey) {
        *self.counts.entry(key.clone()).or_insert(0) += 1;
    }

    /// Record one citation from a Datom (derives the DatomKey automatically).
    pub fn cite_datom(&mut self, datom: &Datom) {
        let key = DatomKey::from_datom(datom);
        self.cite(&key);
    }

    /// Record one citation from a legacy Quad boundary.
    pub fn cite_quad(&mut self, quad: &Quad) {
        self.cite_datom(&Datom::from_legacy_quad(quad.clone(), true));
    }

    /// Total citation count accumulated so far in this epoch.
    pub fn total_citations(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Compute the PageRank-style citation weight for a given Datom.
    ///
    /// Weight = count / total_citations, normalized to [0.0, 1.0].
    /// Returns 0.0 if there are no citations yet.
    pub fn citation_weight(&self, key: &DatomKey) -> f64 {
        let total = self.total_citations();
        if total == 0 {
            return 0.0;
        }
        let count = self.counts.get(key).copied().unwrap_or(0);
        count as f64 / total as f64
    }

    /// Flush the current epoch: compute royalties, reset counters, increment epoch.
    ///
    /// # Parameters
    /// - `total_pool_mkoto`: total mKOTO to distribute among all cited Datoms.
    ///
    /// # Returns
    /// A `Vec<RoyaltyEntry>` with one entry per cited Datom, sorted by royalty
    /// descending.  The entries sum to ≤ `total_pool_mkoto` (rounding remainder
    /// stays in the pool).
    pub fn flush_epoch(&mut self, total_pool_mkoto: Mkoto) -> Vec<RoyaltyEntry> {
        let total_citations = self.total_citations();
        if total_citations == 0 {
            self.epoch += 1;
            return Vec::new();
        }

        let mut entries: Vec<RoyaltyEntry> = self
            .counts
            .iter()
            .map(|(key, &count)| {
                let weight = count as f64 / total_citations as f64;
                let royalty_mkoto = ((total_pool_mkoto as f64) * weight) as Mkoto;
                RoyaltyEntry {
                    datom_key: key.clone(),
                    citation_count: count,
                    royalty_mkoto,
                    weight,
                }
            })
            .collect();

        // Sort by royalty descending for deterministic ordering.
        entries.sort_by(|a, b| b.royalty_mkoto.cmp(&a.royalty_mkoto));

        // Reset for next epoch.
        self.counts.clear();
        self.epoch += 1;

        entries
    }

    /// Current epoch number (read-only).
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Emit ledger Datoms for the given royalty entries into a named audit transaction.
    ///
    /// Each entry produces two datoms:
    /// - `(datom_cid, "citation/count", Integer(count), ledger_tx, true)`
    /// - `(datom_cid, "citation/royalty_mkoto", Integer(royalty), ledger_tx, true)`
    ///
    /// The `ledger_tx` CID is derived from the epoch number so it is stable
    /// and reproducible.
    pub fn royalty_datoms(entries: &[RoyaltyEntry], epoch: u64) -> Vec<Datom> {
        let tx_seed = format!("kotoba/citation/ledger/epoch/{epoch}");
        let tx_cid = KotobaCid::from_bytes(tx_seed.as_bytes());

        let mut datoms = Vec::with_capacity(entries.len() * 2);

        for entry in entries {
            let subject_cid = KotobaCid::from_bytes(&entry.datom_key.0);
            let count_i64 = i64::try_from(entry.citation_count).unwrap_or(i64::MAX);
            let royalty_i64 = i64::try_from(entry.royalty_mkoto).unwrap_or(i64::MAX);

            datoms.push(Datom::assert(
                subject_cid.clone(),
                "citation/count".to_string(),
                Value::Integer(count_i64),
                tx_cid.clone(),
            ));

            datoms.push(Datom::assert(
                subject_cid,
                "citation/royalty_mkoto".to_string(),
                Value::Integer(royalty_i64),
                tx_cid.clone(),
            ));
        }

        datoms
    }

    /// Emit ledger Quads for legacy callers.
    pub fn royalty_quads(entries: &[RoyaltyEntry], epoch: u64) -> Vec<Quad> {
        Self::royalty_datoms(entries, epoch)
            .into_iter()
            .map(Datom::into_legacy_quad)
            .collect()
    }
}

impl Default for CitationLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject};
    use kotoba_core::cid::KotobaCid;

    fn make_quad(seed: &str) -> Quad {
        Quad {
            graph: KotobaCid::from_bytes(b"test-graph"),
            subject: KotobaCid::from_bytes(seed.as_bytes()),
            predicate: "test/predicate".to_string(),
            object: QuadObject::Text(seed.to_string()),
        }
    }

    fn make_datom(seed: &str) -> Datom {
        Datom::assert(
            KotobaCid::from_bytes(seed.as_bytes()),
            "test/predicate".to_string(),
            Value::Text(seed.to_string()),
            KotobaCid::from_bytes(b"test-tx"),
        )
    }

    #[test]
    fn cite_and_flush() {
        let mut ledger = CitationLedger::new();
        let q1 = make_quad("entity-a");
        let q2 = make_quad("entity-b");

        ledger.cite_quad(&q1);
        ledger.cite_quad(&q1);
        ledger.cite_quad(&q2);

        assert_eq!(ledger.total_citations(), 3);

        let entries = ledger.flush_epoch(1_000_000);
        assert_eq!(entries.len(), 2);
        // entity-a has 2/3 of citations → should have more royalty
        assert!(entries[0].royalty_mkoto >= entries[1].royalty_mkoto);
        // After flush, counters reset
        assert_eq!(ledger.total_citations(), 0);
        assert_eq!(ledger.epoch(), 1);
    }

    #[test]
    fn flush_empty_epoch() {
        let mut ledger = CitationLedger::new();
        let entries = ledger.flush_epoch(1_000_000);
        assert!(entries.is_empty());
        assert_eq!(ledger.epoch(), 1);
    }

    #[test]
    fn citation_weight_normalized() {
        let mut ledger = CitationLedger::new();
        let datom = make_datom("single");
        ledger.cite_datom(&datom);
        let key = DatomKey::from_datom(&datom);
        let w = ledger.citation_weight(&key);
        assert!(
            (w - 1.0).abs() < 1e-9,
            "sole citation should have weight 1.0"
        );
    }

    #[test]
    fn royalty_quads_count() {
        let mut ledger = CitationLedger::new();
        ledger.cite_datom(&make_datom("a"));
        ledger.cite_datom(&make_datom("b"));
        let epoch = ledger.epoch();
        let entries = ledger.flush_epoch(2_000_000);
        let datoms = CitationLedger::royalty_datoms(&entries, epoch);
        let quads = CitationLedger::royalty_quads(&entries, epoch);
        // 2 entries × 2 facts each.
        assert_eq!(datoms.len(), 4);
        assert_eq!(quads.len(), 4);
    }

    #[test]
    fn royalty_sum_never_exceeds_pool() {
        // Float truncation means individual royalties may round down.
        // The sum of all royalties must always be ≤ total_pool_mkoto.
        let mut ledger = CitationLedger::new();
        // 7 citations across 3 datoms — creates uneven fractional splits.
        for i in 0..4 {
            ledger.cite_quad(&make_quad(&format!("a{i}")));
        }
        for i in 0..2 {
            ledger.cite_quad(&make_quad(&format!("b{i}")));
        }
        ledger.cite_quad(&make_quad("c0"));

        let pool = 1_000_000_u64;
        let entries = ledger.flush_epoch(pool);
        let sum: u64 = entries.iter().map(|e| e.royalty_mkoto).sum();
        assert!(
            sum <= pool,
            "royalty sum {sum} must not exceed pool {pool} (float truncation invariant)"
        );
    }

    #[test]
    fn sole_citation_gets_full_pool() {
        let mut ledger = CitationLedger::new();
        ledger.cite_quad(&make_quad("only"));
        let pool = 5_000_000_u64;
        let entries = ledger.flush_epoch(pool);
        assert_eq!(entries.len(), 1);
        // 1/1 of citations → full pool (float: (5_000_000.0 * 1.0) as u64 = 5_000_000)
        assert_eq!(entries[0].royalty_mkoto, pool);
    }

    #[test]
    fn equal_citations_split_approximately_equal() {
        let mut ledger = CitationLedger::new();
        let q_a = make_quad("eq-a");
        let q_b = make_quad("eq-b");
        ledger.cite_quad(&q_a);
        ledger.cite_quad(&q_b);
        let pool = 1_000_000_u64;
        let entries = ledger.flush_epoch(pool);
        assert_eq!(entries.len(), 2);
        let sum: u64 = entries.iter().map(|e| e.royalty_mkoto).sum();
        assert!(sum <= pool, "sum must not exceed pool");
        // Each should be ~500_000; allow ±1 for integer truncation.
        for e in &entries {
            assert!(
                e.royalty_mkoto >= 499_999 && e.royalty_mkoto <= 500_001,
                "equal split expected ~500_000, got {}",
                e.royalty_mkoto
            );
        }
    }

    #[test]
    fn multi_epoch_counter_resets() {
        let mut ledger = CitationLedger::new();
        ledger.cite_quad(&make_quad("e1"));
        ledger.flush_epoch(1_000_000);
        assert_eq!(
            ledger.total_citations(),
            0,
            "citations should reset after flush"
        );
        assert_eq!(ledger.epoch(), 1);

        ledger.cite_quad(&make_quad("e2"));
        ledger.cite_quad(&make_quad("e2"));
        ledger.flush_epoch(1_000_000);
        assert_eq!(ledger.total_citations(), 0);
        assert_eq!(ledger.epoch(), 2, "epoch should increment on each flush");
    }

    // ── DatomKey pure-function tests ──────────────────────────────────────────

    #[test]
    fn datom_key_from_datom_uses_exact_five_tuple() {
        let base = make_datom("entity-x");
        let mut changed_value = base.clone();
        changed_value.v = Value::Text("other-value".to_string());
        let mut changed_tx = base.clone();
        changed_tx.tx = KotobaCid::from_bytes(b"other-tx");
        let mut changed_op = base.clone();
        changed_op.op = false;

        let base_key = DatomKey::from_datom(&base);
        assert_eq!(base_key, DatomKey::from_datom(&base));
        assert_ne!(base_key, DatomKey::from_datom(&changed_value));
        assert_ne!(base_key, DatomKey::from_datom(&changed_tx));
        assert_ne!(base_key, DatomKey::from_datom(&changed_op));
    }

    #[test]
    fn datom_key_from_quad_is_deterministic() {
        let q = make_quad("entity-x");
        let k1 = DatomKey::from_quad(&q);
        let k2 = DatomKey::from_quad(&q);
        assert_eq!(
            k1, k2,
            "DatomKey::from_quad must be deterministic for equal inputs"
        );
    }

    #[test]
    fn datom_key_from_quad_differs_by_predicate() {
        // Same graph + subject, different predicate → different key
        let mut q1 = make_quad("entity-y");
        let mut q2 = make_quad("entity-y");
        q2.predicate = "other/predicate".to_string();
        let k1 = DatomKey::from_quad(&q1);
        let k2 = DatomKey::from_quad(&q2);
        assert_ne!(
            k1, k2,
            "different predicate must produce different DatomKey"
        );

        // And also differs by subject
        q1.subject = KotobaCid::from_bytes(b"sub-a");
        q2.subject = KotobaCid::from_bytes(b"sub-b");
        q2.predicate = q1.predicate.clone();
        let k3 = DatomKey::from_quad(&q1);
        let k4 = DatomKey::from_quad(&q2);
        assert_ne!(k3, k4, "different subject must produce different DatomKey");
    }

    #[test]
    fn datom_key_from_cid_preserves_bytes() {
        let cid = KotobaCid::from_bytes(b"some-block");
        let key = DatomKey::from_cid(&cid);
        assert_eq!(
            key.0, cid.0,
            "DatomKey::from_cid must preserve the CID bytes exactly"
        );
    }

    // ── citation_weight edge cases ────────────────────────────────────────────

    #[test]
    fn citation_weight_unseen_key_returns_zero() {
        let mut ledger = CitationLedger::new();
        ledger.cite_quad(&make_quad("known"));
        let unknown_key = DatomKey::from_quad(&make_quad("unknown-entity"));
        let w = ledger.citation_weight(&unknown_key);
        assert_eq!(w, 0.0, "unseen key must have weight 0.0");
    }

    #[test]
    fn citation_weight_empty_ledger_returns_zero() {
        let ledger = CitationLedger::new();
        let key = DatomKey::from_quad(&make_quad("any"));
        assert_eq!(
            ledger.citation_weight(&key),
            0.0,
            "empty ledger total=0 → weight 0.0"
        );
    }

    // ── Default ↔ new equivalence ─────────────────────────────────────────────

    #[test]
    fn ledger_default_is_equivalent_to_new() {
        let l1 = CitationLedger::new();
        let l2 = CitationLedger::default();
        // Both should start at epoch 0 with no citations
        assert_eq!(l1.epoch(), l2.epoch());
        assert_eq!(l1.total_citations(), l2.total_citations());
    }

    // ── royalty_quads edge cases ──────────────────────────────────────────────

    #[test]
    fn royalty_quads_empty_entries_returns_empty_vec() {
        let datoms = CitationLedger::royalty_datoms(&[], 0);
        let quads = CitationLedger::royalty_quads(&[], 0);
        assert!(
            datoms.is_empty(),
            "royalty_datoms([]) must return an empty vec"
        );
        assert!(
            quads.is_empty(),
            "royalty_quads([]) must return an empty vec"
        );
    }

    #[test]
    fn royalty_quads_graph_cid_stable_per_epoch() {
        // The transaction CID for a given epoch must be identical across two calls.
        let entry = {
            let datom = make_datom("e");
            let mut ledger = CitationLedger::new();
            ledger.cite_datom(&datom);
            let epoch = ledger.epoch();
            let entries = ledger.flush_epoch(1_000_000);
            (entries, epoch)
        };
        let (entries, epoch) = entry;
        let datoms1 = CitationLedger::royalty_datoms(&entries, epoch);
        let datoms2 = CitationLedger::royalty_datoms(&entries, epoch);
        // All tx CIDs should be identical.
        for (d1, d2) in datoms1.iter().zip(datoms2.iter()) {
            assert_eq!(
                d1.tx, d2.tx,
                "transaction CID must be stable for the same epoch"
            );
        }
    }

    // ── u64→i64 saturation guards ─────────────────────────────────────────────

    #[test]
    fn royalty_quads_u64_to_i64_cast_is_safe_for_realistic_values() {
        // Realistic max: 5000 KOTO × 1_000_000 mKOTO/KOTO = 5_000_000_000
        let realistic_pool: Mkoto = 5_000 * MKOTO_PER_KOTO;
        assert!(
            realistic_pool <= i64::MAX as u64,
            "realistic royalty pool must fit in i64"
        );
        assert_eq!(
            i64::try_from(realistic_pool).unwrap(),
            realistic_pool as i64
        );
    }

    #[test]
    fn royalty_quads_saturation_on_overflow() {
        // Verify that i64::try_from(u64::MAX).unwrap_or(i64::MAX) == i64::MAX
        // (the pattern used in royalty_quads).
        assert_eq!(i64::try_from(u64::MAX).unwrap_or(i64::MAX), i64::MAX);
        // Also verify that values at i64::MAX boundary are lossless.
        assert_eq!(i64::try_from(i64::MAX as u64).unwrap(), i64::MAX);
    }

    #[test]
    fn royalty_quads_produces_integer_objects_for_count_and_royalty() {
        let mut ledger = CitationLedger::new();
        let datom = make_datom("subject-a");
        ledger.cite_datom(&datom);
        ledger.cite_datom(&datom);
        let entries = ledger.flush_epoch(1_000_000);
        let datoms = CitationLedger::royalty_datoms(&entries, 1);
        assert_eq!(datoms.len(), 2);
        assert!(datoms
            .iter()
            .all(|d| matches!(d.v, Value::Integer(n) if n >= 0)));

        let quads = CitationLedger::royalty_quads(&entries, 1);
        // Expect 2 quads per entry: citation/count and citation/royalty_mkoto
        assert_eq!(quads.len(), 2);
        let count_quad = quads
            .iter()
            .find(|q| q.predicate == "citation/count")
            .unwrap();
        let royalty_quad = quads
            .iter()
            .find(|q| q.predicate == "citation/royalty_mkoto")
            .unwrap();
        match count_quad.object {
            QuadObject::Integer(n) => assert!(n > 0, "citation count must be positive"),
            ref other => panic!("expected Integer for count, got {other:?}"),
        }
        match royalty_quad.object {
            QuadObject::Integer(n) => assert!(n >= 0, "royalty must be non-negative"),
            ref other => panic!("expected Integer for royalty, got {other:?}"),
        }
    }
}
