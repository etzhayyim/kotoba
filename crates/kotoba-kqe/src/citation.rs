//! CitationLedger — tracks how often each Datom (Quad) is referenced
//! during Datalog evaluation and computes royalty distributions in mKOTO.
//!
//! Usage:
//! ```ignore
//! let mut ledger = CitationLedger::new();
//! ledger.cite(&quad_key);          // called by the Datalog engine for each join hit
//! let epoch_royalties = ledger.flush_epoch(total_pool_mkoto);
//! ```

use std::collections::HashMap;
use kotoba_core::cid::KotobaCid;
use crate::quad::{Quad, QuadObject};

/// Micro-KOTO token unit (1 KOTO = 1_000_000 mKOTO)
pub type Mkoto = u64;

/// 1 KOTO in mKOTO
pub const MKOTO_PER_KOTO: Mkoto = 1_000_000;

/// Opaque key that uniquely identifies a Datom for citation tracking.
/// Derived from the Quad's (graph, subject, predicate) triple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DatomKey(pub [u8; 36]);

impl DatomKey {
    /// Derive a DatomKey from a Quad's graph + subject CIDs and predicate string.
    pub fn from_quad(quad: &Quad) -> Self {
        let mut buf = Vec::with_capacity(72 + quad.predicate.len());
        buf.extend_from_slice(&quad.graph.0);
        buf.extend_from_slice(&quad.subject.0);
        buf.extend_from_slice(quad.predicate.as_bytes());
        let cid = KotobaCid::from_bytes(&buf);
        DatomKey(cid.0)
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
/// the ledger quads for that epoch.
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
    /// Called by the Datalog engine each time a quad is used in a join.
    pub fn cite(&mut self, key: &DatomKey) {
        *self.counts.entry(key.clone()).or_insert(0) += 1;
    }

    /// Record one citation from a Quad (derives the DatomKey automatically).
    pub fn cite_quad(&mut self, quad: &Quad) {
        let key = DatomKey::from_quad(quad);
        self.cite(&key);
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

    /// Emit ledger Quads for the given royalty entries into a named audit graph.
    ///
    /// Each entry produces two quads:
    /// - `(ledger_graph, datom_cid, "citation/count", Integer(count))`
    /// - `(ledger_graph, datom_cid, "citation/royalty_mkoto", Integer(royalty))`
    ///
    /// The `ledger_graph` CID is derived from the epoch number so it is stable
    /// and reproducible.
    pub fn royalty_quads(entries: &[RoyaltyEntry], epoch: u64) -> Vec<Quad> {
        // Stable graph CID for this epoch's ledger.
        let graph_seed = format!("kotoba/citation/ledger/epoch/{epoch}");
        let graph_cid = KotobaCid::from_bytes(graph_seed.as_bytes());

        let mut quads = Vec::with_capacity(entries.len() * 2);

        for entry in entries {
            let subject_cid = KotobaCid::from_bytes(&entry.datom_key.0);

            quads.push(Quad {
                graph: graph_cid.clone(),
                subject: subject_cid.clone(),
                predicate: "citation/count".to_string(),
                object: QuadObject::Integer(entry.citation_count as i64),
            });

            quads.push(Quad {
                graph: graph_cid.clone(),
                subject: subject_cid,
                predicate: "citation/royalty_mkoto".to_string(),
                object: QuadObject::Integer(entry.royalty_mkoto as i64),
            });
        }

        quads
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
    use kotoba_core::cid::KotobaCid;
    use crate::quad::{Quad, QuadObject};

    fn make_quad(seed: &str) -> Quad {
        Quad {
            graph:     KotobaCid::from_bytes(b"test-graph"),
            subject:   KotobaCid::from_bytes(seed.as_bytes()),
            predicate: "test/predicate".to_string(),
            object:    QuadObject::Text(seed.to_string()),
        }
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
        let q = make_quad("single");
        ledger.cite_quad(&q);
        let key = DatomKey::from_quad(&q);
        let w = ledger.citation_weight(&key);
        assert!((w - 1.0).abs() < 1e-9, "sole citation should have weight 1.0");
    }

    #[test]
    fn royalty_quads_count() {
        let mut ledger = CitationLedger::new();
        ledger.cite_quad(&make_quad("a"));
        ledger.cite_quad(&make_quad("b"));
        let epoch = ledger.epoch();
        let entries = ledger.flush_epoch(2_000_000);
        let quads = CitationLedger::royalty_quads(&entries, epoch);
        // 2 entries × 2 quads each
        assert_eq!(quads.len(), 4);
    }

    #[test]
    fn royalty_sum_never_exceeds_pool() {
        // Float truncation means individual royalties may round down.
        // The sum of all royalties must always be ≤ total_pool_mkoto.
        let mut ledger = CitationLedger::new();
        // 7 citations across 3 datoms — creates uneven fractional splits.
        for i in 0..4 { ledger.cite_quad(&make_quad(&format!("a{i}"))); }
        for i in 0..2 { ledger.cite_quad(&make_quad(&format!("b{i}"))); }
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
                "equal split expected ~500_000, got {}", e.royalty_mkoto
            );
        }
    }

    #[test]
    fn multi_epoch_counter_resets() {
        let mut ledger = CitationLedger::new();
        ledger.cite_quad(&make_quad("e1"));
        ledger.flush_epoch(1_000_000);
        assert_eq!(ledger.total_citations(), 0, "citations should reset after flush");
        assert_eq!(ledger.epoch(), 1);

        ledger.cite_quad(&make_quad("e2"));
        ledger.cite_quad(&make_quad("e2"));
        ledger.flush_epoch(1_000_000);
        assert_eq!(ledger.total_citations(), 0);
        assert_eq!(ledger.epoch(), 2, "epoch should increment on each flush");
    }
}
