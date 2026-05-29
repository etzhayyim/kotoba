//! IVF (Inverted File) flat index — pure Rust, no external vector DB.
//!
//! Algorithm: farthest-first centroid initialization + Lloyd's iteration.
//! ANN search: probe `nprobe` nearest centroids, collect candidates, re-rank by cosine.
//!
//! Persistence: IvfIndex <-> QuadStore via `to_quads()` / `from_quads()`.
//! Centroid quads live in the cc:2026-12:chunks named graph with predicates:
//!   cc/ivf/centroid_id  — Integer(k)
//!   cc/ivf/vector       — VectorF32(dim)
//!   cc/ivf/model        — Text(model_id)
//!   cc/ivf/k            — Integer(total_k)
//!   cc/ivf/n            — Integer(member_count)

use kotoba_core::cid::KotobaCid;
use kotoba_kqe::datom::{Datom, Value};
use kotoba_kqe::quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Squared L2 distance between two equal-length slices.
fn l2_sq(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y) * (x - y)).sum()
}

/// Cosine similarity.  Returns 0.0 if either vector is zero-norm.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

// ---------------------------------------------------------------------------
// IvfIndex
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct IvfIndex {
    k: usize,
    dim: usize,
    centroids: Vec<Vec<f32>>,
    model_id: String,
}

impl IvfIndex {
    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn k(&self) -> usize {
        self.k
    }
    pub fn dim(&self) -> usize {
        self.dim
    }

    // -----------------------------------------------------------------------
    // Build
    // -----------------------------------------------------------------------

    /// Build an IVF index from `embeddings` using farthest-first init + Lloyd's.
    ///
    /// * `k`        — number of clusters (clamped to `embeddings.len()`)
    /// * `model_id` — recorded in the index for provenance
    /// * `max_iter` — Lloyd iteration limit
    pub fn build(
        embeddings: &[(KotobaCid, Vec<f32>)],
        k: usize,
        model_id: &str,
        max_iter: usize,
    ) -> Self {
        assert!(!embeddings.is_empty(), "embeddings must not be empty");
        let n = embeddings.len();
        let k = k.min(n);
        let dim = embeddings[0].1.len();

        // --- farthest-first centroid initialisation ---
        let mut centroids: Vec<Vec<f32>> = Vec::with_capacity(k);
        // First centroid: always index 0 (deterministic).
        centroids.push(embeddings[0].1.clone());

        for _ in 1..k {
            // Pick the point with the largest minimum distance to existing centroids.
            let next = (0..n)
                .max_by(|&i, &j| {
                    let di = centroids
                        .iter()
                        .map(|c| l2_sq(&embeddings[i].1, c))
                        .fold(f32::INFINITY, f32::min);
                    let dj = centroids
                        .iter()
                        .map(|c| l2_sq(&embeddings[j].1, c))
                        .fold(f32::INFINITY, f32::min);
                    di.partial_cmp(&dj).unwrap_or(std::cmp::Ordering::Equal)
                })
                .unwrap_or(0);
            centroids.push(embeddings[next].1.clone());
        }

        // --- Lloyd's iteration ---
        let mut assignments = vec![0usize; n];
        for _ in 0..max_iter {
            // Assignment step.
            let mut changed = false;
            for (i, (_, v)) in embeddings.iter().enumerate() {
                let (best, _) = Self::assign_to(&centroids, v);
                if assignments[i] != best {
                    assignments[i] = best;
                    changed = true;
                }
            }
            if !changed {
                break;
            }

            // Update step: recompute each centroid as the mean of its members.
            let mut sums: Vec<Vec<f32>> = vec![vec![0.0f32; dim]; k];
            let mut counts: Vec<usize> = vec![0usize; k];
            for (i, (_, v)) in embeddings.iter().enumerate() {
                let ci = assignments[i];
                counts[ci] += 1;
                for (d, x) in sums[ci].iter_mut().zip(v.iter()) {
                    *d += x;
                }
            }
            for ci in 0..k {
                if counts[ci] > 0 {
                    for d in sums[ci].iter_mut() {
                        *d /= counts[ci] as f32;
                    }
                    centroids[ci] = sums[ci].clone();
                }
                // If a cluster is empty, its centroid stays unchanged (farthest-first
                // init makes this rare).
            }
        }

        Self {
            k,
            dim,
            centroids,
            model_id: model_id.to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Internal assignment helper (static, works on an arbitrary centroid slice)
    // -----------------------------------------------------------------------

    fn assign_to(centroids: &[Vec<f32>], v: &[f32]) -> (usize, f32) {
        centroids
            .iter()
            .enumerate()
            .map(|(i, c)| (i, l2_sq(v, c)))
            .min_by(|(_, da), (_, db)| da.partial_cmp(db).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or((0, f32::INFINITY))
    }

    // -----------------------------------------------------------------------
    // Public query API
    // -----------------------------------------------------------------------

    /// Return `(centroid_idx, l2_squared_distance)` for the nearest centroid.
    pub fn assign(&self, v: &[f32]) -> (usize, f32) {
        Self::assign_to(&self.centroids, v)
    }

    /// Return the indices of the `nprobe` nearest centroids, sorted by distance (closest first).
    pub fn nearest_centroids(&self, query: &[f32], nprobe: usize) -> Vec<usize> {
        let nprobe = nprobe.min(self.k);
        let mut dists: Vec<(usize, f32)> = self
            .centroids
            .iter()
            .enumerate()
            .map(|(i, c)| (i, l2_sq(query, c)))
            .collect();
        dists.sort_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        dists.into_iter().take(nprobe).map(|(i, _)| i).collect()
    }

    /// ANN search.
    ///
    /// `candidates` is a slice of `(centroid_idx, embedding)` pairs (pre-filtered by
    /// the caller to those belonging to the `nprobe` nearest centroids).
    /// Returns up to `top_k` results as `(cosine_score, candidate_index)` sorted
    /// by score descending.
    pub fn search(
        &self,
        query: &[f32],
        candidates: &[(usize, &[f32])],
        nprobe: usize,
        top_k: usize,
    ) -> Vec<(f32, usize)> {
        let probe_set: std::collections::HashSet<usize> =
            self.nearest_centroids(query, nprobe).into_iter().collect();

        let mut scores: Vec<(f32, usize)> = candidates
            .iter()
            .enumerate()
            .filter(|(_, (ci, _))| probe_set.contains(ci))
            .map(|(idx, (_, v))| (cosine(query, v), idx))
            .collect();

        scores.sort_by(|(a, _), (b, _)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(top_k);
        scores
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    /// Serialise centroids into quads stored in `graph_cid`.
    ///
    /// Each centroid `k_idx` produces a cluster of quads sharing the subject
    /// `KotobaCid::from_bytes(b"ivf-centroid:{k_idx}")`.
    pub fn to_quads(&self, graph_cid: &KotobaCid, member_counts: &[usize]) -> Vec<Quad> {
        let mut quads = Vec::with_capacity(self.k * 5);
        for (k_idx, centroid) in self.centroids.iter().enumerate() {
            let subject = KotobaCid::from_bytes(format!("ivf-centroid:{}", k_idx).as_bytes());
            let n = member_counts.get(k_idx).copied().unwrap_or(0);

            quads.push(Quad {
                graph: graph_cid.clone(),
                subject: subject.clone(),
                predicate: "cc/ivf/centroid_id".to_string(),
                object: QuadObject::Integer(k_idx as i64),
            });
            quads.push(Quad {
                graph: graph_cid.clone(),
                subject: subject.clone(),
                predicate: "cc/ivf/vector".to_string(),
                object: QuadObject::VectorF32(centroid.clone()),
            });
            quads.push(Quad {
                graph: graph_cid.clone(),
                subject: subject.clone(),
                predicate: "cc/ivf/model".to_string(),
                object: QuadObject::Text(self.model_id.clone()),
            });
            quads.push(Quad {
                graph: graph_cid.clone(),
                subject: subject.clone(),
                predicate: "cc/ivf/k".to_string(),
                object: QuadObject::Integer(self.k as i64),
            });
            quads.push(Quad {
                graph: graph_cid.clone(),
                subject: subject.clone(),
                predicate: "cc/ivf/n".to_string(),
                object: QuadObject::Integer(n as i64),
            });
        }
        quads
    }

    /// Restore an `IvfIndex` from a flat slice of quads.
    ///
    /// Expects quads produced by `to_quads`.  Returns `None` if the quads are
    /// insufficient to reconstruct a valid index.
    pub fn from_quads(quads: &[Quad]) -> Option<Self> {
        use std::collections::BTreeMap;

        // Group quads by centroid_id → vector + model.
        let mut id_to_vector: BTreeMap<i64, Vec<f32>> = BTreeMap::new();
        let mut model_id = String::new();
        let mut total_k: Option<i64> = None;

        for q in quads {
            match q.predicate.as_str() {
                "cc/ivf/centroid_id" => {
                    // Just a marker; actual index is the integer value.
                    if let QuadObject::Integer(id) = &q.object {
                        id_to_vector.entry(*id).or_default();
                    }
                }
                "cc/ivf/vector" => {
                    if let QuadObject::VectorF32(v) = &q.object {
                        // Derive the centroid index from the subject CID by
                        // matching any already-seen centroid_id quad with the
                        // same subject.
                        let key = subject_to_centroid_id(&q.subject)?;
                        id_to_vector.insert(key, v.clone());
                    }
                }
                "cc/ivf/model" => {
                    if let QuadObject::Text(m) = &q.object {
                        model_id = m.clone();
                    }
                }
                "cc/ivf/k" => {
                    if let QuadObject::Integer(v) = &q.object {
                        total_k = Some(*v);
                    }
                }
                _ => {}
            }
        }

        let k = total_k.unwrap_or(id_to_vector.len() as i64) as usize;
        if id_to_vector.is_empty() {
            return None;
        }

        // Reconstruct centroids ordered by id.
        let centroids: Vec<Vec<f32>> = id_to_vector.into_values().collect();
        let dim = centroids.first()?.len();
        if dim == 0 {
            return None;
        }

        Some(Self {
            k: k.max(centroids.len()),
            dim,
            centroids,
            model_id,
        })
    }

    /// Restore an `IvfIndex` from Datomic atomic facts.
    ///
    /// This is the Datom-native counterpart to `from_quads`; legacy Quad
    /// restoration is kept only for compatibility with older persisted data.
    pub fn from_datoms(datoms: &[Datom]) -> Option<Self> {
        use std::collections::BTreeMap;

        let mut id_to_vector: BTreeMap<i64, Vec<f32>> = BTreeMap::new();
        let mut model_id = String::new();
        let mut total_k: Option<i64> = None;

        for datom in datoms.iter().filter(|d| d.op) {
            match datom.a.as_str() {
                "cc/ivf/centroid_id" => {
                    if let Value::Integer(id) = &datom.v {
                        id_to_vector.entry(*id).or_default();
                    }
                }
                "cc/ivf/vector" => {
                    if let Value::VectorF32(v) = &datom.v {
                        let key = subject_to_centroid_id(&datom.e)?;
                        id_to_vector.insert(key, v.clone());
                    }
                }
                "cc/ivf/model" => {
                    if let Value::Text(m) = &datom.v {
                        model_id = m.clone();
                    }
                }
                "cc/ivf/k" => {
                    if let Value::Integer(v) = &datom.v {
                        total_k = Some(*v);
                    }
                }
                _ => {}
            }
        }

        let k = total_k.unwrap_or(id_to_vector.len() as i64) as usize;
        if id_to_vector.is_empty() {
            return None;
        }

        let centroids: Vec<Vec<f32>> = id_to_vector.into_values().collect();
        let dim = centroids.first()?.len();
        if dim == 0 {
            return None;
        }

        Some(Self {
            k: k.max(centroids.len()),
            dim,
            centroids,
            model_id,
        })
    }
}

/// Extract the integer centroid id encoded in `"ivf-centroid:{id}"` subject CID.
///
/// The subject is produced by `KotobaCid::from_bytes(b"ivf-centroid:{id}")`,
/// so we rehash candidate ids until we find a match (ids are small: 0..k).
fn subject_to_centroid_id(subject: &KotobaCid) -> Option<i64> {
    // Brute-force up to 65 536 centroids — more than any realistic IVF index.
    for id in 0i64..65_536 {
        let candidate = KotobaCid::from_bytes(format!("ivf-centroid:{}", id).as_bytes());
        if candidate == *subject {
            return Some(id);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate `n` 2-D points in two well-separated clusters:
    ///   cluster 0 centred at (10, 0), cluster 1 at (-10, 0).
    fn two_cluster_points(n: usize) -> Vec<(KotobaCid, Vec<f32>)> {
        (0..n)
            .map(|i| {
                let offset = (i % 5) as f32 * 0.1;
                let v = if i % 2 == 0 {
                    vec![10.0 + offset, offset]
                } else {
                    vec![-10.0 - offset, offset]
                };
                let cid = KotobaCid::from_bytes(format!("pt-{}", i).as_bytes());
                (cid, v)
            })
            .collect()
    }

    #[test]
    fn build_and_assign_basic() {
        let pts = two_cluster_points(100);
        let idx = IvfIndex::build(&pts, 2, "test-model", 50);
        assert_eq!(idx.k(), 2);
        assert_eq!(idx.dim(), 2);

        // The two centroids should be on opposite sides of the x-axis.
        let c0 = &idx.centroids[0];
        let c1 = &idx.centroids[1];
        // One centroid x > 5, the other x < -5.
        let xs: Vec<f32> = vec![c0[0], c1[0]];
        assert!(
            xs.iter().any(|&x| x > 5.0),
            "expected a centroid near (10, 0)"
        );
        assert!(
            xs.iter().any(|&x| x < -5.0),
            "expected a centroid near (-10, 0)"
        );

        // Every even-indexed point should land in the centroid with positive x.
        let pos_ci = if c0[0] > 0.0 { 0 } else { 1 };
        let neg_ci = 1 - pos_ci;
        for (i, (_, v)) in pts.iter().enumerate() {
            let (ci, _) = idx.assign(v);
            if i % 2 == 0 {
                assert_eq!(ci, pos_ci, "even point {} should be in positive cluster", i);
            } else {
                assert_eq!(ci, neg_ci, "odd point {} should be in negative cluster", i);
            }
        }
    }

    #[test]
    fn search_returns_top_k() {
        let pts = two_cluster_points(50);
        // Build index.
        let idx = IvfIndex::build(&pts, 2, "test-model", 30);

        // Build a candidate list: (centroid_idx, embedding).
        // We must store the vecs so we can take slices of them.
        let assigned: Vec<(usize, Vec<f32>)> = pts
            .iter()
            .map(|(_, v)| {
                let (ci, _) = idx.assign(v);
                (ci, v.clone())
            })
            .collect();
        let cand_refs: Vec<(usize, &[f32])> =
            assigned.iter().map(|(ci, v)| (*ci, v.as_slice())).collect();

        let query = vec![10.0f32, 0.0];
        let result = idx.search(&query, &cand_refs, 2, 5);
        assert_eq!(result.len(), 5);

        // Scores should be in [0, 1] for non-negative vectors.
        for (score, _) in &result {
            assert!(
                *score >= -1.0 && *score <= 1.0,
                "cosine score out of range: {}",
                score
            );
        }

        // Results should be sorted descending.
        for w in result.windows(2) {
            assert!(w[0].0 >= w[1].0, "results not sorted descending");
        }
    }

    #[test]
    fn to_quads_and_from_quads_roundtrip() {
        let pts = two_cluster_points(20);
        let idx = IvfIndex::build(&pts, 2, "round-trip-model", 20);

        let graph = KotobaCid::from_bytes(b"test-graph");
        let counts = vec![10usize, 10];
        let quads = idx.to_quads(&graph, &counts);

        // Sanity: should produce 5 quads per centroid.
        assert_eq!(quads.len(), 2 * 5);

        let restored = IvfIndex::from_quads(&quads).expect("from_quads must succeed");
        assert_eq!(restored.k(), idx.k());
        assert_eq!(restored.dim(), idx.dim());
        assert_eq!(restored.model_id, idx.model_id);

        // Centroid values should be identical within f32 tolerance.
        for (orig, rest) in idx.centroids.iter().zip(restored.centroids.iter()) {
            for (a, b) in orig.iter().zip(rest.iter()) {
                assert!(
                    (a - b).abs() < 1e-6,
                    "centroid component mismatch: {} vs {}",
                    a,
                    b
                );
            }
        }
    }

    #[test]
    fn to_quads_and_from_datoms_roundtrip() {
        let pts = two_cluster_points(20);
        let idx = IvfIndex::build(&pts, 2, "round-trip-model", 20);

        let graph = KotobaCid::from_bytes(b"test-graph");
        let counts = vec![10usize, 10];
        let quads = idx.to_quads(&graph, &counts);
        let datoms: Vec<_> = quads
            .into_iter()
            .map(|quad| kotoba_kqe::datom::Datom::from_legacy_quad(quad, true))
            .collect();

        let restored = IvfIndex::from_datoms(&datoms).expect("from_datoms must succeed");
        assert_eq!(restored.k(), idx.k());
        assert_eq!(restored.dim(), idx.dim());
        assert_eq!(restored.model_id, idx.model_id);

        for (orig, rest) in idx.centroids.iter().zip(restored.centroids.iter()) {
            for (a, b) in orig.iter().zip(rest.iter()) {
                assert!((a - b).abs() < 1e-6);
            }
        }
    }

    #[test]
    fn nearest_centroids_sorted() {
        let pts = two_cluster_points(10);
        let idx = IvfIndex::build(&pts, 2, "m", 10);
        let near = idx.nearest_centroids(&[10.0, 0.0], 2);
        assert_eq!(near.len(), 2);
        // The nearest centroid should be the positive-x one.
        let c_near = &idx.centroids[near[0]];
        assert!(c_near[0] > 0.0, "nearest centroid should have positive x");
    }

    #[test]
    fn l2_sq_zero() {
        let a = vec![1.0f32, 2.0, 3.0];
        assert_eq!(l2_sq(&a, &a), 0.0);
    }

    #[test]
    fn cosine_identical() {
        let a = vec![1.0f32, 0.0, 0.0];
        assert!((cosine(&a, &a) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_orthogonal() {
        let a = vec![1.0f32, 0.0];
        let b = vec![0.0f32, 1.0];
        assert!((cosine(&a, &b)).abs() < 1e-6);
    }

    #[test]
    fn cosine_zero_vector() {
        let a = vec![1.0f32, 2.0];
        let z = vec![0.0f32, 0.0];
        assert_eq!(cosine(&a, &z), 0.0);
        assert_eq!(cosine(&z, &z), 0.0);
    }

    // ---- New tests --------------------------------------------------------

    #[test]
    fn l2_sq_known_value() {
        // (3,4) vs (0,0) → 9 + 16 = 25
        let a = vec![3.0f32, 4.0];
        let b = vec![0.0f32, 0.0];
        assert!((l2_sq(&a, &b) - 25.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_opposite_vectors() {
        let a = vec![1.0f32, 0.0];
        let b = vec![-1.0f32, 0.0];
        assert!(
            (cosine(&a, &b) + 1.0).abs() < 1e-6,
            "opposite vectors: cosine = -1"
        );
    }

    #[test]
    fn build_k_clamped_to_n() {
        // Requesting more clusters than points: k must be clamped to n.
        let pts: Vec<(KotobaCid, Vec<f32>)> = (0..3u8)
            .map(|i| (KotobaCid::from_bytes(&[i]), vec![i as f32, 0.0]))
            .collect();
        let idx = IvfIndex::build(&pts, 100, "clamp-model", 5);
        assert_eq!(idx.k(), 3, "k must be clamped to number of embeddings");
    }

    #[test]
    fn build_k_equals_one() {
        let pts = vec![(KotobaCid::from_bytes(b"single"), vec![1.0f32, 2.0, 3.0])];
        let idx = IvfIndex::build(&pts, 1, "singleton", 5);
        assert_eq!(idx.k(), 1);
        assert_eq!(idx.dim(), 3);
        let (ci, dist) = idx.assign(&[1.0, 2.0, 3.0]);
        assert_eq!(ci, 0);
        assert!(
            dist < 1e-6,
            "assign to self should have zero l2_sq distance"
        );
    }

    #[test]
    fn nearest_centroids_nprobe_clamped_to_k() {
        let pts = two_cluster_points(10);
        let idx = IvfIndex::build(&pts, 2, "m", 5);
        // Requesting more probes than clusters: result length ≤ k.
        let near = idx.nearest_centroids(&[10.0f32, 0.0], 100);
        assert!(near.len() <= idx.k(), "nprobe must be clamped to k");
    }

    #[test]
    fn from_quads_empty_returns_none() {
        assert!(
            IvfIndex::from_quads(&[]).is_none(),
            "empty quads must return None"
        );
    }

    #[test]
    fn search_top_k_clamped_by_candidate_count() {
        let pts = two_cluster_points(6);
        let idx = IvfIndex::build(&pts, 2, "m", 10);
        let assigned: Vec<(usize, Vec<f32>)> = pts
            .iter()
            .map(|(_, v)| {
                let (ci, _) = idx.assign(v);
                (ci, v.clone())
            })
            .collect();
        let cand_refs: Vec<(usize, &[f32])> =
            assigned.iter().map(|(ci, v)| (*ci, v.as_slice())).collect();
        // Ask for more results than candidates.
        let result = idx.search(&[10.0f32, 0.0], &cand_refs, 2, 1000);
        assert!(
            result.len() <= cand_refs.len(),
            "search cannot return more results than candidates"
        );
    }

    #[test]
    fn to_quads_produces_correct_predicates() {
        let pts = two_cluster_points(10);
        let idx = IvfIndex::build(&pts, 2, "pred-model", 10);
        let graph = KotobaCid::from_bytes(b"g");
        let quads = idx.to_quads(&graph, &[5, 5]);
        // Each centroid produces 5 quads: centroid_id, vector, model, k, n.
        let predicates: std::collections::HashSet<_> =
            quads.iter().map(|q| q.predicate.as_str()).collect();
        for p in &[
            "cc/ivf/centroid_id",
            "cc/ivf/vector",
            "cc/ivf/model",
            "cc/ivf/k",
            "cc/ivf/n",
        ] {
            assert!(predicates.contains(p), "missing predicate: {p}");
        }
    }
}
