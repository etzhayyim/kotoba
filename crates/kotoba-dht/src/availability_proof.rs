//! Availability Proofs — epoch-based storage reliability verification.
//!
//! Each epoch a `AvailabilityChallenge` is broadcast via GossipSub.
//! Nodes respond with an `AvailabilityProof`.  The verifier scores the
//! proof and decides whether to trigger a reward or slash.
//!
//! Score thresholds:
//! - score ≥ 0.80 → `eligible_for_reward()`
//! - score < 0.50 → `trigger_slash()`

use serde::{Deserialize, Serialize};

/// A storage-availability challenge broadcast during an epoch.
///
/// The challenger selects a random subset of CIDs that the target node
/// should be storing and asks it to prove possession by returning blake3
/// hashes of the raw block bytes.
///
/// CID bytes are stored as `Vec<u8>` (36 bytes each) for serde compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityChallenge {
    /// Monotonically-increasing epoch counter (matches GossipSub epoch).
    pub epoch: u64,
    /// The peer being challenged (libp2p PeerId bytes).
    pub target_peer: Vec<u8>,
    /// CID bytes (36-byte KotobaCid each) of blocks to prove.
    pub challenge_cids: Vec<Vec<u8>>,
    /// Unix timestamp when this challenge expires (seconds).
    pub expires_at: u64,
}

/// A single entry in the availability proof: the blake3 hash of the
/// block identified by `cid_bytes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEntry {
    /// 36-byte KotobaCid of the block (as Vec<u8>).
    pub cid_bytes: Vec<u8>,
    /// blake3 hash of the raw block content (32 bytes).
    pub content_hash: Vec<u8>,
}

/// An availability proof submitted in response to an `AvailabilityChallenge`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityProof {
    /// Epoch this proof responds to.
    pub epoch: u64,
    /// The proving peer (libp2p PeerId bytes).
    pub prover_peer: Vec<u8>,
    /// One entry per challenged CID.
    pub entries: Vec<ProofEntry>,
    /// Ed25519 signature over (epoch ‖ prover_peer ‖ entries_hash).
    pub signature: Vec<u8>,
}

/// The outcome of verifying an `AvailabilityProof` against its challenge.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub epoch: u64,
    pub prover_peer: Vec<u8>,
    /// Fraction of challenged blocks correctly proven ∈ [0.0, 1.0].
    pub score: f64,
    /// Total blocks challenged.
    pub challenged: usize,
    /// Blocks correctly proven.
    pub proven: usize,
}

impl VerificationResult {
    /// Returns `true` when the prover qualifies for an epoch reward.
    /// Threshold: score ≥ 0.80.
    pub fn eligible_for_reward(&self) -> bool {
        self.score >= 0.80
    }

    /// Returns `true` when a slash should be triggered for poor availability.
    /// Threshold: score < 0.50.
    pub fn trigger_slash(&self) -> bool {
        self.score < 0.50
    }
}

/// Verify an `AvailabilityProof` against the original `AvailabilityChallenge`.
///
/// For each challenged CID, the verifier re-computes the expected blake3 hash
/// from the locally-stored block bytes (`expected_hashes`) and compares it to
/// the prover's answer.  Missing or incorrect entries count against the score.
///
/// # Parameters
/// - `challenge`: the original challenge.
/// - `proof`: the prover's response.
/// - `expected_hashes`: blake3 hashes of the locally-held block bytes, in the
///   same order as `challenge.challenge_cids`.  Pass `None` for a CID when the
///   verifier itself does not hold the block (those are excluded from scoring).
///
/// # Returns
/// `None` if the epoch or peer identity does not match.
pub fn verify_proof(
    challenge: &AvailabilityChallenge,
    proof: &AvailabilityProof,
    expected_hashes: &[Option<Vec<u8>>],
) -> Option<VerificationResult> {
    // Basic sanity: epoch + peer must match.
    if proof.epoch != challenge.epoch {
        return None;
    }
    if proof.prover_peer != challenge.target_peer {
        return None;
    }

    // Build a lookup from CID bytes → prover's supplied hash.
    let proof_map: std::collections::HashMap<&[u8], &[u8]> = proof
        .entries
        .iter()
        .map(|e| (e.cid_bytes.as_slice(), e.content_hash.as_slice()))
        .collect();

    let mut challenged = 0usize;
    let mut proven = 0usize;

    for (cid, maybe_expected) in challenge.challenge_cids.iter().zip(expected_hashes.iter()) {
        let expected = match maybe_expected {
            Some(h) => h,
            None => continue, // verifier doesn't hold this block; skip
        };
        challenged += 1;

        if let Some(supplied) = proof_map.get(cid.as_slice()) {
            if *supplied == expected.as_slice() {
                proven += 1;
            }
        }
    }

    let score = if challenged == 0 {
        1.0 // vacuously proven (no checkable blocks)
    } else {
        proven as f64 / challenged as f64
    };

    Some(VerificationResult {
        epoch: challenge.epoch,
        prover_peer: proof.prover_peer.clone(),
        score,
        challenged,
        proven,
    })
}

/// Compute the blake3 hash of a block's raw bytes, suitable for inclusion in
/// a `ProofEntry`.
pub fn hash_block(block_bytes: &[u8]) -> Vec<u8> {
    blake3::hash(block_bytes).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cid(seed: u8) -> Vec<u8> {
        let mut v = vec![0u8; 36];
        v[0] = 0x01; // CIDv1 marker
        v[4] = seed;
        v
    }

    fn make_challenge(cids: Vec<Vec<u8>>) -> AvailabilityChallenge {
        AvailabilityChallenge {
            epoch: 1,
            target_peer: vec![0u8; 32],
            challenge_cids: cids,
            expires_at: u64::MAX,
        }
    }

    fn make_proof(epoch: u64, entries: Vec<ProofEntry>) -> AvailabilityProof {
        AvailabilityProof {
            epoch,
            prover_peer: vec![0u8; 32],
            entries,
            signature: vec![],
        }
    }

    #[test]
    fn perfect_score() {
        let block = b"hello world";
        let h = hash_block(block);
        let cid = make_cid(1);

        let challenge = make_challenge(vec![cid.clone()]);
        let proof = make_proof(1, vec![ProofEntry { cid_bytes: cid, content_hash: h.clone() }]);
        let result = verify_proof(&challenge, &proof, &[Some(h)]).unwrap();

        assert_eq!(result.score, 1.0);
        assert!(result.eligible_for_reward());
        assert!(!result.trigger_slash());
    }

    #[test]
    fn zero_score_triggers_slash() {
        let cid = make_cid(2);
        let expected = vec![0xAAu8; 32];
        let wrong    = vec![0xBBu8; 32];

        let challenge = make_challenge(vec![cid.clone()]);
        let proof = make_proof(1, vec![ProofEntry { cid_bytes: cid, content_hash: wrong }]);
        let result = verify_proof(&challenge, &proof, &[Some(expected)]).unwrap();

        assert_eq!(result.score, 0.0);
        assert!(result.trigger_slash());
        assert!(!result.eligible_for_reward());
    }

    #[test]
    fn epoch_mismatch_returns_none() {
        let challenge = make_challenge(vec![]);
        let proof = make_proof(99, vec![]);
        assert!(verify_proof(&challenge, &proof, &[]).is_none());
    }

    #[test]
    fn vacuous_proof_scores_1() {
        // All expected hashes are None → verifier has no blocks to check.
        let cid = make_cid(3);
        let challenge = make_challenge(vec![cid]);
        let proof = make_proof(1, vec![]);
        let result = verify_proof(&challenge, &proof, &[None]).unwrap();
        assert_eq!(result.score, 1.0);
        assert!(result.eligible_for_reward());
    }

    #[test]
    fn partial_score_no_slash_no_reward() {
        // 60% proven → no slash (≥ 0.50), no reward (< 0.80)
        let cids: Vec<Vec<u8>> = (0..5).map(make_cid).collect();
        let hashes: Vec<Vec<u8>> = cids.iter().map(|c| hash_block(c)).collect();

        // Only prove first 3 out of 5
        let entries: Vec<ProofEntry> = cids[..3]
            .iter()
            .zip(hashes[..3].iter())
            .map(|(c, h)| ProofEntry { cid_bytes: c.clone(), content_hash: h.clone() })
            .collect();

        let challenge = make_challenge(cids);
        let proof = make_proof(1, entries);
        let expected: Vec<Option<Vec<u8>>> = hashes.into_iter().map(Some).collect();
        let result = verify_proof(&challenge, &proof, &expected).unwrap();

        assert!((result.score - 0.6).abs() < 1e-9);
        assert!(!result.trigger_slash());
        assert!(!result.eligible_for_reward());
    }

    #[test]
    fn peer_mismatch_returns_none() {
        let mut challenge = make_challenge(vec![]);
        challenge.target_peer = vec![0xAAu8; 32];
        let mut proof = make_proof(1, vec![]);
        proof.prover_peer = vec![0xBBu8; 32]; // different peer
        assert!(verify_proof(&challenge, &proof, &[]).is_none());
    }

    #[test]
    fn hash_block_empty_returns_32_bytes() {
        let h = hash_block(b"");
        assert_eq!(h.len(), 32, "blake3 hash must always be 32 bytes");
    }

    #[test]
    fn hash_block_is_deterministic() {
        let data = b"reproducible block content";
        let h1 = hash_block(data);
        let h2 = hash_block(data);
        assert_eq!(h1, h2, "hash_block must be deterministic");
    }

    #[test]
    fn score_exactly_0_8_is_eligible_not_slash() {
        // 4 of 5 correct → score = 0.8 → eligible_for_reward, not trigger_slash
        let cids: Vec<Vec<u8>> = (0..5).map(make_cid).collect();
        let hashes: Vec<Vec<u8>> = cids.iter().map(|c| hash_block(c)).collect();

        let entries: Vec<ProofEntry> = cids[..4]
            .iter()
            .zip(hashes[..4].iter())
            .map(|(c, h)| ProofEntry { cid_bytes: c.clone(), content_hash: h.clone() })
            .collect();

        let challenge = make_challenge(cids);
        let proof = make_proof(1, entries);
        let expected: Vec<Option<Vec<u8>>> = hashes.into_iter().map(Some).collect();
        let result = verify_proof(&challenge, &proof, &expected).unwrap();

        assert!((result.score - 0.8).abs() < 1e-9);
        assert!(result.eligible_for_reward(), "score=0.8 must be eligible");
        assert!(!result.trigger_slash(), "score=0.8 must not slash");
    }

    #[test]
    fn score_exactly_0_5_no_slash_no_reward() {
        // 1 of 2 correct → score = 0.5 → no slash (< 0.50 required), no reward (< 0.80)
        let cids: Vec<Vec<u8>> = (0..2).map(make_cid).collect();
        let hashes: Vec<Vec<u8>> = cids.iter().map(|c| hash_block(c)).collect();

        let entries: Vec<ProofEntry> = vec![
            ProofEntry { cid_bytes: cids[0].clone(), content_hash: hashes[0].clone() },
        ];

        let challenge = make_challenge(cids);
        let proof = make_proof(1, entries);
        let expected: Vec<Option<Vec<u8>>> = hashes.into_iter().map(Some).collect();
        let result = verify_proof(&challenge, &proof, &expected).unwrap();

        assert!((result.score - 0.5).abs() < 1e-9);
        assert!(!result.trigger_slash(), "score=0.5 must not trigger slash (threshold is < 0.50)");
        assert!(!result.eligible_for_reward(), "score=0.5 must not be eligible for reward");
    }

    #[test]
    fn extra_proof_entries_not_in_challenge_are_ignored() {
        let cid = make_cid(10);
        let h = hash_block(&cid);
        let challenge = make_challenge(vec![cid.clone()]);
        let extra_cid = make_cid(99);
        let proof = make_proof(1, vec![
            ProofEntry { cid_bytes: cid,       content_hash: h.clone() },
            ProofEntry { cid_bytes: extra_cid, content_hash: vec![0u8; 32] }, // extra — not in challenge
        ]);
        let result = verify_proof(&challenge, &proof, &[Some(h)]).unwrap();
        assert_eq!(result.score, 1.0, "extra entries must not degrade score");
        assert_eq!(result.challenged, 1);
        assert_eq!(result.proven, 1);
    }

    #[test]
    fn proof_entry_clone_is_equal() {
        let entry = ProofEntry { cid_bytes: vec![1, 2, 3], content_hash: vec![4, 5, 6] };
        let cloned = entry.clone();
        assert_eq!(entry.cid_bytes, cloned.cid_bytes);
        assert_eq!(entry.content_hash, cloned.content_hash);
    }

    #[test]
    fn proof_entry_serde_roundtrip() {
        let entry = ProofEntry { cid_bytes: vec![0u8; 36], content_hash: hash_block(b"test") };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ProofEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.cid_bytes, back.cid_bytes);
        assert_eq!(entry.content_hash, back.content_hash);
    }
}
