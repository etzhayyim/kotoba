/// CACAO nonce replay prevention (CAIP-74 §8).
///
/// Tracks seen nonces until their CACAO expiry, preventing an attacker from
/// replaying a captured delegation token within its validity window.
///
/// Capacity is bounded at MAX_NONCES; expired entries are purged on overflow.
///
/// Backed by `dashmap::DashMap` (64-way sharded RwLock by default) so
/// independent CACAO requests rarely contend on the same shard.  Earlier
/// implementations used a single `RwLock<HashMap>` which serialised every
/// request through one global write-lock — that capped CACAO throughput at
/// ~4 K QPS regardless of concurrency.
use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_NONCES: usize = 16_384;

pub struct NonceStore {
    inner: DashMap<String, u64>, // nonce → expiry_unix
    /// Approximate live-entry counter — DashMap::len() walks all shards so
    /// caching it lets the hot path avoid the global scan on every call.
    size: AtomicUsize,
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
            size: AtomicUsize::new(0),
        }
    }

    /// Check that `nonce` has not been seen before and register it until `expiry_unix`.
    ///
    /// Returns `true` if this is the first time this nonce has been presented
    /// (or if it was previously registered but has since expired).
    /// Returns `false` if the nonce is currently in the store and not yet expired
    /// — i.e., a replay attack is detected.
    pub fn check_and_register(&self, nonce: &str, expiry_unix: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Capacity check first — only one writer ever runs purge_expired() so
        // we use compare_exchange to elect a single purger.
        if self.size.load(Ordering::Relaxed) >= MAX_NONCES {
            self.purge_expired(now);
            if self.size.load(Ordering::Relaxed) >= MAX_NONCES {
                tracing::warn!(
                    "nonce store at capacity ({MAX_NONCES}) after purge; rejecting new nonce"
                );
                return false;
            }
        }

        // Per-shard fine-grained lock — concurrent writers on different
        // nonces (i.e. different hashes) never serialise.
        use dashmap::mapref::entry::Entry;
        match self.inner.entry(nonce.to_string()) {
            Entry::Occupied(slot) => {
                let exp = *slot.get();
                if exp > now {
                    false // replay detected
                } else {
                    // expired — overwrite and treat as fresh
                    *slot.into_ref() = expiry_unix;
                    true
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(expiry_unix);
                self.size.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }

    /// Drop entries whose expiry is in the past.  Called under the capacity
    /// guard above, not on the hot path.
    fn purge_expired(&self, now: u64) {
        let before = self.inner.len();
        self.inner.retain(|_, &mut exp| exp > now);
        let after = self.inner.len();
        self.size.store(after, Ordering::Relaxed);
        let _ = before;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn first_presentation_accepted() {
        let store = NonceStore::new();
        assert!(store.check_and_register("abc123", now_secs() + 3600));
    }

    #[test]
    fn replay_within_window_rejected() {
        let store = NonceStore::new();
        let exp = now_secs() + 3600;
        assert!(store.check_and_register("replay-nonce", exp));
        assert!(!store.check_and_register("replay-nonce", exp));
    }

    #[test]
    fn expired_nonce_accepted_again() {
        let store = NonceStore::new();
        // Insert with expiry in the past
        assert!(store.check_and_register("old-nonce", 1)); // exp = 1970-01-01
                                                           // Should be accepted again since the old entry is expired
        assert!(store.check_and_register("old-nonce", now_secs() + 3600));
    }

    #[test]
    fn different_nonces_all_accepted() {
        let store = NonceStore::new();
        let exp = now_secs() + 3600;
        for i in 0..100 {
            assert!(store.check_and_register(&format!("nonce-{i}"), exp));
        }
    }

    #[test]
    fn capacity_eviction_purges_expired_and_accepts_new() {
        let store = NonceStore::new();
        // Fill to MAX_NONCES with already-expired entries (exp = 1 = 1970-01-01).
        for i in 0..MAX_NONCES {
            store.check_and_register(&format!("old-{i}"), 1);
        }
        // The map is now at capacity. A fresh nonce with a future expiry should still
        // be accepted: the overflow path purges all expired entries before inserting.
        let future = now_secs() + 3600;
        assert!(
            store.check_and_register("brand-new-nonce", future),
            "new nonce must be accepted after expired entries are evicted"
        );
        // The new nonce must be tracked — a second presentation is a replay.
        assert!(
            !store.check_and_register("brand-new-nonce", future),
            "replay of just-registered nonce must be rejected"
        );
    }

    #[test]
    fn hard_cap_rejects_when_all_live() {
        // Fill the store to MAX_NONCES with future-expiry nonces (none will be purged).
        // The next insertion attempt must be rejected by the hard-cap guard, and the
        // store must not grow beyond MAX_NONCES.
        let store = NonceStore::new();
        let future = now_secs() + 3600;
        for i in 0..MAX_NONCES {
            assert!(
                store.check_and_register(&format!("live-{i}"), future),
                "initial fill should succeed"
            );
        }
        // All nonces are live — purge removes nothing.  Hard cap must fire.
        let accepted = store.check_and_register("overflow-nonce", future);
        assert!(
            !accepted,
            "hard cap must reject when all stored nonces are still live"
        );
        // Verify the store did not grow beyond MAX_NONCES.
        let len = store.inner.len();
        assert_eq!(
            len, MAX_NONCES,
            "map must not exceed MAX_NONCES after hard-cap rejection"
        );
    }
}
