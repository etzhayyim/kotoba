/// CACAO nonce replay prevention (CAIP-74 §8).
///
/// Tracks seen nonces until their CACAO expiry, preventing an attacker from
/// replaying a captured delegation token within its validity window.
///
/// Capacity is bounded at MAX_NONCES; expired entries are purged on overflow.
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_NONCES: usize = 16_384;

pub struct NonceStore {
    inner: RwLock<HashMap<String, u64>>, // nonce → expiry_unix
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore {
    pub fn new() -> Self {
        Self { inner: RwLock::new(HashMap::new()) }
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

        let mut map = self.inner.write().unwrap_or_else(|e| e.into_inner());

        // Purge expired entries when at capacity to keep memory bounded.
        if map.len() >= MAX_NONCES {
            map.retain(|_, &mut exp| exp > now);
        }
        // Hard cap: if purge freed nothing (all nonces still live), reject to prevent
        // unbounded growth beyond MAX_NONCES.  The caller treats this as a failed
        // check, which is the safe fail-closed behaviour.
        if map.len() >= MAX_NONCES {
            tracing::warn!(
                "nonce store at capacity ({MAX_NONCES}) after purge; rejecting new nonce"
            );
            return false;
        }

        match map.get(nonce) {
            Some(&exp) if exp > now => false, // still valid — replay detected
            _ => {
                map.insert(nonce.to_string(), expiry_unix);
                true
            }
        }
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
        assert!(!accepted, "hard cap must reject when all stored nonces are still live");
        // Verify the store did not grow beyond MAX_NONCES.
        let len = store.inner.read().unwrap().len();
        assert_eq!(len, MAX_NONCES, "map must not exceed MAX_NONCES after hard-cap rejection");
    }
}
