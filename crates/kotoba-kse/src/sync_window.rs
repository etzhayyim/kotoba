use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;

/// Describes the subset of history an agent loop needs to operate.
///
/// An agent creates a `SyncWindow` on startup from its last persisted state.
/// It then:
/// 1. Calls `pin_into(store)` to protect anchor CIDs from eviction.
/// 2. Calls `Journal::read_since(self.since_seq)` to replay missed entries.
/// 3. Calls `QuadStore::commits_since(graph_cid, self.head_cid.as_ref())`
///    to fetch only the delta commits it hasn't processed yet.
/// 4. Calls `advance(new_head, new_seq, store)` after each processed commit.
/// 5. Calls `unpin_from(store)` when the agent session ends.
///
/// This prevents full history replication: only the window's worth of data
/// is fetched and kept alive in local storage.
#[derive(Debug, Clone)]
pub struct SyncWindow {
    /// Named graph being tracked.
    pub graph_cid: KotobaCid,
    /// Journal sequence watermark — only entries ≥ since_seq are needed.
    pub since_seq: u64,
    /// Last commit head the agent has already processed.
    /// `None` = fresh agent with no prior state.
    pub head_cid: Option<KotobaCid>,
}

impl SyncWindow {
    /// Create a window starting from a known position.
    pub fn new(graph_cid: KotobaCid, since_seq: u64, head_cid: Option<KotobaCid>) -> Self {
        Self { graph_cid, since_seq, head_cid }
    }

    /// Fresh window — subscribe from the current tip only.
    /// Pass `current_seq` from `Journal::current_seq()`.
    pub fn head_only(graph_cid: KotobaCid, current_seq: u64) -> Self {
        Self { graph_cid, since_seq: current_seq, head_cid: None }
    }

    /// Pin the window's anchor CIDs into `store` so eviction never removes them.
    pub fn pin_into(&self, store: &dyn BlockStore) {
        store.pin(&self.graph_cid);
        if let Some(head) = &self.head_cid {
            store.pin(head);
        }
    }

    /// Release the window's pin locks when the agent session ends.
    pub fn unpin_from(&self, store: &dyn BlockStore) {
        store.unpin(&self.graph_cid);
        if let Some(head) = &self.head_cid {
            store.unpin(head);
        }
    }

    /// Advance the window after the agent successfully processes a new commit.
    ///
    /// Unpins the old head (so it can be evicted) and pins the new head.
    pub fn advance(&mut self, new_head: KotobaCid, new_seq: u64, store: &dyn BlockStore) {
        if let Some(old) = &self.head_cid {
            store.unpin(old);
        }
        store.pin(&new_head);
        self.head_cid = Some(new_head);
        self.since_seq = new_seq;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::store::BlockStore;
    use std::collections::HashSet;
    use std::sync::{Arc, RwLock};
    use bytes::Bytes;

    /// Minimal in-test BlockStore that tracks pins.
    #[derive(Default)]
    struct PinStore { pinned: Arc<RwLock<HashSet<[u8; 36]>>> }
    impl BlockStore for PinStore {
        fn put(&self, _: &KotobaCid, _: &[u8]) -> anyhow::Result<()> { Ok(()) }
        fn get(&self, _: &KotobaCid) -> anyhow::Result<Option<Bytes>> { Ok(None) }
        fn has(&self, _: &KotobaCid) -> bool { false }
        fn pin(&self, cid: &KotobaCid) { self.pinned.write().unwrap().insert(cid.0); }
        fn unpin(&self, cid: &KotobaCid) { self.pinned.write().unwrap().remove(&cid.0); }
        fn is_pinned(&self, cid: &KotobaCid) -> bool { self.pinned.read().unwrap().contains(&cid.0) }
    }

    fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

    #[test]
    fn pin_into_pins_graph_and_head() {
        let store = PinStore::default();
        let g = cid("graph");
        let h = cid("head");
        let win = SyncWindow::new(g.clone(), 0, Some(h.clone()));
        win.pin_into(&store);
        assert!(store.is_pinned(&g));
        assert!(store.is_pinned(&h));
    }

    #[test]
    fn unpin_from_releases_both() {
        let store = PinStore::default();
        let g = cid("graph");
        let h = cid("head");
        let win = SyncWindow::new(g.clone(), 0, Some(h.clone()));
        win.pin_into(&store);
        win.unpin_from(&store);
        assert!(!store.is_pinned(&g));
        assert!(!store.is_pinned(&h));
    }

    #[test]
    fn head_only_sets_none_head() {
        let g = cid("graph");
        let win = SyncWindow::head_only(g.clone(), 42);
        assert_eq!(win.since_seq, 42);
        assert!(win.head_cid.is_none());
    }

    #[test]
    fn advance_moves_pin_to_new_head() {
        let store = PinStore::default();
        let g = cid("graph");
        let h1 = cid("head1");
        let h2 = cid("head2");

        let mut win = SyncWindow::new(g.clone(), 1, Some(h1.clone()));
        win.pin_into(&store);

        win.advance(h2.clone(), 5, &store);

        assert!(!store.is_pinned(&h1), "old head must be unpinned");
        assert!(store.is_pinned(&h2), "new head must be pinned");
        assert_eq!(win.since_seq, 5);
        assert_eq!(win.head_cid, Some(h2));
    }

    #[test]
    fn pin_into_with_no_head_only_pins_graph() {
        let store = PinStore::default();
        let g = cid("graph");
        let win = SyncWindow::head_only(g.clone(), 0);
        win.pin_into(&store);
        assert!(store.is_pinned(&g));
    }
}
