use crate::store::KseStore;
use crate::topic::Topic;
use kotoba_core::cid::KotobaCid;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

/// Default number of entries kept in the in-process ring buffer.
/// Enough for a typical agent session window without unbounded growth.
const DEFAULT_LOG_CAP: usize = 65_536;

/// Journal entry — one ordered record in a Topic's log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub seq:     u64,
    pub ts:      u64,   // unix ms
    pub topic:   String,
    pub payload: Vec<u8>,  // raw bytes (Bytes not Serialize, stored as Vec<u8>)
    pub cid:     KotobaCid,
}

/// Cursor — consumer position in a Journal
pub struct Cursor {
    pub id:       String,
    pub position: u64,
    rx:           broadcast::Receiver<JournalEntry>,
}

impl Cursor {
    pub async fn next(&mut self) -> Option<JournalEntry> {
        self.rx.recv().await.ok()
    }
}

pub struct CursorAck;

/// Journal — ordered persistent log for a set of Topics.
///
/// Each entry is broadcast to live subscribers AND appended to a bounded
/// in-process ring buffer (`log`).  Callers can replay history with
/// [`read_since`] without touching the persistent store.
///
/// If built with `with_store()`, entries are also asynchronously persisted to
/// the backing `KseStore` (fire-and-forget; does not block `publish()`).
pub struct Journal {
    seq:     Arc<RwLock<u64>>,
    tx:      broadcast::Sender<JournalEntry>,
    store:   Option<Arc<KseStore>>,
    /// Bounded in-process ring buffer for selective replay.
    log:     Arc<RwLock<VecDeque<JournalEntry>>>,
    log_cap: usize,
}

impl Journal {
    /// In-memory only — no persistence.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_LOG_CAP)
    }

    pub fn with_capacity(log_cap: usize) -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self {
            seq: Arc::new(RwLock::new(0)),
            tx,
            store: None,
            log: Arc::new(RwLock::new(VecDeque::with_capacity(log_cap.min(4096)))),
            log_cap,
        }
    }

    /// Persistent — entries are also written to `store`.
    pub fn with_store(store: Arc<KseStore>) -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self {
            seq: Arc::new(RwLock::new(0)),
            tx,
            store: Some(store),
            log: Arc::new(RwLock::new(VecDeque::with_capacity(4096))),
            log_cap: DEFAULT_LOG_CAP,
        }
    }

    pub async fn publish(&self, topic: Topic, payload: Bytes) -> JournalEntry {
        let mut seq_guard = self.seq.write().await;
        *seq_guard += 1;
        let seq = *seq_guard;
        drop(seq_guard);

        let cid = KotobaCid::from_bytes(&payload);
        let entry = JournalEntry {
            seq,
            ts: now_ms(),
            topic: topic.0,
            payload: payload.to_vec(),
            cid,
        };
        let _ = self.tx.send(entry.clone());

        // Append to ring buffer, evict oldest if over cap
        {
            let mut log = self.log.write().await;
            log.push_back(entry.clone());
            while log.len() > self.log_cap {
                log.pop_front();
            }
        }

        if let Some(store) = &self.store {
            let entry_clone = entry.clone();
            let store_clone = Arc::clone(store);
            tokio::spawn(async move {
                let cid_mb = entry_clone.cid.to_multibase();
                // seq index: cheap pointer used by persistent read_since fallback
                let seq_key = format!("seq/{:020}", entry_clone.seq);
                let _ = store_clone.put(&seq_key, Bytes::from(cid_mb.clone().into_bytes())).await;
                // full entry CBOR
                let entry_key = format!("{}.cbor", cid_mb);
                let mut buf = Vec::new();
                if ciborium::into_writer(&entry_clone, &mut buf).is_ok() {
                    let _ = store_clone.put(&entry_key, Bytes::from(buf)).await;
                }
            });
        }

        entry
    }

    pub fn subscribe(&self) -> Cursor {
        Cursor {
            id: uuid(),
            position: 0,
            rx: self.tx.subscribe(),
        }
    }

    /// Return all entries with `seq >= since`.
    ///
    /// Scans the ring buffer first.  When `since` predates the oldest entry in
    /// the ring buffer AND a persistent store is configured, fetches the gap
    /// from the seq-index written by `publish()`.
    pub async fn read_since(&self, since: u64) -> Vec<JournalEntry> {
        let log = self.log.read().await;
        let oldest_ring_seq = log.front().map(|e| e.seq);
        let ring_entries: Vec<JournalEntry> = log.iter()
            .filter(|e| e.seq >= since)
            .cloned()
            .collect();
        drop(log);

        let needs_persistent = self.store.is_some() && match oldest_ring_seq {
            None => true,
            Some(oldest) => since < oldest,
        };

        if needs_persistent {
            if let Some(store) = &self.store {
                let until = oldest_ring_seq.unwrap_or(u64::MAX);
                let mut entries = Self::fetch_seq_range_from_store(store, since, until).await;
                entries.extend(ring_entries);
                return entries;
            }
        }
        ring_entries
    }

    /// Fetch entries from the persistent seq-index in the range `[since, before)`.
    async fn fetch_seq_range_from_store(
        store: &Arc<KseStore>,
        since: u64,
        before: u64,
    ) -> Vec<JournalEntry> {
        let keys = store.list_prefix("seq/").await;
        let mut entries = Vec::new();
        for key in keys {
            let Some(seq_str) = key.strip_prefix("seq/") else { continue };
            let Ok(seq) = seq_str.trim().parse::<u64>() else { continue };
            if seq < since || seq >= before { continue; }
            let Ok(cid_bytes) = store.get(&key).await else { continue };
            let cid_mb = String::from_utf8_lossy(&cid_bytes).into_owned();
            let entry_key = format!("{}.cbor", cid_mb);
            let Ok(data) = store.get(&entry_key).await else { continue };
            if let Ok(entry) = ciborium::from_reader::<JournalEntry, _>(&data[..]) {
                entries.push(entry);
            }
        }
        entries.sort_unstable_by_key(|e| e.seq);
        entries
    }

    /// Return the current highest sequence number (0 if nothing published yet).
    pub async fn current_seq(&self) -> u64 {
        *self.seq.read().await
    }

    /// Remove ring-buffer entries with `seq < before`.
    ///
    /// Frees memory for sessions that no longer need old history.
    /// Does NOT delete from the persistent store.
    pub async fn trim_before(&self, before: u64) {
        let mut log = self.log.write().await;
        while let Some(front) = log.front() {
            if front.seq < before {
                log.pop_front();
            } else {
                break;
            }
        }
    }

    /// Delete seq-index keys (`seq/{seq:020}`) **and** the associated `{cid_mb}.cbor` blob
    /// entries for all entries with `seq < before` from the persistent store.
    ///
    /// Both deletes are best-effort (errors are silently ignored).  Total count of
    /// deleted keys (seq-index + cbor blobs) is logged at debug level.
    ///
    /// Runs to completion; callers should `tokio::spawn` if fire-and-forget is preferred.
    pub async fn trim_persistent_before(&self, before: u64) {
        let store = match &self.store {
            Some(s) => Arc::clone(s),
            None    => return,
        };
        let keys = store.list_prefix("seq/").await;
        let mut deleted = 0usize;
        for key in keys {
            let Some(seq_str) = key.strip_prefix("seq/") else { continue };
            let Ok(seq) = seq_str.trim().parse::<u64>() else { continue };
            if seq < before {
                // Read the seq key value to obtain the CID multibase string.
                if let Ok(cid_bytes) = store.get(&key).await {
                    let cid_mb = String::from_utf8_lossy(&cid_bytes).into_owned();
                    // Best-effort: delete the {cid_mb}.cbor blob.
                    let blob_key = format!("{}.cbor", cid_mb);
                    let _ = store.delete_key(&blob_key).await;
                    deleted += 1;
                }
                // Best-effort: delete the seq/{N} key.
                let _ = store.delete_key(&key).await;
                deleted += 1;
            }
        }
        if deleted > 0 {
            tracing::debug!(deleted, before, "Journal: trimmed persistent seq-index and cbor blob entries");
        }
    }

    /// Persist a checkpoint blob at `checkpoint/heads` in the backing store.
    /// Overwrites any previous checkpoint (latest wins).
    pub async fn write_checkpoint(&self, data: bytes::Bytes) {
        if let Some(store) = &self.store {
            if let Err(e) = store.put("checkpoint/heads", data).await {
                tracing::warn!("Journal: checkpoint write failed: {e}");
            }
        }
    }

    /// Read the latest checkpoint blob from `checkpoint/heads`.
    /// Returns `None` if the backing store is absent or the key does not exist.
    pub async fn read_checkpoint(&self) -> Option<bytes::Bytes> {
        let store = self.store.as_ref()?;
        store.get("checkpoint/heads").await.ok()
    }
}

impl Default for Journal {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topic::Topic;
    use bytes::Bytes;

    #[tokio::test]
    async fn publish_increments_seq() {
        let journal = Journal::new();
        let t = Topic::new("test/seq");
        let e1 = journal.publish(t.clone(), Bytes::from_static(b"a")).await;
        let e2 = journal.publish(t.clone(), Bytes::from_static(b"b")).await;
        let e3 = journal.publish(t.clone(), Bytes::from_static(b"c")).await;
        assert_eq!(e1.seq, 1);
        assert_eq!(e2.seq, 2);
        assert_eq!(e3.seq, 3);
    }

    #[tokio::test]
    async fn publish_cid_is_deterministic() {
        let journal = Journal::new();
        let t = Topic::new("test/cid");
        let payload = Bytes::from_static(b"hello kotoba");
        let e1 = journal.publish(t.clone(), payload.clone()).await;
        let e2 = journal.publish(t.clone(), payload.clone()).await;
        assert_eq!(e1.cid, e2.cid, "same payload must produce same CID");
    }

    #[tokio::test]
    async fn publish_returns_correct_topic_and_payload() {
        let journal = Journal::new();
        let topic_str = "kotoba/test/entry";
        let payload = Bytes::from(vec![1u8, 2, 3, 4]);
        let entry = journal
            .publish(Topic::new(topic_str), payload.clone())
            .await;
        assert_eq!(entry.topic, topic_str);
        assert_eq!(entry.payload, payload.to_vec());
    }

    #[tokio::test]
    async fn subscribe_cursor_receives_published_entry() {
        let journal = Journal::new();
        let mut cursor = journal.subscribe();
        let topic = Topic::new("test/subscribe");
        let payload = Bytes::from_static(b"broadcast me");
        let published = journal.publish(topic, payload).await;
        let received = cursor.next().await.expect("cursor should receive entry");
        assert_eq!(received.seq, published.seq);
        assert_eq!(received.cid, published.cid);
        assert_eq!(received.payload, published.payload);
    }

    #[tokio::test]
    async fn read_since_returns_only_entries_after_watermark() {
        let journal = Journal::new();
        let t = Topic::new("window/test");
        journal.publish(t.clone(), Bytes::from_static(b"seq1")).await;
        journal.publish(t.clone(), Bytes::from_static(b"seq2")).await;
        let anchor = journal.publish(t.clone(), Bytes::from_static(b"seq3")).await;
        journal.publish(t.clone(), Bytes::from_static(b"seq4")).await;
        journal.publish(t.clone(), Bytes::from_static(b"seq5")).await;

        let since = anchor.seq; // 3
        let entries = journal.read_since(since).await;
        assert_eq!(entries.len(), 3, "should return seq 3, 4, 5");
        assert!(entries.iter().all(|e| e.seq >= since));
        assert_eq!(entries[0].seq, 3);
        assert_eq!(entries[2].seq, 5);
    }

    #[tokio::test]
    async fn trim_before_removes_old_entries() {
        let journal = Journal::new();
        let t = Topic::new("trim/test");
        for i in 0..10u8 {
            journal.publish(t.clone(), Bytes::from(vec![i])).await;
        }
        // Before trim: all 10 entries
        assert_eq!(journal.read_since(1).await.len(), 10);

        journal.trim_before(6).await;

        let remaining = journal.read_since(1).await;
        assert!(remaining.iter().all(|e| e.seq >= 6),
            "all remaining entries must have seq >= 6");
        assert_eq!(remaining.len(), 5, "entries 6..=10 remain");
    }

    #[tokio::test]
    async fn read_since_falls_back_to_persistent_store() {
        use object_store::local::LocalFileSystem;
        use crate::store::KseStore;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("kotoba-journal-persist-{}", nanos));
        std::fs::create_dir_all(&dir).unwrap();

        let fs = Arc::new(LocalFileSystem::new_with_prefix(&dir).unwrap());
        let store = Arc::new(KseStore::new(fs, "journal/"));
        // Ring cap = 3; publish 5 entries so seq 1,2 fall out of ring
        let journal = {
            let (tx, _) = tokio::sync::broadcast::channel(4096);
            Journal {
                seq: Arc::new(RwLock::new(0)),
                tx,
                store: Some(Arc::clone(&store)),
                log: Arc::new(RwLock::new(VecDeque::with_capacity(3))),
                log_cap: 3,
            }
        };

        let t = Topic::new("persist/test");
        for i in 0..5u8 {
            journal.publish(t.clone(), Bytes::from(vec![i])).await;
        }
        // Let fire-and-forget persist tasks complete
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Ring now holds seq 3,4,5; seq 1,2 are in persistent store only
        let all = journal.read_since(1).await;
        let seqs: Vec<u64> = all.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5], "persistent fallback must fill the gap");
    }

    #[tokio::test]
    async fn ring_buffer_evicts_oldest_when_at_cap() {
        let journal = Journal::with_capacity(3);
        let t = Topic::new("cap/test");
        journal.publish(t.clone(), Bytes::from_static(b"a")).await; // seq 1
        journal.publish(t.clone(), Bytes::from_static(b"b")).await; // seq 2
        journal.publish(t.clone(), Bytes::from_static(b"c")).await; // seq 3
        journal.publish(t.clone(), Bytes::from_static(b"d")).await; // seq 4 — evicts seq 1

        let all = journal.read_since(1).await;
        assert_eq!(all.len(), 3, "only 3 entries fit in cap-3 buffer");
        assert_eq!(all[0].seq, 2, "oldest kept entry should be seq 2");
        assert_eq!(all[2].seq, 4);
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn uuid() -> String {
    format!("cursor-{}", now_ms())
}
