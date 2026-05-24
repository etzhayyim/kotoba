use crate::store::KseStore;
use crate::topic::Topic;
use kotoba_core::cid::KotobaCid;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};


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
/// If built with `with_store()`, each entry is asynchronously persisted to the
/// backing `KseStore` at key `{cid}.cbor` (fire-and-forget; does not block
/// `publish()`).  The in-process broadcast channel is always maintained for
/// low-latency subscribers.
pub struct Journal {
    seq:   Arc<RwLock<u64>>,
    tx:    broadcast::Sender<JournalEntry>,
    store: Option<Arc<KseStore>>,
}

impl Journal {
    /// In-memory only — no persistence.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self { seq: Arc::new(RwLock::new(0)), tx, store: None }
    }

    /// Persistent — entries are also written to `store`.
    pub fn with_store(store: Arc<KseStore>) -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self { seq: Arc::new(RwLock::new(0)), tx, store: Some(store) }
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

        if let Some(store) = &self.store {
            let entry_clone = entry.clone();
            let store_clone = Arc::clone(store);
            tokio::spawn(async move {
                let key = format!("{}.cbor", entry_clone.cid.to_multibase());
                let mut buf = Vec::new();
                if ciborium::into_writer(&entry_clone, &mut buf).is_ok() {
                    let _ = store_clone.put(&key, Bytes::from(buf)).await;
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
        // subscribe BEFORE publishing so the broadcast receiver is live
        let mut cursor = journal.subscribe();
        let topic = Topic::new("test/subscribe");
        let payload = Bytes::from_static(b"broadcast me");
        let published = journal.publish(topic, payload).await;
        let received = cursor.next().await.expect("cursor should receive entry");
        assert_eq!(received.seq, published.seq);
        assert_eq!(received.cid, published.cid);
        assert_eq!(received.payload, published.payload);
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
