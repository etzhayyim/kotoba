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

/// Journal — ordered persistent log for a set of Topics
pub struct Journal {
    seq:    Arc<RwLock<u64>>,
    tx:     broadcast::Sender<JournalEntry>,
    // TODO: segment storage via object_store
}

impl Journal {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(4096);
        Self {
            seq: Arc::new(RwLock::new(0)),
            tx,
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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn uuid() -> String {
    format!("cursor-{}", now_ms())
}
