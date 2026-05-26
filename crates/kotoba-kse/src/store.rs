use bytes::Bytes;
use object_store::path::Path;
use std::sync::Arc;

/// KseStore — thin wrapper around an ObjectStore with a fixed key prefix.
///
/// In production: wraps an `AmazonS3` (B2 S3-compat) instance.
/// In dev/test: wraps `LocalFileSystem`.
pub struct KseStore {
    inner:  Arc<dyn object_store::ObjectStore>,
    prefix: String,
}

impl KseStore {
    /// Construct from any ObjectStore implementation.
    pub fn new(store: Arc<dyn object_store::ObjectStore>, prefix: impl Into<String>) -> Self {
        Self { inner: store, prefix: prefix.into() }
    }

    fn path(&self, key: &str) -> Path {
        Path::from(format!("{}{}", self.prefix, key))
    }

    /// Write bytes at `{prefix}{key}`.
    pub async fn put(&self, key: &str, data: Bytes) -> object_store::Result<()> {
        self.inner.put(&self.path(key), data.into()).await?;
        Ok(())
    }

    /// Read bytes at `{prefix}{key}`.
    pub async fn get(&self, key: &str) -> object_store::Result<Bytes> {
        self.inner.get(&self.path(key)).await?.bytes().await
    }

    /// Return true if the object exists.
    pub async fn exists(&self, key: &str) -> bool {
        self.inner.head(&self.path(key)).await.is_ok()
    }

    /// Delete the object at `{prefix}{key}`.
    pub async fn delete_key(&self, key: &str) -> object_store::Result<()> {
        self.inner.delete(&self.path(key)).await
    }

    /// List all keys under `{prefix}{sub_prefix}`, returning them relative to `self.prefix`.
    ///
    /// E.g. with `self.prefix = "journal/"` and `sub_prefix = "seq/"`, returns strings like
    /// `"seq/00000000000000000001"`.
    pub async fn list_prefix(&self, sub_prefix: &str) -> Vec<String> {
        use tokio_stream::StreamExt as _;
        let full_prefix = format!("{}{}", self.prefix, sub_prefix);
        let prefix_path = Path::from(full_prefix.as_str());
        let mut stream = self.inner.list(Some(&prefix_path));
        let store_prefix = self.prefix.as_str();
        let mut keys = Vec::new();
        while let Some(item) = stream.next().await {
            if let Ok(meta) = item {
                let location = meta.location.to_string();
                if let Some(relative) = location.strip_prefix(store_prefix) {
                    keys.push(relative.to_string());
                }
            }
        }
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::{Journal, JournalEntry},
        topic::Topic,
        vault::Vault,
    };
    use object_store::local::LocalFileSystem;

    fn tmp_dir(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("kotoba-{}-{}", prefix, nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn journal_persists_to_local_fs() {
        let dir = tmp_dir("journal");
        let fs = Arc::new(LocalFileSystem::new_with_prefix(&dir).unwrap());
        let store = Arc::new(KseStore::new(fs, "journal/"));
        let journal = Journal::with_store(Arc::clone(&store));
        let topic = Topic::new("test/topic");
        let entry = journal.publish(topic, Bytes::from_static(b"hello")).await;
        // allow the fire-and-forget spawn to complete
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let key = format!("{}.cbor", entry.cid.to_multibase());
        let data = store.get(&key).await.unwrap();
        let recovered: JournalEntry = ciborium::from_reader(&data[..]).unwrap();
        assert_eq!(recovered.seq, entry.seq);
    }

    #[tokio::test]
    async fn vault_persists_and_retrieves() {
        let dir = tmp_dir("vault");
        let fs = Arc::new(LocalFileSystem::new_with_prefix(&dir).unwrap());
        let store = Arc::new(KseStore::new(fs, "vault/"));
        let vault = Vault::with_store(Arc::clone(&store));
        let data = Bytes::from_static(b"binary blob content");
        let blob_ref = vault.put(data.clone()).await;
        // allow the fire-and-forget spawn to complete
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // new vault instance — empty memory cache, must read from store
        let vault2 = Vault::with_store(Arc::clone(&store));
        let retrieved = vault2.get(&blob_ref.cid).await.unwrap();
        assert_eq!(retrieved, data);
    }
}
