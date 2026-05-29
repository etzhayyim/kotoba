//! Browser E2E tests for IdbBlockStore.
//!
//! Run with:
//!   CHROMEDRIVER=<path> wasm-pack test --headless --chrome crates/kotoba-store-web

#![cfg(target_arch = "wasm32")]

use kotoba_core::{async_store::AsyncBlockStore, cid::KotobaCid};
use kotoba_store_web::IdbBlockStore;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn cid(s: &str) -> KotobaCid {
    KotobaCid::from_bytes(s.as_bytes())
}

async fn open() -> IdbBlockStore {
    IdbBlockStore::open(Some(1024 * 1024))
        .await
        .expect("open IDB")
}

// ── basic CRUD ────────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
async fn put_and_get_roundtrip() {
    let store = open().await;
    let key = cid("put-get-roundtrip");
    let data = b"hello kotoba";

    store.put_async(&key, data).await.expect("put");
    let got = store.get_async(&key).await.expect("get");
    assert_eq!(got.as_deref(), Some(data.as_ref()));
}

#[wasm_bindgen_test]
async fn has_before_and_after_put() {
    let store = open().await;
    let key = cid("has-before-after");

    assert!(!store.has_async(&key).await, "should not exist before put");
    store.put_async(&key, b"data").await.expect("put");
    assert!(store.has_async(&key).await, "should exist after put");
}

#[wasm_bindgen_test]
async fn get_missing_returns_none() {
    let store = open().await;
    let key = cid("definitely-missing-xyz");
    let got = store.get_async(&key).await.expect("get");
    assert!(got.is_none());
}

#[wasm_bindgen_test]
async fn delete_removes_block() {
    let store = open().await;
    let key = cid("delete-removes");
    store.put_async(&key, b"to be deleted").await.expect("put");
    store.delete_async(&key).await.expect("delete");

    assert!(!store.has_async(&key).await);
    let got = store.get_async(&key).await.expect("get after delete");
    assert!(got.is_none());
}

// ── pin / unpin ───────────────────────────────────────────────────────────────

#[wasm_bindgen_test]
async fn pin_and_unpin_roundtrip() {
    let store = open().await;
    let key = cid("pin-unpin");

    assert!(!store.is_pinned_async(&key).await);
    store.pin_async(&key).await;
    assert!(store.is_pinned_async(&key).await);
    store.unpin_async(&key).await;
    assert!(!store.is_pinned_async(&key).await);
}

#[wasm_bindgen_test]
async fn pin_protects_block_from_eviction() {
    // Budget = 100 bytes.  Put 3 × 50-byte blocks; first block is pinned.
    // After evict_cold_async, the pinned block must survive.
    let store = IdbBlockStore::open(None).await.expect("open IDB no-budget");

    let pinned_key = cid("evict-pinned-block");
    let cold1 = cid("evict-cold-1");
    let cold2 = cid("evict-cold-2");
    let payload = vec![0u8; 50];

    // Store in last_used order: cold1 < cold2 < pinned (pinned is most recent but flagged)
    store.put_async(&cold1, &payload).await.expect("put cold1");
    store.put_async(&cold2, &payload).await.expect("put cold2");
    store
        .put_async(&pinned_key, &payload)
        .await
        .expect("put pinned");
    store.pin_async(&pinned_key).await;

    // total = 150 bytes, budget = 100 → evict until ≤ 100
    let freed = store.evict_cold_async(100).await;
    assert!(freed > 0, "expected some bytes freed");
    assert!(
        store.has_async(&pinned_key).await,
        "pinned block must survive eviction"
    );
}

// ── evict_cold_async LRU order ────────────────────────────────────────────────

#[wasm_bindgen_test]
async fn evict_cold_removes_oldest_unpinned_lru() {
    let store = IdbBlockStore::open(None).await.expect("open IDB no-budget");

    // Put three blocks sequentially.  last_used timestamps should reflect order.
    let old = cid("lru-old");
    let mid = cid("lru-mid");
    let new = cid("lru-new");
    let payload = vec![1u8; 50];

    store.put_async(&old, &payload).await.expect("put old");
    store.put_async(&mid, &payload).await.expect("put mid");
    store.put_async(&new, &payload).await.expect("put new");

    // total = 150 bytes, budget = 100 → must evict at least the coldest (old)
    let freed = store.evict_cold_async(100).await;
    assert!(freed >= 50, "should have freed at least one block");

    // The "new" block should still be present
    assert!(store.has_async(&new).await, "newest block should survive");
}

// ── get updates last_used ─────────────────────────────────────────────────────

#[wasm_bindgen_test]
async fn get_updates_last_used_so_block_survives_eviction() {
    let store = IdbBlockStore::open(None).await.expect("open IDB no-budget");

    let resurrected = cid("get-updates-lru");
    let sacrificial = cid("get-updates-sacrificial");
    let payload = vec![2u8; 50];

    // Put the "old" block first, then the "new" one
    store
        .put_async(&resurrected, &payload)
        .await
        .expect("put old");
    store
        .put_async(&sacrificial, &payload)
        .await
        .expect("put new");

    // Access "old" — this bumps its last_used so it becomes warm
    let _ = store.get_async(&resurrected).await.expect("get to warm up");

    // total = 100 bytes, budget = 60 → must evict ≥ 1 block (40 byte slack)
    let freed = store.evict_cold_async(60).await;
    assert!(freed >= 50, "should have freed one block");

    // The accessed block must survive (it was warmed up by get_async)
    assert!(
        store.has_async(&resurrected).await,
        "block accessed via get_async should have fresh last_used and survive"
    );
}
