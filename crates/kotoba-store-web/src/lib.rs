//! Browser-side block store for KOTOBA using IndexedDB.
//!
//! # Architecture
//!
//! ```text
//! Agent loop (server)          Browser cache
//! ┌────────────────────┐       ┌──────────────────────────────┐
//! │ QuadStore          │──────▶│ IdbBlockStore                │
//! │ SyncWindow         │       │   "blocks" object store      │
//! │ commits_since(…)   │       │   "meta"   object store      │
//! │ Journal::read_since│       │   (cid → {pinned, last_used, │
//! └────────────────────┘       │            size})            │
//!                              └──────────────────────────────┘
//! ```
//!
//! The browser **caches** a rolling window of blocks. It does not run Pregel
//! or execute WASM guests — that stays server-side.  The cache enables:
//! - Fast re-reads without round-trips (recent quad data is local)
//! - Offline browsing of the last committed graph snapshot
//! - SyncWindow negotiation (browser knows its head CID → requests delta only)
//!
//! # Schema
//! Two IndexedDB object stores:
//! - `"blocks"` — key: CID multibase string, value: `Uint8Array` of block bytes
//! - `"meta"`   — key: CID multibase string, value: `{pinned: bool, last_used: f64, size: u32}`
//!
//! `evict_cold_async(max_bytes)` scans `"meta"` sorted by `last_used` ascending,
//! deletes unpinned entries until stored bytes ≤ `max_bytes`.

pub use kotoba_core::async_store::AsyncBlockStore;

#[cfg(target_arch = "wasm32")]
pub use idb_impl::IdbBlockStore;

#[cfg(target_arch = "wasm32")]
mod idb_impl {
    use anyhow::{anyhow, Result};
    use async_trait::async_trait;
    use bytes::Bytes;
    use js_sys::{Array, Object, Reflect, Uint8Array};
    use kotoba_core::async_store::AsyncBlockStore;
    use kotoba_core::cid::KotobaCid;
    use std::cell::RefCell;
    use std::collections::HashSet;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{IdbDatabase, IdbTransactionMode};

    const DB_NAME: &str = "kotoba-blocks";
    const DB_VERSION: u32 = 1;
    const STORE_BLOCKS: &str = "blocks";
    const STORE_META: &str = "meta";

    /// IndexedDB-backed block store for the browser.
    ///
    /// `!Send` because it wraps browser JS objects.  Use with
    /// `#[async_trait(?Send)]` — see `AsyncBlockStore`.
    pub struct IdbBlockStore {
        db:       IdbDatabase,
        pinned:   RefCell<HashSet<String>>, // in-memory; reset on page reload
        max_bytes: Option<usize>,
    }

    impl IdbBlockStore {
        /// Open (or create) the KOTOBA IndexedDB database.
        pub async fn open(max_bytes: Option<usize>) -> Result<Self> {
            let window = web_sys::window().ok_or_else(|| anyhow!("no window"))?;
            let idb_factory = window
                .indexed_db()
                .map_err(|e| anyhow!("{e:?}"))?
                .ok_or_else(|| anyhow!("no IndexedDB"))?;

            let request = idb_factory
                .open_with_u32(DB_NAME, DB_VERSION)
                .map_err(|e| anyhow!("{e:?}"))?;

            // Upgrade handler — called only when creating/migrating the database
            let on_upgrade: Closure<dyn FnMut(JsValue)> = Closure::new(|event: JsValue| {
                let req: web_sys::IdbOpenDbRequest = event
                    .dyn_into::<web_sys::IdbVersionChangeEvent>()
                    .ok()
                    .and_then(|e| e.target())
                    .and_then(|t| t.dyn_into::<web_sys::IdbOpenDbRequest>().ok())
                    .expect("upgrade event target");
                let db: IdbDatabase = req.result()
                    .expect("db result")
                    .dyn_into()
                    .expect("IdbDatabase");
                let _ = db.create_object_store(STORE_BLOCKS);
                let _ = db.create_object_store(STORE_META);
            });
            request.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
            on_upgrade.forget();

            let db: IdbDatabase = JsFuture::from(
                js_sys::Promise::new(&mut |resolve, reject| {
                    let req_clone = request.clone();
                    let res_cb: Closure<dyn FnMut()> = Closure::new(move || {
                        let db = req_clone.result().unwrap();
                        resolve.call1(&JsValue::undefined(), &db).unwrap();
                    });
                    let rej_cb: Closure<dyn FnMut(JsValue)> = Closure::new(move |e: JsValue| {
                        reject.call1(&JsValue::undefined(), &e).unwrap();
                    });
                    request.set_onsuccess(Some(res_cb.as_ref().unchecked_ref()));
                    request.set_onerror(Some(rej_cb.as_ref().unchecked_ref()));
                    res_cb.forget();
                    rej_cb.forget();
                }),
            )
            .await
            .map_err(|e| anyhow!("IDB open: {e:?}"))?
            .dyn_into()
            .map_err(|_| anyhow!("not IdbDatabase"))?;

            Ok(Self {
                db,
                pinned: RefCell::new(HashSet::new()),
                max_bytes,
            })
        }

        /// Helper: resolve an IdbRequest to its result as a JsValue.
        async fn await_request(req: &web_sys::IdbRequest) -> Result<JsValue> {
            JsFuture::from(js_sys::Promise::new(&mut |resolve, reject| {
                let req = req.clone();
                let res_cb: Closure<dyn FnMut()> = Closure::new(move || {
                    resolve.call1(&JsValue::undefined(), &req.result().unwrap_or(JsValue::undefined())).unwrap();
                });
                let rej_cb: Closure<dyn FnMut(JsValue)> = Closure::new(move |e: JsValue| {
                    reject.call1(&JsValue::undefined(), &e).unwrap();
                });
                req.set_onsuccess(Some(res_cb.as_ref().unchecked_ref()));
                req.set_onerror(Some(rej_cb.as_ref().unchecked_ref()));
                res_cb.forget();
                rej_cb.forget();
            }))
            .await
            .map_err(|e| anyhow!("IDB request: {e:?}"))
        }

        /// Build a meta object `{pinned, last_used, size}`.
        fn meta_obj(pinned: bool, last_used: f64, size: u32) -> JsValue {
            let obj = Object::new();
            Reflect::set(&obj, &"pinned".into(), &JsValue::from_bool(pinned)).unwrap();
            Reflect::set(&obj, &"last_used".into(), &JsValue::from_f64(last_used)).unwrap();
            Reflect::set(&obj, &"size".into(), &JsValue::from_f64(size as f64)).unwrap();
            obj.into()
        }

        fn now_ms() -> f64 {
            js_sys::Date::now()
        }
    }

    #[async_trait(?Send)]
    impl AsyncBlockStore for IdbBlockStore {
        async fn put_async(&self, cid: &KotobaCid, data: &[u8]) -> Result<()> {
            let key = JsValue::from_str(&cid.to_multibase());
            let val = Uint8Array::from(data);
            let size = data.len() as u32;

            let stores = Array::of2(
                &JsValue::from_str(STORE_BLOCKS),
                &JsValue::from_str(STORE_META),
            );
            let tx = self.db
                .transaction_with_str_sequence_and_mode(&stores, IdbTransactionMode::Readwrite)
                .map_err(|e| anyhow!("{e:?}"))?;

            let blocks = tx.object_store(STORE_BLOCKS).map_err(|e| anyhow!("{e:?}"))?;
            let meta   = tx.object_store(STORE_META).map_err(|e| anyhow!("{e:?}"))?;

            blocks.put_with_key(&val, &key).map_err(|e| anyhow!("{e:?}"))?;
            let pinned = self.pinned.borrow().contains(&cid.to_multibase());
            meta.put_with_key(&Self::meta_obj(pinned, Self::now_ms(), size), &key)
                .map_err(|e| anyhow!("{e:?}"))?;

            JsFuture::from(tx.commit().map_err(|e| anyhow!("{e:?}"))?)
                .await
                .map_err(|e| anyhow!("tx commit: {e:?}"))?;

            // Auto-evict if over budget
            if let Some(max) = self.max_bytes {
                self.evict_cold_async(max).await;
            }
            Ok(())
        }

        async fn get_async(&self, cid: &KotobaCid) -> Result<Option<Bytes>> {
            let key = JsValue::from_str(&cid.to_multibase());

            let tx = self.db
                .transaction_with_str_sequence_and_mode(
                    &Array::of2(
                        &JsValue::from_str(STORE_BLOCKS),
                        &JsValue::from_str(STORE_META),
                    ),
                    IdbTransactionMode::Readwrite, // readwrite to update last_used
                )
                .map_err(|e| anyhow!("{e:?}"))?;

            let blocks = tx.object_store(STORE_BLOCKS).map_err(|e| anyhow!("{e:?}"))?;
            let meta   = tx.object_store(STORE_META).map_err(|e| anyhow!("{e:?}"))?;

            let block_req = blocks.get(&key).map_err(|e| anyhow!("{e:?}"))?;
            let val = Self::await_request(&block_req).await?;

            if val.is_null() || val.is_undefined() {
                return Ok(None);
            }

            // Update last_used in meta
            let meta_req = meta.get(&key).map_err(|e| anyhow!("{e:?}"))?;
            let existing_meta = Self::await_request(&meta_req).await?;
            if !existing_meta.is_null() && !existing_meta.is_undefined() {
                let pinned = Reflect::get(&existing_meta, &"pinned".into())
                    .map(|v| v.as_bool().unwrap_or(false))
                    .unwrap_or(false);
                let size = Reflect::get(&existing_meta, &"size".into())
                    .map(|v| v.as_f64().unwrap_or(0.0) as u32)
                    .unwrap_or(0);
                meta.put_with_key(&Self::meta_obj(pinned, Self::now_ms(), size), &key)
                    .map_err(|e| anyhow!("{e:?}"))?;
            }
            JsFuture::from(tx.commit().map_err(|e| anyhow!("{e:?}"))?)
                .await
                .map_err(|e| anyhow!("tx commit: {e:?}"))?;

            let arr: Uint8Array = val.dyn_into().map_err(|_| anyhow!("not Uint8Array"))?;
            Ok(Some(Bytes::from(arr.to_vec())))
        }

        async fn has_async(&self, cid: &KotobaCid) -> bool {
            let key = JsValue::from_str(&cid.to_multibase());
            let Ok(tx) = self.db.transaction_with_str(STORE_BLOCKS) else { return false; };
            let Ok(store) = tx.object_store(STORE_BLOCKS) else { return false; };
            let Ok(req) = store.count_with_key(&key) else { return false; };
            Self::await_request(&req).await
                .ok()
                .and_then(|v| v.as_f64())
                .map(|n| n > 0.0)
                .unwrap_or(false)
        }

        async fn delete_async(&self, cid: &KotobaCid) -> Result<()> {
            let key = JsValue::from_str(&cid.to_multibase());
            let stores = Array::of2(
                &JsValue::from_str(STORE_BLOCKS),
                &JsValue::from_str(STORE_META),
            );
            let tx = self.db
                .transaction_with_str_sequence_and_mode(&stores, IdbTransactionMode::Readwrite)
                .map_err(|e| anyhow!("{e:?}"))?;
            tx.object_store(STORE_BLOCKS).map_err(|e| anyhow!("{e:?}"))?.delete(&key).map_err(|e| anyhow!("{e:?}"))?;
            tx.object_store(STORE_META).map_err(|e| anyhow!("{e:?}"))?.delete(&key).map_err(|e| anyhow!("{e:?}"))?;
            JsFuture::from(tx.commit().map_err(|e| anyhow!("{e:?}"))?)
                .await
                .map_err(|e| anyhow!("tx commit: {e:?}"))?;
            Ok(())
        }

        async fn pin_async(&self, cid: &KotobaCid) {
            self.pinned.borrow_mut().insert(cid.to_multibase());
        }

        async fn unpin_async(&self, cid: &KotobaCid) {
            self.pinned.borrow_mut().remove(&cid.to_multibase());
        }

        async fn is_pinned_async(&self, cid: &KotobaCid) -> bool {
            self.pinned.borrow().contains(&cid.to_multibase())
        }

        /// Evict unpinned blocks (LRU by last_used) until stored bytes ≤ `max_bytes`.
        async fn evict_cold_async(&self, max_bytes: usize) -> usize {
            // Collect all meta entries via cursor, sorted by last_used ascending
            let Ok(tx) = self.db.transaction_with_str_sequence_and_mode(
                &Array::of2(&JsValue::from_str(STORE_BLOCKS), &JsValue::from_str(STORE_META)),
                IdbTransactionMode::Readwrite,
            ) else { return 0; };

            let Ok(meta_store) = tx.object_store(STORE_META) else { return 0; };

            // Get all keys + meta to determine what to evict
            let Ok(all_req) = meta_store.get_all() else { return 0; };
            let Ok(keys_req) = meta_store.get_all_keys() else { return 0; };

            let all_vals = Self::await_request(&all_req).await.unwrap_or(JsValue::undefined());
            let all_keys = Self::await_request(&keys_req).await.unwrap_or(JsValue::undefined());

            let vals: js_sys::Array = all_vals.dyn_into().unwrap_or_default();
            let keys: js_sys::Array = all_keys.dyn_into().unwrap_or_default();

            // Build sorted list of (key, last_used, size, pinned)
            let mut entries: Vec<(String, f64, usize, bool)> = Vec::new();
            let mut total: usize = 0;
            for i in 0..keys.length() {
                let k = keys.get(i).as_string().unwrap_or_default();
                let v = vals.get(i);
                let last_used = Reflect::get(&v, &"last_used".into()).ok()
                    .and_then(|x| x.as_f64()).unwrap_or(0.0);
                let size = Reflect::get(&v, &"size".into()).ok()
                    .and_then(|x| x.as_f64()).unwrap_or(0.0) as usize;
                let pinned = Reflect::get(&v, &"pinned".into()).ok()
                    .and_then(|x| x.as_bool()).unwrap_or(false);
                total += size;
                entries.push((k, last_used, size, pinned));
            }

            if total <= max_bytes { return 0; }

            // Sort cold-first (ascending last_used)
            entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

            let Ok(blocks_store) = tx.object_store(STORE_BLOCKS) else { return 0; };
            let mut freed = 0usize;

            for (key, _, size, pinned) in &entries {
                if total - freed <= max_bytes { break; }
                if *pinned { continue; }
                let k = JsValue::from_str(key);
                let _ = blocks_store.delete(&k);
                let _ = meta_store.delete(&k);
                freed += size;
            }

            let _ = JsFuture::from(tx.commit().unwrap_or_else(|_| js_sys::Promise::resolve(&JsValue::undefined()))).await;
            freed
        }
    }
}
