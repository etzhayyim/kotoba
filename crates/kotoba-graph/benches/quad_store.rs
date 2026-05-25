/// QuadStore insert + query benchmarks.
///
/// ## Scope
///
/// All insert and hot-path query benchmarks use `MemoryBlockStore` — they measure
/// the **in-memory Arrangement path only** (no BlockStore I/O during query).
///
/// The cold-path query group (`query_cold_prolly_*`) measures the **committed data
/// read path**: ProllyTree node traversal through a `SimulatedLatencyBlockStore`.
/// This simulates what happens when quads have been committed and the Arrangement
/// is no longer hot:
///   - iroh LAN  (1 ms GET)  → one ProllyTree level = 1 ms overhead
///   - iroh WAN  (80 ms GET) → each node = 80 ms; multi-level = additive
///   - S3 same-AZ (2 ms GET) → comparable to iroh LAN
///
/// ## Key result interpretation
///
/// | benchmark group            | includes IPFS/S3 I/O? |
/// |----------------------------|-----------------------|
/// | insert_per_quad            | no  (hot Arrangement) |
/// | insert_batch               | no  (hot Arrangement) |
/// | insert_batch_chunked       | no  (hot Arrangement) |
/// | query_hot_arrangement      | no  (in-memory only)  |
/// | query_cold_prolly_commit   | YES (simulated RTT)   |
///
/// Run:
///   cargo bench -p kotoba-graph --bench quad_store
use std::{sync::Arc, time::Duration};
use anyhow::Result;
use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kotoba_core::{cid::KotobaCid, prolly::ProllyTree, store::BlockStore};
use kotoba_graph::quad_store::QuadStore;
use kotoba_kqe::quad::{Quad, QuadObject};
use kotoba_kse::journal::Journal;
use kotoba_store::MemoryBlockStore;

fn make_cid(n: u64) -> KotobaCid {
    KotobaCid::from_bytes(&n.to_le_bytes())
}

fn make_quads(n: u64) -> Vec<Quad> {
    (0..n).flat_map(|i| {
        let g = make_cid(1);
        let s = make_cid(i % (n / 2 + 1));
        [
            Quad { graph: g.clone(), subject: s.clone(),
                   predicate: "name".to_string(),
                   object: QuadObject::Text("Alice".to_string()) },
            Quad { graph: g, subject: s,
                   predicate: "knows".to_string(),
                   object: QuadObject::Cid(make_cid((i + 1) % (n / 2 + 1))) },
        ]
    }).collect()
}

fn make_store() -> QuadStore {
    let journal     = Arc::new(Journal::new());
    let block_store = Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
    QuadStore::new(journal, block_store)
}

/// Per-quad async insert via `assert_silent` (1 lock acquisition per quad).
fn bench_insert_per_quad(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("quad_store/insert_per_quad");
    for &(n, samples) in &[(1_000u64, 100), (10_000, 20), (100_000, 10)] {
        let quads = make_quads(n);
        group.throughput(Throughput::Elements(n * 2)); // 2 quads per entity
        group.sample_size(samples);
        group.bench_with_input(BenchmarkId::from_parameter(n), &quads, |b, quads| {
            b.to_async(&rt).iter(|| async {
                let qs = make_store();
                for q in quads {
                    qs.assert_silent(q.clone()).await;
                }
                qs
            });
        });
    }
    group.finish();
}

/// Batch insert via `assert_batch_silent` (1 lock acquisition for all quads).
fn bench_insert_batch(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("quad_store/insert_batch");
    for n in [1_000u64, 10_000, 100_000] {
        let quads = make_quads(n);
        group.throughput(Throughput::Elements(n * 2));
        group.bench_with_input(BenchmarkId::from_parameter(n), &quads, |b, quads| {
            b.to_async(&rt).iter(|| async {
                let qs = make_store();
                qs.assert_batch_silent(quads.clone()).await;
                qs
            });
        });
    }
    group.finish();
}

/// Chunked batch insert at 50K quads per chunk — matches the loadtest pattern.
fn bench_insert_batch_chunked(c: &mut Criterion) {
    const CHUNK: usize = 50_000;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("quad_store/insert_batch_chunked");
    for n in [100_000u64, 1_000_000] {
        let quads = make_quads(n);
        group.throughput(Throughput::Elements(n * 2));
        group.sample_size(if n >= 1_000_000 { 10 } else { 50 });
        group.bench_with_input(BenchmarkId::from_parameter(n), &quads, |b, quads| {
            b.to_async(&rt).iter(|| async {
                let qs = make_store();
                for chunk in quads.chunks(CHUNK) {
                    qs.assert_batch_silent(chunk.to_vec()).await;
                }
                qs
            });
        });
    }
    group.finish();
}

// ─── Hot-path query bench ─────────────────────────────────────────────────────

/// Query benchmarks against the hot in-memory Arrangement (no BlockStore I/O).
fn bench_query_hot(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let qs = rt.block_on(async {
        let store = make_store();
        let n = 100_000u64;
        for chunk in make_quads(n).chunks(50_000) {
            store.assert_batch_silent(chunk.to_vec()).await;
        }
        store
    });
    let graph = make_cid(1);
    let subject = make_cid(42);

    let mut group = c.benchmark_group("quad_store/query_hot");
    group.bench_function("get_entity_quads_eavt", |b| {
        b.to_async(&rt).iter(|| async {
            qs.get_entity_quads(Some(&graph), &subject).await
        });
    });
    group.bench_function("lookup_by_predicate_object_avet", |b| {
        b.to_async(&rt).iter(|| async {
            qs.lookup_subject_by_po(Some(&graph), "name", "Alice").await
        });
    });
    group.bench_function("quads_by_predicate_prefix_avet", |b| {
        b.to_async(&rt).iter(|| async {
            qs.quads_by_predicate_prefix(Some(&graph), "name").await
        });
    });
    group.finish();
}

// ─── Cold-path: ProllyTree commit + re-read with simulated IPFS/S3 RTT ────────

/// Wraps MemoryBlockStore with a fixed sleep per get/put to simulate network RTT.
struct SimulatedLatencyBlockStore {
    inner:   MemoryBlockStore,
    get_rtt: Duration,
    put_rtt: Duration,
}
impl SimulatedLatencyBlockStore {
    fn iroh_lan()       -> Self { Self { inner: MemoryBlockStore::new(), get_rtt: ms(1),  put_rtt: ms(2)  } }
    fn iroh_wan()       -> Self { Self { inner: MemoryBlockStore::new(), get_rtt: ms(80), put_rtt: ms(100) } }
    fn s3_same_az()     -> Self { Self { inner: MemoryBlockStore::new(), get_rtt: ms(2),  put_rtt: ms(10) } }
}
fn ms(n: u64) -> Duration { Duration::from_millis(n) }

impl BlockStore for SimulatedLatencyBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> Result<()> {
        std::thread::sleep(self.put_rtt);
        self.inner.put(cid, data)
    }
    fn get(&self, cid: &KotobaCid) -> Result<Option<Bytes>> {
        std::thread::sleep(self.get_rtt);
        self.inner.get(cid)
    }
    fn has(&self, cid: &KotobaCid) -> bool { self.inner.has(cid) }
    fn delete(&self, cid: &KotobaCid) -> Result<()> { self.inner.delete(cid) }
    fn pin(&self, cid: &KotobaCid) { self.inner.pin(cid) }
    fn unpin(&self, cid: &KotobaCid) { self.inner.unpin(cid) }
    fn is_pinned(&self, cid: &KotobaCid) -> bool { self.inner.is_pinned(cid) }
}

/// Build a small ProllyTree (1K entries) with a simulated-latency store, then
/// do a single-key lookup.  Each ProllyTree level = 1 BlockStore.get() call.
/// With a branching factor of ~128 entries/node, 1K entries = 2-3 levels.
///
/// This measures: commit (PUT per node) + point-query (GET per level traversal).
///
/// The benchmark runs inside a 64 MiB stack thread to avoid overflowing the
/// criterion bench binary's default main-thread stack after the hot-path setup.
fn bench_query_cold_prolly(c: &mut Criterion) {
    type ScenarioData = (&'static str, Arc<SimulatedLatencyBlockStore>, KotobaCid, Vec<u8>);

    // Build all tree roots in a thread with a large stack so build_tree
    // (which may recurse across multiple levels) doesn't overflow.
    let scenarios: Vec<ScenarioData> = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .name("prolly-bench-setup".to_string())
        .spawn(|| -> Vec<ScenarioData> {
            let entries: Vec<(Vec<u8>, Vec<u8>)> = (0u64..1_000)
                .map(|i| (i.to_le_bytes().to_vec(), format!("v{i}").into_bytes()))
                .collect();
            let lookup_key = 500u64.to_le_bytes().to_vec();

            let spec: &[(&'static str, fn() -> SimulatedLatencyBlockStore)] = &[
                ("iroh_lan_1ms_get",   SimulatedLatencyBlockStore::iroh_lan),
                ("iroh_wan_80ms_get",  SimulatedLatencyBlockStore::iroh_wan),
                ("s3_same_az_2ms_get", SimulatedLatencyBlockStore::s3_same_az),
            ];
            spec.iter().map(|(name, make)| {
                let store = Arc::new(make());
                let root = ProllyTree::build_tree(entries.clone(), &*store).unwrap();
                (*name, store, root, lookup_key.clone())
            }).collect()
        })
        .expect("spawn prolly-bench-setup")
        .join()
        .expect("prolly-bench-setup panicked");

    let mut group = c.benchmark_group("quad_store/query_cold_prolly_1k");
    group.sample_size(10);

    for (name, store, root, lookup_key) in &scenarios {
        let store = store.clone();
        let root  = root.clone();
        let key   = lookup_key.clone();
        group.bench_function(*name, move |b| {
            b.iter(|| ProllyTree::get(&root, &key, &*store));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_insert_per_quad,
    bench_insert_batch,
    bench_insert_batch_chunked,
    bench_query_hot,
    bench_query_cold_prolly,
);
criterion_main!(benches);
