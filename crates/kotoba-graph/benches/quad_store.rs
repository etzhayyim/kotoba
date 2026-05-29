use anyhow::Result;
use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kotoba_auth::delegation::DelegationChain;
use kotoba_core::{cid::KotobaCid, prolly::ProllyTree, store::BlockStore};
use kotoba_graph::quad_store::QuadStore;
use kotoba_kqe::quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject};
use kotoba_kse::journal::Journal;
use kotoba_store::MemoryBlockStore;
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
///   - kubo LAN  (1 ms GET)  → one ProllyTree level = 1 ms overhead
///   - kubo WAN  (80 ms GET) → each node = 80 ms; multi-level = additive
///   - S3 same-AZ (2 ms GET) → comparable to kubo LAN
///
/// ## Key result interpretation
///
/// | benchmark group            | includes IPFS/S3 I/O? |
/// |----------------------------|-----------------------|
/// | insert_per_quad            | no  (hot Arrangement) |
/// | insert_batch               | no  (hot Arrangement) |
/// | insert_batch_chunked       | no  (hot Arrangement) |
/// | insert_batch_authed        | no  (hot + CACAO gate)|
/// | query_hot_arrangement      | no  (in-memory only)  |
/// | query_cold_prolly_commit   | YES (simulated RTT)   |
///
/// Run:
///   cargo bench -p kotoba-graph --bench quad_store
use std::{sync::Arc, time::Duration};

fn make_cid(n: u64) -> KotobaCid {
    KotobaCid::from_bytes(&n.to_le_bytes())
}

fn make_quads(n: u64) -> Vec<Quad> {
    (0..n)
        .flat_map(|i| {
            let g = make_cid(1);
            let s = make_cid(i % (n / 2 + 1));
            [
                Quad {
                    graph: g.clone(),
                    subject: s.clone(),
                    predicate: "name".to_string(),
                    object: QuadObject::Text("Alice".to_string()),
                },
                Quad {
                    graph: g,
                    subject: s,
                    predicate: "knows".to_string(),
                    object: QuadObject::Cid(make_cid((i + 1) % (n / 2 + 1))),
                },
            ]
        })
        .collect()
}

fn make_store() -> QuadStore {
    let journal = Arc::new(Journal::new());
    let block_store =
        Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
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

/// CACAO-gated batch insert benchmark.
///
/// Measures the combined overhead of CACAO authorization + batch insert relative
/// to bare `assert_batch_silent`.  Uses `verify_skip_sig` (all logic: capability
/// scope, graph-CID scope, temporal expiry — crypto skipped) because criterion
/// benches run under `test-utils` and a real EdDSA key is not available.
///
/// ## How to read
///
///   auth_overhead ≈ authed_time − silent_time
///
/// In production, add ≈ 0.1 ms per-batch for real Ed25519/EIP-191 verification
/// (one-shot per batch call, not per quad).
///
/// | batch size | expected auth overhead |
/// |------------|------------------------|
/// | 1 000 q    | < 1 µs   (1 graph CID) |
/// | 10 000 q   | < 1 µs   (1 graph CID) |
/// | 100 000 q  | < 1 µs   (1 graph CID) |
fn bench_insert_batch_authed(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let graph_mb = make_cid(1).to_multibase();
    let chain = DelegationChain::new_for_test(&graph_mb, "datom:write");

    let mut group = c.benchmark_group("quad_store/insert_batch_authed");
    for n in [1_000u64, 10_000, 100_000] {
        let quads = make_quads(n);
        group.throughput(Throughput::Elements(n * 2));
        group.bench_with_input(BenchmarkId::from_parameter(n), &quads, |b, quads| {
            b.to_async(&rt).iter(|| async {
                let qs = make_store();
                // Auth gate: verify capability + graph scope + expiry (no crypto).
                // Real Ed25519 ≈ +0.1 ms per batch call.
                chain.verify_skip_sig(&graph_mb, "datom:write").unwrap();
                qs.assert_batch_silent(quads.clone()).await;
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
        b.to_async(&rt)
            .iter(|| async { qs.get_entity_quads(Some(&graph), &subject).await });
    });
    group.bench_function("lookup_by_predicate_object_avet", |b| {
        b.to_async(&rt)
            .iter(|| async { qs.lookup_subject_by_po(Some(&graph), "name", "Alice").await });
    });
    group.bench_function("quads_by_predicate_prefix_avet", |b| {
        b.to_async(&rt)
            .iter(|| async { qs.quads_by_predicate_prefix(Some(&graph), "name").await });
    });
    group.finish();
}

// ─── Cold-path: ProllyTree commit + re-read with simulated IPFS/S3 RTT ────────

/// Wraps MemoryBlockStore with a fixed sleep per get/put to simulate network RTT.
struct SimulatedLatencyBlockStore {
    inner: MemoryBlockStore,
    get_rtt: Duration,
    put_rtt: Duration,
}
impl SimulatedLatencyBlockStore {
    fn kubo_lan() -> Self {
        Self {
            inner: MemoryBlockStore::new(),
            get_rtt: ms(1),
            put_rtt: ms(2),
        }
    }
    fn kubo_wan() -> Self {
        Self {
            inner: MemoryBlockStore::new(),
            get_rtt: ms(80),
            put_rtt: ms(100),
        }
    }
    fn s3_same_az() -> Self {
        Self {
            inner: MemoryBlockStore::new(),
            get_rtt: ms(2),
            put_rtt: ms(10),
        }
    }
}
fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

impl BlockStore for SimulatedLatencyBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> Result<()> {
        std::thread::sleep(self.put_rtt);
        self.inner.put(cid, data)
    }
    fn get(&self, cid: &KotobaCid) -> Result<Option<Bytes>> {
        std::thread::sleep(self.get_rtt);
        self.inner.get(cid)
    }
    fn has(&self, cid: &KotobaCid) -> bool {
        self.inner.has(cid)
    }
    fn delete(&self, cid: &KotobaCid) -> Result<()> {
        self.inner.delete(cid)
    }
    fn pin(&self, cid: &KotobaCid) {
        self.inner.pin(cid)
    }
    fn unpin(&self, cid: &KotobaCid) {
        self.inner.unpin(cid)
    }
    fn is_pinned(&self, cid: &KotobaCid) -> bool {
        self.inner.is_pinned(cid)
    }
}

/// Build a small ProllyTree (1K entries) with a simulated-latency store, then
/// do a single-key lookup.  Each ProllyTree level = 1 BlockStore.get() call.
/// With a branching factor of ~256 entries/node, 1K entries = 1–2 levels.
///
/// This measures point-query (GET per level traversal) at realistic IPFS/S3 RTTs.
fn bench_query_cold_prolly(c: &mut Criterion) {
    let entries: Vec<(Vec<u8>, Vec<u8>)> = (0u64..1_000)
        .map(|i| (i.to_le_bytes().to_vec(), format!("v{i}").into_bytes()))
        .collect();
    let lookup_key = 500u64.to_le_bytes().to_vec();

    let scenarios: &[(&str, fn() -> SimulatedLatencyBlockStore)] = &[
        ("kubo_lan_1ms_get", SimulatedLatencyBlockStore::kubo_lan),
        ("kubo_wan_80ms_get", SimulatedLatencyBlockStore::kubo_wan),
        ("s3_same_az_2ms_get", SimulatedLatencyBlockStore::s3_same_az),
    ];

    let mut group = c.benchmark_group("quad_store/query_cold_prolly_1k");
    group.sample_size(10);

    for (name, make_store) in scenarios {
        let store = Arc::new(make_store());
        let root = ProllyTree::build_tree(entries.clone(), &*store).unwrap();

        group.bench_function(*name, |b| {
            b.iter(|| ProllyTree::get(&root, &lookup_key, &*store));
        });
    }
    group.finish();
}

// ─── Cold-path: QuadStore committed reads (EAVT / AEVT / AVET / VAET / multi-hop) ──

/// Build a committed QuadStore backed by SimulatedLatencyBlockStore.
/// Returns (qs, graph_cid, representative_subject_cid).
async fn make_committed_qs_latency(
    get_rtt: Duration,
    put_rtt: Duration,
    n_entities: u64,
) -> (QuadStore, KotobaCid, KotobaCid) {
    let inner = SimulatedLatencyBlockStore {
        inner: MemoryBlockStore::new(),
        get_rtt,
        put_rtt,
    };
    let store = Arc::new(inner) as Arc<dyn BlockStore + Send + Sync>;
    let qs = QuadStore::new(Arc::new(Journal::new()), store);
    let graph = make_cid(1);
    let quads: Vec<Quad> = (0..n_entities)
        .flat_map(|i| {
            let s = make_cid(i + 100);
            [
                Quad {
                    graph: graph.clone(),
                    subject: s.clone(),
                    predicate: "name".to_string(),
                    object: QuadObject::Text(format!("entity-{i}")),
                },
                Quad {
                    graph: graph.clone(),
                    subject: s.clone(),
                    predicate: "knows".to_string(),
                    object: QuadObject::Cid(make_cid((i + 1) % n_entities + 100)),
                },
            ]
        })
        .collect();
    qs.assert_batch_silent(quads).await;
    let graph_cid = qs.commit("did:bench", graph.clone(), 1).await.unwrap();
    qs.reset_arrangement(&graph_cid).await;
    let subject = make_cid(100 + n_entities / 2);
    (qs, graph_cid, subject)
}

/// Cold EAVT: `get_entity_quads_cold` — one subject's full attribute set.
fn bench_cold_eavt(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("quad_store/cold_eavt");
    group.sample_size(10);

    for (name, get_rtt, put_rtt) in [
        ("kubo_lan_1ms", ms(1), ms(2)),
        ("kubo_wan_80ms", ms(80), ms(100)),
        ("s3_same_az_2ms", ms(2), ms(10)),
    ] {
        let (qs, graph_cid, subject) =
            rt.block_on(make_committed_qs_latency(get_rtt, put_rtt, 1_000));
        group.bench_function(name, |b| {
            b.to_async(&rt).iter(|| async {
                qs.get_entity_quads_cold(&graph_cid, &subject)
                    .await
                    .unwrap()
            });
        });
    }
    group.finish();
}

/// Cold AEVT: `quads_by_predicate_prefix_cold` — all quads with predicate "name".
fn bench_cold_aevt(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("quad_store/cold_aevt");
    group.sample_size(10);

    for (name, get_rtt, put_rtt) in [
        ("kubo_lan_1ms", ms(1), ms(2)),
        ("kubo_wan_80ms", ms(80), ms(100)),
        ("s3_same_az_2ms", ms(2), ms(10)),
    ] {
        let (qs, graph_cid, _) = rt.block_on(make_committed_qs_latency(get_rtt, put_rtt, 1_000));
        group.bench_function(name, |b| {
            b.to_async(&rt).iter(|| async {
                qs.quads_by_predicate_prefix_cold(&graph_cid, "name")
                    .await
                    .unwrap()
            });
        });
    }
    group.finish();
}

/// Cold AVET: `lookup_subject_by_po_cold` — subjects where predicate=name, object="entity-100".
fn bench_cold_avet(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("quad_store/cold_avet");
    group.sample_size(10);

    for (name, get_rtt, put_rtt) in [
        ("kubo_lan_1ms", ms(1), ms(2)),
        ("kubo_wan_80ms", ms(80), ms(100)),
        ("s3_same_az_2ms", ms(2), ms(10)),
    ] {
        let (qs, graph_cid, _) = rt.block_on(make_committed_qs_latency(get_rtt, put_rtt, 1_000));
        group.bench_function(name, |b| {
            b.to_async(&rt).iter(|| async {
                qs.lookup_subject_by_po_cold(&graph_cid, "name", "entity-100")
                    .await
                    .unwrap()
            });
        });
    }
    group.finish();
}

/// Cold VAET: `reverse_lookup_cold` — all subjects that reference a given object CID.
fn bench_cold_vaet(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("quad_store/cold_vaet");
    group.sample_size(10);

    for (name, get_rtt, put_rtt) in [
        ("kubo_lan_1ms", ms(1), ms(2)),
        ("kubo_wan_80ms", ms(80), ms(100)),
        ("s3_same_az_2ms", ms(2), ms(10)),
    ] {
        // entity-100 is referenced by entity-99 via "knows"
        let object_cid = make_cid(100 + 500);
        let (qs, graph_cid, _) = rt.block_on(make_committed_qs_latency(get_rtt, put_rtt, 1_000));
        group.bench_function(name, |b| {
            b.to_async(&rt).iter(|| async {
                qs.reverse_lookup_cold(&graph_cid, &object_cid)
                    .await
                    .unwrap()
            });
        });
    }
    group.finish();
}

/// Cold multi-hop: BFS traversal 2 hops from start entity.
fn bench_cold_multi_hop(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("quad_store/cold_multi_hop");
    group.sample_size(10);

    for (name, get_rtt, put_rtt) in [
        ("kubo_lan_1ms", ms(1), ms(2)),
        ("s3_same_az_2ms", ms(2), ms(10)),
    ] {
        let (qs, graph_cid, start) = rt.block_on(make_committed_qs_latency(get_rtt, put_rtt, 200));
        group.bench_function(name, |b| {
            b.to_async(&rt)
                .iter(|| async { qs.multi_hop_cold(&graph_cid, &start, 2).await.unwrap() });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_insert_per_quad,
    bench_insert_batch,
    bench_insert_batch_chunked,
    bench_insert_batch_authed,
    bench_query_hot,
    bench_query_cold_prolly,
    bench_cold_eavt,
    bench_cold_aevt,
    bench_cold_avet,
    bench_cold_vaet,
    bench_cold_multi_hop,
);
criterion_main!(benches);
