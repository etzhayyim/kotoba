/// QuadStore insert benchmarks — per-quad async vs. batch insert.
///
/// Measures wall-clock throughput (quads/s) for the full QuadStore insert path
/// including RwLock acquisition, so the batch speedup shows clearly.
///
/// Run:
///   cargo bench -p kotoba-graph --bench quad_store
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kotoba_core::cid::KotobaCid;
use kotoba_graph::quad_store::QuadStore;
use kotoba_kqe::quad::{Quad, QuadObject};
use kotoba_kse::journal::Journal;
use kotoba_store::MemoryBlockStore;
use std::sync::Arc;

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
    for n in [1_000u64, 10_000, 100_000] {
        let quads = make_quads(n);
        group.throughput(Throughput::Elements(n * 2)); // 2 quads per entity
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

criterion_group!(
    benches,
    bench_insert_per_quad,
    bench_insert_batch,
    bench_insert_batch_chunked,
);
criterion_main!(benches);
