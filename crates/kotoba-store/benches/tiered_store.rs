use anyhow::Result;
use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kotoba_core::{cid::KotobaCid, store::BlockStore};
use kotoba_store::{BudgetedBlockStore, MemoryBlockStore, TieredBlockStore};
/// TieredBlockStore benchmarks — hot/cold + simulated network latency.
///
/// Network model (realistic RTT assumptions, single-hop):
///
/// | Tier              | GET latency   | PUT latency   | Notes                        |
/// |-------------------|---------------|---------------|------------------------------|
/// | hot (memory)      | ~0 µs         | ~0 µs         | this file                    |
/// | cold (kubo LAN)   | ~0.5–2 ms     | ~1–5 ms       | Kubo HTTP, same datacenter |
/// | cold (kubo WAN)   | ~30–150 ms    | ~50–200 ms    | Kubo daemon, depends on node prox.   |
///
/// Simulated by a `SimulatedLatencyBlockStore` wrapper using `std::thread::sleep`.
use std::time::Duration;

// ─── Latency simulation ───────────────────────────────────────────────────────

struct SimulatedLatencyBlockStore {
    inner: MemoryBlockStore,
    get_rtt: Duration,
    put_rtt: Duration,
}

impl SimulatedLatencyBlockStore {
    fn new(get_rtt: Duration, put_rtt: Duration) -> Self {
        Self {
            inner: MemoryBlockStore::new(),
            get_rtt,
            put_rtt,
        }
    }

    /// kubo/HTTP LAN: GET ~1 ms, PUT ~2 ms
    fn kubo_lan() -> Self {
        Self::new(ms(1), ms(2))
    }
    /// kubo/HTTP WAN: GET ~80 ms, PUT ~100 ms
    fn kubo_wan() -> Self {
        Self::new(ms(80), ms(100))
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
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_cid(n: u64) -> KotobaCid {
    KotobaCid::from_bytes(&n.to_le_bytes())
}
fn make_block(n: u64) -> Vec<u8> {
    format!("block-data-{n:020}").into_bytes()
}

// ─── Baselines (no-network, memory only) ─────────────────────────────────────

fn bench_hot_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("network/baseline_hot_memory");
    for n in [100u64, 1_000] {
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let store = TieredBlockStore::new(MemoryBlockStore::new(), MemoryBlockStore::new());
                for i in 0..n {
                    store.put(&make_cid(i), &make_block(i)).unwrap();
                }
                for i in 0..n {
                    let _ = store.get(&make_cid(i)).unwrap();
                }
            });
        });
    }
    group.finish();
}

// ─── Cold-miss single GET (raw network overhead) ──────────────────────────────

fn bench_single_cold_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("network/cold_get_single");
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(20);

    let scenarios: &[(&str, Duration, Duration)] = &[
        ("kubo_lan_1ms", ms(1), ms(2)),
        ("kubo_wan_80ms", ms(80), ms(100)),
    ];

    for (name, get_rtt, put_rtt) in scenarios {
        let store = TieredBlockStore::new(
            MemoryBlockStore::new(),
            SimulatedLatencyBlockStore::new(*get_rtt, *put_rtt),
        );
        for i in 0..100 {
            store
                .cold()
                .inner
                .put(&make_cid(i), &make_block(i))
                .unwrap();
        }

        group.bench_function(*name, |b| {
            let mut i = 0u64;
            b.iter(|| {
                let target = i % 100;
                i += 1;
                let _ = store.get(&make_cid(target)).unwrap();
            });
        });
    }
    group.finish();
}

// ─── Cache amortization: first access (cold) vs repeat (hot) ─────────────────

fn bench_cold_vs_hot_amortization(c: &mut Criterion) {
    let mut group = c.benchmark_group("network/amortization");
    group.measurement_time(Duration::from_secs(12));
    group.sample_size(20);

    // kubo LAN: first access (cold miss + promote) vs repeat (hot hit)
    {
        group.bench_function("kubo_lan/first_access_50", |b| {
            b.iter(|| {
                let cold = SimulatedLatencyBlockStore::kubo_lan();
                for i in 0..50 {
                    cold.inner.put(&make_cid(i), &make_block(i)).unwrap();
                }
                let s = TieredBlockStore::new(MemoryBlockStore::new(), cold);
                for i in 0..50 {
                    let _ = s.get(&make_cid(i)).unwrap();
                }
            });
        });

        // Pre-warm hot tier then measure repeat hot-hit cost
        let cold2 = SimulatedLatencyBlockStore::kubo_lan();
        for i in 0..50 {
            cold2.inner.put(&make_cid(i), &make_block(i)).unwrap();
        }
        let store2 = TieredBlockStore::new(MemoryBlockStore::new(), cold2);
        for i in 0..50 {
            let _ = store2.get(&make_cid(i)).unwrap();
        }

        group.bench_function("kubo_lan/repeat_access_hot_50", |b| {
            b.iter(|| {
                for i in 0..50 {
                    let _ = store2.get(&make_cid(i)).unwrap();
                }
            });
        });
    }

    group.finish();
}

// ─── Baselines (in-memory, no network) ───────────────────────────────────────

fn bench_hot_put_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered/hot");
    for n in [1_000u64, 10_000] {
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::new("put+get", n), &n, |b, &n| {
            b.iter(|| {
                let store = TieredBlockStore::new(MemoryBlockStore::new(), MemoryBlockStore::new());
                for i in 0..n {
                    store.put(&make_cid(i), &make_block(i)).unwrap();
                }
                for i in 0..n {
                    let _ = store.get(&make_cid(i)).unwrap();
                }
            });
        });
    }
    group.finish();
}

fn bench_cold_promote(c: &mut Criterion) {
    let mut group = c.benchmark_group("tiered/cold_promote");
    for n in [100u64, 1_000] {
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let hot = MemoryBlockStore::new();
                let cold = MemoryBlockStore::new();
                for i in 0..n {
                    cold.put(&make_cid(i), &make_block(i)).unwrap();
                }
                let store = TieredBlockStore::new(hot, cold);
                for i in 0..n {
                    let _ = store.get(&make_cid(i)).unwrap();
                }
                for i in 0..n {
                    assert!(store.has(&make_cid(i)));
                }
            });
        });
    }
    group.finish();
}

fn bench_budgeted_eviction(c: &mut Criterion) {
    c.bench_function("budgeted/evict_under_pressure", |b| {
        b.iter(|| {
            let store = BudgetedBlockStore::new(MemoryBlockStore::new(), 1024 * 1024);
            for i in 0..256u64 {
                let data: Vec<u8> = vec![i as u8; 8192];
                let _ = store.put(&make_cid(i), &data);
            }
            store.used_bytes()
        });
    });
}

criterion_group!(
    benches,
    bench_hot_only,
    bench_hot_put_get,
    bench_cold_promote,
    bench_budgeted_eviction,
    bench_single_cold_get,
    bench_cold_vs_hot_amortization,
);
criterion_main!(benches);
