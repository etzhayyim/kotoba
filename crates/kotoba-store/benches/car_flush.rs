/// CAR bundle flush benchmarks.
///
/// Measures three things:
///
/// 1. `car/serialize_Nblocks`    — pack N blocks into a single CAR byte buffer
///    (pure CPU: no I/O, no network). Models the serialization overhead of
///    `CarBundleWriter::finish()` per commit.
///
/// 2. `car/flush_simulated`      — serialize + simulate a single PUT to S3/B2/kubo,
///    vs the same blocks sent as N individual PUTs.
///    Uses `std::thread::sleep` to model realistic network latency.
///
/// 3. `car/range_get_simulated`  — simulate a cold range GET for a single block
///    from a pre-uploaded CAR (one HTTP range GET vs one full block GET).
///
/// Block sizing for the 1M-quad commit scenario:
///   ~15,873 blocks, ~4 KB average → ~63 MB total CAR file.
///
/// Network latency model (same as tiered_store bench):
///   S3 same-AZ    : PUT ~10 ms,  GET ~2 ms  (range GET ≈ GET)
///   B2 same-AZ    : PUT ~15 ms,  GET ~3 ms
///   kubo LAN      : PUT ~2 ms,   GET ~1 ms
use std::time::Duration;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kotoba_core::cid::KotobaCid;
use kotoba_store::{CarBundleWriter, CarBlockIndex, parse_index, extract_block};

fn fake_cid(n: u64) -> KotobaCid { KotobaCid::from_bytes(&n.to_le_bytes()) }

/// Generate `count` fake blocks of `block_size` bytes each.
fn gen_blocks(count: usize, block_size: usize) -> Vec<(KotobaCid, Vec<u8>)> {
    (0..count as u64)
        .map(|i| {
            let cid  = fake_cid(i + 1);
            let data = vec![(i & 0xff) as u8; block_size];
            (cid, data)
        })
        .collect()
}

// ─── 1. Serialization throughput ──────────────────────────────────────────────

fn bench_serialize(c: &mut Criterion) {
    // (block_count, block_size_bytes, label)
    // Representative commit sizes:
    //   small  : 1K blocks × 1 KB  = 1 MB  (100K quads)
    //   medium : 4K blocks × 4 KB  = 16 MB (400K quads, single ProllyTree)
    //   commit : 16K blocks × 4 KB = 64 MB (1M quads, 4 trees)
    let scenarios: &[(&str, usize, usize)] = &[
        ("1K×1KB",   1_000,  1_024),
        ("4K×4KB",   4_000,  4_096),
        ("16K×4KB", 16_000,  4_096),
    ];

    let mut group = c.benchmark_group("car/serialize");
    for (label, n_blocks, block_size) in scenarios {
        let total_bytes = (n_blocks * block_size) as u64;
        group.throughput(Throughput::Bytes(total_bytes));
        group.bench_with_input(
            BenchmarkId::new("blocks", label),
            &(*n_blocks, *block_size),
            |b, &(n, sz)| {
                let blocks = gen_blocks(n, sz);
                let root   = fake_cid(0);
                b.iter(|| {
                    let mut w = CarBundleWriter::new(root.clone());
                    for (cid, data) in &blocks { w.append(cid, data); }
                    let (car, _idx) = w.finish();
                    car.len() // prevent optimization
                });
            },
        );
    }
    group.finish();
}

// ─── 2. Single-PUT vs per-block-PUT flush comparison ─────────────────────────

/// Simulate uploading `n_blocks` blocks as a single CAR PUT.
/// Returns (car_size_bytes, simulated_duration).
fn simulate_car_flush(
    blocks: &[(KotobaCid, Vec<u8>)],
    root: &KotobaCid,
    put_latency: Duration,
) -> (usize, Duration) {
    let mut w = CarBundleWriter::new(root.clone());
    for (cid, data) in blocks { w.append(cid, data); }
    let (car, _) = w.finish();
    let car_size = car.len();

    // 1 PUT for the entire CAR
    std::thread::sleep(put_latency);
    (car_size, put_latency)
}

/// Simulate uploading `n_blocks` blocks as individual PUTs (current approach).
fn simulate_individual_flush(n_blocks: usize, put_latency: Duration) -> Duration {
    // Serial individual PUTs (worst case)
    let total = put_latency * n_blocks as u32;
    std::thread::sleep(total);
    total
}

fn bench_flush_comparison(c: &mut Criterion) {
    // Use very small sleep values so the bench completes in reasonable time.
    // We scale down actual latencies by 1000× for benchmarking purposes
    // and report the extrapolated real-world estimate in comments.
    //
    // Real:  S3 PUT 10ms → bench sleep 10µs
    //        kubo PUT 2ms → bench sleep 2µs
    //
    // 400 blocks = representative single ProllyTree (100K quads)
    // 16K blocks = full 1M-quad commit (4 trees × 4K blocks)

    let scenarios: &[(&str, usize, u64, &str)] = &[
        // (label, n_blocks, put_µs, network)
        ("400blk_s3",   400,  10, "S3 same-AZ 10ms/PUT → 4s serial → 10ms CAR"),
        ("16K blk_s3",  16_000,  10, "S3 same-AZ: 160s serial → 10ms CAR"),
        ("400blk_kubo",  400,   2, "kubo LAN 2ms/PUT → 0.8s serial → 2ms CAR"),
        ("16K blk_kubo", 16_000,   2, "kubo LAN: 32s serial → 2ms CAR"),
    ];

    let mut group = c.benchmark_group("car/flush_simulated");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(8));

    for (label, n_blocks, put_µs, _desc) in scenarios {
        let put_latency = Duration::from_micros(*put_µs);
        let blocks      = gen_blocks(*n_blocks, 512); // smaller blocks for bench speed
        let root        = fake_cid(0);

        group.bench_function(format!("car_single_put/{label}"), |b| {
            b.iter(|| {
                simulate_car_flush(&blocks, &root, put_latency)
            });
        });
    }

    // Per-block serial (only for small N — large N takes too long even with µs sleep)
    for (label, n_blocks, put_µs, _desc) in &scenarios[..2] {
        let put_latency = Duration::from_micros(*put_µs);

        group.bench_function(format!("per_block_serial/{label}"), |b| {
            b.iter(|| simulate_individual_flush(*n_blocks, put_latency));
        });
    }

    group.finish();
}

// ─── 3. Range GET simulation ──────────────────────────────────────────────────

/// Cold range GET: look up a CID in the index → extract from CAR bytes.
/// In production this is a single HTTP range GET; here we simulate it by
/// pre-building the CAR in memory and doing an in-memory slice + sleep.
fn bench_range_get(c: &mut Criterion) {
    let n_blocks = 4_000usize; // single ProllyTree, 400K quads
    let block_sz = 4_096usize;
    let blocks   = gen_blocks(n_blocks, block_sz);
    let root     = fake_cid(0);

    // Build CAR once
    let mut w = CarBundleWriter::new(root);
    for (cid, data) in &blocks { w.append(cid, data); }
    let (car_bytes, idx_entries) = w.finish();

    // Populate CarBlockIndex
    let mut index = CarBlockIndex::new();
    index.insert_car("commit-bench", &idx_entries);

    let car_slice = car_bytes.as_slice();

    // Target block in the middle of the file
    let target_cid = fake_cid(n_blocks as u64 / 2);

    let mut group = c.benchmark_group("car/range_get");
    group.sample_size(100);

    // Baseline: extract with no simulated I/O (pure in-memory slice cost)
    group.bench_function("index_lookup+extract_noio/4K_blocks", |b| {
        b.iter(|| {
            let (_, off, len) = index.get(&target_cid).unwrap();
            extract_block(car_slice, off, len).unwrap()
        });
    });

    // Simulated S3 range GET (2ms — same latency as a full block GET)
    group.bench_function("simulated_s3_2ms/range_get", |b| {
        b.iter(|| {
            let (_, off, len) = index.get(&target_cid).unwrap();
            std::thread::sleep(Duration::from_millis(2));
            extract_block(car_slice, off, len).unwrap()
        });
    });

    // Simulated kubo LAN range GET (1ms)
    group.bench_function("simulated_kubo_lan_1ms/range_get", |b| {
        b.iter(|| {
            let (_, off, len) = index.get(&target_cid).unwrap();
            std::thread::sleep(Duration::from_millis(1));
            extract_block(car_slice, off, len).unwrap()
        });
    });

    group.finish();
}

// ─── 4. Index insertion throughput (after commit) ────────────────────────────

fn bench_index_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("car/index_insert");

    for n in [1_000usize, 16_000] {
        let blocks = gen_blocks(n, 64);
        let root   = fake_cid(0);

        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                let mut w = CarBundleWriter::new(root.clone());
                for (cid, data) in &blocks { w.append(cid, data); }
                let (_, idx) = w.finish();

                let mut index = CarBlockIndex::new();
                index.insert_car("car-key", &idx);
                index.len()
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_serialize,
    bench_flush_comparison,
    bench_range_get,
    bench_index_insert,
);
criterion_main!(benches);
