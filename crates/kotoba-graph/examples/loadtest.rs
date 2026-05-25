/// Load test: Arrangement 4-index + QuadStore commit cycle at 1M / 10M / 100M quads.
///
/// Usage:
///   cargo run --release --example loadtest -p kotoba-graph
///   LOADTEST_MAX=100M cargo run --release --example loadtest -p kotoba-graph
///
/// Output format: TSV lines → easy to paste into a spreadsheet.
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use kotoba_core::cid::KotobaCid;
use kotoba_graph::quad_store::QuadStore;
use kotoba_kqe::{
    arrangement::Arrangement,
    quad::{Quad, QuadObject},
};
use kotoba_kse::journal::Journal;
use kotoba_store::MemoryBlockStore;

// ─── RSS helper (macOS / Linux) ──────────────────────────────────────────────

fn rss_mb() -> f64 {
    #[cfg(target_os = "macos")]
    {
        // task_info MACH_TASK_BASIC_INFO → resident_size (bytes)
        use std::mem;
        extern "C" {
            fn task_info(
                target_task: u32,
                flavor: u32,
                task_info_out: *mut i32,
                task_info_count: *mut u32,
            ) -> i32;
            fn mach_task_self_() -> u32;
        }
        const MACH_TASK_BASIC_INFO: u32 = 20;
        const MACH_TASK_BASIC_INFO_COUNT: u32 = 12;
        #[repr(C)]
        struct MachTaskBasicInfo {
            virtual_size:     u64,
            resident_size:    u64,
            resident_size_max:u64,
            user_time:        [u32; 2],
            system_time:      [u32; 2],
            policy:           i32,
            suspend_count:    i32,
        }
        unsafe {
            let mut info: MachTaskBasicInfo = mem::zeroed();
            let mut count = MACH_TASK_BASIC_INFO_COUNT;
            task_info(
                mach_task_self_(),
                MACH_TASK_BASIC_INFO,
                &mut info as *mut _ as *mut i32,
                &mut count,
            );
            info.resident_size as f64 / 1_048_576.0
        }
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<f64>().ok())
            })
            .map(|kb| kb / 1024.0)
            .unwrap_or(0.0)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    { 0.0 }
}

// ─── Quad generators ─────────────────────────────────────────────────────────

fn cid(n: u64) -> KotobaCid { KotobaCid::from_bytes(&n.to_le_bytes()) }

fn text_quad(g: u64, s: u64, p: &str, o: &str) -> Quad {
    Quad { graph: cid(g), subject: cid(s), predicate: p.to_string(),
           object: QuadObject::Text(o.to_string()) }
}

fn ref_quad(g: u64, s: u64, p: &str, o: u64) -> Quad {
    Quad { graph: cid(g), subject: cid(s), predicate: p.to_string(),
           object: QuadObject::Cid(cid(o)) }
}

// Two quads per "entity": one text attr, one CID ref (exercises all 4 indexes)
fn insert_n(arr: &mut Arrangement, n: u64, base_s: u64, g: u64) {
    for i in 0..n {
        let s = base_s + i;
        arr.insert(&text_quad(g, s,     "name",  "Alice"));
        arr.insert(&ref_quad (g, s,     "knows", (s + 1) % (n + base_s + 1)));
    }
}

// ─── Latency histogram (p50 / p95 / p99) ─────────────────────────────────────

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let idx = ((sorted.len() as f64 * p / 100.0) as usize).min(sorted.len() - 1);
    sorted[idx]
}

fn query_latencies(arr: &Arrangement, n: u64, g: u64, iters: usize) -> (Duration, Duration, Duration) {
    let mut times = Vec::with_capacity(iters * 4);
    let bound = n.max(1);

    for i in 0..iters {
        let s = cid((i as u64 * 7919) % bound);       // pseudo-random subject
        let p = if i % 2 == 0 { "name" } else { "knows" };
        let ocid = cid(((i as u64 + 1) * 6271) % bound);

        // EAVT
        let t = Instant::now(); let _ = arr.get_objects(&s, p); times.push(t.elapsed());
        // AEVT
        let t = Instant::now(); let _ = arr.get_subjects_by_predicate(p); times.push(t.elapsed());
        // AVET
        let t = Instant::now(); let _ = arr.get_subjects_by_predicate_object(p, "Alice"); times.push(t.elapsed());
        // VAET
        let t = Instant::now(); let _ = arr.get_referencing_subjects(&ocid); times.push(t.elapsed());
    }
    times.sort_unstable();
    (percentile(&times, 50.0), percentile(&times, 95.0), percentile(&times, 99.0))
}

// ─── Phase 1: pure Arrangement (in-memory) ───────────────────────────────────

fn phase1(targets: &[u64]) {
    println!("\n=== Phase 1: Arrangement (in-memory, 4-index) ===");
    println!("{:<12}  {:>10}  {:>10}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}",
        "quads", "insert_ms", "MB_rss", "p50_us", "p95_us", "p99_us",
        "quad/s", "MB/Mquad");

    for &n in targets {
        let mut arr = Arrangement::new();
        let before_mb = rss_mb();

        let t0 = Instant::now();
        insert_n(&mut arr, n / 2, 0, 1);   // n/2 entities × 2 quads = n quads
        let insert_ms = t0.elapsed().as_millis();

        let after_mb = rss_mb();
        let delta_mb = after_mb - before_mb;
        let qps = (n as f64 / (insert_ms as f64 / 1000.0)) as u64;
        let mb_per_mq = delta_mb / (n as f64 / 1_000_000.0);

        let (p50, p95, p99) = query_latencies(&arr, n / 2, 1, 2000);

        println!("{:<12}  {:>10}  {:>10.1}  {:>8.1}  {:>8.1}  {:>8.1}  {:>8}  {:>8.0}",
            fmt_n(n), insert_ms, delta_mb,
            p50.as_micros(), p95.as_micros(), p99.as_micros(),
            qps, mb_per_mq);
    }
}

// ─── Phase 2: QuadStore + MemoryBlockStore, batch-commit cycle ───────────────

#[tokio::main]
async fn main() {
    let max_str = std::env::var("LOADTEST_MAX").unwrap_or_else(|_| "10M".to_string());
    let max: u64 = parse_scale(&max_str);

    // Phase 1: in-memory arrangement only
    let p1_targets: Vec<u64> = [1_000_000u64, 10_000_000]
        .into_iter()
        .filter(|&t| t <= max)
        .collect();
    if !p1_targets.is_empty() {
        phase1(&p1_targets);
    }

    // Phase 2: QuadStore commit cycle (batch 1M, repeat up to max)
    if max >= 1_000_000 {
        phase2(max).await;
    }
}

async fn phase2(total: u64) {
    const BATCH: u64 = 1_000_000; // quads per batch (= 500K entities × 2 quads)
    let batches = (total / BATCH).max(1);

    println!("\n=== Phase 2: QuadStore commit cycle (MemoryBlockStore, batch={}) ===", fmt_n(BATCH));
    println!("{:<8}  {:>10}  {:>12}  {:>10}  {:>10}  {:>10}  {:>10}",
        "batch", "insert_ms", "total_quads", "commit_ms", "MB_rss",
        "ins_q/s", "cum_q/s");

    let journal     = Arc::new(Journal::new());
    let block_store = Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
    let qs          = QuadStore::new(journal, block_store);
    let graph       = cid(999);

    let mut total_quads = 0u64;
    let run_start = Instant::now();

    for batch in 0..batches {
        let base_s  = batch * (BATCH / 2);
        let t_ins   = Instant::now();

        // Insert BATCH quads (BATCH/2 entities × 2 quads each)
        for i in 0..(BATCH / 2) {
            let s = base_s + i;
            qs.assert_silent(text_quad(999, s, "name", "Alice")).await;
            qs.assert_silent(ref_quad (999, s, "knows", (s + 1) % (base_s + BATCH / 2 + 1))).await;
        }
        let insert_ms = t_ins.elapsed().as_millis();
        total_quads  += BATCH;

        // Commit to ProllyTree
        let t_commit = Instant::now();
        let _cid = qs.commit("did:loadtest", graph.clone(), batch + 1).await.unwrap();
        let commit_ms = t_commit.elapsed().as_millis();

        // Clear in-memory arrangement to reclaim RAM for next batch
        qs.reset_arrangement(&graph).await;

        let rss      = rss_mb();
        let ins_qps  = (BATCH as f64 / (insert_ms as f64 / 1000.0)) as u64;
        let cum_qps  = (total_quads as f64 / run_start.elapsed().as_secs_f64()) as u64;

        println!("{:<8}  {:>10}  {:>12}  {:>10}  {:>10.1}  {:>10}  {:>10}",
            batch + 1, insert_ms, fmt_n(total_quads), commit_ms, rss,
            ins_qps, cum_qps);
    }

    println!("\n  total: {} quads in {:.1}s  avg throughput: {} quad/s",
        fmt_n(total_quads),
        run_start.elapsed().as_secs_f64(),
        (total_quads as f64 / run_start.elapsed().as_secs_f64()) as u64);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn fmt_n(n: u64) -> String {
    if n >= 1_000_000_000 { format!("{:.0}B", n as f64 / 1e9) }
    else if n >= 1_000_000 { format!("{:.0}M", n as f64 / 1e6) }
    else if n >= 1_000     { format!("{:.0}K", n as f64 / 1e3) }
    else                   { n.to_string() }
}

fn parse_scale(s: &str) -> u64 {
    let s = s.trim().to_uppercase();
    if let Some(n) = s.strip_suffix('B') {
        (n.parse::<f64>().unwrap_or(1.0) * 1e9) as u64
    } else if let Some(n) = s.strip_suffix('M') {
        (n.parse::<f64>().unwrap_or(1.0) * 1e6) as u64
    } else if let Some(n) = s.strip_suffix('K') {
        (n.parse::<f64>().unwrap_or(1.0) * 1e3) as u64
    } else {
        s.parse::<u64>().unwrap_or(10_000_000)
    }
}
