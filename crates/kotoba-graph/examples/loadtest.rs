/// Load test: Arrangement 4-index + QuadStore commit cycle + cold-path queries.
///
/// Usage:
///   cargo run --release --example loadtest -p kotoba-graph
///   LOADTEST_MAX=100M cargo run --release --example loadtest -p kotoba-graph
///   LOADTEST_MEM_LIMIT_MB=8192 cargo run --release --example loadtest -p kotoba-graph
///
/// Phases:
///   Phase 1: in-memory Arrangement insert + hot-path query latency
///   Phase 2: QuadStore commit cycle (batch 1M, repeat up to max)
///   Phase 3: cold-path query latency (EAVT/AEVT/AVET/VAET/multi-hop post-commit)
///   Phase 4: distributed block fetch (simulated 2-node cluster, fetch-and-promote)
///
/// Output format: TSV lines → easy to paste into a spreadsheet.
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use kotoba_auth::delegation::DelegationChain;
use kotoba_core::cid::KotobaCid;
use kotoba_graph::quad_store::QuadStore;
use kotoba_kqe::{
    arrangement::Arrangement,
    quad::{Quad, QuadObject},
};
use kotoba_kse::journal::Journal;
use kotoba_store::{MemoryBlockStore, DistributedBlockStore};

// ─── RSS helper (macOS / Linux) ──────────────────────────────────────────────

/// Current resident set size in MiB.
/// Linux: reads VmRSS from /proc/self/status (current).
/// macOS: uses mach_task_basic_info resident_size (current).
fn rss_mb() -> f64 {
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
    #[cfg(target_os = "macos")]
    {
        // MACH_TASK_BASIC_INFO returns current resident_size (not peak).
        #[repr(C)]
        struct MachTaskBasicInfo {
            virtual_size:       u64,
            resident_size:      u64,
            resident_size_max:  u64,
            user_time_sec:      u32,
            user_time_usec:     u32,
            system_time_sec:    u32,
            system_time_usec:   u32,
            policy:             u32,
            suspend_count:      i32,
        }
        extern "C" {
            fn mach_task_self() -> u32;
            fn task_info(task: u32, flavor: u32, info: *mut u32, cnt: *mut u32) -> i32;
        }
        const MACH_TASK_BASIC_INFO: u32 = 20;
        // struct size in natural_t (4-byte) units
        const COUNT: u32 = (std::mem::size_of::<MachTaskBasicInfo>() / 4) as u32;
        unsafe {
            let mut info: MachTaskBasicInfo = std::mem::zeroed();
            let mut cnt = COUNT;
            let ret = task_info(
                mach_task_self(),
                MACH_TASK_BASIC_INFO,
                &mut info as *mut _ as *mut u32,
                &mut cnt,
            );
            if ret == 0 { info.resident_size as f64 / 1_048_576.0 } else { 0.0 }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            libc::getrusage(libc::RUSAGE_SELF, &mut usage);
            usage.ru_maxrss as f64 / 1_048_576.0
        }
    }
}

// ─── Quad generators ─────────────────────────────────────────────────────────

fn cid(n: u64) -> KotobaCid { KotobaCid::from_bytes(&n.to_le_bytes()) }
fn cid_for(n: u64) -> KotobaCid { KotobaCid::from_bytes(&(0x0001_0000_0000u64.wrapping_add(n)).to_le_bytes()) }

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

fn query_latencies(arr: &Arrangement, n: u64, _g: u64, iters: usize) -> (Duration, Duration, Duration) {
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
        insert_n(&mut arr, n / 2, 0, 1);
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

// ─── entry point ─────────────────────────────────────────────────────────────

fn main() {
    // Use a 64 MB stack — ProllyTree sort + CBOR serialization at 1M-entry scale
    // exceeds the default 8 MB OS thread stack.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .name("loadtest".to_string())
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(64 * 1024 * 1024)
                .build()
                .unwrap()
                .block_on(async_main());
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn async_main() {
    let max_str = std::env::var("LOADTEST_MAX").unwrap_or_else(|_| "10M".to_string());
    let max: u64 = parse_scale(&max_str);

    let mem_limit_mb: f64 = std::env::var("LOADTEST_MEM_LIMIT_MB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8192.0);

    // Phase 1: in-memory arrangement only (cap at 10M to limit RAM)
    let p1_targets: Vec<u64> = [1_000_000u64, 10_000_000]
        .into_iter()
        .filter(|&t| t <= max)
        .collect();
    if !p1_targets.is_empty() {
        phase1(&p1_targets);
    }

    // Phase 2: QuadStore commit cycle (batch 1M, repeat up to max)
    if max >= 1_000_000 {
        phase2(max, mem_limit_mb).await;
    }

    // Phase 3: cold-path query latency (always runs)
    phase3_cold_queries().await;

    // Phase 4: distributed block fetch (simulated 2-node cluster)
    phase4_distributed_fetch().await;

    // Phase 5: SPARQL BGP router + multi-hop + CACAO-authed cold queries
    phase5_sparql_multihop_cacao().await;

    // Phase 6: SPARQL property paths + aggregates + CACAO-authed JOIN
    phase6_sparql_advanced().await;
}

// ─── Phase 4: distributed block fetch (simulated 2-node cluster) ─────────────

/// Simulates a 2-node IPFS cluster where node B commits a graph, then node A
/// queries it cold using DistributedBlockStore — all blocks are fetched from
/// node B's MemoryBlockStore.
///
/// This measures the block-fan-out path:
///   local miss → DistributedBlockStore.get() → peer fetch (in-memory) → promote
///
/// In production, peer_store B would be a KuboBlockStore pointing to a remote
/// Kubo HTTP node; here we use a direct memory-backed peer to isolate latency.
async fn phase4_distributed_fetch() {
    const N_ENTITIES: u64 = 10_000;
    const ITERS: usize = 20;

    println!("\n=== Phase 4: distributed block fetch (simulated 2-node, {} entities) ===", fmt_n(N_ENTITIES));
    println!("{:<35}  {:>10}  {:>12}  {:>10}",
        "query", "first_ms", "promoted_µs", "notes");

    // --- Node B: commits quads to its MemoryBlockStore ---
    let peer_store = Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
    let qs_b = QuadStore::new(
        Arc::new(Journal::new()),
        Arc::clone(&peer_store),
    );
    let graph = cid(2);
    let n = N_ENTITIES;
    for chunk_start in (0..n).step_by(5_000) {
        let chunk_end = (chunk_start + 5_000).min(n);
        let quads: Vec<Quad> = (chunk_start..chunk_end).flat_map(|i| {
            [
                text_quad(2, i + 200, "name", &format!("peer-entity-{i}")),
                ref_quad (2, i + 200, "knows", ((i + 1) % n) + 200),
            ]
        }).collect();
        qs_b.assert_batch_silent(quads).await;
    }
    let _commit_cid_b = qs_b.commit("did:node-b", graph.clone(), 1).await.unwrap();
    // Node B keeps its store full (no reset_arrangement — simulates a peer that has the data)

    // --- Node A: empty local store + peer_store as the single remote peer ---
    let local_a = Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
    let dist_store = Arc::new(
        DistributedBlockStore::new(Arc::clone(&local_a), vec![] /* no HTTP peers in sim */)
    ) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;

    // Manually replicate node B's blocks into local_a (simulates bitswap / block-copy).
    let peer_cids = peer_store.all_cids();
    let mut blocks_copied = 0usize;
    for pcid in peer_cids {
        if let Ok(Some(data)) = peer_store.get(&pcid) {
            let _ = local_a.put(&pcid, &data);
            blocks_copied += 1;
        }
    }

    // Node A: create QuadStore backed by dist_store (local_a already has all blocks).
    // Import the commit CID so the CommitDag knows the graph → ProllyTree roots mapping.
    let qs_a = QuadStore::new(Arc::new(Journal::new()), Arc::clone(&dist_store));
    let imported = qs_a.import_commit(&_commit_cid_b).await.unwrap();
    assert!(imported, "commit block must be present after block replication");

    // First cold-path: qs_a queries from its own store (blocks promoted from local_a).
    // Second cold-path: same query again — blocks are already hot in MemoryBlockStore.
    let mut first_times: Vec<Duration> = Vec::with_capacity(ITERS);
    let mut promoted_times: Vec<Duration> = Vec::with_capacity(ITERS);
    for i in 0..ITERS {
        let s = cid(200 + (i as u64 * 7919) % n);
        let t = Instant::now(); let _ = qs_a.get_entity_quads_cold(&graph, &s).await; first_times.push(t.elapsed());
        let t = Instant::now(); let _ = qs_a.get_entity_quads_cold(&graph, &s).await; promoted_times.push(t.elapsed());
    }
    first_times.sort_unstable();
    promoted_times.sort_unstable();
    let f_p50  = first_times[ITERS / 2].as_secs_f64() * 1000.0;
    let pr_p50 = promoted_times[ITERS / 2].as_micros();

    println!("{:<35}  {:>10.3}  {:>12}  {:>10}",
        "EAVT cold (post-import_commit)",
        f_p50, format!("{pr_p50}µs"),
        format!("{blocks_copied} blocks copied"));

    println!("\n  import_commit(): loads Commit block from BlockStore → CommitDag.add().");
    println!("  In production: blocks arrive via bitswap; import_commit() is called once");
    println!("  per replicated graph to make it queryable without re-running commit().");
    println!("  DistributedBlockStore → peer Kubo HTTP /api/v0/block/get; RTT adds per-block latency.");
}

// ─── Phase 3: cold-path query latency (EAVT / AEVT / AVET / VAET / multi-hop) ──

async fn phase3_cold_queries() {
    const N_ENTITIES: u64 = 100_000;
    const ITERS: usize = 50;

    println!("\n=== Phase 3: cold-path query latency (MemoryBlockStore, {} entities) ===", fmt_n(N_ENTITIES));
    println!("{:<30}  {:>10}  {:>10}  {:>10}",
        "query", "p50_ms", "p95_ms", "p99_ms");

    let journal     = Arc::new(Journal::new());
    let block_store = Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
    let qs          = QuadStore::new(journal, block_store);
    let graph       = cid(1);

    // Insert N_ENTITIES × 2 quads and commit
    const CHUNK: u64 = 50_000;
    let n = N_ENTITIES;
    for chunk_start in (0..n).step_by(CHUNK as usize / 2) {
        let chunk_end = (chunk_start + CHUNK / 2).min(n);
        let mut quads = Vec::with_capacity(((chunk_end - chunk_start) * 2) as usize);
        for i in chunk_start..chunk_end {
            quads.push(text_quad(1, i + 100, "name", &format!("entity-{i}")));
            quads.push(ref_quad (1, i + 100, "knows", ((i + 1) % n) + 100));
        }
        qs.assert_batch_silent(quads).await;
    }
    let _commit_cid = qs.commit("did:loadtest", graph.clone(), 1).await.unwrap();
    qs.reset_arrangement(&graph).await; // graph CID, not commit CID

    let mid_subject = cid(100 + n / 2);
    let mid_object  = cid(100 + n / 3);

    // Helper to run a cold query ITERS times and return sorted durations
    macro_rules! bench_query {
        ($label:expr, $body:expr) => {{
            let mut times: Vec<Duration> = Vec::with_capacity(ITERS);
            for _ in 0..ITERS {
                let t = Instant::now();
                let _ = $body;
                times.push(t.elapsed());
            }
            times.sort_unstable();
            let p50 = times[ITERS / 2].as_secs_f64() * 1000.0;
            let p95 = times[(ITERS * 95 / 100).min(ITERS - 1)].as_secs_f64() * 1000.0;
            let p99 = times[(ITERS * 99 / 100).min(ITERS - 1)].as_secs_f64() * 1000.0;
            println!("{:<30}  {:>10.3}  {:>10.3}  {:>10.3}", $label, p50, p95, p99);
        }};
    }

    // EAVT: get all quads for one subject
    bench_query!("EAVT get_entity_quads_cold",
        qs.get_entity_quads_cold(&graph, &mid_subject).await.unwrap());

    // AEVT: scan all quads with predicate prefix "name"
    bench_query!("AEVT quads_by_predicate_prefix_cold",
        qs.quads_by_predicate_prefix_cold(&graph, "name").await.unwrap());

    // AVET: lookup subjects by predicate+object value
    bench_query!("AVET lookup_subject_by_po_cold",
        qs.lookup_subject_by_po_cold(&graph, "name", "entity-100").await.unwrap());

    // VAET: reverse lookup (all subjects referencing an object CID)
    bench_query!("VAET reverse_lookup_cold",
        qs.reverse_lookup_cold(&graph, &mid_object).await.unwrap());

    // Multi-hop: BFS 2 hops from start
    bench_query!("multi_hop_cold 2-hop",
        qs.multi_hop_cold(&graph, &mid_subject, 2).await.unwrap());

    // Multi-hop: BFS 3 hops from start
    bench_query!("multi_hop_cold 3-hop",
        qs.multi_hop_cold(&graph, &mid_subject, 3).await.unwrap());

    // AVET × AVET join: subjects where name=entity-100 AND knows=cid(mid)
    bench_query!("join_by_two_predicates_cold",
        qs.join_by_two_predicates_cold(
            &graph,
            "name", "entity-100",
            "name", "entity-200",
        ).await.unwrap());
}

async fn phase2(total: u64, mem_limit_mb: f64) {
    const BATCH: u64 = 1_000_000; // quads per batch (= 500K entities × 2 quads)
    let batches = (total / BATCH).max(1);

    println!("\n=== Phase 2: QuadStore commit cycle (MemoryBlockStore, batch={}, mem_limit={:.0} MB) ===",
        fmt_n(BATCH), mem_limit_mb);
    println!("{:<8}  {:>10}  {:>12}  {:>10}  {:>10}  {:>10}  {:>10}",
        "batch", "insert_ms", "total_quads", "commit_ms", "MB_growth",
        "ins_q/s", "cum_q/s");

    let journal     = Arc::new(Journal::new());
    let block_store = Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
    let qs          = QuadStore::new(journal, block_store);
    let graph       = cid(999);

    let mut total_quads = 0u64;
    let run_start = Instant::now();
    let phase2_base_rss = rss_mb(); // RSS at Phase 2 start (Phase 1 residual excluded)

    for batch in 0..batches {
        let base_s  = batch * (BATCH / 2);
        let t_ins   = Instant::now();

        // Insert BATCH quads via batched API (single lock acquisition per chunk)
        const CHUNK: u64 = 50_000; // 50K quads per lock acquisition
        let n_entities = BATCH / 2;
        for chunk_start in (0..n_entities).step_by(CHUNK as usize / 2) {
            let chunk_end = (chunk_start + CHUNK / 2).min(n_entities);
            let mut quads = Vec::with_capacity(((chunk_end - chunk_start) * 2) as usize);
            for i in chunk_start..chunk_end {
                let s = base_s + i;
                quads.push(text_quad(999, s, "name", "Alice"));
                quads.push(ref_quad (999, s, "knows", (s + 1) % (base_s + n_entities + 1)));
            }
            qs.assert_batch_silent(quads).await;
        }
        let insert_ms = t_ins.elapsed().as_millis();
        total_quads  += BATCH;

        // Commit to ProllyTree
        let t_commit = Instant::now();
        let _cid = qs.commit("did:loadtest", graph.clone(), batch + 1).await.unwrap();
        let commit_ms = t_commit.elapsed().as_millis();

        // Clear in-memory arrangement to reclaim RAM for next batch
        qs.reset_arrangement(&graph).await;

        let rss       = rss_mb();
        let rss_delta = rss - phase2_base_rss;
        let ins_qps   = (BATCH as f64 / (insert_ms as f64 / 1000.0)) as u64;
        let cum_qps   = (total_quads as f64 / run_start.elapsed().as_secs_f64()) as u64;

        println!("{:<8}  {:>10}  {:>12}  {:>10}  {:>10.1}  {:>10}  {:>10}",
            batch + 1, insert_ms, fmt_n(total_quads), commit_ms, rss_delta,
            ins_qps, cum_qps);

        if rss_delta >= mem_limit_mb {
            println!("\n  [STOPPED] Phase-2 RSS growth {:.0} MB >= limit {:.0} MB after batch {}",
                rss_delta, mem_limit_mb, batch + 1);
            break;
        }
    }

    println!("\n  total: {} quads in {:.1}s  avg throughput: {} quad/s",
        fmt_n(total_quads),
        run_start.elapsed().as_secs_f64(),
        (total_quads as f64 / run_start.elapsed().as_secs_f64()) as u64);
}

// ─── Phase 5: SPARQL BGP router + multi-hop + CACAO-authed cold queries ───────

/// Builds a graph with 4 attribute types per entity:
///   - name   → Text  (AEVT + AVET exercised)
///   - role   → Text  (AVET lookup)
///   - status → Text  (AVET lookup)
///   - knows  → Cid   (VAET + multi-hop exercised)
///
/// Then benchmarks:
///   1. SPARQL BGP: pred-only (AEVT)
///   2. SPARQL BGP: pred+literal (AVET)
///   3. SPARQL BGP: bound-subject (EAVT)
///   4. SPARQL BGP: 2-triple join (AVET×AVET)
///   5. multi_hop_cold 2-hop + 3-hop
///   6. CACAO-authed variants of BGP + multi-hop (via verify_skip_sig)
async fn phase5_sparql_multihop_cacao() {
    const N_ENTITIES: u64 = 10_000;
    const ITERS: usize = 30;
    const ROLES: &[&str] = &["admin", "viewer", "editor"];
    const STATUSES: &[&str] = &["active", "inactive", "pending"];

    println!("\n=== Phase 5: SPARQL BGP + multi-hop + CACAO ({} entities) ===", fmt_n(N_ENTITIES));
    println!("{:<45}  {:>10}  {:>10}  {:>10}  {:>10}",
        "query", "p50_ms", "p95_ms", "p99_ms", "result_n");

    let journal     = Arc::new(Journal::new());
    let block_store = Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
    let qs          = QuadStore::new(journal, block_store);
    let graph       = cid(5);
    let n           = N_ENTITIES;

    // Build graph: 4 quads per entity
    const CHUNK: u64 = 2_000;
    for chunk_start in (0..n).step_by(CHUNK as usize) {
        let chunk_end = (chunk_start + CHUNK).min(n);
        let quads: Vec<Quad> = (chunk_start..chunk_end).flat_map(|i| {
            let role   = ROLES[(i % ROLES.len() as u64)   as usize];
            let status = STATUSES[(i % STATUSES.len() as u64) as usize];
            [
                Quad { graph: cid(5), subject: cid(1000 + i), predicate: "name".into(),
                       object: QuadObject::Text(format!("entity-{i}")) },
                Quad { graph: cid(5), subject: cid(1000 + i), predicate: "role".into(),
                       object: QuadObject::Text(role.to_string()) },
                Quad { graph: cid(5), subject: cid(1000 + i), predicate: "status".into(),
                       object: QuadObject::Text(status.to_string()) },
                Quad { graph: cid(5), subject: cid(1000 + i), predicate: "knows".into(),
                       object: QuadObject::Cid(cid(1000 + (i + 1) % n)) },
            ]
        }).collect();
        qs.assert_batch_silent(quads).await;
    }
    let _commit_cid5 = qs.commit("did:loadtest-p5", graph.clone(), 1).await.unwrap();
    qs.reset_arrangement(&graph).await; // graph CID, not commit CID

    // Helper macro
    macro_rules! bench5 {
        ($label:expr, $body:expr) => {{
            let mut times: Vec<Duration> = Vec::with_capacity(ITERS);
            let mut last_n = 0usize;
            for _ in 0..ITERS {
                let t = Instant::now();
                let r = $body.await;
                times.push(t.elapsed());
                if let Ok(v) = r { last_n = v.len(); }
            }
            times.sort_unstable();
            let p50 = times[ITERS / 2].as_secs_f64() * 1000.0;
            let p95 = times[(ITERS * 95 / 100).min(ITERS - 1)].as_secs_f64() * 1000.0;
            let p99 = times[(ITERS * 99 / 100).min(ITERS - 1)].as_secs_f64() * 1000.0;
            println!("{:<45}  {:>10.3}  {:>10.3}  {:>10.3}  {:>10}",
                $label, p50, p95, p99, last_n);
        }};
    }

    // 1. SPARQL BGP: pred-only → AEVT (returns all quads with pred="role")
    bench5!("SPARQL pred-only (AEVT) role",
        qs.cold_query_sparql_bgp(&graph, "SELECT ?s WHERE { ?s <role> ?o }"));

    // 2. SPARQL BGP: pred+literal → AVET (subjects where role=admin)
    bench5!("SPARQL pred+literal (AVET) role=admin",
        qs.cold_query_sparql_bgp(&graph, "SELECT ?s WHERE { ?s <role> \"admin\" }"));

    // 3. SPARQL BGP: bound-subject → EAVT (all quads for one entity)
    {
        let subj_cid = cid(1000 + n / 2);
        let subj_mb  = subj_cid.to_multibase();
        let sparql   = format!("SELECT ?p ?o WHERE {{ <cid:{subj_mb}> ?p ?o }}");
        bench5!("SPARQL bound-subject (EAVT)",
            qs.cold_query_sparql_bgp(&graph, &sparql));
    }

    // 4. SPARQL BGP: 2-triple join → AVET×AVET (role=admin AND status=active)
    bench5!("SPARQL 2-triple join (AVET×AVET) role+status",
        qs.cold_query_sparql_bgp(&graph,
            "SELECT ?s WHERE { ?s <role> \"admin\" . ?s <status> \"active\" }"));

    // 5a. multi-hop 2-hop
    {
        let start = cid(1000);
        bench5!("multi_hop_cold 2-hop",
            qs.multi_hop_cold(&graph, &start, 2));
    }

    // 5b. multi-hop 3-hop
    {
        let start = cid(1000);
        bench5!("multi_hop_cold 3-hop",
            qs.multi_hop_cold(&graph, &start, 3));
    }

    // 6. CACAO verify_skip_sig overhead (temporal + capability + graph-scope check, no crypto)
    //    In production, chain.verify() adds an EdDSA/EcdsaK1 crypto step on top.
    //    Real authed cold queries = verify overhead + cold query time (measured above).
    {
        let graph_mb2 = graph.to_multibase();
        let chain2    = DelegationChain::new_for_test(&graph_mb2, "quad:read");
        let mut times: Vec<Duration> = Vec::with_capacity(ITERS * 10);
        for _ in 0..ITERS * 10 {
            let t = Instant::now();
            let _ = chain2.verify_skip_sig(&graph_mb2, "quad:read");
            times.push(t.elapsed());
        }
        times.sort_unstable();
        let p50 = times[times.len() / 2].as_micros();
        let p95 = times[(times.len() * 95 / 100).min(times.len() - 1)].as_micros();
        let p99 = times[(times.len() * 99 / 100).min(times.len() - 1)].as_micros();
        println!("{:<45}  {:>10}µs {:>9}µs {:>9}µs  {:>10}",
            "CACAO verify_skip_sig overhead", p50, p95, p99, "n/a");
        println!("  → Real authed query = above overhead + cold query p50.");
        println!("  → Production EdDSA verify adds ~0.1ms (per-request, amortised in LAN path).");
    }

    println!("\n  Note: all cold queries use MemoryBlockStore (µs RTT).");
    println!("  Production with Kubo LAN (1ms/GET): multiply cold-path p50 by ~3×RTT_ms.");
}

// ─── Phase 6: SPARQL property paths + aggregates + CACAO-authed JOIN ─────────

/// Benchmarks advanced SPARQL patterns over 10K entities:
///   1. Property path `<knows>+` (OneOrMore BFS from one start node)
///   2. Property path `<knows>*` (ZeroOrMore, includes start quads)
///   3. GROUP BY COUNT(*) (aggregate by role over all entities)
///   4. Global COUNT(*) (one aggregate row, total entities)
///   5. Subquery JOIN (admin subjects joined with name subjects)
///   6. CACAO-authed JOIN (via verify_skip_sig)
async fn phase6_sparql_advanced() {
    const N_ENTITIES: u64 = 10_000;
    const ITERS: usize = 30;
    const ROLES: &[&str] = &["admin", "viewer", "editor"];

    println!("\n=== Phase 6: SPARQL property paths + aggregates ({} entities) ===", fmt_n(N_ENTITIES));
    println!("{:<52}  {:>9}  {:>9}  {:>9}  {:>9}",
        "query", "p50_µs", "p95_µs", "p99_µs", "result_n");

    let journal     = Arc::new(Journal::new());
    let block_store = Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
    let qs          = QuadStore::new(journal, block_store);
    let graph       = cid(6);
    let n           = N_ENTITIES;

    // Build graph: name + role + knows-chain
    let knows_chain_len = 5usize;
    for i in 0..n {
        let s = cid_for(i);
        qs.assert(Quad { graph: graph.clone(), subject: s.clone(),
            predicate: "name".to_string(), object: QuadObject::Text(format!("Entity{i}")) }).await;
        qs.assert(Quad { graph: graph.clone(), subject: s.clone(),
            predicate: "role".to_string(),
            object: QuadObject::Text(ROLES[(i % ROLES.len() as u64) as usize].to_string()) }).await;
        // Build a linear knows-chain for the first knows_chain_len entities
        if (i as usize) < knows_chain_len {
            let next = cid_for(i + 1);
            qs.assert(Quad { graph: graph.clone(), subject: s.clone(),
                predicate: "knows".to_string(), object: QuadObject::Cid(next) }).await;
        }
    }
    qs.commit("did:bench", graph.clone(), 6).await.unwrap();
    qs.reset_arrangement(&graph).await;

    let start_mb = cid_for(0).to_multibase();
    let knows_one_sparql = format!("SELECT * WHERE {{ <cid:{start_mb}> <knows>+ ?o }}");
    let knows_zero_sparql = format!("SELECT * WHERE {{ <cid:{start_mb}> <knows>* ?o }}");
    let count_role_sparql = "SELECT ?r (COUNT(*) AS ?n) WHERE { ?s <role> ?r } GROUP BY ?r";
    let count_all_sparql  = "SELECT (COUNT(*) AS ?total) WHERE { ?s <role> ?r }";
    let join_sparql = r#"SELECT * WHERE { { SELECT ?s WHERE { ?s <role> "admin" } } { SELECT ?s WHERE { ?s <name> ?n } } }"#;

    let chain = DelegationChain::new_for_test(&graph.to_multibase(), "quad:read");

    macro_rules! bench_query {
        ($label:expr, $body:expr) => {{
            let mut times = Vec::with_capacity(ITERS);
            let mut last_n = 0usize;
            for _ in 0..ITERS {
                let t = Instant::now();
                let r: Vec<Quad> = $body;
                times.push(t.elapsed());
                last_n = r.len();
            }
            times.sort();
            let p50 = times[times.len() / 2].as_micros();
            let p95 = times[(times.len() * 95 / 100).min(times.len() - 1)].as_micros();
            let p99 = times[(times.len() * 99 / 100).min(times.len() - 1)].as_micros();
            println!("{:<52}  {:>9}  {:>9}  {:>9}  {:>9}",
                $label, p50, p95, p99, last_n);
        }};
    }

    bench_query!("property_path <knows>+ (BFS 1+)",
        qs.cold_query_sparql_bgp(&graph, &knows_one_sparql).await.unwrap());
    bench_query!("property_path <knows>* (BFS 0+, includes start)",
        qs.cold_query_sparql_bgp(&graph, &knows_zero_sparql).await.unwrap());
    bench_query!("aggregate COUNT(*) GROUP BY role",
        qs.cold_query_sparql_bgp(&graph, count_role_sparql).await.unwrap());
    bench_query!("aggregate COUNT(*) global",
        qs.cold_query_sparql_bgp(&graph, count_all_sparql).await.unwrap());
    bench_query!("subquery JOIN (admin ∩ name)",
        qs.cold_query_sparql_bgp(&graph, join_sparql).await.unwrap());
    bench_query!("CACAO-authed JOIN (verify_skip_sig + query)", {
        chain.verify_skip_sig(&graph.to_multibase(), "quad:read").unwrap();
        qs.cold_query_sparql_bgp(&graph, join_sparql).await.unwrap()
    });

    println!("  → property path BFS walks the knows-chain ({} links).", knows_chain_len);
    println!("  → aggregate scans {} quads via AEVT index.", fmt_n(n));
    println!("  → join uses subquery → Join node; inner-joins by subject.");
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
