use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kotoba_core::cid::KotobaCid;
use kotoba_kqe::{
    arrangement::Arrangement,
    quad::{Quad, QuadObject},
};

fn make_cid(n: u64) -> KotobaCid {
    KotobaCid::from_bytes(&n.to_le_bytes())
}

fn make_text_quad(s: u64, p: &str, o: &str) -> Quad {
    Quad {
        graph: make_cid(0),
        subject: make_cid(s),
        predicate: p.to_string(),
        object: QuadObject::Text(o.to_string()),
    }
}

fn make_ref_quad(s: u64, p: &str, o: u64) -> Quad {
    Quad {
        graph: make_cid(0),
        subject: make_cid(s),
        predicate: p.to_string(),
        object: QuadObject::Cid(make_cid(o)),
    }
}

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("arrangement/insert");
    for n in [1_000u64, 10_000, 100_000] {
        group.throughput(Throughput::Elements(n));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mut arr = Arrangement::new();
                for i in 0..n {
                    arr.insert(&make_text_quad(i % 1000, "name", "value"));
                    arr.insert(&make_ref_quad(i % 1000, "knows", (i + 1) % 1000));
                }
                arr
            });
        });
    }
    group.finish();
}

fn bench_spo_lookup(c: &mut Criterion) {
    // Pre-build arrangement with 10k quads
    let mut arr = Arrangement::new();
    for i in 0..10_000u64 {
        arr.insert(&make_text_quad(i % 1000, "name", "Alice"));
    }
    let subject = make_cid(42);

    c.bench_function("arrangement/spo_lookup_eavt", |b| {
        b.iter(|| arr.get_values(&subject, "name"));
    });
}

fn bench_pso_lookup(c: &mut Criterion) {
    let mut arr = Arrangement::new();
    for i in 0..10_000u64 {
        arr.insert(&make_text_quad(i % 1000, "role", "admin"));
    }

    c.bench_function("arrangement/pso_get_subjects_aevt", |b| {
        b.iter(|| arr.get_entities_by_attribute("role"));
    });

    c.bench_function("arrangement/pso_get_by_predicate_aevt", |b| {
        b.iter(|| arr.get_by_attribute("role"));
    });
}

fn bench_pos_lookup(c: &mut Criterion) {
    let mut arr = Arrangement::new();
    for i in 0..10_000u64 {
        arr.insert(&make_text_quad(
            i,
            "status",
            if i % 2 == 0 { "active" } else { "inactive" },
        ));
    }

    c.bench_function("arrangement/pos_lookup_avet", |b| {
        b.iter(|| arr.get_entities_by_attribute_value("status", "active"));
    });
}

fn bench_ocp_lookup(c: &mut Criterion) {
    let mut arr = Arrangement::new();
    let target = make_cid(999);
    for i in 0..10_000u64 {
        arr.insert(&make_ref_quad(i % 1000, "knows", 999));
    }

    c.bench_function("arrangement/ocp_reverse_ref_vaet", |b| {
        b.iter(|| arr.get_referencing_subjects(&target));
    });
}

fn bench_predicate_prefix_scan(c: &mut Criterion) {
    let mut arr = Arrangement::new();
    for i in 0..10_000u64 {
        arr.insert(&make_text_quad(
            i % 100,
            &format!("weight/block/{}/attn/q", i % 32),
            "v",
        ));
        arr.insert(&make_text_quad(
            i % 100,
            &format!("weight/block/{}/ffn/gate", i % 32),
            "v",
        ));
    }
    let g = make_cid(0);

    c.bench_function("arrangement/prefix_scan_avet_weight", |b| {
        b.iter(|| arr.datoms_with_attribute_prefix(&g, "weight/"));
    });
}

// ─── Complex / join queries ───────────────────────────────────────────────────

/// 2-hop traversal: for each entity e, follow `knows` once (VAET lookup),
/// then for each neighbour follow `knows` again → set of 2nd-hop subjects.
/// Models "who knows someone who knows Alice?"
fn bench_multi_hop_traversal(c: &mut Criterion) {
    let mut arr = Arrangement::new();
    let n = 10_000u64;
    for i in 0..n {
        // ring: i → knows → (i+1)%n
        arr.insert(&make_ref_quad(i, "knows", (i + 1) % n));
        arr.insert(&make_text_quad(i, "name", "Alice"));
    }

    let seed = make_cid(0); // start node for traversal

    c.bench_function("arrangement/multi_hop_2hop_vaet_eavt", |b| {
        b.iter(|| {
            // hop1: VAET — who references seed via "knows"?
            let hop1: Vec<KotobaCid> = arr.get_referencing_subjects_by_predicate(&seed, "knows");
            // hop2: for each, follow "knows" again (VAET)
            let mut hop2: Vec<KotobaCid> = Vec::new();
            for h in &hop1 {
                hop2.extend(arr.get_referencing_subjects_by_predicate(h, "knows"));
            }
            hop2
        });
    });

    c.bench_function("arrangement/multi_hop_3hop_vaet", |b| {
        b.iter(|| {
            let hop1 = arr.get_referencing_subjects_by_predicate(&seed, "knows");
            let mut hop2: Vec<KotobaCid> = hop1
                .iter()
                .flat_map(|h| arr.get_referencing_subjects_by_predicate(h, "knows"))
                .collect();
            hop2.dedup();
            let hop3: Vec<KotobaCid> = hop2
                .iter()
                .flat_map(|h| arr.get_referencing_subjects_by_predicate(h, "knows"))
                .collect();
            hop3
        });
    });
}

/// Join query: AVET ∩ AVET — find all subjects where `status=active` AND `role=admin`.
/// Models a two-attribute filter (SQL: WHERE status='active' AND role='admin').
fn bench_join_avet_intersection(c: &mut Criterion) {
    let mut arr = Arrangement::new();
    let n = 10_000u64;
    for i in 0..n {
        arr.insert(&make_text_quad(
            i,
            "status",
            if i % 3 == 0 { "active" } else { "inactive" },
        ));
        arr.insert(&make_text_quad(
            i,
            "role",
            if i % 7 == 0 { "admin" } else { "viewer" },
        ));
    }

    c.bench_function("arrangement/join_avet_status_active_and_role_admin", |b| {
        b.iter(|| {
            let active: std::collections::HashSet<_> = arr
                .get_entities_by_attribute_value("status", "active")
                .into_iter()
                .collect();
            let admins = arr.get_entities_by_attribute_value("role", "admin");
            // intersection
            admins
                .iter()
                .filter(|s| active.contains(s))
                .cloned()
                .collect::<Vec<_>>()
        });
    });
}

/// Population count: count distinct subjects per predicate value (GROUP BY equivalent).
/// Models "how many entities have each status value?"
fn bench_population_count_aevt(c: &mut Criterion) {
    let mut arr = Arrangement::new();
    let n = 50_000u64;
    for i in 0..n {
        let status = match i % 4 {
            0 => "active",
            1 => "inactive",
            2 => "pending",
            _ => "archived",
        };
        arr.insert(&make_text_quad(i, "status", status));
    }

    c.bench_function("arrangement/population_count_by_status_aevt", |b| {
        b.iter(|| {
            // AEVT scan: all subjects per predicate
            let all = arr.get_by_attribute("status");
            // count unique subjects per object value
            let mut counts: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for (_, objs) in &all {
                for obj in objs {
                    if let kotoba_kqe::quad::LegacyQuadObject::Text(v) = obj {
                        *counts.entry(v.clone()).or_default() += 1;
                    }
                }
            }
            counts
        });
    });
}

/// Star pattern: fetch all triples for a single entity (EAVT full entity).
/// Models "give me everything about entity X".
fn bench_star_pattern_eavt(c: &mut Criterion) {
    let mut arr = Arrangement::new();
    let g = make_cid(0);
    let target = make_cid(42);
    // Add 20 predicates to the target entity
    let preds = [
        "name",
        "email",
        "role",
        "status",
        "country",
        "city",
        "org",
        "dept",
        "level",
        "score",
        "created",
        "updated",
        "weight/embed",
        "weight/lm_head",
        "knows",
        "manages",
        "reports_to",
        "member_of",
        "owner",
        "lang",
    ];
    for p in &preds {
        arr.insert(&make_text_quad(42, p, "value"));
    }
    // Add noise entities
    for i in 0..10_000u64 {
        arr.insert(&make_text_quad(i % 1000 + 100, "name", "noise"));
    }

    c.bench_function("arrangement/star_pattern_eavt_20pred", |b| {
        b.iter(|| arr.get_subject_datoms(&g, &target));
    });
}

/// Reverse graph: find all entities that transitively point to a target via "knows".
/// Models "give me all ancestors of X in the social graph" (fan-in traversal).
fn bench_reverse_fanin_vaet(c: &mut Criterion) {
    let mut arr = Arrangement::new();
    let n = 5_000u64;
    let hub = make_cid(0);
    // Star topology: 5000 entities all point to hub
    for i in 1..=n {
        arr.insert(&make_ref_quad(i, "knows", 0));
    }
    // Add chain: 100 others form a chain pointing at hub
    for i in 0..100u64 {
        arr.insert(&make_ref_quad(n + i + 1, "follows", 0));
    }

    c.bench_function("arrangement/reverse_fanin_vaet_5k_to_hub", |b| {
        b.iter(|| arr.get_referencing_subjects(&hub));
    });

    c.bench_function("arrangement/reverse_fanin_by_pred_vaet", |b| {
        b.iter(|| arr.get_referencing_subjects_by_predicate(&hub, "knows"));
    });
}

criterion_group!(
    benches,
    bench_insert,
    bench_spo_lookup,
    bench_pso_lookup,
    bench_pos_lookup,
    bench_ocp_lookup,
    bench_predicate_prefix_scan,
    bench_multi_hop_traversal,
    bench_join_avet_intersection,
    bench_population_count_aevt,
    bench_star_pattern_eavt,
    bench_reverse_fanin_vaet,
);
criterion_main!(benches);
