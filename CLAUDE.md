# ai-gftd-project-kotoba

KOTOBA: Content-Addressed Distributed Datalog Database.

SSoT: `90-docs/adr/2605240001-kotoba-cleanroom-architecture.md`

## 一行定義

KOTOBA ≝ Datom[CID/T] × EAVT[KSE Topic] × Pregel[BSP] × Datalog[Δ]
          × CACAO × AT Protocol × LLM/Weight × WASM/WIT

## コンポーネント

| crate | 役割 |
|---|---|
| kotoba-core | CIDv1 blake3, KAIS 8-bit frame, Prolly Tree |
| kotoba-kse | Journal (Merkle WAL on Arc<dyn BlockStore>, head JSON, Merkle chain cold-path), Vault (file-type chunking: Single/FixedLen 512KB/CDC gear-hash/CodecAware CBOR-item; BlobManifest CID; flush_as_car() CAR v1 batch), SecureVault, Topic, Shelf, chunker.rs **[IPLD-only 2026-05-26]**; **AgentIdentity** (Ed25519+X25519 keypair, from_env/generate_ephemeral); **SovereignCrypto** (AgentCrypto impl: vault key gen→HPKE wrap→BlockStore; load_or_genesis; rotate; key-ref JSON pointer in KseStore) **[2026-05-26]** |
| kotoba-kqe | Datalog engine, Arrangement, Delta, MV (KQE) |
| kotoba-dht | Source Chain, Warrant, Neighborhood (KDHT) |
| kotoba-net | libp2p QUIC/Noise/GossipSub |
| kotoba-auth | CACAO chain verification, DID Document |
| kotoba-graph | Quad API, SPARQL→Datalog, Commit DAG |
| kotoba-vm | Invoke/Result ChainEntry, CALL_FOREIGN bridge (KVM) |
| kotoba-llm | Weight blob (FP8), LoRA Delta, KV-cache, inference, WebGPU training (embed+lm_head), WebGPU inference (full transformer, Gemma 4 E2B/E4B) |
| kotoba-runtime | WASM Component Model host: WasmExecutor + UdfExecutor + WIT bindings |
| kotoba-ingest | Gmail OAuth2 poll + RFC 2822 parse + E2E encrypt → QuadStore (ADR-2605252400); **EmailIngestor** now uses `Arc<dyn AgentCrypto>` + `Arc<Vault>` (raw vault_key removed 2026-05-26) |
| kotoba-server | XRPC / MCP endpoints |
| kotoba-store | BlockStore implementations: Memory (hot); **KuboBlockStore** (Kubo HTTP cold tier, Dual-CID: blake3 internal + SHA2-256 IPFS, 2026-05-27); BudgetedBlockStore<S> LRU eviction; TieredBlockStore<H,C> hot/cold tiering; **CapturingBlockStore** (pass-through + recorder for CAR bundling); **CarBundleWriter / CarBlockIndex** (CARv1 format: 72B header + blocks + 48B/entry index, 3.8 GiB/s serialize); **IpfsPinClient** (Kubo-compatible HTTP RPC: pin/add, pin/rm, pin/ls — kotoba 自体が IPFS node として自前 pin; 1GB 超の extended pin は kotobase.gftd.ai が担当). S3BlockStore + LayeredBlockStore + KotobasePinClient + IrohBlockStore removed 2026-05-27. |
| kotoba-store-web | Browser IndexedDB block store (wasm32), AsyncBlockStore trait |

## 実装順序

1. kotoba-core (CID + 8-bit frame + Prolly Tree PoC)
2. kotoba-kse (Journal + Topic + Shelf)
3. kotoba-auth (CACAO chain verify)
4. kotoba-kqe (Datalog + Arrangement + Delta)
5. kotoba-dht (Source Chain + Warrant + Neighborhood)
6. kotoba-vm (Invoke/Result + CALL_FOREIGN)
7. kotoba-llm (weight, LoRA, KV-cache, inference, WebGPU training)
8. kotoba-runtime (WasmExecutor + UdfExecutor + WIT host bindings)
9. kotoba-server (XRPC / MCP)

## LLM / Weight 設計

- Weight = Quad(model_cid, "weight/layer/N", blob_cid) — Datom として格納
- LoRA = Delta(Quad(model_cid, "lora/adapter", adapter_cid), +1) — Delta がアダプタ
- KV-cache = ephemeral Arrangement per session_cid
- Inference = Invoke ChainEntry {program_cid: inference_datalog}
- FP8 tensor = Vault blob (dim > 1024 はオフロード)

## 統一 Weight 述語スキーム (ADR-2605250005)

| 述語 | 説明 |
|---|---|
| `weight/embed` | Embedding table [vocab × H] |
| `weight/lm_head` | LM head [H × vocab] |
| `weight/norm/final` | Final RMSNorm [H] |
| `weight/block/{N}/attn/{q,k,v,o}` | Attention projections |
| `weight/block/{N}/ffn/{gate,up,down}` | SwiGLU FFN |
| `weight/block/{N}/norm/{attn,ffn}` | RMSNorm per block |

Rust: `WeightKind` enum + `WeightKind::predicate()` / `WeightKind::path()`.

## WebGPU Inference 設計 (ADR-2605250005)

### 対象モデル

| モデル | n_layers | hidden | n_heads | n_kv_heads | head_dim |
|---|---|---|---|---|---|
| Gemma 4 E2B | 26 | 2048 | 8 | 4 | 256 |
| Gemma 4 E4B | 34 | 2560 | 16 | 8 | 160 |

### dtype 境界 (training と同一)

```
Vault FP8 ──dequantize──▶ f32 CPU/GPU buffer ──infer──▶ token IDs
```

### WGSL シェーダー

| 定数名 | 演算 |
|---|---|
| `RMS_NORM_WGSL` | RMSNorm + weight scale |
| `ROPE_WGSL` | Rotary Position Embedding |
| `ATTENTION_WGSL` | Scaled dot-product (GQA causal) |
| `SWIGLU_FFN_WGSL` | SwiGLU: `down(silu(gate) * up)` |
| `SAMPLE_WGSL` | Greedy argmax |

### Feature ゲート

```toml
webgpu-infer = ["dep:wgpu", "dep:bytemuck"]
```

### gpu_common (feature 不要、常時コンパイル)

- `dequantize_fp8_e4m3` / `quantize_f32_to_fp8_e4m3`
- `MATMUL_WGSL` / `cpu_matmul` / `f32_slice_to_bytes` / `bytes_to_f32_slice`

### KV キャッシュ

- In-memory f32: `[n_layers][seq_pos × n_kv_heads × head_dim]`
- Vault / Arrangement に保存しない (session-scoped ephemeral)

### 禁止

- GPU 上での FP8 計算
- KV キャッシュを Vault に永続化
- `n_kv_heads > n_heads`

## WebGPU Training 設計 (ADR-2605250004)

SSoT: `90-docs/adr/2605250004-kotoba-webgpu-training.md`

### dtype 境界

```
Vault FP8 ──dequantize──▶ f32 GPU buffer ──train──▶ quantize ──▶ Vault FP8
```

- WebGPU は f32 のみ。FP8 は Vault read/write 時のみ変換
- `dequantize_fp8_e4m3` / `quantize_f32_to_fp8_e4m3` (CPU-side, E4M3FN: NaN = S_1111_111 のみ)

### Fine-tuning スコープ (Phase 1)

| layer | predicate | shape |
|---|---|---|
| Embedding | `weight/embed` | `[vocab × H]` |
| LM head | `weight/lm_head` | `[H × vocab]` |

中間 Transformer 層は凍結。

### Datom エンコーディング

- Gradient (ephemeral): `Quad(model_cid, "grad/layer/{N}/step/{M}", TensorCid{F32})` — optimizer step 後に `Delta::retract`
- AdamW m1: `Quad(model_cid, "train/adam/m1/layer/{N}", TensorCid{F32})` — 永続
- AdamW m2: `Quad(model_cid, "train/adam/m2/layer/{N}", TensorCid{F32})` — 永続
- 重み更新: `[Delta::retract(old), Delta::assert(new)]` — 原子的ペア

### WGSL シェーダー

`MATMUL_WGSL` (forward) / `MATMUL_AT_WGSL` (backward) / `CE_LOSS_WGSL` (quality-scaled loss) / `ADAMW_WGSL` (optimizer)

### Feature ゲート

```toml
# kotoba-llm: feature = "webgpu-train"
wgpu     = { version = "24", optional = true }  # kami-engine と同一バージョン
bytemuck = { version = "1",  features = ["derive"], optional = true }
```

### 禁止

- GPU 上で FP8 計算
- `Delta::retract` なしで旧 WeightRef を放置 (二重 Datom)
- `quality_scale = NaN / Inf`
- optimizer step 後に grad テンソルを Arrangement に残す

## 4-Index Arrangement (Datomic EAVT/AEVT/AVET/VAET)

| 名前 | Datomic | 内部構造 | 用途 |
|---|---|---|---|
| `spo` | EAVT | `HashMap<S, BTreeMap<P, Vec<O>>>` | エンティティ全属性 |
| `pso` | AEVT | `BTreeMap<P, HashMap<S, Vec<O>>>` | 属性スキャン (P範囲) |
| `pos` | AVET | `BTreeMap<P, BTreeMap<okey, Vec<S>>>` | 値引き P+O→S |
| `ocp` | VAET | `HashMap<O_cid, BTreeMap<P, Vec<S>>>` | 逆参照 (ref型のみ) |

- VAET は `QuadObject::Cid` のみインデックス — Text/Integer/Float 禁止
- `CommitDag::Commit` に `index_roots: HashMap<String, KotobaCid>` 追加 (`serde(default, skip_serializing_if)` で旧 commit CID 安定)
- `QuadStore::commit()` は EAVT/AEVT/AVET/VAET を **4 並列 64MB スタックスレッド** で同時ビルド (各スレッドは `CapturingBlockStore` でブロックを記録); 完了後 `CarBundleWriter` で全ブロックを単一 CAR ファイルにパック → ブロックストアに 1 PUT。実測: 3.1–3.8s/1Mquad commit (serial 4.7s → **28% 高速化**; MemoryBlockStore, M4 Mac)
- `QuadStore::get_entity_quads_cold()`: hot Arrangement clear 後の cold 読み取り。ProllyTree `scan_prefix(subject_bytes)` → EAVT エントリ再構成。実測コスト: kubo LAN (1ms/GET) 3.1ms / kubo WAN (80ms/GET) 169ms / S3 same-AZ (2ms/GET) 5.9ms (1K entries, 2 tree levels)
- Journal: 4 トピック SPO + PSO + POS + OSP に publish

## TieredBlockStore / KuboBlockStore

- `TieredBlockStore<H, C>`: hot (BudgetedBlockStore<MemoryBlockStore>) + cold (KuboBlockStore) の 2 層
  - put: hot に即時書き込み + cold に `tokio::spawn` fire-and-forget
  - get: hot ヒット → 即返却; hot miss → cold fetch + hot promote
  - pin/unpin: hot 層に委譲 (SyncWindow compatible)
- `KuboBlockStore`: Kubo HTTP RPC cold store (Dual-CID, 2026-05-27)
  - 内部キー = `KotobaCid` (blake3-256 CIDv1); ストレージ境界で SHA2-256 CIDv1 を計算
  - インデックス: `HashMap<[u8;36], String>` (blake3 → SHA2-256 multibase)
  - `KOTOBA_IPFS_ENDPOINT` (default `http://localhost:5001`); `KOTOBA_IPFS_TOKEN` optional Bearer
  - `/api/v0/block/put?cid-codec=raw&mhtype=sha2-256` (multipart), `/api/v0/block/get`, `/api/v0/block/rm`
  - sync BlockStore は `tokio::task::block_in_place` でブリッジ
  - iroh-blobs / netwatch-fix-02 / netwatch-fix-03 依存を完全撤去

## criterion ベンチマーク

### ベンチ一覧

| ファイル | グループ | 内容 |
|---|---|---|
| `kotoba-kqe/benches/arrangement.rs` | `arrangement/insert` | Arrangement insert 1K/10K/100K |
| | `arrangement/spo_lookup_eavt` | EAVT 点引き |
| | `arrangement/pso_*_aevt` | AEVT subjects / by_predicate |
| | `arrangement/pos_lookup_avet` | AVET 値引き |
| | `arrangement/ocp_reverse_ref_vaet` | VAET 逆参照 |
| | `arrangement/prefix_scan_avet_weight` | 述語プレフィックス scan |
| | `arrangement/multi_hop_2hop_vaet_eavt` | 2-hop 経路探索 |
| | `arrangement/multi_hop_3hop_vaet` | 3-hop 経路探索 |
| | `arrangement/join_avet_status_active_and_role_admin` | 2-属性 AVET 交差 join |
| | `arrangement/population_count_by_status_aevt` | AEVT 集計 (GROUP BY 相当) |
| | `arrangement/star_pattern_eavt_20pred` | EAVT star pattern (全述語取得) |
| | `arrangement/reverse_fanin_vaet_5k_to_hub` | VAET fan-in (5K→hub) |
| `kotoba-graph/benches/quad_store.rs` | `quad_store/insert_per_quad` | assert_silent × N (1ロック/quad) |
| | `quad_store/insert_batch` | assert_batch_silent (1ロック/全quads) |
| | `quad_store/insert_batch_chunked` | 50K chunk バッチ (loadtest 同等) |
| | `quad_store/insert_batch_authed` | CACAO verify_skip_sig + batch insert (auth overhead 分離) |
| | `quad_store/query_hot` | Arrangement hot-path クエリ |
| | `quad_store/query_cold_prolly_1k` | ProllyTree 点引き + 模擬RTT |
| `kotoba-store/benches/tiered_store.rs` | `tiered_store/*` | hot put/get, cold-promote, 予算 eviction |
| `kotoba-store/benches/car_flush.rs` | `car/serialize` | CAR バンドルシリアライズ (GiB/s) |
| | `car/flush_simulated` | single PUT vs 個別 PUT 比較 (simulated RTT) |
| | `car/range_get` | インデックス lookup + range GET (simulated) |
| | `car/index_insert` | CarBlockIndex 一括挿入スループット |

### ベンチの IPFS/S3 I/O スコープ

**重要**: 現在のクエリベンチは2種類ある。

| ベンチグループ | BlockStore I/O を含む? | 説明 |
|---|---|---|
| `arrangement/*` | **含まない** | 純インメモリ Arrangement |
| `quad_store/insert_*` | **含まない** | MemoryBlockStore、Arrangement のみ |
| `quad_store/query_hot` | **含まない** | hot Arrangement (commit 後も in-memory) |
| `quad_store/query_cold_prolly_1k` | **含む (模擬)** | ProllyTree 点引き、RTT = kubo LAN 1ms / kubo WAN 80ms / S3 same-AZ 2ms |
| `tiered_store/*` | **含む (模擬)** | TieredBlockStore hot/cold 経路 |

**cold-path クエリ (IPFS/S3) の特性**:  
- ProllyTree の1レベル = 1 BlockStore.get() = 1 RTT  
- BOUNDARY_MASK=0xFF (1/256 確率)、内部ノード境界はリーフ max_key ではなく **子 CID** で決定  
  (max_key による境界チェックは各レベルで同一キーが毎回 trigger → 無限再帰のため修正)  
- 実測深さ (1K entries, 2026-05-25): **~3 レベル** → 3 RTTs  
- 理論深さ: ceil(log256(N)) — 1K → 2-3 RTT、1M → 3-4 RTT、1B → 5-6 RTT  
- **実測**: kubo LAN 1ms × 3 RTT = **3.3 ms**  
- **実測**: kubo WAN 80ms × ~2 RTT = **175 ms**  
- **実測**: S3 same-AZ 2ms × 3 RTT = **6.0 ms**  
- TieredBlockStore(hot=memory, cold=kubo): hot ヒット時は **µs オーダー**

### 実測値 (2026-05-25, macOS aarch64, release build)

#### Arrangement hot-path (インメモリ, criterion 実測値 2026-05-25)

| ベンチ | p50 | 備考 |
|---|---|---|
| EAVT 点引き (SPO) | ~180 ns | 1 HashMap lookup |
| AEVT 逆引き subjects | ~8 µs | BTreeMap range |
| AVET 値引き (P+O→S) | ~18 µs | BTreeMap range |
| VAET 逆参照 (全述語) | ~83–147 µs | 10K entity |
| **2-hop 経路探索** (VAET×2) | **748 ns** | 10K ring graph |
| **3-hop 経路探索** (VAET×3+dedup) | **1.16 µs** | 10K ring graph |
| **join AVET×2** (status=active AND role=admin) | **783 µs** | HashSet intersection、10K |
| **population count** (GROUP BY status, AEVT) | **47 ms** | 50K entity 全スキャン |
| **star pattern** (EAVT 全述語, 20 pred) | **6.4 µs** | 10K noise |
| **reverse fan-in** (VAET, 5K→hub) | **76 µs** | star topology |
| **reverse fan-in by pred** (VAET+P) | **21 µs** | pred=knows フィルタ |

#### QuadStore insert (criterion bench, macOS aarch64, 2026-05-25)

entities × 2 quads = 要素数 (throughput = quad/s)

| パス | 1K entities (2K q) | 10K entities (20K q) | 100K entities (200K q) | 1M entities (2M q) |
|---|---|---|---|---|
| `insert_per_quad` (1ロック/quad) | 13.7ms **146K/s** | 138ms **145K/s** | 1.54s **130K/s** | — |
| `insert_batch` (1ロック/全quads) | 5.1ms **390K/s** (2.7×) | 79ms **252K/s** (1.7×) | 1.11s **180K/s** (1.4×) | — |
| `insert_batch_chunked` (50K chunk) | — | — | 1.33s **150K/s** | 38.6s **52K/s** ¹ |
| `insert_batch_authed` (verify_skip_sig + insert) | 3.7ms **540K/s** | 43ms **465K/s** | 596ms **335K/s** | — |

¹ 1M entities (2M quads) の bench は HashMap/BTreeMap 成長コストを含む。実運用 (batch commit cycle で reset_arrangement) は loadtest 測定値を参照。

`insert_batch_authed` と `insert_batch` の差 ≈ **<1 µs/batch** (CACAO 非暗号チェック: capability + graph scope + temporal)。本番 Ed25519 verify ≈ +0.1 ms/batch (per-call, quad 数に非依存)。

#### QuadStore cold-path (ProllyTree + 模擬 IPFS/S3 RTT, 2026-05-25, 1K entries)

| シナリオ | p50 | RTT モデル | 実測 depth |
|---|---|---|---|
| kubo_lan_1ms_get | **3.3 ms** | kubo LAN 1ms/GET | ~3 RTT |
| kubo_wan_80ms_get | **175 ms** | kubo WAN 80ms/GET | ~2 RTT |
| s3_same_az_2ms_get | **6.0 ms** | S3 same-AZ 2ms/GET | ~3 RTT |

- `build_internal_level` の境界チェックを max_key → **子 CID** に修正 (max_key は各レベルで同一 key が発火し無限再帰)
- 1K entries での実測深さ ~3 levels → 1M quads は ~3-4 RTT、1B quads は ~5-6 RTT

#### loadtest Phase 1 (純 Arrangement, 2026-05-26, post-sled-removal)

| quads | insert_ms | MB_rss | p50 | p95 | p99 | quad/s | MB/Mquad |
|---|---|---|---|---|---|---|---|
| 1M | 1382 ms | 1919 MB | 8µs | 1759µs | 1969µs | 724K | 1919 |
| 10M | 19274 ms | 7038 MB | 24µs | 16742µs | 18369µs | 519K | 704 |

#### loadtest Phase 2 (QuadStore commit cycle + ProllyTree, 2026-05-26)

バッチ 1M quad ずつ insert → `commit()` (4 ProllyTree build) → `reset_arrangement()` を繰り返す。  
`LOADTEST_MEM_LIMIT_MB=8192` (Phase-2 RSS 成長が 8 GB に達したら打ち切り)。

| batch | insert_ms | commit_ms | MB_growth | ins_q/s | cum_q/s |
|---|---|---|---|---|---|
| 1 (1M) | 2029 | 3969 | +856 | 493K | 147K |
| 2 (2M) | 1576 | 3854 | -2834 | 635K | 148K |
| 3 (3M) | 2523 | 3719 | -2816 | 396K | 146K |
| 4 (4M) | 2095 | 4584 | -3615 | 477K | 139K |
| 5 (5M) | 2203 | 4667 | -5678 | 454K | 134K |
| 6 (6M) | 2165 | 5192 | -6911 | 462K | 128K |
| 7 (7M) | 1832 | 4970 | -6222 | 546K | 126K |
| 8 (8M) | 1714 | 4638 | -5110 | 583K | 126K |
| 9 (9M) | 1607 | 5082 | -6413 | 622K | 124K |
| 10 (10M) | 1709 | 3492 | -2731 | 585K | 128K |

- **insert**: ~393–635K q/s (バッチ単独)
- **commit**: **~3.5–5.2 s/batch** (MemoryBlockStore、serial 4 prolly)
- **combined throughput**: **~128K q/s** (total 10M quads in 78.3s)
- **peak RSS growth**: +856 MB (batch 1)。以降 OS がページ回収し負 (batch 2–10)
- Phase-2 は 8 GB 上限未達で全 10 バッチ完走

#### loadtest Phase 5 (SPARQL BGP + multi-hop + CACAO overhead, 2026-05-27)

MemoryBlockStore、10K entities × 4 quads (name/role/status/knows)。reset_arrangement 後の cold-path (ProllyTree scan)。

| query | p50_ms | result_n | routing |
|---|---|---|---|
| SPARQL pred-only (AEVT) role | 25ms | 10000 | AEVT scan |
| SPARQL pred+literal (AVET) role=admin | 36ms | 3334 | AVET P+O→S |
| SPARQL bound-subject (EAVT) | 44ms | 4 | EAVT entity |
| SPARQL 2-triple join (AVET×AVET) role+status | 72ms | 6668 | AVET intersect |
| multi_hop_cold 2-hop | 90ms | 12 | BFS ×2 |
| multi_hop_cold 3-hop | 113ms | 16 | BFS ×3 |
| CACAO verify_skip_sig overhead | **<1µs** | — | pure auth check |

- CACAO auth overhead <1µs; production EdDSA verify adds ~0.1ms → dominates only sub-ms hot queries
- **EdDSA CACAO E2E verified (2026-05-27)**: real `SigningKey::from_bytes` + `Signer::sign(siwe_message)` + `DelegationChain::new(cacao).verify()` succeeds; `cold_query_sparql_bgp_authed` and `get_entity_quads_cold_authed` both return correct results with real-sig chains; 5 cacao.rs tests + 2 quad_store.rs tests pass
- **SPARQL FILTER/UNION/OPTIONAL (2026-05-27)**: `cold_query_sparql_bgp` refactored to recursive `execute_sparql_graph_pattern`; supports `Filter { Not(Equal) }` (≠), `Filter { FunctionCall Contains }`, `Union` (merge-dedup), `LeftJoin` (OPTIONAL, left-outer-join by subject); `eval_filter_expr` handles Not/Or/And/Equal/Greater/Less/Contains/StrStarts; 4 new tests: `filter_not_equal` (Bob only), `filter_contains` (Carol), `union` (all 3), `optional` (name+role); 117 kotoba-graph tests pass
- **SPARQL Property Paths (2026-05-27)**: `GraphPattern::Path` dispatched to `eval_property_path`; supports `<pred>+` (OneOrMore — BFS ≥1 hop via `bfs_pred_path`), `<pred>*` (ZeroOrMore — BFS ≥0 hops including start), `<p1>/<p2>` (Sequence — 1+1 hop chaining), bare `<pred>` (NamedNode — single hop); 3 new tests: `property_path_one_or_more` (alice→bob via `knows+`), `property_path_zero_or_more_includes_start`, `property_path_no_cid_edges_returns_empty`; 120 kotoba-graph tests pass
- **SPARQL Join + Aggregates (2026-05-28)**: `GraphPattern::Join` dispatched (inner-join by shared subjects, strips `Project` wrappers); `GraphPattern::Group` dispatched (COUNT(*) grouped by object value; global aggregate when no GROUP-BY variables); `GraphPattern::Extend` dispatched (renames internal UUID aggregate variable to user-declared name); 3 new tests: `explicit_join_subquery` (subqueries → Join → Alice+Carol only), `aggregate_count_by_role` (admin=2, user=1), `aggregate_count_all` (total=3); 123 kotoba-graph tests pass
- **SPARQL Minus + VALUES + OrderBy/Slice (2026-05-28)**: `GraphPattern::Minus` (set difference — exclude left quads whose subject appears in right); `GraphPattern::Values` standalone (synthetic quads) + `Join { left: Values }` short-circuit (object-value filter); `GraphPattern::OrderBy` (sort by object text ASC/DESC); `GraphPattern::Slice` (LIMIT/OFFSET — `start` skip + `length` take); `ground_term_to_str()` helper extracts string from spargebra `Literal` using `.value()`; 8 new tests (minus×2, values×3, orderby×3); 131 kotoba-graph tests pass; debug `sparql_dbg3.rs` removed
- **Real EdDSA CACAO + aggregate/MINUS/OrderBy-Limit (2026-05-28)**: 3 new `cold_query_sparql_bgp_authed` tests with real Ed25519 sig: `sparql_authed_real_sig_aggregate_count_by_role` (GROUP BY COUNT → admin=2), `sparql_authed_real_sig_orderby_limit` (ORDER BY ?r LIMIT 2 → 2 admin quads), `sparql_authed_real_sig_minus` (MINUS admin → Bob only); 134 kotoba-graph tests pass
- **N-triple BGP general inner join (2026-05-28)**: `route_bgp_triples` N-triple path: executes each triple as a 1-triple query (via `Box::pin` recursive call), intersects subject sets across all per-triple results, returns all quads for shared subjects; handles unbounded predicates and objects (`?s <p1> ?o1 . ?s <p2> ?o2 . ?s <p3> ?o3`); 4 new tests: `sparql_bgp_three_triple_intersection` (Alice only — has role+name+knows = 3 quads), `sparql_bgp_three_triple_no_match` (Bob no knows → empty), `sparql_bgp_two_triple_general_path_pred_only` (3 subjects × 2 preds = 6 quads), `sparql_bgp_n_triple_with_cacao_auth` (real Ed25519 + 3-triple → 3 quads); 138 kotoba-graph tests pass
- **SPARQL `GraphPattern::Graph` — named graph + multi-graph queries (2026-05-28)**: `execute_sparql_graph_pattern` handles `Graph { name, inner }` — bound (`GRAPH <cid> { ... }` strips `k:` base prefix, parses multibase → `KotobaCid`, executes inner in target graph) and variable (`GRAPH ?g { ... }` enumerates all known graphs via `QuadStore::all_graph_cids()` = CommitDag heads ∪ in-memory Arrangements, fans out inner execution, merges results); `CommitDag::graph_cids()` + `QuadStore::all_graph_cids()` added; 4 new tests: `sparql_graph_bound_named_graph_returns_quads` (2 admins in bound graph), `sparql_graph_bound_unknown_iri_returns_empty` (unknown CID → empty), `sparql_graph_variable_multi_graph_returns_all` (2 graphs → 2 quads each graph represented), `sparql_graph_variable_with_real_eddsa_cacao` (real Ed25519 + GRAPH ?g → 2 quads); 142 kotoba-graph tests pass
- **SPARQL DISTINCT + HAVING + CACAO multi-graph delegation (2026-05-28)**: `GraphPattern::Distinct` arm added (deduplicates by subject+predicate+object key, ignores graph CID for cross-graph dedup); `unwrap_bgp_pattern` no longer strips Distinct (Distinct arm handles inner Project unwrap); `eval_filter_expr` Greater/Less fixed to use `cmp_values()` (numeric i64/f64 comparison before string fallback); `GreaterOrEqual` + `LessOrEqual` handlers added; HAVING works as FILTER on Group output; `CacaoPayload::all_graph_cids()` returns all `kotoba://graph/{cid}` resources; `DelegationChain::authorized_graphs()` + `verify_capability_only()` added; `QuadStore::cold_query_sparql_bgp_multi_graph_authed()` verifies capability + filters results to authorized named graphs; 6 new tests: `sparql_distinct_deduplicates_union_overlap` (UNION+DISTINCT→2 unique quads), `sparql_distinct_cross_graph` (GRAPH?g+DISTINCT→1 deduplicated triple), `sparql_having_filters_aggregate_groups` (HAVING>1→admin only), `sparql_having_ge_passes_all` (HAVING>=1→both groups), `sparql_multi_graph_cacao_filters_unauthorized` (CACAO covers graph_a only→1 quad filtered), `sparql_multi_graph_cacao_two_graphs_authorized` (real Ed25519 multi-graph CACAO→2 quads); **148 kotoba-graph tests pass**
- **SUM/MIN/MAX/AVG/Sample/GroupConcat aggregates + numeric cmp_values (2026-05-28)**: Group handler refactored from u64-only to string-typed dispatch; `AggregateFunction::Min` / `Max` use `cmp_values()` (i64→f64→string fallback, fixes lexicographic ordering for multi-digit numbers); `Sum` tries `i64` fold first then `f64`; `Avg` returns `"{:.2}"` formatted float; `Sample` returns first element; `GroupConcat` joins with separator (default space); 7 new tests: `sparql_aggregate_min_name` (alphabetical MIN=Alice), `sparql_aggregate_max_name` (alphabetical MAX=Carol), `sparql_aggregate_sample_name` (any of {Alice,Bob,Carol}), `sparql_aggregate_group_concat_names` (all 3 names in output), `sparql_aggregate_sum_numeric` (SUM(10+25+15)=50), `sparql_aggregate_avg_numeric` (AVG(10+20+30)=20.00), `sparql_aggregate_min_numeric` (numeric MIN(9,10,100)=9 not lexicographic "10"); **155 kotoba-graph tests pass**
- **Sub-SELECT support (`GraphPattern::Project` in JOIN context, 2026-05-28)**: `execute_sparql_graph_pattern` now handles `GraphPattern::Project { inner }` by recursively executing inner (enables nested `{ SELECT ... WHERE { ... } }` sub-queries); Join handler detects left-side `Project` (sub-SELECT) and uses it for subject filtering only, returning right-side quads that match (correct SPARQL semantics: sub-SELECT projects only its output variables); 2 new tests: `sparql_sub_select_in_join` (`{ SELECT ?s WHERE { ?s <role> "admin" } } ?s <name> ?n` → 2 name quads for admins only), `sparql_sub_select_with_aggregate` (sub-SELECT with GROUP BY COUNT → 2 role-count rows); **157 kotoba-graph tests pass**
- **FILTER EXISTS / NOT EXISTS (2026-05-28)**: `GraphPattern::Filter` arm now detects `Expression::Exists(pattern)` (semi-join: keep outer quads whose subject appears in EXISTS pattern result) and `Expression::Not(Exists(pattern))` (anti-join: keep outer quads whose subject does NOT appear); standard `eval_filter_expr` path used for all other FILTER expressions; 2 new tests: `sparql_filter_exists_semi_join` (`FILTER EXISTS { ?s <knows> ?x }` → only Alice who has a <knows> edge), `sparql_filter_not_exists_anti_join` (`FILTER NOT EXISTS { ?s <knows> ?x }` → Bob+Carol with no <knows>); **159 kotoba-graph tests pass**
- **Property path Alternative/Reverse/ZeroOrOne (2026-05-28)**: `eval_property_path` now handles `Alternative(a|b)` (recursive union of both paths), `Reverse(^pred)` (anti-direction via AEVT predicate scan + CID-object filter → subjects that link TO start), `ZeroOrOne(pred?)` (own quads + 1-hop CID-object expansion); 3 new tests: `sparql_property_path_alternative` (Alice `<name>|<role>` → 2 quads), `sparql_property_path_reverse` (bob `^<knows>` → Alice who knows bob), `sparql_property_path_zero_or_one` (alice `<knows>?` → own + bob's quads); **162 kotoba-graph tests pass**
- **SPARQL UPDATE INSERT DATA / DELETE DATA (2026-05-28)**: `QuadStore::sparql_update(default_graph, sparql)` parses SPARQL 1.1 UPDATE via spargebra `Update::parse`; handles `InsertData { data }` (calls `assert` per quad) and `DeleteData { data }` (calls `retract`); `GRAPH <cid:mb>` clause routes to named graph; helpers `sparql_graph_name_to_cid` / `sparql_named_node_to_cid` / `sparql_term_to_quad_object` / `sparql_term_to_quad_object_ground` convert spargebra types to KotobaCid/QuadObject; 3 new tests: `sparql_update_insert_data` (INSERT 2 quads then query), `sparql_update_delete_data` (assert 2 quads, DELETE 1, verify name survives), `sparql_update_insert_named_graph` (INSERT into GRAPH <cid> clause); **165 kotoba-graph tests pass**
- **CACAO-authed SPARQL UPDATE `sparql_update_authed` (2026-05-28)**: `QuadStore::sparql_update_authed(default_graph, sparql, chain)` calls `chain.verify(graph_mb, "quad:write")` (full Ed25519 sig + capability + graph-scope check) before executing; 3 new tests: `sparql_update_authed_allowed` (real EdDSA CACAO `quad:write` on correct graph → ok, uses `make_real_eddsa_cacao`), `sparql_update_authed_denied_wrong_graph` (wrong graph CID → denied), `sparql_update_authed_denied_wrong_capability` (`quad:read` token → denied for write); **168 kotoba-graph tests pass**
- **SPARQL VALUES inline filter (2026-05-28)**: `GraphPattern::Values` handler matches SPARQL `VALUES ?var { ... }` bindings by converting `GroundTerm` to object strings and filtering quads whose object matches; 3 new tests: `sparql_values_multiple_bindings`, `sparql_values_inline_filter`, `sparql_values_no_match_returns_empty`; test count included in 168 total
- **SPARQL UPDATE MODIFY — INSERT/DELETE WHERE (2026-05-28)**: `GraphUpdateOperation::DeleteInsert` implements pattern-driven graph mutations; WHERE clause executed via `execute_sparql_graph_pattern` → per-matched-quad instantiation of DELETE/INSERT templates via `instantiate_ground_quad_pattern` / `instantiate_quad_pattern`; variable binding: subject `Variable` → `matched.subject`, object `Variable` → `matched.object`, predicates must be concrete named nodes; 2 new tests: `sparql_update_insert_where_marks_admins` (`INSERT { ?s <verified> "yes" } WHERE { ?s <role> "admin" }` → marks 2 admins), `sparql_update_delete_where_removes_by_pattern` (`DELETE { ?s <role> ?r } WHERE { ?s <role> ?r FILTER(?r = "user") }` → retracts user role); **170 kotoba-graph tests pass**
- **SPARQL CONSTRUCT (2026-05-28)**: `QuadStore::sparql_construct(graph_cid, sparql)` parses CONSTRUCT query via spargebra, executes WHERE pattern, and materialises each CONSTRUCT triple template for each matched quad (variable binding: `Variable` → position-based `matched.subject`/`matched.object`); helper `triple_pat_to_quad_pattern` converts `TriplePattern` to `QuadPattern` with DefaultGraph; enables graph-to-graph transfer for distributed sync; 2 new tests: `sparql_construct_single_triple_where` (2 admins → 2 label quads), `sparql_construct_cross_predicate_copy` (copy name → fullname for all 3 subjects); **172 kotoba-graph tests pass**
- **SPARQL ASK + CACAO-authed ASK (2026-05-28)**: `QuadStore::sparql_ask(graph_cid, sparql)` returns `bool` (true if WHERE matches ≥1 quad); `sparql_ask_authed(graph_cid, sparql, chain)` verifies `quad:read` via full Ed25519 sig before executing; 4 new tests: `sparql_ask_existing_pattern_returns_true` (Alice is admin → true), `sparql_ask_missing_pattern_returns_false` (Bob is not admin → false), `sparql_ask_authed_allowed` (real EdDSA CACAO → Ok(true)), `sparql_ask_authed_denied_wrong_graph` (wrong graph CID → denied); **176 kotoba-graph tests pass**
- **BGP routing fix: bound subject + bound predicate + bound object (2026-05-28)**: `route_bgp_triples` bound-subject path now correctly filters by object when object is also bound (literal text/int/float/bool or named-node CID comparison); previously `<cid:s> <p> "v"` returned ALL p-predicated quads for s ignoring the object constraint; fixes SPARQL ASK and SELECT patterns with all three components bound
- **SPARQL DESCRIBE + CACAO-authed DESCRIBE (2026-05-28)**: `QuadStore::sparql_describe(graph_cid, sparql)` returns all quads about each matched entity; supports `DESCRIBE <cid:mb>` (explicit IRI list) and `DESCRIBE ?var WHERE { ... }` (var resolved via WHERE pattern); IRIs extracted via string parsing (spargebra's `Describe` variant embeds resources in pattern), WHERE clause re-parsed as `SELECT *` for algebra execution; subjects deduplicated then each fetched via `get_entity_quads_cold`; `sparql_describe_authed(graph_cid, sparql, chain)` requires `quad:read`; 5 new tests: `sparql_describe_explicit_iri` (Alice → 3 quads: name+role+knows), `sparql_describe_where_clause` (admins → Alice 3 + Carol 2 = 5 quads), `sparql_describe_unknown_iri_returns_empty`, `sparql_describe_authed_allowed`, `sparql_describe_authed_denied_wrong_graph`; useful for distributed entity profile fetching across IPFS nodes; **181 kotoba-graph tests pass**
- **Phase 10 loadtest benchmarks (2026-05-28, 5000 entities)**: DISTINCT p50=188ms, GROUP BY HAVING COUNT p50=131ms, SUM global aggregate p50=113ms, MIN/MAX/AVG GROUP BY p50=1.15s (heavier — 5000 numeric quads ×3 aggregates), GRAPH ?g DISTINCT 3-graph fan-out p50=340ms (9998 results), GRAPH ?g GROUP BY COUNT 3-graph fan-out p50=269ms — IPFS-backed ProllyTree cold path scales linearly with quad count under 4-index routing
- **Phase 11 loadtest — SPARQL DESCRIBE + CACAO (2026-05-28, 5000 entities, release mode)**: `DESCRIBE <cid:single>` p50=863µs (3 quads), `DESCRIBE 10 IRIs` multi-pop p50=4.84ms (30 quads), `DESCRIBE ?s WHERE role=admin` p50=850ms (1666 admins → 5001 quads), real EdDSA CACAO + DESCRIBE 10 IRIs p50=5.02ms (+3.7% vs unauthed), real EdDSA CACAO + DESCRIBE ?s WHERE role=admin p50=851ms, complex 2-triple BGP DESCRIBE (`?s <role> "admin" . ?s <name> ?n`) p50=873ms — sig verification overhead is ~1-4% on DESCRIBE; distributed entity profile fetching scales linearly with entity count
- **BGP routing fix: bound subject + bound predicate (2026-05-28)**: `route_bgp_triples` bound-subject path now also filters by predicate when predicate is bound (previously returned all subject quads ignoring predicate constraint); fixes `<cid:s> <p> ?o` pattern which was returning all quads for s instead of just p-predicated quads
- `cold_query_sparql_bgp` bug fix: cold methods require **original graph CID** (not the commit CID returned by `commit()`)

#### Distributed E2E — import_commit() (2026-05-27)

`QuadStore::import_commit(commit_cid)`: loads a Commit block from the node's own BlockStore into the CommitDag. Enables distributed sync without re-running `commit()`:

```
Node B: commit() → block store has Commit + ProllyTree blocks
Block replication (bitswap/copy): B.block_store → A.block_store
Node A: import_commit(&commit_cid) → CommitDag.add(commit)
Node A: get_entity_quads_cold(&graph, &subject) → reads via ProllyTree
```

loadtest Phase 4 (10K entities, MemoryBlockStore, 293 blocks replicated):
- EAVT cold (post-import_commit) first: ~1.9ms, promoted: ~1.8ms

#### loadtest Phase 6 — SPARQL property paths + aggregates (2026-05-28, 10K entities)

| Query | p50_µs | result_n | Notes |
|---|---|---|---|
| `<knows>+` OneOrMore BFS | 11ms | 5 | 5-hop chain traversal |
| `<knows>*` ZeroOrMore BFS | 14ms | 7 | includes start node quads |
| `GROUP BY role COUNT(*)` | 26ms | 3 | AEVT scan 10K quads |
| Global `COUNT(*)` | 24ms | 1 | AEVT scan 10K quads |
| Subquery JOIN (admin ∩ name) | 205ms | 6668 | AVET(admin)+AEVT(name) inner join |
| CACAO-authed JOIN (verify_skip_sig) | 215ms | 6668 | +10ms auth overhead on JOIN |

#### loadtest Phase 7 — MINUS / VALUES / ORDER BY LIMIT + real EdDSA CACAO (2026-05-28, 10K entities)

| Query | p50_µs | result_n | Notes |
|---|---|---|---|
| `MINUS exclude viewer` | 33ms | 6667 | AEVT scan; excludes 1/3 |
| `VALUES { "admin" } filter` | 24ms | 3334 | object-value HashSet filter |
| `VALUES { "admin" "viewer" } 2-value` | 21ms | 6667 | 2-value filter |
| `ORDER BY ASC LIMIT 10` | 23ms | 10 | full AEVT scan + sort + take(10) |
| `ORDER BY DESC LIMIT 100` | 19ms | 100 | full AEVT scan + sort desc |
| Real EdDSA CACAO + `COUNT(*)` global | 17ms | 1 | Ed25519 verify (~0.1ms) + aggregate |
| Real EdDSA CACAO + `GROUP BY COUNT(*)` | 17ms | 3 | Ed25519 verify + group |
| Distributed `import_commit` + GROUP BY | 2.5ms | 3 | 1K entities / 15 blocks replicated |

#### loadtest Phase 9 — GraphPattern::Graph named graph + multi-graph queries (2026-05-28, 5 graphs × 2K entities)

| Query | p50_µs | result_n | Notes |
|---|---|---|---|
| `GRAPH <cid> ?s <role>="admin"` (single graph) | 3.5ms | 667 | AVET cold single-graph lookup |
| `GRAPH <cid> ?s <name>` (single graph) | 4.8ms | 2000 | AEVT cold single-graph |
| `GRAPH ?g ?s <role>="admin"` (5 graphs fan-out) | 16ms | 3335 | 5× bound-graph cost |
| `GRAPH ?g ?s <name>` (5 graphs fan-out) | 18ms | 10000 | 5× AEVT fan-out |
| `GRAPH ?g ?s <name> ORDER BY LIMIT 20` (5 graphs) | 39ms | 20 | fan-out + cross-graph sort |

#### loadtest Phase 8 — N-triple BGP general inner join (2026-05-28, 10K entities)

| Query | p50_µs | result_n | Notes |
|---|---|---|---|
| 2-triple `?s <name>+<role>` unbound (all) | 1175ms | 20000 | 2 full AEVT scans, intersect all 10K subjects |
| 2-triple `?s <role>="admin" + <name>` | 187ms | 6668 | AVET(admin=3334 subj) × AEVT(name) inner join |
| 3-triple `<role>=admin + <name> + <knows>` | 335ms | 10002 | 3334 admin entities × 3 quads = 10002 |
| 3-triple `<role>=viewer + <name> + <knows>` | 60ms | 0 | viewer has no knows → empty intersection |
| real EdDSA CACAO + 3-triple admin∩name∩knows | 386ms | 10002 | +50ms Ed25519 verify overhead |

Run: `cargo bench -p kotoba-kqe --bench arrangement`  
Run: `cargo bench -p kotoba-graph --bench quad_store`  
Run: `cargo bench -p kotoba-store --bench tiered_store`  
Run: `cargo bench -p kotoba-store --bench car_flush`  
Run: `LOADTEST_MAX=10M LOADTEST_MEM_LIMIT_MB=8192 cargo run --release --example loadtest -p kotoba-graph`

#### TieredBlockStore (2026-05-25, macOS aarch64)

| ベンチ | p50 | スループット |
|---|---|---|
| hot put+get 1K blocks (memory) | 607 µs | **1.65 M blocks/s** |
| hot put+get 10K blocks (memory) | 5.89 ms | **1.70 M blocks/s** |
| cold promote 100 blocks (memory→hot) | 73.8 µs | **1.35 M blocks/s** |
| cold promote 1K blocks | 847 µs | **1.18 M blocks/s** |
| budgeted eviction under pressure | 583 µs | 256×8KB blocks, 1MB budget |
| kubo LAN first_access_50 (cold miss) | **65.7 ms** (50 blocks × 1.31ms) | → 1.31ms/block cold |
| kubo LAN repeat_access_hot_50 | **12.1 µs** (50 blocks) | → 242 ns/block hot |
| S3 same-AZ first_access_10 (cold miss) | **25.6 ms** (10 blocks × 2.56ms) | → 2.56ms/block cold |
| S3 same-AZ repeat_access_hot_10 | **2.55 µs** (10 blocks) | → 255 ns/block hot |

hot キャッシュ効果: kubo LAN **5,413×**、S3 same-AZ **10,039×** 高速。

#### CAR bundle flush (2026-05-25, macOS aarch64)

`CarBundleWriter` — 複数ブロックを 1 ファイルにパックして S3/B2 を **単一 PUT** で flush (Hummock SST 相当)。

**シリアライズ速度**:

| サイズ | 時間 | スループット |
|---|---|---|
| 1K blocks × 1KB (1 MB) | **107 µs** | 8.9 GiB/s |
| 4K blocks × 4KB (16 MB) | **4.45 ms** | 3.4 GiB/s |
| 16K blocks × 4KB (64 MB) | **16.2 ms** | 3.8 GiB/s |

1M quad commit (~16K blocks, ~64MB) のシリアライズは **16ms**。コミット全体 (4.7s) の 0.3%。

**単一 PUT vs 個別 PUT 比較** (bench sleep は実 RTT の 1/1000; 実世界は ×1000):

| シナリオ | CAR 単一 PUT | 個別 PUT 直列 | 実世界換算 (直列) | 実世界換算 (CAR) |
|---|---|---|---|---|
| S3 400 blocks | 38 µs (bench) | 4.98 ms (bench) | **4s** | **serialize 3ms + upload ~1-2s** |
| S3 16K blocks | 1.77 ms (bench) | 163 ms (bench) | **163s** | **serialize 16ms + upload ~2-4s** |
| kubo LAN 16K | 1.92 ms (bench) | 未計測 | **32s** | **serialize 16ms + transfer ~640ms** |

**Range GET** (cold: block index lookup → 単一 HTTP range GET で 4KB 取得):

| パターン | p50 |
|---|---|
| index lookup + extract (I/O なし) | **127 ns** |
| S3 range GET (2ms simulated) | **2.52 ms** |
| kubo LAN range GET (1ms simulated) | **1.28 ms** |

range GET レイテンシは個別 block GET と同等 (帯域コスト削減が主目的)。  
**CarBlockIndex 挿入**: 16K entries で **3.7ms** (HashMap 一括挿入)。

**1M quad commit の end-to-end flush 試算 (CAR bundle 使用)**:

| ステップ | 時間 |
|---|---|
| ProllyTree build (4 trees) | ~4.7 s |
| CAR serialize (16K blocks, 64MB) | ~16 ms |
| S3/B2 upload (64MB, single PUT) | ~2–4 s |
| CarBlockIndex update (16K entries) | ~4 ms |
| IPFS pin (root CID, fire-and-forget) | async |
| **合計** | **~7–9 s** |

現状 (個別 block async fire-and-forget): ProllyTree build 4.7s + cold sync 不保証。  
CAR bundle: **total 7–9s で S3 flush 完了保証**。

#### 100億 quad スケール ディスク試算

1 quad あたりのサイズ根拠 (aarch64 実測、1M quad loadtest):
- EAVT/AEVT: ~84 bytes/quad (8B key + 36B subject + 16B pred + 24B object + ~20B overhead per node)
- AVET: ~40 bytes/quad (述語+値引きのみ、Text 対象)
- VAET: ~45 bytes/quad (ref 型のみ、~30% が ref と仮定)
- Journal WAL: ~218 bytes/quad (CBOR quad エントリ + meta)

| ストレージ層 | 100億 quad 生サイズ | zstd ~2× 圧縮後 |
|---|---|---|
| EAVT (ProllyTree) | 8.4 TB | 4.2 TB |
| AEVT (ProllyTree) | 8.4 TB | 4.2 TB |
| AVET (ProllyTree) | 4.0 TB | 2.0 TB |
| VAET (ProllyTree) | 4.5 TB | 2.3 TB |
| Journal WAL | 21.8 TB | 10.9 TB |
| **合計** | **~47 TB** | **~23.5 TB** |

- 内部ノード容量: ~0.1 TB (全体の 0.2% — 無視可)
- **RAM**: 840 MB 定常 (1M quad バッチウィンドウ、総 quad 数に非依存)
- 単ノード ingest: 290K q/s で 100億 quad = ~4.0 日
- 40 ノード shard: ~10M q/s で 100億 quad = ~2.8 時間
- クエリ深さ (ProllyTree, 100億 quad): ceil(log256(10B)) ≈ **5 levels** → 5 RTTs cold

## Selective Sync + Storage Budget 設計

### SyncWindow (kotoba-kse)
- エージェントが必要な履歴窓を宣言: `SyncWindow { graph_cid, since_seq, head_cid }`
- `pin_into(store)` → anchor CID を BudgetedBlockStore の eviction から保護
- `advance(new_head, seq, store)` → 旧 head アンピン → 新 head ピン
- `unpin_from(store)` → セッション終了時に解放

### Journal Selective Replay (persistent fallback 含む)
- `Journal::read_since(seq)` → ring buffer から `seq` 以降を返す。`seq < oldest_ring_seq` かつ store が Some なら `seq/{seq:020}` seq-index で persistent fallback
- `Journal::trim_before(seq)` → ring buffer の古いエントリを解放
- `Journal::with_capacity(n)` → ring buffer サイズをカスタマイズ (デフォルト 65,536)
- `Journal::publish()` は `{cid}.cbor` に加えて `seq/{seq:020}` → CID multibase の seq-index も書く
- `KseStore::list_prefix(sub_prefix)` → `object_store::list()` を `tokio_stream::StreamExt` でストリーム処理

### QuadStore Delta Sync
- `QuadStore::commits_since(graph_cid, since_head)` → head から `since_head` まで DAG を遡り oldest-first で返す
- fresh agent: `since_head = None` → 全履歴
- 再開 agent: `since_head = Some(last_known_cid)` → delta のみ

### BudgetedBlockStore (kotoba-store)
- `BudgetedBlockStore::new(inner, max_bytes)` → LRU + pin-aware eviction wrapper
- `evict_cold()` → 予算超過時に unpinned cold blocks を `inner.delete()` で削除、target = 80%
- `pin/unpin/is_pinned` → SyncWindow が anchor CID を保護するために使用

### AsyncBlockStore + IdbBlockStore (kotoba-store-web)
- `AsyncBlockStore` trait: `put/get/has/delete/pin/unpin/evict_cold` の async 版 (wasm32: `?Send`)
- `IdbBlockStore` (wasm32 only): IndexedDB `"blocks"` + `"meta"` 2 store
- `evict_cold_async(max_bytes)` → meta の `last_used` 昇順で unpinned entries を削除
- ブラウザはキャッシュのみ。Pregel / WASM 実行はサーバーサイド

### Bitswap WantSince delta wire format (kotoba-net)
- `WantSince { graph_cid, since_seq, head_cid: Option<_> }` — `BitswapRequest.want_since` フィールド (`#[serde(default)]`)
- `BitswapResponse.delta_commits` — CBOR-serialised `Commit` のリスト (oldest-first)
- `KotobaSwarm::want_since(peer, graph_cid, since_seq, head_cid)` でリクエスト送信

### kotoba-server SyncWindow integration
- `maybe_wrap<S: BlockStore + Send + Sync + 'static>(inner: S, budget: Option<usize>) -> Arc<dyn BlockStore + Send + Sync>` — `BudgetedBlockStore<S>` は `S: Sized` バインドのため concrete type で適用してから `Arc<dyn>` にキャスト
- `KOTOBA_STORAGE_BUDGET_BYTES` 環境変数で `BudgetedBlockStore` を有効化
- `KotobaState.agent_sessions: Arc<RwLock<HashMap<String, SyncWindow>>>` — セッション管理
- XRPC: `agent.syncopen` / `agent.syncadvance` / `agent.syncclose`

### 禁止
- `BudgetedBlockStore` 生成時に `max_bytes = 0` (全ブロックが即時 evict される)
- ピンなしで `SyncWindow::advance()` を呼ぶ (store が None でも呼び出せるが古い head が unpin されない)
- `IdbBlockStore` をサーバーサイドで使用 (wasm32 cfg で ガード済み)
- `BudgetedBlockStore<Arc<S>>` の構築 (`Arc<S>: BlockStore` は未実装 → E0277。`maybe_wrap(concrete, budget)` を使う)

## StateGraph 設計 (ADR-2605250002)

SSoT: `90-docs/adr/2605250002-kotoba-state-graph-langgraph-api.md`

### API

```rust
// builder
StateGraph::new(schema)
  .add_node("name", NodeKind::Fn(fn))   // or NodeKind::ToolNode
  .add_edge("from", EdgeTarget::Node("to"))
  .add_conditional_edges("from", router_fn)
  .set_entry_point("name")
  .compile()                             // → CompiledGraph { graph_def_cid, .. }

// run
let thread = compiled.run(thread)?;
```

### Reducer セマンティクス
- `Reducer::Override` — last-write-wins
- `Reducer::Append` — extend semantics: update が Array → `arr.extend(new_items)` (spread); scalar → `arr.push(scalar)`。LangGraph `add_messages` と同一。**push ではなく extend** — ネスト禁止

### graph_def_cid 導出ルール
- 入力: sorted channel 宣言 + sorted node 名 + sorted edge 文字列 + entry point
- Rust クロージャは含めない (シリアライズ不可)
- 同一トポロジーは常に同一 CID → キャッシュ・分散複製に安全

### ToolNode
- `state["tool_calls"]` (Array of `{name, arguments}`) を読み `ToolRegistry` に dispatch
- 結果を `state["messages"]` に append
- ToolNode を使う graph は `messages: Append` + `tool_calls: Override` が必須

### definition_datoms()
- `lgraph/node/{name}` / `lgraph/edge/{from}` / `lgraph/entry` / `lgraph/channel/{name}` Quad を返す
- KQE Datalog でグラフ構造を introspect 可能

### Thread 実行モデル
- Thread ごとに 1 Pregel vertex; 全ノードが 1 BSP superstep 内で順次実行
- KQE Arrangement backing (Phase 1 target): `subject=thread_cid / predicate=channel_name / object=JSON`
- Time-travel: Arrangement Delta から過去の Thread 状態を再構築

### 禁止
- `Reducer::Append` で update value (Array) を `push` する (extend が正)
- `graph_def_cid` にクロージャを含める (shape のみ)
- StateGraph Thread を `DistributedPregelRunner` に渡す (分散実行は未対応)

## WASM Runtime 設計

- WIT world: `crates/kotoba-runtime/wit/world.wit` — `kotoba:kais@0.1.0` パッケージ
- 2 ワールド: `kotoba-node` (フル Pregel ノード) / `kotoba-udf` (ステートレス UDF)
- Host interfaces: `kqe` (Quad 読み書き) / `kse` (Journal) / `auth` (CACAO) / `llm` (CALL_FOREIGN 0xF) / `chain` (SourceChain)
- ガス: assert=10 / query=100 / llm.infer=1000 / default limit=10_000_000
- 多言語 SDK: Rust (wit-bindgen) / Python (componentize-py) / JS/TS (jco) / Go (TinyGo) / C (clang)
- program_cid = WASM bytes の CIDv1 blake3 → Vault/Shelf["KOTOBA_PROGRAMS"] に保存
- ProgramStore: Cranelift JIT 済み Component を DashMap でキャッシュ (再コンパイル不要)

## 実行 Host アーキテクチャ (2026-05-26)

### 実行パス一覧

| 実行バックエンド | crate | 用途 | サーバ接続 |
|---|---|---|---|
| `WasmExecutor` | kotoba-runtime | WASM Component Model host; gas_limit=10M | ✓ `KotobaState.executor` |
| `WasmPregelRunner` | kotoba-vm | WASM を Pregel BSP に乗せる (単頂点 self-loop) | ✓ MCP tool `kotoba_wasm_run` (2026-05-26) |
| `KotobaVm::execute()` | kotoba-vm | Datalog を Pregel BSP で実行; 各 superstep を BlockStore に checkpoint | partial `InvokeRouter` |
| `ReActRunner` | kotoba-vm | sync ReAct ループ (embedded/test) | — |
| `PregelReActRunner` | kotoba-vm | ReAct を Pregel superstep にマッピング | ✓ `xrpc.rs agent.run` |
| `DistributedPregelRunner` | kotoba-vm | cross-node BSP; KotobaSwarm GossipSub 経由 | ✓ `main.rs channel_pair(1024)` |

### Pregel BSP host の設計特性

- **決定論**: inbox sort (src CID multibase) + active vertex sort → 同一メッセージセットで全ノードが同一 compute 入力
- **Checkpoint**: `PregelGraph::checkpoint()` → ProllyTree leaf (BlockStore, CAS); `checkpoint_chained()` → `CID=blake3(root||prev)` で Merkle chain 形成
- **分散**: `DistributedPregelRunner` が local / remote vertex を分離; remote メッセージは `outbound_tx` → `KotobaSwarm::send_pregel_message` (Phase 6 full-mesh replication; Phase 8 shard)

### Economy system — 実装状況 (2026-05-26)

**実装済み (接続あり)**:
- Attestation staking: 自己認証 1,000 KOTO / 検証済み 5,000 KOTO → Quad `attest/stake_mkoto` に永続化
- `WasmExecutor::execute()` → `InvokeResult::gas_used` を返す
- `KotobaVm::execute()` → `ExecResult::gas_used` + `checkpoint_cids` を返す
- `DatalogProgram::evaluate_delta_cited(&deltas, &mut CitationLedger)` — join hit 時に `CitationLedger::cite()` を呼ぶ; `evaluate_delta()` は backward compat で ledger なし版を維持
- MCP tool `kotoba_wasm_run` → `WasmPregelRunner` → `WasmRunResult::total_gas_used` → Quad `gas/consumed_mkoto` per agent DID
- MCP tool `kotoba_datalog_run` → `evaluate_delta_cited` → `flush_epoch()` → `royalty_quads()` → `QuadStore::assert()` per epoch

**未実装 (etzhayyim-exclusive)**:
4. on-chain settlement: ERC-4337 / Base L2 への mKOTO royalty 送金ブリッジ (ADR-2605260004)

**Browser / Edge WASM (Phase N)**:
- `wasmtime` は native-only (wasm32 にコンパイル不可)
- ブラウザ実行は `kotoba-runtime-web` crate が必要 (browser native WebAssembly + IdbBlockStore + metered interpreter)

## 禁止

- 中央マスターノード (DHT 分散)
- `wit-bindgen` macro を kotoba-runtime の **host 側** で使用 (host は dynamic Val dispatch)
- guest WASM を kotoba-runtime crate 内に同梱 (guest は別 crate / 別ビルドターゲット)
- wasmtime version 固定せず range を使用 (`= "22"` で固定)
- gas_limit = 0 での WasmExecutor 生成 (ガスなし実行禁止)
