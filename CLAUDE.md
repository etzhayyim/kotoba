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
| kotoba-kse | Journal, Topic, Shelf, Vault (KSE) |
| kotoba-kqe | Datalog engine, Arrangement, Delta, MV (KQE) |
| kotoba-dht | Source Chain, Warrant, Neighborhood (KDHT) |
| kotoba-net | libp2p QUIC/Noise/GossipSub |
| kotoba-auth | CACAO chain verification, DID Document |
| kotoba-graph | Quad API, SPARQL→Datalog, Commit DAG |
| kotoba-vm | Invoke/Result ChainEntry, CALL_FOREIGN bridge (KVM) |
| kotoba-llm | Weight blob (FP8), LoRA Delta, KV-cache, inference, WebGPU training (embed+lm_head), WebGPU inference (full transformer, Gemma 4 E2B/E4B) |
| kotoba-runtime | WASM Component Model host: WasmExecutor + UdfExecutor + WIT bindings |
| kotoba-ingest | Gmail OAuth2 poll + RFC 2822 parse + E2E encrypt → QuadStore (ADR-2605252400) |
| kotoba-server | XRPC / MCP endpoints |
| kotoba-store | BlockStore implementations: Memory, Sled, S3; BudgetedBlockStore<S> LRU eviction; TieredBlockStore<H,C> hot/cold tiering; IrohBlockStore (feature=iroh-cold, iroh-blobs 0.30) |
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
- `QuadStore::commit()` は EAVT/AEVT/AVET/VAET の 4 ProllyTree を個別 persist
- Journal: 4 トピック SPO + PSO + POS + OSP に publish

## TieredBlockStore / IrohBlockStore

- `TieredBlockStore<H, C>`: hot (Sled/Budgeted) + cold (iroh/S3) の 2 層
  - put: hot に即時書き込み + cold に `tokio::spawn` fire-and-forget
  - get: hot ヒット → 即返却; hot miss → cold fetch + hot promote
  - pin/unpin: hot 層に委譲 (SyncWindow compatible)
- `IrohBlockStore` (feature=`iroh-cold`): iroh-blobs 0.30 の in-process store
  - `blake3 CIDv1 hash = cid.0[4..36]` → `iroh_blobs::Hash`
  - daemon 不要、Kubo 不使用
  - sync BlockStore は `tokio::task::block_in_place` でブリッジ

## criterion ベンチマーク

- `kotoba-kqe/benches/arrangement.rs`: insert (1k/10k/100k), SPO/PSO/POS/OCP lookup, prefix scan
- `kotoba-store/benches/tiered_store.rs`: hot put/get, cold-promote, budgeted eviction

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

## 禁止

- IPFS daemon 依存 (CID のみ、Kubo 不使用)
- PostgreSQL wire 互換 (意図的に RisingWave 非互換)
- EVM 実行 (CALL_FOREIGN でブリッジ)
- 中央マスターノード (DHT 分散)
- `wit-bindgen` macro を kotoba-runtime の **host 側** で使用 (host は dynamic Val dispatch)
- guest WASM を kotoba-runtime crate 内に同梱 (guest は別 crate / 別ビルドターゲット)
- wasmtime version 固定せず range を使用 (`= "22"` で固定)
- gas_limit = 0 での WasmExecutor 生成 (ガスなし実行禁止)
