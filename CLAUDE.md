# ai-gftd-project-kotoba

KOTOBA: Content-Addressed Distributed Datalog Database.

SSoT: `90-docs/adr/2605240001-kotoba-cleanroom-architecture.md`

## 一行定義

KOTOBA ≝ Datom[CID/T] × EAVT[KSE Topic] × Pregel[BSP] × Datalog[Δ]
          × CACAO × AT Protocol × LLM/Weight

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
| kotoba-llm | Weight blob (FP8), LoRA Delta, KV-cache, inference |
| kotoba-server | XRPC / MCP endpoints |

## 実装順序

1. kotoba-core (CID + 8-bit frame + Prolly Tree PoC)
2. kotoba-kse (Journal + Topic + Shelf)
3. kotoba-auth (CACAO chain verify)
4. kotoba-kqe (Datalog + Arrangement + Delta)
5. kotoba-dht (Source Chain + Warrant + Neighborhood)
6. kotoba-vm (Invoke/Result + CALL_FOREIGN)
7. kotoba-llm (weight, LoRA, KV-cache, inference)
8. kotoba-server (XRPC / MCP)

## LLM / Weight 設計

- Weight = Quad(model_cid, "weight/layer/N", blob_cid) — Datom として格納
- LoRA = Delta(Quad(model_cid, "lora/adapter", adapter_cid), +1) — Delta がアダプタ
- KV-cache = ephemeral Arrangement per session_cid
- Inference = Invoke ChainEntry {program_cid: inference_datalog}
- FP8 tensor = Vault blob (dim > 1024 はオフロード)

## 禁止

- IPFS daemon 依存 (CID のみ、Kubo 不使用)
- PostgreSQL wire 互換 (意図的に RisingWave 非互換)
- EVM 実行 (CALL_FOREIGN でブリッジ)
- 中央マスターノード (DHT 分散)
