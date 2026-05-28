# kotoba

**Content-Addressed Distributed Datalog Database**

```
KOTOBA ≝ Datom[CID/T] × EAVT[KSE Topic] × Pregel[BSP] × Datalog[Δ]
          × CACAO × AT Protocol × LLM/Weight × WASM/WIT
```

Kotoba is a distributed, content-addressed knowledge graph database designed
for decentralized AI agent systems.  It combines Datomic-style immutable
datoms, Pregel BSP graph computation, a real SPARQL 1.1 executor over IPFS
storage, native CACAO authentication, and WASM Component Model execution.

## Install

### Homebrew (macOS / Linux)

```bash
# Tap the kotoba formula
brew tap etzhayyim/kotoba          # one-time
brew install kotoba                # installs the `kotoba` binary
```

To track the upstream `main` branch instead of the latest tagged release,
add `--HEAD`:

```bash
brew install --HEAD kotoba
```

Or, install the formula directly from this repo without tapping:

```bash
brew install --build-from-source ./Formula/kotoba.rb
```

### From source (any platform)

```bash
git clone https://github.com/etzhayyim/kotoba.git
cd kotoba
cargo install --locked --path crates/kotoba-cli --bin kotoba
```

## Quick start

The full IPFS + CACAO + SPARQL stack runs as four single-shot commands:

```bash
# 1. One-time: generate Ed25519 + X25519 + DID, persist to macOS Keychain
#    (or ~/.gftd/kotoba.env on Linux/other, chmod 600).
kotoba init

# 2. Start the server. IPFS cold tier + CACAO Private-default are ON by
#    default.  Add KOTOBA_PEERS="http://p1:5001 http://p2:5001" to fan-out
#    across multi-peer DistributedBlockStore.
kotoba serve &

# 3. Smoke-test: ingest a sample entity and run all four SPARQL forms
#    (SELECT / DESCRIBE / CONSTRUCT / ASK) through the direct-SPARQL endpoint.
kotoba demo

# 4. HTTP loadtest the running server.  `--cacao-seed <hex>` runs the bench
#    through the full CACAO + Private-graph path with fresh nonces per request.
kotoba bench --iters 1000 -c 16 'SELECT * WHERE { ?s <kg/claim/role> "admin" }'
```

Bare CLI features:

```bash
kotoba whoami                                    # print resolved config
kotoba sparql 'ASK { ?s <kg/claim/role> "admin" }'
kotoba sparql 'DESCRIBE <cid:abc...>' --cacao <b64>
kotoba cypher 'MATCH (a)-[r]->(b) RETURN a, b'
kotoba health                                    # ping /health
```

CACAO ecosystem helpers:

```bash
kotoba did-derive <32-byte-hex-seed>             # → did:key:z…
kotoba cacao-sign <seed> --graph <cid> \
    --capability quad:read [--private] [--aud <did>]
```

## Defaults that just work

| Knob                       | Default                                                  | Override                       |
|----------------------------|----------------------------------------------------------|--------------------------------|
| Cold tier                  | `KuboBlockStore` against `KOTOBA_IPFS_ENDPOINT`          | `KOTOBA_IPFS=off`              |
| IPFS endpoint              | `http://localhost:5001`                                  | `KOTOBA_IPFS_ENDPOINT=…`       |
| Multi-peer federation      | none (single-node)                                        | `KOTOBA_PEERS="http://… http://…"` |
| Default graph visibility   | `Private { owner_did = operator_did }` (CACAO required)  | `KOTOBA_DEFAULT_VISIBILITY=authenticated\|public\|private` |
| Agent identity             | macOS Keychain → `~/.gftd/kotoba.env` → env → ephemeral  | `kotoba init`                   |

`kotoba serve` boots with a clear startup probe: if `ipfs daemon` is not
reachable on `KOTOBA_IPFS_ENDPOINT`, you get a single WARN line telling you
exactly how to silence or fix it.

## Crates

| Crate              | Role                                                                       |
|--------------------|----------------------------------------------------------------------------|
| `kotoba-core`      | CIDv1 blake3, KAIS 8-bit frame, Prolly Tree                                |
| `kotoba-kse`       | Journal (Merkle WAL), Vault (CDC chunker), Topic, Shelf, AgentIdentity     |
| `kotoba-kqe`       | Datalog engine, Arrangement (EAVT/AEVT/AVET/VAET), Delta, MV               |
| `kotoba-dht`       | Source Chain, Warrant, Neighborhood (DHT)                                  |
| `kotoba-net`       | libp2p QUIC/Noise/GossipSub                                                |
| `kotoba-auth`      | CACAO chain (depth-2), multi-graph grants, EdDSA verify, did:key, Passkey  |
| `kotoba-graph`     | Quad API, SPARQL 1.1 (BGP/Filter/Union/Optional/Group/Path/Service/…), Datalog cold, CID-MV cache, Commit DAG, N-hop DESCRIBE |
| `kotoba-vm`        | Invoke/Result ChainEntry, CALL_FOREIGN bridge                              |
| `kotoba-llm`       | Weight blob (FP8), LoRA Delta, KV-cache, WebGPU train + infer (Gemma 4)     |
| `kotoba-runtime`   | WASM Component Model host: WasmExecutor + UdfExecutor + WIT bindings       |
| `kotoba-store`     | BlockStore: Memory, Kubo HTTP, BudgetedBlockStore LRU, TieredBlockStore, DistributedBlockStore multi-peer |
| `kotoba-store-web` | Browser IndexedDB block store (wasm32)                                     |
| `kotoba-crypto`    | AEAD (AES-256-GCM), HKDF, key wrap                                         |
| `kotoba-signal`    | Signal Protocol (X3DH + Double Ratchet + MLS)                              |
| `kotoba-ingest`    | Gmail OAuth2 poll + RFC 2822 parse + E2E encrypt → QuadStore               |
| `kotoba-server`    | XRPC / MCP endpoints (kg.ingest / kg.ingest_batch / kg.query / kg.sparql)  |
| `kotoba-cli`       | `kotoba` binary (init, serve, demo, bench, sparql, …)                      |
| `kotoba-guest`     | WASM guest SDK (WIT bindings for kotoba nodes)                             |

## Properties

- **Content-addressed** — every block keyed by CIDv1 blake3 + dag-cbor
- **Immutable datoms** — Datomic-style EAVT with Delta (assert/retract)
- **4-index arrangement** — EAVT / AEVT / AVET / VAET for O(1)–O(log n) access
- **Prolly Tree storage** — deterministic, hash-consistent B-tree over blocks
- **Distributed Pregel** — BSP graph computation across nodes via libp2p
- **AT Protocol native** — quad store backed by commit DAG and JetStream
- **WASM runtime** — arbitrary graph logic as Component Model guests
- **E2E encryption** — Signal Protocol + CACAO auth for consent-gated data
- **SPARQL 1.1 + Datalog** — same QuadStore answers both; CID-addressed MV cache turns repeat queries into µs lookups
- **CACAO-native authz** — depth-2 delegation chains, multi-graph grants, anti-replay nonce

## SPARQL surface

Server endpoint: `POST /xrpc/ai.gftd.apps.kotoba.graph.sparql`

Auto-detects the form from the leading keyword and dispatches to the
matching `QuadStore` cold-path method:

- `SELECT` — BGP / Filter / Union / Optional / Sub-SELECT / VALUES / GROUP BY / HAVING / ORDER BY / LIMIT / OFFSET / Property paths `+ * ? ^ |` / Sequence
- `DESCRIBE` — explicit IRIs and `?var WHERE { … }` forms; parallel per-subject fetch
- `CONSTRUCT` — template instantiation from any WHERE pattern
- `ASK` — constant-time short-circuit on first match
- `UPDATE` — `INSERT DATA` / `DELETE DATA` / `INSERT/DELETE WHERE`
- `SERVICE <cid:remote-graph>` — federated query across content-addressed graphs

Every form has a CACAO-authed variant — pass `cacaoB64` in the request body.

## Performance

Measurements taken on M4 Mac, release build, `KOTOBA_IPFS=off`,
`kotoba bench` against `kotoba serve`.

### Ingest

| path                                | rate                       |
|-------------------------------------|----------------------------|
| `kg.ingest`        (single, HTTP)   | 28 entities/sec            |
| `kg.ingest_batch`  (1 batch × 1000) | **3981 entities/sec** (142×) |
| `kg.ingest_batch`  (10 × 1000)      | **5222 entities/sec** sustained |

### Query (unauthed, 2000-entity graph)

| query                                  | result_n | seq p50 | seq QPS | c=16 QPS |
|----------------------------------------|----------|---------|---------|----------|
| `ASK     ?s <role> "admin"`            | true     | 0.32 ms | 2586    | —        |
| `SELECT  ?s <role> "admin"`            | 666      | 11.3 ms | 21      | 398      |
| 2-triple JOIN role+score               | 1332     | 18.5 ms | 51      | —        |
| `GROUP BY role COUNT(*)`               | 2 grp    | 5.1 ms  | 183     | —        |
| `CONSTRUCT … WHERE role=admin`         | 666      | 5.9 ms  | 135     | —        |

### CACAO-gated (5000 entities, fresh CACAO per request, 100% success)

| query                          | result_n | seq p50 | seq QPS |
|--------------------------------|----------|---------|---------|
| `ASK`                          | true     | 0.68 ms | 1212    |
| `SELECT role=admin`            | 1667     | 11.5 ms | 71      |
| 2-triple JOIN role+dept        | 3334     | 41.0 ms | 23      |
| `GROUP BY role COUNT(*)`       | 2 grp    | 4.5 ms  | 189     |

### CACAO concurrency sweep (3000-entity graph)

| concurrency | QPS         | p50      |
|-------------|-------------|----------|
| 1           | 3916        | 0.20 ms  |
| 8           | 10113       | 0.52 ms  |
| 16          | 10140       | 1.27 ms  |
| 32          | **12753**   | 2.15 ms  |

Trust-boundary throughput **12.8K QPS** at c=32, 100% replay-protected.

## Build

```bash
cargo build --workspace
cargo test --workspace                  # ~1184 tests pass
cargo build --release -p kotoba-cli     # final `kotoba` binary
```

## ADR

Design decisions live in
[`90-docs/adr/2605240001-kotoba-cleanroom-architecture.md`](https://github.com/gftdcojp/ai-gftd-apps-gftdcojp/blob/main/90-docs/adr/2605240001-kotoba-cleanroom-architecture.md)
of the parent monorepo.  Section §27 captures the current SPARQL surface,
HTTP loadtest matrix, and operator-UX defaults.

## License

Apache-2.0 — see [LICENSE](LICENSE).
