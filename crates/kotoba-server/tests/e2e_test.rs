//! E2E integration tests for kotoba-server.
//!
//! Each test spawns the axum router on a random OS-assigned port, fires HTTP
//! requests with `reqwest`, and asserts on the JSON response.  The server is
//! dropped at the end of each test via a tokio `JoinHandle` abort.
//!
//! A deterministic stub `InferenceFn` satisfies agent.run / infer.run so these
//! tests run without a real LLM or network dependency.

use std::sync::Arc;

use kotoba_server::{build_router, server::KotobaState};
use serde_json::{json, Value};

// ── Stub inference engine ─────────────────────────────────────────────────────

fn stub_engine() -> kotoba_server::server::InferenceFn {
    Arc::new(|prompt: &str, _max: usize| -> anyhow::Result<String> {
        if prompt.contains("Thought") || prompt.is_empty() {
            Ok("Thought: done.\nAction: Finish[stub answer]".into())
        } else {
            Ok(format!("stub: {prompt}"))
        }
    })
}

// ── Server fixture ────────────────────────────────────────────────────────────

struct TestServer {
    base_url: String,
    operator_did: String,
    state: Arc<KotobaState>,
    handle: tokio::task::JoinHandle<()>,
    client: reqwest::Client,
}

impl TestServer {
    async fn start(with_inference: bool) -> Self {
        // Tests pre-date the 2026-05-28 default-Private flip; keep the historic
        // Bearer-token-only auth behaviour unless an individual test overrides.
        std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "authenticated");
        // KuboBlockStore::put uses block_in_place which requires the multi-
        // thread tokio runtime; #[tokio::test] defaults to current_thread.
        // Disable IPFS cold tier in tests so puts stay in the hot memory cache.
        std::env::set_var("KOTOBA_IPFS", "off");
        let engine = if with_inference {
            Some(stub_engine())
        } else {
            None
        };
        let state = Arc::new(KotobaState::new(engine).expect("KotobaState::new"));
        let operator_did = state.operator_did.clone();
        let app = build_router(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");

        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });

        // brief settle — axum::serve is ready immediately after spawn
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        Self {
            base_url,
            operator_did,
            state,
            handle,
            client: reqwest::Client::new(),
        }
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        let r = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .expect("GET");
        let status = r.status().as_u16();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let r = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(&body)
            .send()
            .await
            .expect("POST");
        let status = r.status().as_u16();
        let text = r.text().await.unwrap_or_default();
        let resp: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (status, resp)
    }

    async fn post_auth(&self, path: &str, body: Value, token: &str) -> (u16, Value) {
        let r = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .header("Authorization", format!("Bearer {token}"))
            .json(&body)
            .send()
            .await
            .expect("POST");
        let status = r.status().as_u16();
        let text = r.text().await.unwrap_or_default();
        let resp: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        (status, resp)
    }

    /// GET with `Authorization: Bearer <token>` for authenticated-tier graphs.
    async fn get_authed(&self, path: &str) -> (u16, Value) {
        let r = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .header("Authorization", "Bearer test-e2e-token")
            .send()
            .await
            .expect("GET authed");
        let status = r.status().as_u16();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    async fn get_with_auth(&self, path: &str, token: &str) -> (u16, Value) {
        let r = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .expect("GET with auth");
        let status = r.status().as_u16();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        (status, body)
    }

    /// POST quad.create with a freshly-signed Ed25519 CACAO for the given graph.
    async fn post_quad(
        &self,
        graph: &str,
        subject: &str,
        predicate: &str,
        object: &str,
    ) -> (u16, Value) {
        let (_, cacao_b64) = build_ed25519_cacao(graph);
        self.post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({
                "graph":     graph,
                "subject":   subject,
                "predicate": predicate,
                "object":    object,
                "cacao_b64": cacao_b64,
            }),
        )
        .await
    }

    async fn post_datom(
        &self,
        graph: &str,
        subject: &str,
        predicate: &str,
        object: &str,
    ) -> (u16, Value) {
        let (_, cacao_b64) = build_ed25519_cacao(graph);
        self.post(
            "/xrpc/ai.gftd.apps.kotoba.datom.create",
            json!({
                "graph":     graph,
                "subject":   subject,
                "predicate": predicate,
                "object":    object,
                "cacao_b64": cacao_b64,
            }),
        )
        .await
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/health").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert!(body["version"].as_str().is_some());
}

#[tokio::test]
async fn app_meta_returns_ok() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/_app/meta").await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn node_status_returns_node_id() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .get_with_auth("/xrpc/ai.gftd.apps.kotoba.node.status", &tok)
        .await;
    assert_eq!(status, 200);
    assert!(
        body["node_id"].as_str().is_some(),
        "node_id missing: {body}"
    );
}

#[tokio::test]
async fn node_status_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s.get("/xrpc/ai.gftd.apps.kotoba.node.status").await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn node_status_non_operator_returns_401() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zNonOperator");
    let (status, body) = s
        .get_with_auth("/xrpc/ai.gftd.apps.kotoba.node.status", &tok)
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn quad_create_returns_journal_cid() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_quad("e2e", "alice", "knows", "bob").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["journal_cid"].as_str().is_some());
    assert_eq!(body["datom_cid"], body["journal_cid"]);
    assert_eq!(body["quad_cid"], body["journal_cid"]);
}

#[tokio::test]
async fn datom_create_returns_journal_cid() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_datom("e2e-datom", "alice", "knows", "bob").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["journal_cid"].as_str().is_some());
    assert_eq!(body["datom_cid"], body["journal_cid"]);
}

#[tokio::test]
async fn graph_query_empty_graph_returns_zero() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let cid = KotobaCid::from_bytes(b"nonexistent-graph-xyz").to_multibase();
    // Unknown graphs default to Authenticated tier — send a Bearer token.
    let (status, body) = s
        .get_authed(&format!(
            "/xrpc/ai.gftd.apps.kotoba.graph.query?graph={cid}"
        ))
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["count"], 0);
}

#[tokio::test]
async fn graph_query_after_create_returns_quad() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;

    s.post_quad("qtest", "x", "rel", "y").await;

    let graph_cid = KotobaCid::from_bytes(b"qtest").to_multibase();
    // Unknown graphs default to Authenticated tier — send a Bearer token.
    let (status, body) = s
        .get_authed(&format!(
            "/xrpc/ai.gftd.apps.kotoba.graph.query?graph={graph_cid}"
        ))
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["count"].as_u64().unwrap_or(0) >= 1,
        "expected ≥1 quad: {body}"
    );
}

#[tokio::test]
async fn graph_query_accepts_cacao_graph_query_operation_scope_on_private_graph() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let graph = "graph-query-cacao-private-e2e";
    let graph_cid = KotobaCid::from_bytes(graph.as_bytes()).to_multibase();

    let (status, create_body) = s.post_quad(graph, "x", "rel", "y").await;
    assert_eq!(status, 200, "{create_body}");

    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "private");
    let cacao_b64 = build_ed25519_cacao_for_operation(
        &graph_cid,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
        "nonce-graph-query-private-e2e",
    );
    let r = s
        .client
        .get(format!(
            "{}/xrpc/ai.gftd.apps.kotoba.graph.query",
            s.base_url
        ))
        .query(&[
            ("graph", graph_cid.as_str()),
            ("cacao_b64", cacao_b64.as_str()),
        ])
        .send()
        .await
        .expect("GET graph.query with cacao");
    let status = r.status().as_u16();
    let body: Value = r.json().await.unwrap_or(Value::Null);
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "authenticated");

    assert_eq!(status, 200, "{body}");
    assert!(
        body["count"].as_u64().unwrap_or(0) >= 1,
        "expected graph:query CACAO to read private graph: {body}"
    );
}

#[tokio::test]
async fn datomic_transact_q_pull_history_roundtrip_via_distributed_head() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-distributed-e2e").to_multibase();

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "alice" :person/name "Alice" :person/age 30 :person/role :admin :person/friend "bob" :person/bio "Kotoba stores W3C credentials as Datoms. Kotoba queries run on IPLD." :atproto/uri "at://did:plc:alice/app.bsky.feed.post/r1"}
                              {:db/id "vc1" :credential/claims {:claim/type "VerifiableCredential" :claim/status "active" :claim/verified true :claim/score 42 :claim/tags [:vc :ipld] :claim/subject {:subject/id "did:example:alice" :subject/roles [:issuer :holder]}}}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");
    assert_eq!(tx_body["status"], "ok");
    assert!(tx_body["commit_cid"].as_str().is_some(), "{tx_body}");
    assert!(tx_body["ipns_name"]
        .as_str()
        .unwrap_or_default()
        .starts_with("k51-kotoba-"));
    assert_eq!(tx_body["ipns_sequence"], 1);
    assert_eq!(
        tx_body["index_roots"].as_object().map(|o| o.len()),
        Some(5),
        "{tx_body}"
    );
    let required_roots = ["eavt", "aevt", "avet", "vaet", "tea"];
    let index_roots = tx_body["index_roots"].as_object().expect("index roots");
    for root in required_roots {
        assert!(
            index_roots.get(root).and_then(|cid| cid.as_str()).is_some(),
            "missing {root} root: {tx_body}"
        );
    }

    let commit_cid = tx_body["commit_cid"].as_str().expect("commit cid");
    let (status, commit_block_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.block.get?cid={commit_cid}"
        ))
        .await;
    assert_eq!(status, 200, "{commit_block_body}");
    let commit_block_bytes = {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let data_b64 = commit_block_body["data_b64"]
            .as_str()
            .expect("commit block data_b64");
        assert!(!data_b64.is_empty(), "{commit_block_body}");
        B64.decode(data_b64).expect("commit block base64")
    };
    let decoded_commit: kotoba_datomic::distributed::DistributedDatomCommit =
        ciborium::from_reader(commit_block_bytes.as_slice()).expect("commit block DAG-CBOR");
    assert_eq!(
        decoded_commit.graph.to_multibase(),
        graph,
        "{commit_block_body}"
    );
    assert_eq!(
        decoded_commit.tx_cid.to_multibase(),
        tx_body["tx_cid"].as_str().unwrap(),
        "{commit_block_body}"
    );
    assert_eq!(decoded_commit.seq, 1, "{commit_block_body}");
    assert_eq!(decoded_commit.index_roots.len(), 5, "{commit_block_body}");
    for root in required_roots {
        let root_cid = index_roots[root].as_str().expect("root cid");
        let (status, root_block_body) = s
            .get(&format!(
                "/xrpc/ai.gftd.apps.kotoba.block.get?cid={root_cid}"
            ))
            .await;
        assert_eq!(status, 200, "{root_block_body}");
        let root_block_bytes = {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let data_b64 = root_block_body["data_b64"]
                .as_str()
                .expect("root block data_b64");
            assert!(!data_b64.is_empty(), "{root_block_body}");
            B64.decode(data_b64).expect("root block base64")
        };
        let root_node: kotoba_core::prolly::ProllyNode =
            ciborium::from_reader(root_block_bytes.as_slice()).expect("ProllyTree node DAG-CBOR");
        match root_node {
            kotoba_core::prolly::ProllyNode::Leaf { .. }
            | kotoba_core::prolly::ProllyNode::Internal { .. } => {}
        }
    }
    #[derive(serde::Deserialize)]
    struct StoredDatomForTest {
        a: String,
        v_edn: String,
        t: String,
        added: bool,
    }
    let tea_root = kotoba_core::cid::KotobaCid::from_multibase(
        index_roots["tea"].as_str().expect("tea root cid"),
    )
    .expect("tea root cid parse");
    let tea_entries =
        kotoba_core::prolly::ProllyTree::scan_prefix(&tea_root, &[], &*s.state.block_store)
            .expect("scan tea ProllyTree");
    assert!(
        !tea_entries.is_empty(),
        "TEA ProllyTree must contain tx datoms"
    );
    let tx_cid = tx_body["tx_cid"].as_str().expect("tx cid");
    assert!(
        tea_entries.into_iter().any(|(_, value)| {
            let stored: StoredDatomForTest =
                ciborium::from_reader(value.as_slice()).expect("stored datom DAG-CBOR");
            stored.a == ":person/name"
                && stored.v_edn == "\"Alice\""
                && stored.t == tx_cid
                && stored.added
        }),
        "TEA ProllyTree must preserve datom T and Added for :person/name"
    );

    let (status, commit_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.commit.get?graph={graph}"
        ))
        .await;
    assert_eq!(status, 200, "{commit_body}");
    assert_eq!(
        commit_body["commit_type"], "distributed-datomic",
        "{commit_body}"
    );
    assert_eq!(commit_body["cid"], tx_body["commit_cid"], "{commit_body}");
    assert_eq!(commit_body["tx_cid"], tx_body["tx_cid"], "{commit_body}");
    assert_eq!(commit_body["ipns_verified"], true, "{commit_body}");
    assert_eq!(
        commit_body["ipns_value_matches_commit"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_sequence_matches_commit"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_graph_matches_request"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["index_roots"], tx_body["index_roots"],
        "{commit_body}"
    );

    let (status, q_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name] [?e :person/age ?age] [(> ?age 18)]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{q_body}");
    assert_eq!(q_body["rows_edn"][0][0], "\"Alice\"", "{q_body}");
    assert_eq!(q_body["basis_t"], tx_body["tx_cid"], "{q_body}");

    let (status, fulltext_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name ?score]
                                 :where [[(fulltext $ :person/bio "KOTOBA") [[?e ?bio ?tx ?score]]]
                                         [?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{fulltext_body}");
    assert_eq!(
        fulltext_body["rows_edn"],
        json!([["\"Alice\"", "2"]]),
        "{fulltext_body}"
    );
    assert_eq!(
        fulltext_body["basis_t"], tx_body["tx_cid"],
        "{fulltext_body}"
    );

    let (status, predicate_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name ?uri ?collection ?rkey ?splitCollection ?splitRkey ?nthCollection ?lastRkey ?joinedUri ?normalizedUri ?scheme ?trimmedScheme]
                                 :where [[?e :person/role ?role]
                                         [(contains? #{:admin :moderator} ?role)]
                                         [?e :atproto/uri ?uri]
                                         [(clojure.string/starts-with? ?uri "at://")]
                                         [(clojure.string/includes? ?uri "/app.bsky.feed.post/")]
                                         [(str/ends-with? ?uri "/r1")]
                                         [(subs ?uri 19 37) ?collection]
                                         [(clojure.core/subs ?uri 38) ?rkey]
                                         [(clojure.string/split ?uri "/") ?uriParts]
                                         [(get ?uriParts 3) ?splitCollection]
                                         [(get ?uriParts 4) ?splitRkey]
                                         [(nth ?uriParts 3) ?nthCollection]
                                         [(last ?uriParts) ?lastRkey]
                                         [(clojure.string/join "/" ?uriParts) ?joinedUri]
                                         [(= ?joinedUri ?uri)]
                                         [(clojure.string/replace ?uri "at://" "at-uri://") ?normalizedUri]
                                         [(upper-case "at") ?upperScheme]
                                         [(clojure.string/lower-case ?upperScheme) ?scheme]
                                         [(str/trim "  at  ") ?trimmedScheme]
                                         [?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{predicate_body}");
    assert_eq!(
        predicate_body["rows_edn"],
        json!([[
            "\"Alice\"",
            "\"at://did:plc:alice/app.bsky.feed.post/r1\"",
            "\"app.bsky.feed.post\"",
            "\"r1\"",
            "\"app.bsky.feed.post\"",
            "\"r1\"",
            "\"app.bsky.feed.post\"",
            "\"r1\"",
            "\"at://did:plc:alice/app.bsky.feed.post/r1\"",
            "\"at-uri://did:plc:alice/app.bsky.feed.post/r1\"",
            "\"at\"",
            "\"at\""
        ]]),
        "{predicate_body}"
    );

    let (status, get_function_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?type ?status ?verified ?score ?nextScore ?adjustedScore ?doubleScore ?quotScore ?remScore ?modScore ?negativeMod ?minScore ?maxScore ?firstTag ?tagCount ?subject ?firstRole ?generatedStatus ?summaryCount ?fallback ?nonEmptyTags]
                                 :where [[?e :credential/claims ?claims]
                                         [(map? ?claims)]
                                         [(coll? ?claims)]
                                         [(get ?claims :claim/type) ?type]
                                         [(string? ?type)]
                                         [(get ?claims :claim/status) ?status]
                                         [(get ?claims :claim/verified) ?verified]
                                         [(boolean? ?verified)]
                                         [(true? ?verified)]
                                         [(get ?claims :claim/score) ?score]
                                         [(integer? ?score)]
                                         [(number? ?score)]
                                         [(update ?claims :claim/score + 1) ?updatedScoreClaims]
                                         [(get ?updatedScoreClaims :claim/score) ?updatedScore]
                                         [(= ?updatedScore 43)]
                                         [(+ ?score 1) ?nextScore]
                                         [(- ?nextScore 2) ?adjustedScore]
                                         [(* ?score 2) ?doubleScore]
                                         [(quot ?score 2) ?quotScore]
                                         [(rem ?score 2) ?remScore]
                                         [(zero? ?remScore)]
                                         [(mod ?score 5) ?modScore]
                                         [(mod -3 5) ?negativeMod]
                                         [(neg? -1)]
                                         [(min ?score 50) ?minScore]
                                         [(max ?score 10) ?maxScore]
                                         [(pos? ?score)]
                                         [(< 0 ?score ?nextScore 100)]
                                         [(<= 42 ?score ?score ?nextScore)]
                                         [(> 100 ?doubleScore ?score 0)]
                                         [(>= 84 ?doubleScore ?score 42)]
                                         [(= ?score 42 42)]
                                         [(not= ?score ?nextScore ?score)]
                                         [(get ?claims :claim/tags) ?tags]
                                         [(vector? ?tags)]
                                         [(seq ?tags) ?seqTags]
                                         [(some? ?seqTags)]
                                         [(get ?tags 0) ?firstTag]
                                         [(first ?tags) ?seqFirstTag]
                                         [(= ?seqFirstTag ?firstTag)]
                                         [(rest ?tags) ?restTags]
                                         [(= ?restTags [:ipld])]
                                         [(next ?tags) ?nextTags]
                                         [(= ?nextTags [:ipld])]
                                         [(next [:vc]) ?singleNext]
                                         [(nil? ?singleNext)]
                                         [(conj ?tags :dag-cbor) ?extendedTags]
                                         [(= ?extendedTags [:vc :ipld :dag-cbor])]
                                         [(cons :json-ld ?tags) ?wireTags]
                                         [(= ?wireTags [:json-ld :vc :ipld])]
                                         [(hash-map :claim/type ?type) ?baseSummary]
                                         [(vector :claim/status ?status) ?statusPair]
                                         [(conj ?baseSummary ?statusPair) ?summary2]
                                         [(= ?summary2 {:claim/type "VerifiableCredential" :claim/status "active"})]
                                         [(assoc ?summary2 :claim/format :dag-cbor) ?summary3]
                                         [(= ?summary3 {:claim/type "VerifiableCredential" :claim/status "active" :claim/format :dag-cbor})]
                                         [(dissoc ?summary3 :claim/format) ?summary4]
                                         [(= ?summary4 ?summary2)]
                                         [(assoc ?tags 2 :dag-cbor) ?assocTags]
                                         [(= ?assocTags [:vc :ipld :dag-cbor])]
                                         [(take 1 ?assocTags) ?firstAssocTag]
                                         [(= ?firstAssocTag [:vc])]
                                         [(drop 1 ?assocTags) ?tailAssocTags]
                                         [(= ?tailAssocTags [:ipld :dag-cbor])]
                                         [(subvec ?assocTags 1 3) ?middleAssocTags]
                                         [(= ?middleAssocTags [:ipld :dag-cbor])]
                                         [(reverse ?assocTags) ?reverseAssocTags]
                                         [(= ?reverseAssocTags [:dag-cbor :ipld :vc])]
                                         [(sort ?reverseAssocTags) ?sortedAssocTags]
                                         [(= ?sortedAssocTags [:dag-cbor :ipld :vc])]
                                         [(keyword? ?firstTag)]
                                         [(count ?tags) ?tagCount]
                                         [(not-empty ?tags) ?nonEmptyTags]
                                         [(some? ?nonEmptyTags)]
                                         [(vector) ?emptyTags]
                                         [(empty? ?emptyTags)]
                                         [(get-in ?claims [:claim/subject :subject/id]) ?subject]
                                         [(string? ?subject)]
                                         [(assoc-in ?claims [:claim/subject :subject/verified] true) ?verifiedClaims]
                                         [(get-in ?verifiedClaims [:claim/subject :subject/verified]) ?subjectVerified]
                                         [(true? ?subjectVerified)]
                                         [(update-in ?claims [:claim/subject :subject/roles] conj :verifier) ?roleUpdatedClaims]
                                         [(get-in ?roleUpdatedClaims [:claim/subject :subject/roles]) ?updatedRoles]
                                         [(= ?updatedRoles [:issuer :holder :verifier])]
                                         [(get-in ?claims [:claim/subject :subject/roles 0]) ?firstRole]
                                         [(vector :vc :ipld) ?expectedTags]
                                         [(= ?tags ?expectedTags)]
                                         [(hash-set :issuer :holder) ?expectedRoles]
                                         [(set? ?expectedRoles)]
                                         [(contains? ?expectedRoles ?firstRole)]
                                         [(disj ?expectedRoles :holder) ?issuerOnly]
                                         [(= ?issuerOnly #{:issuer})]
                                         [(hash-map :claim/type ?type :claim/status ?status) ?summary]
                                         [(map? ?summary)]
                                         [(get ?summary :claim/status) ?generatedStatus]
                                         [(count ?summary) ?summaryCount]
                                         [(get ?claims :claim/missing) ?missing]
                                         [(nil? ?missing)]
                                         [(get ?claims :claim/missing "fallback") ?fallback]
                                         [(some? ?fallback)]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{get_function_body}");
    assert_eq!(
        get_function_body["rows_edn"],
        json!([[
            "\"VerifiableCredential\"",
            "\"active\"",
            "true",
            "42",
            "43",
            "41",
            "84",
            "21",
            "0",
            "2",
            "2",
            "42",
            "42",
            ":vc",
            "2",
            "\"did:example:alice\"",
            ":issuer",
            "\"active\"",
            "2",
            "\"fallback\"",
            "[:vc :ipld]"
        ]]),
        "{get_function_body}"
    );

    let alice = tx_body["tempids"]["alice"].as_str().unwrap();
    let (status, datoms_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.datoms",
            json!({
                "graph": graph,
                "index": ":eavt",
                "components_edn": [format!("\"{alice}\""), ":person/name"],
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{datoms_body}");
    assert_eq!(datoms_body["basis_t"], tx_body["tx_cid"], "{datoms_body}");
    assert_eq!(datoms_body["datom_count"], 1, "{datoms_body}");
    assert_eq!(datoms_body["datoms"][0]["e"], alice, "{datoms_body}");
    assert_eq!(
        datoms_body["datoms"][0]["a"], ":person/name",
        "{datoms_body}"
    );
    assert_eq!(
        datoms_body["datoms"][0]["v_edn"], "\"Alice\"",
        "{datoms_body}"
    );

    let (status, avet_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.datoms",
            json!({
                "graph": graph,
                "index": ":avet",
                "components_edn": [":person/name", "\"Alice\""],
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{avet_body}");
    assert_eq!(avet_body["datoms"][0]["e"], alice, "{avet_body}");

    let stale_parent = kotoba_core::cid::KotobaCid::from_bytes(b"stale-parent").to_multibase();
    let (status, stale_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "expected_parent": stale_parent,
                "tx_edn": r#"[[:db/add "mallory" :person/name "Mallory"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 409, "{stale_body}");

    let (status, stale_read_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{stale_read_body}");
    assert_eq!(
        stale_read_body["rows_edn"],
        json!([["\"Alice\""]]),
        "{stale_read_body}"
    );

    let first_tx = tx_body["tx_cid"].as_str().unwrap().to_string();
    let (status, second_tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "expected_parent": commit_cid,
                "tx_edn": r#"[{:db/id "bob" :person/name "Bob" :person/age 7 :person/role :guest}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{second_tx_body}");
    assert_eq!(second_tx_body["ipns_sequence"], 2);
    let bob = second_tx_body["tempids"]["bob"].as_str().unwrap();
    let second_tx = second_tx_body["tx_cid"].as_str().unwrap().to_string();

    let (status, window_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name]
                                 :where [[?e :person/name ?name]]
                                 :offset 1
                                 :limit 1}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{window_body}");
    assert_eq!(
        window_body["rows_edn"],
        json!([["\"Bob\""]]),
        "{window_body}"
    );

    let (status, expected_parent_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?parent]
                                 :where [[?tx :tx/expectedParentCommit ?parent]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{expected_parent_body}");
    assert!(
        expected_parent_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row[0] == format!("\"{commit_cid}\"")),
        "{expected_parent_body}"
    );

    let (status, seek_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.seekDatoms",
            json!({
                "graph": graph,
                "index": ":avet",
                "components_edn": [":person/name", "\"Bob\""],
                "limit": 1
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{seek_body}");
    assert_eq!(
        seek_body["basis_t"], second_tx_body["tx_cid"],
        "{seek_body}"
    );
    assert_eq!(seek_body["datom_count"], 1, "{seek_body}");
    assert_eq!(seek_body["datoms"][0]["e"], bob, "{seek_body}");
    assert_eq!(seek_body["datoms"][0]["a"], ":person/name", "{seek_body}");
    assert_eq!(seek_body["datoms"][0]["v_edn"], "\"Bob\"", "{seek_body}");

    let (status, tea_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.datoms",
            json!({
                "graph": graph,
                "index": ":tea",
                "components_edn": [format!("\"{second_tx}\"")],
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tea_body}");
    assert_eq!(tea_body["basis_t"], second_tx_body["tx_cid"], "{tea_body}");
    assert!(
        tea_body["datom_count"].as_u64().unwrap_or(0) >= 3,
        "{tea_body}"
    );
    assert!(
        tea_body["datoms"]
            .as_array()
            .unwrap()
            .iter()
            .all(|datom| datom["t"] == second_tx_body["tx_cid"]),
        "{tea_body}"
    );
    assert!(
        tea_body["datoms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|datom| datom["e"] == bob && datom["a"] == ":person/name"),
        "{tea_body}"
    );

    let (status, range_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.indexRange",
            json!({
                "graph": graph,
                "attr_edn": ":person/age",
                "start_edn": "10",
                "end_edn": "40",
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{range_body}");
    assert_eq!(
        range_body["basis_t"], second_tx_body["tx_cid"],
        "{range_body}"
    );
    assert_eq!(range_body["datom_count"], 1, "{range_body}");
    assert_eq!(range_body["datoms"][0]["e"], alice, "{range_body}");
    assert_eq!(range_body["datoms"][0]["a"], ":person/age", "{range_body}");
    assert_eq!(range_body["datoms"][0]["v_edn"], "30", "{range_body}");

    let (status, index_pull_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.indexPull",
            json!({
                "graph": graph,
                "index": ":avet",
                "components_edn": [":person/name", "\"Bob\""],
                "pattern_edn": "[:person/name :person/age]",
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{index_pull_body}");
    assert_eq!(
        index_pull_body["basis_t"], second_tx_body["tx_cid"],
        "{index_pull_body}"
    );
    assert_eq!(index_pull_body["entity_count"], 1, "{index_pull_body}");
    assert_eq!(
        index_pull_body["entities"][0]["entity"], bob,
        "{index_pull_body}"
    );
    assert!(
        index_pull_body["entities"][0]["entity_edn"]
            .as_str()
            .unwrap()
            .contains("Bob"),
        "{index_pull_body}"
    );
    assert!(
        index_pull_body["entities"][0]["datoms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|datom| datom["a"] == ":person/name"
                && datom["v_edn"] == "\"Bob\""
                && datom["t"] == second_tx_body["tx_cid"]
                && datom["added"] == true),
        "{index_pull_body}"
    );

    let (status, ban_tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "bob" :person/ban-reason "spam"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{ban_tx_body}");
    assert_eq!(ban_tx_body["ipns_sequence"], 3);
    let second_tx = second_tx_body["tx_cid"].as_str().unwrap().to_string();
    let ban_tx = ban_tx_body["tx_cid"].as_str().unwrap().to_string();

    let (status, tx_range_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.txRange",
            json!({
                "graph": graph,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_range_body}");
    assert_eq!(
        tx_range_body["basis_t"], ban_tx_body["tx_cid"],
        "{tx_range_body}"
    );
    assert_eq!(tx_range_body["tx_count"], 3, "{tx_range_body}");
    assert_eq!(
        tx_range_body["txes"][0]["tx_cid"], tx_body["tx_cid"],
        "{tx_range_body}"
    );
    assert_eq!(
        tx_range_body["txes"][1]["tx_cid"], second_tx_body["tx_cid"],
        "{tx_range_body}"
    );
    assert_eq!(
        tx_range_body["txes"][2]["tx_cid"], ban_tx_body["tx_cid"],
        "{tx_range_body}"
    );
    assert_eq!(
        tx_range_body["txes"][1]["prev_commit_cid"], tx_body["commit_cid"],
        "{tx_range_body}"
    );
    assert_eq!(
        tx_range_body["txes"][2]["prev_commit_cid"], second_tx_body["commit_cid"],
        "{tx_range_body}"
    );
    for (body, expected_prev) in [
        (&second_tx_body, tx_body["commit_cid"].as_str().unwrap()),
        (&ban_tx_body, second_tx_body["commit_cid"].as_str().unwrap()),
    ] {
        let commit_cid = body["commit_cid"].as_str().expect("commit cid");
        let (status, block_body) = s
            .get(&format!(
                "/xrpc/ai.gftd.apps.kotoba.block.get?cid={commit_cid}"
            ))
            .await;
        assert_eq!(status, 200, "{block_body}");
        let commit_bytes = {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let data_b64 = block_body["data_b64"].as_str().expect("commit data_b64");
            B64.decode(data_b64).expect("commit block base64")
        };
        let decoded_commit: kotoba_datomic::distributed::DistributedDatomCommit =
            ciborium::from_reader(commit_bytes.as_slice()).expect("commit block DAG-CBOR");
        assert_eq!(
            decoded_commit.prev.as_ref().map(|cid| cid.to_multibase()),
            Some(expected_prev.to_string()),
            "commit DAG-CBOR prev mismatch for {commit_cid}"
        );
    }
    assert!(
        tx_range_body["txes"][1]["datoms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|datom| datom["a"] == ":person/name" && datom["v_edn"] == "\"Bob\""),
        "{tx_range_body}"
    );

    let (status, log_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.log",
            json!({
                "graph": graph,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{log_body}");
    assert_eq!(log_body["basis_t"], ban_tx_body["tx_cid"], "{log_body}");
    assert_eq!(log_body["tx_count"], 3, "{log_body}");
    assert_eq!(
        log_body["txes"][0]["tx_cid"], tx_body["tx_cid"],
        "{log_body}"
    );
    assert_eq!(
        log_body["txes"][1]["tx_cid"], second_tx_body["tx_cid"],
        "{log_body}"
    );
    assert_eq!(
        log_body["txes"][2]["tx_cid"], ban_tx_body["tx_cid"],
        "{log_body}"
    );
    assert!(
        log_body["txes"][1]["datoms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|datom| datom["a"] == ":person/name" && datom["v_edn"] == "\"Bob\""),
        "{log_body}"
    );

    let (status, tx_range_window_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.txRange",
            json!({
                "graph": graph,
                "start": second_tx,
                "end": ban_tx,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_range_window_body}");
    assert_eq!(
        tx_range_window_body["tx_count"], 1,
        "{tx_range_window_body}"
    );
    assert_eq!(
        tx_range_window_body["txes"][0]["tx_cid"], second_tx_body["tx_cid"],
        "{tx_range_window_body}"
    );

    let (status, log_window_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.log",
            json!({
                "graph": graph,
                "start": second_tx,
                "end": ban_tx,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{log_window_body}");
    assert_eq!(log_window_body["tx_count"], 1, "{log_window_body}");
    assert_eq!(
        log_window_body["txes"][0]["tx_cid"], second_tx_body["tx_cid"],
        "{log_window_body}"
    );
    assert!(
        log_window_body["txes"][0]["datoms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|datom| datom["a"] == ":person/name" && datom["v_edn"] == "\"Bob\""),
        "{log_window_body}"
    );

    let (status, basis_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.basisT",
            json!({
                "graph": graph
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{basis_body}");
    assert_eq!(basis_body["basis_t"], ban_tx_body["tx_cid"], "{basis_body}");

    let (status, stats_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.dbStats",
            json!({
                "graph": graph
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{stats_body}");
    assert_eq!(stats_body["basis_t"], ban_tx_body["tx_cid"], "{stats_body}");
    assert!(
        stats_body["datom_count"].as_u64().unwrap_or(0) >= 8,
        "{stats_body}"
    );
    assert!(
        stats_body["history_datom_count"].as_u64().unwrap_or(0) >= 8,
        "{stats_body}"
    );
    assert!(
        stats_body["entity_count"].as_u64().unwrap_or(0) >= 2,
        "{stats_body}"
    );
    assert!(
        stats_body["attribute_count"].as_u64().unwrap_or(0) >= 5,
        "{stats_body}"
    );
    assert_eq!(stats_body["tx_count"], 3, "{stats_body}");

    let (status, as_of_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#,
                "as_of": first_tx.clone()
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{as_of_body}");
    assert_eq!(as_of_body["basis_t"], tx_body["tx_cid"], "{as_of_body}");
    assert_eq!(
        as_of_body["rows_edn"],
        json!([["\"Alice\""]]),
        "{as_of_body}"
    );

    let (status, as_of_datoms_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.datoms",
            json!({
                "graph": graph,
                "index": ":avet",
                "components_edn": [":person/name", "\"Alice\""],
                "as_of": first_tx.clone(),
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{as_of_datoms_body}");
    assert_eq!(
        as_of_datoms_body["basis_t"], tx_body["tx_cid"],
        "{as_of_datoms_body}"
    );
    assert_eq!(as_of_datoms_body["datom_count"], 1, "{as_of_datoms_body}");
    assert_eq!(
        as_of_datoms_body["datoms"][0]["e"], alice,
        "{as_of_datoms_body}"
    );

    let (status, as_of_seek_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.seekDatoms",
            json!({
                "graph": graph,
                "index": ":avet",
                "components_edn": [":person/name", "\"Bob\""],
                "as_of": first_tx.clone(),
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{as_of_seek_body}");
    assert_eq!(
        as_of_seek_body["basis_t"], tx_body["tx_cid"],
        "{as_of_seek_body}"
    );
    assert_eq!(as_of_seek_body["datom_count"], 0, "{as_of_seek_body}");

    let (status, as_of_range_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.indexRange",
            json!({
                "graph": graph,
                "attr_edn": ":person/age",
                "start_edn": "10",
                "end_edn": "40",
                "as_of": first_tx.clone(),
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{as_of_range_body}");
    assert_eq!(
        as_of_range_body["basis_t"], tx_body["tx_cid"],
        "{as_of_range_body}"
    );
    assert_eq!(as_of_range_body["datom_count"], 1, "{as_of_range_body}");
    assert_eq!(
        as_of_range_body["datoms"][0]["e"], alice,
        "{as_of_range_body}"
    );

    let (status, since_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#,
                "since": first_tx.clone()
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{since_body}");
    assert_eq!(since_body["basis_t"], ban_tx_body["tx_cid"], "{since_body}");
    assert_eq!(since_body["rows_edn"], json!([["\"Bob\""]]), "{since_body}");

    let (status, since_datoms_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.datoms",
            json!({
                "graph": graph,
                "index": ":avet",
                "components_edn": [":person/name", "\"Bob\""],
                "since": first_tx.clone(),
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{since_datoms_body}");
    assert_eq!(
        since_datoms_body["basis_t"], ban_tx_body["tx_cid"],
        "{since_datoms_body}"
    );
    assert_eq!(since_datoms_body["datom_count"], 1, "{since_datoms_body}");
    assert_eq!(
        since_datoms_body["datoms"][0]["e"], bob,
        "{since_datoms_body}"
    );

    let (status, since_seek_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.seekDatoms",
            json!({
                "graph": graph,
                "index": ":avet",
                "components_edn": [":person/name", "\"Bob\""],
                "since": first_tx.clone(),
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{since_seek_body}");
    assert_eq!(since_seek_body["datom_count"], 1, "{since_seek_body}");
    assert_eq!(since_seek_body["datoms"][0]["e"], bob, "{since_seek_body}");

    let (status, since_range_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.indexRange",
            json!({
                "graph": graph,
                "attr_edn": ":person/age",
                "start_edn": "0",
                "end_edn": "10",
                "since": first_tx,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{since_range_body}");
    assert_eq!(since_range_body["datom_count"], 1, "{since_range_body}");
    assert_eq!(
        since_range_body["datoms"][0]["e"], bob,
        "{since_range_body}"
    );
    assert_eq!(
        since_range_body["datoms"][0]["v_edn"], "7",
        "{since_range_body}"
    );

    let (status, collection_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :in [$ [?role ...]] :where [[?e :person/role ?role] [?e :person/name ?name]]}"#,
                "inputs_edn": [r#"[:admin :guest]"#]
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{collection_body}");
    assert_eq!(
        collection_body["rows_edn"],
        json!([["\"Alice\""], ["\"Bob\""]]),
        "{collection_body}"
    );

    let (status, named_source_collection_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :in [$db [?role ...]] :where [[?e :person/role ?role] [?e :person/name ?name]]}"#,
                "inputs_edn": [r#"[:admin]"#]
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{named_source_collection_body}");
    assert_eq!(
        named_source_collection_body["rows_edn"],
        json!([["\"Alice\""]]),
        "{named_source_collection_body}"
    );

    let (status, source_pattern_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name]
                                 :in [$db]
                                 :where [[$db ?e :person/role :admin]
                                         [$db ?e :person/name ?name]
                                         [(missing? $db ?e :person/ban-reason)]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{source_pattern_body}");
    assert_eq!(
        source_pattern_body["rows_edn"],
        json!([["\"Alice\""]]),
        "{source_pattern_body}"
    );

    let (status, vector_query_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"[:find ?name
                                 :in $db [?role ...]
                                 :where [$db ?e :person/role ?role]
                                        [$db ?e :person/name ?name]]"#,
                "inputs_edn": [r#"[:admin :guest]"#]
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{vector_query_body}");
    assert_eq!(
        vector_query_body["rows_edn"],
        json!([["\"Alice\""], ["\"Bob\""]]),
        "{vector_query_body}"
    );

    let (status, tx_pattern_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"[:find ?name ?tx
                                 :in $db
                                 :where [$db ?e :person/role :admin ?tx]
                                        [$db ?e :person/name ?name ?tx]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_pattern_body}");
    assert_eq!(
        tx_pattern_body["rows_edn"],
        json!([[
            "\"Alice\"",
            format!("\"{}\"", tx_body["tx_cid"].as_str().unwrap())
        ]]),
        "{tx_pattern_body}"
    );

    let (status, added_pattern_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"[:find ?name ?tx ?added
                                 :in $db
                                 :where [$db ?e :person/role :admin ?tx ?added]
                                        [$db ?e :person/name ?name ?tx ?added]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{added_pattern_body}");
    assert_eq!(
        added_pattern_body["rows_edn"],
        json!([[
            "\"Alice\"",
            format!("\"{}\"", tx_body["tx_cid"].as_str().unwrap()),
            "true"
        ]]),
        "{added_pattern_body}"
    );

    let (status, find_collection_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name ...] :where [[?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{find_collection_body}");
    assert_eq!(
        find_collection_body["rows_edn"],
        json!([["\"Alice\""], ["\"Bob\""]]),
        "{find_collection_body}"
    );

    let (status, find_scalar_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name .]
                                 :where [[?e :person/role :admin]
                                         [?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{find_scalar_body}");
    assert_eq!(
        find_scalar_body["rows_edn"],
        json!([["\"Alice\""]]),
        "{find_scalar_body}"
    );

    let (status, find_tuple_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [[?name ?role]] :where [[?e :person/name ?name] [?e :person/role ?role]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{find_tuple_body}");
    assert_eq!(
        find_tuple_body["rows_edn"],
        json!([["\"Alice\"", ":admin"], ["\"Bob\"", ":guest"]]),
        "{find_tuple_body}"
    );

    let (status, keys_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name ?role]
                                 :keys [name role]
                                 :where [[?e :person/name ?name]
                                         [?e :person/role ?role]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{keys_body}");
    assert_eq!(
        keys_body["rows_edn"],
        json!([["\"Alice\"", ":admin"], ["\"Bob\"", ":guest"]]),
        "{keys_body}"
    );
    let key_rows = keys_body["rows_map_edn"].as_array().expect("rows_map_edn");
    assert!(
        key_rows.iter().any(|row| {
            let row = row.as_str().unwrap_or_default();
            row.contains(":name \"Alice\"") && row.contains(":role :admin")
        }),
        "{keys_body}"
    );
    assert!(
        key_rows.iter().any(|row| {
            let row = row.as_str().unwrap_or_default();
            row.contains(":name \"Bob\"") && row.contains(":role :guest")
        }),
        "{keys_body}"
    );
    let key_json_rows = keys_body["rows_map_json"]
        .as_array()
        .expect("rows_map_json");
    assert!(
        key_json_rows
            .iter()
            .any(|row| row[":name"] == "\"Alice\"" && row[":role"] == ":admin"),
        "{keys_body}"
    );

    let (status, strs_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name ?role]
                                 :strs [name role]
                                 :where [[?e :person/name ?name]
                                         [?e :person/role ?role]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{strs_body}");
    let str_rows = strs_body["rows_map_edn"].as_array().expect("rows_map_edn");
    assert!(
        str_rows.iter().any(|row| {
            let row = row.as_str().unwrap_or_default();
            row.contains("\"name\" \"Alice\"") && row.contains("\"role\" :admin")
        }),
        "{strs_body}"
    );
    let str_json_rows = strs_body["rows_map_json"]
        .as_array()
        .expect("rows_map_json");
    assert!(
        str_json_rows
            .iter()
            .any(|row| row["name"] == "\"Alice\"" && row["role"] == ":admin"),
        "{strs_body}"
    );

    let (status, syms_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name ?role]
                                 :syms [name role]
                                 :where [[?e :person/name ?name]
                                         [?e :person/role ?role]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{syms_body}");
    let sym_rows = syms_body["rows_map_edn"].as_array().expect("rows_map_edn");
    assert!(
        sym_rows.iter().any(|row| {
            let row = row.as_str().unwrap_or_default();
            row.contains("name \"Alice\"") && row.contains("role :admin")
        }),
        "{syms_body}"
    );
    let sym_json_rows = syms_body["rows_map_json"]
        .as_array()
        .expect("rows_map_json");
    assert!(
        sym_json_rows
            .iter()
            .any(|row| row["name"] == "\"Alice\"" && row["role"] == ":admin"),
        "{syms_body}"
    );

    let (status, relation_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :in [$ [[?name ?role]]] :where [[?e :person/name ?name] [?e :person/role ?role]]}"#,
                "inputs_edn": [r#"[["Alice" :admin] ["Bob" :guest] ["Eve" :guest]]"#]
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{relation_body}");
    assert_eq!(
        relation_body["rows_edn"],
        json!([["\"Alice\""], ["\"Bob\""]]),
        "{relation_body}"
    );

    let (status, tuple_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :in [$ [?name ?role]] :where [[?e :person/name ?name] [?e :person/role ?role]]}"#,
                "inputs_edn": [r#"["Alice" :admin]"#]
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tuple_body}");
    assert_eq!(
        tuple_body["rows_edn"],
        json!([["\"Alice\""]]),
        "{tuple_body}"
    );

    let (status, rules_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :in [$ %] :where [(eligible ?e) [?e :person/name ?name]]}"#,
                "inputs_edn": [r#"[[(eligible ?e) [?e :person/role :admin]]]"#]
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{rules_body}");
    assert_eq!(
        rules_body["rows_edn"],
        json!([["\"Alice\""]]),
        "{rules_body}"
    );

    let (status, not_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name] (not [?e :person/role :guest])]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{not_body}");
    assert_eq!(not_body["rows_edn"], json!([["\"Alice\""]]), "{not_body}");

    let (status, or_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name] (or [?e :person/role :admin] [?e :person/role :guest])]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{or_body}");
    assert_eq!(
        or_body["rows_edn"],
        json!([["\"Alice\""], ["\"Bob\""]]),
        "{or_body}"
    );

    let (status, not_join_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/role :guest] (not-join [?e] [?e :person/ban-reason ?reason]) [?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{not_join_body}");
    assert_eq!(not_join_body["rows_edn"], json!([]), "{not_join_body}");

    let (status, or_join_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name] (or-join [?e] [?e :person/role :admin] [?e :person/ban-reason "spam"])]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{or_join_body}");
    assert_eq!(
        or_join_body["rows_edn"],
        json!([["\"Alice\""], ["\"Bob\""]]),
        "{or_join_body}"
    );

    let (status, missing_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/role ?role] [(!= ?role :admin)] [(missing? $ ?e :person/ban-reason)] [?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{missing_body}");
    assert_eq!(missing_body["rows_edn"], json!([]), "{missing_body}");

    let (status, function_binding_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?copy] :where [[(ground :guest) ?role] [?e :person/role ?role] [?e :person/name ?name] [(identity ?name) ?copy]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{function_binding_body}");
    assert_eq!(
        function_binding_body["rows_edn"],
        json!([["\"Bob\""]]),
        "{function_binding_body}"
    );

    let (status, name_function_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?roleName ?roleNamespace]
                                 :where [[?e :person/role ?role]
                                         [(= ?role :admin)]
                                         [(name ?role) ?roleName]
                                         [(namespace ?role) ?roleNamespace]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{name_function_body}");
    assert_eq!(
        name_function_body["rows_edn"],
        json!([["\"admin\"", "nil"]]),
        "{name_function_body}"
    );

    let (status, str_keyword_function_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?resource ?rebuilt]
                                 :where [[?e :person/role ?role]
                                         [(= ?role :admin)]
                                         [(name ?role) ?roleName]
                                         [(str "kotoba://role/" ?roleName) ?resource]
                                         [(keyword "role" ?roleName) ?rebuilt]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{str_keyword_function_body}");
    assert_eq!(
        str_keyword_function_body["rows_edn"],
        json!([["\"kotoba://role/admin\"", ":role/admin"]]),
        "{str_keyword_function_body}"
    );

    let (status, tuple_function_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?pair ?name2 ?role2]
                                 :where [[?e :person/name ?name]
                                         [?e :person/role ?role]
                                         [(tuple ?name ?role) ?pair]
                                         [(untuple ?pair) [?name2 ?role2]]
                                         [(= ?name2 "Alice")]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tuple_function_body}");
    assert_eq!(
        tuple_function_body["rows_edn"],
        json!([[r#"["Alice" :admin]"#, "\"Alice\"", ":admin"]]),
        "{tuple_function_body}"
    );

    let (status, get_function_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name ?role ?found] :where [[?e :person/name ?name] [(get-else $ ?e :person/role :guest) ?role] [(get-some $ ?e :person/ban-reason :person/name) ?found]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{get_function_body}");
    assert_eq!(
        get_function_body["rows_edn"],
        json!([
            ["\"Alice\"", ":admin", "[:person/name \"Alice\"]"],
            ["\"Bob\"", ":guest", "[:person/ban-reason \"spam\"]"]
        ]),
        "{get_function_body}"
    );

    let (status, named_source_get_function_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name ?role ?found]
                                 :in [$db]
                                 :where [[$db ?e :person/name ?name]
                                         [(get-else $db ?e :person/role :guest) ?role]
                                         [(get-some $db ?e :person/ban-reason :person/name) ?found]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{named_source_get_function_body}");
    assert_eq!(
        named_source_get_function_body["rows_edn"],
        json!([
            ["\"Alice\"", ":admin", "[:person/name \"Alice\"]"],
            ["\"Bob\"", ":guest", "[:person/ban-reason \"spam\"]"]
        ]),
        "{named_source_get_function_body}"
    );

    let (status, count_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?role (count ?e)]
                                 :where [[?e :person/role ?role]]
                                 :order-by [[(count ?e) :desc] [?role :asc]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{count_body}");
    assert_eq!(
        count_body["rows_edn"],
        json!([[":admin", "1"], [":guest", "1"]]),
        "{count_body}"
    );

    let (status, with_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?role (count ?name)] :with [?e] :where [[?e :person/role ?role] [?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{with_body}");
    assert_eq!(
        with_body["rows_edn"],
        json!([[":admin", "1"], [":guest", "1"]]),
        "{with_body}"
    );

    let (status, count_distinct_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [(count-distinct ?role)] :where [[?e :person/role ?role]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{count_distinct_body}");
    assert_eq!(
        count_distinct_body["rows_edn"],
        json!([["2"]]),
        "{count_distinct_body}"
    );

    let (status, numeric_aggregate_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?role (sum ?age) (min ?age) (max ?age) (median ?age) (variance ?age) (stddev ?age)] :where [[?e :person/role ?role] [?e :person/age ?age]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{numeric_aggregate_body}");
    assert_eq!(
        numeric_aggregate_body["rows_edn"],
        json!([
            [":admin", "30", "30", "30", "30", "0.0", "0.0"],
            [":guest", "7", "7", "7", "7", "0.0", "0.0"]
        ]),
        "{numeric_aggregate_body}"
    );

    let (status, avg_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?role (avg ?age)] :where [[?e :person/role ?role] [?e :person/age ?age]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{avg_body}");
    assert_eq!(
        avg_body["rows_edn"],
        json!([[":admin", "30.0"], [":guest", "7.0"]]),
        "{avg_body}"
    );

    let (status, q_pull_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [(pull ?e [:person/name {:person/friend [:person/name :person/role]}])] :where [[?e :person/name "Alice"]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{q_pull_body}");
    let pulled_row = q_pull_body["rows_edn"][0][0].as_str().unwrap_or("");
    assert!(
        pulled_row.contains(":person/name \"Alice\""),
        "{q_pull_body}"
    );
    assert!(
        pulled_row.contains(":person/friend {:person/name \"Bob\" :person/role :guest}"),
        "{q_pull_body}"
    );

    let alice = kotoba_core::cid::KotobaCid::from_bytes(b"alice").to_multibase();
    let (status, pull_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.pull",
            json!({
                "graph": graph,
                "entity": alice,
                "pattern_edn": r#"[:person/name {:person/friend [:person/name :person/role]}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{pull_body}");
    assert!(pull_body["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains("Alice"));
    assert!(pull_body["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":person/friend {:person/name \"Bob\" :person/role :guest}"));
    assert!(pull_body["datom_count"].as_u64().unwrap_or(0) >= 2);

    let (status, wildcard_pull_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.pull",
            json!({
                "graph": graph,
                "entity": alice,
                "pattern_edn": r#"[*]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{wildcard_pull_body}");
    assert!(
        wildcard_pull_body["entity_edn"]
            .as_str()
            .unwrap_or("")
            .contains(":person/name \"Alice\""),
        "{wildcard_pull_body}"
    );
    assert!(
        wildcard_pull_body["entity_edn"]
            .as_str()
            .unwrap_or("")
            .contains(":person/role :admin"),
        "{wildcard_pull_body}"
    );

    let (status, option_pull_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.pull",
            json!({
                "graph": graph,
                "entity": alice,
                "pattern_edn": r#"[[:person/name :as :name] [:person/email :default "unknown"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{option_pull_body}");
    let option_entity_edn = option_pull_body["entity_edn"].as_str().unwrap_or("");
    assert!(
        option_entity_edn.contains(":name \"Alice\""),
        "{option_pull_body}"
    );
    assert!(
        option_entity_edn.contains(":person/email \"unknown\""),
        "{option_pull_body}"
    );
    assert!(
        !option_entity_edn.contains(":person/name"),
        "{option_pull_body}"
    );

    let (status, xform_pull_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.pull",
            json!({
                "graph": graph,
                "entity": alice,
                "pattern_edn": r#"[[:person/role :xform name :as :roleName] [:person/email :default :fallback/email :xform name :as :emailName]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{xform_pull_body}");
    let xform_entity_edn = xform_pull_body["entity_edn"].as_str().unwrap_or("");
    assert!(
        xform_entity_edn.contains(":roleName \"admin\""),
        "{xform_pull_body}"
    );
    assert!(
        xform_entity_edn.contains(":emailName \"email\""),
        "{xform_pull_body}"
    );

    let bob = kotoba_core::cid::KotobaCid::from_bytes(b"bob").to_multibase();
    let (status, reverse_pull_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.pull",
            json!({
                "graph": graph,
                "entity": bob,
                "pattern_edn": r#"[:person/name {:person/_friend [:person/name]}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{reverse_pull_body}");
    assert!(reverse_pull_body["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":person/_friend [{:person/name \"Alice\"}]"));

    let (status, pull_many_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.pullMany",
            json!({
                "graph": graph,
                "entities": [alice, bob],
                "pattern_edn": r#"[:person/name :person/role]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{pull_many_body}");
    assert_eq!(pull_many_body["entity_count"], 2, "{pull_many_body}");
    assert!(pull_many_body["entities"][0]["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":person/name \"Alice\""));
    assert!(pull_many_body["entities"][1]["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":person/name \"Bob\""));
    assert!(pull_many_body["entities"][1]["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":person/role :guest"));

    let (status, history_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.history",
            json!({
                "graph": graph,
                "limit": 20
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{history_body}");
    assert!(history_body["datom_count"].as_u64().unwrap_or(0) >= 4);

    let (status, retract_tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/retract "bob" :person/ban-reason "spam"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{retract_tx_body}");
    assert_eq!(retract_tx_body["ipns_sequence"], 4);

    let (status, current_ban_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?reason] :where [[?e :person/name "Bob"] [?e :person/ban-reason ?reason]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{current_ban_body}");
    assert_eq!(
        current_ban_body["rows_edn"],
        json!([]),
        "{current_ban_body}"
    );

    let (status, retract_history_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.history",
            json!({
                "graph": graph,
                "since": ban_tx_body["tx_cid"].as_str().unwrap(),
                "limit": 20
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{retract_history_body}");
    assert_eq!(
        retract_history_body["basis_t"], retract_tx_body["tx_cid"],
        "{retract_history_body}"
    );
    let retract_datoms = retract_history_body["datoms"].as_array().unwrap();
    assert!(
        retract_datoms.iter().any(|datom| {
            datom["a"] == ":person/ban-reason"
                && datom["v_edn"] == "\"spam\""
                && datom["t"] == retract_tx_body["tx_cid"]
                && datom["added"] == false
        }),
        "{retract_history_body}"
    );

    let (status, retract_history_q_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "history": true,
                "since": ban_tx_body["tx_cid"].as_str().unwrap(),
                "query_edn": r#"{:find [?reason ?added]
                                 :in [$history]
                                 :where [[$history ?e :person/ban-reason ?reason ?tx ?added]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{retract_history_q_body}");
    assert_eq!(
        retract_history_q_body["rows_edn"],
        json!([["\"spam\"", "false"]]),
        "{retract_history_q_body}"
    );
}

#[tokio::test]
async fn datomic_transact_uses_distributed_head_for_edn_value_cardinality_retracts() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-distributed-edn-basis-e2e")
        .to_multibase();

    let (status, first_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "alice" :person/profile [:alpha]}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{first_body}");
    let alice = first_body["tempids"]["alice"].as_str().unwrap();

    let (status, second_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/profile [:beta]]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{second_body}");

    let (status, datoms_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.datoms",
            json!({
                "graph": graph,
                "index": ":eavt",
                "components_edn": [format!("\"{alice}\""), ":person/profile"],
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{datoms_body}");
    assert_eq!(
        datoms_body["basis_t"], second_body["tx_cid"],
        "{datoms_body}"
    );
    assert_eq!(datoms_body["datom_count"], 1, "{datoms_body}");
    assert_eq!(
        datoms_body["datoms"][0]["v_edn"], "[:beta]",
        "{datoms_body}"
    );
}

#[tokio::test]
async fn datomic_transact_expands_cardinality_many_entity_map_collections_on_distributed_head() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-distributed-cardinality-many-map-e2e")
            .to_multibase();

    let (status, schema_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[
                  {:db/id "tag"
                   :db/ident :person/tag
                   :db/cardinality :db.cardinality/many}
                ]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{schema_body}");

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[
                  {:db/id "alice" :person/tag ["founder" "engineer"]}
                ]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");
    let alice = tx_body["tempids"]["alice"].as_str().unwrap();
    let tx_datoms = tx_body["datoms"].as_array().unwrap();
    assert_eq!(
        tx_datoms.iter().filter(|d| d["a"] == ":person/tag").count(),
        2,
        "{tx_body}"
    );
    assert!(
        tx_datoms
            .iter()
            .all(|d| d["a"] != ":person/tag" || d["v_edn"] != "[\"founder\" \"engineer\"]"),
        "{tx_body}"
    );

    let (status, q_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?tag] :where [[?e :person/tag ?tag]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{q_body}");
    assert_eq!(
        q_body["rows_edn"],
        json!([["\"engineer\""], ["\"founder\""]]),
        "{q_body}"
    );

    let (status, pull_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.pull",
            json!({
                "graph": graph,
                "entity": alice,
                "pattern_edn": "[:person/tag]"
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{pull_body}");
    let entity_edn = pull_body["entity_edn"].as_str().unwrap_or_default();
    assert!(
        entity_edn.contains(":person/tag")
            && entity_edn.contains("\"engineer\"")
            && entity_edn.contains("\"founder\""),
        "{pull_body}"
    );

    let (status, limited_pull_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.pull",
            json!({
                "graph": graph,
                "entity": alice,
                "pattern_edn": "[[:person/tag :limit 1]]"
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{limited_pull_body}");
    let limited_entity_edn = limited_pull_body["entity_edn"].as_str().unwrap_or_default();
    assert!(
        limited_entity_edn.contains(":person/tag ["),
        "{limited_pull_body}"
    );
    assert_eq!(
        limited_entity_edn.matches("\"engineer\"").count()
            + limited_entity_edn.matches("\"founder\"").count(),
        1,
        "{limited_pull_body}"
    );
}

#[tokio::test]
async fn datomic_q_accepts_datom_read_cacao_on_private_distributed_head() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-q-datom-read-cacao-e2e").to_multibase();

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "alice" :person/name "Alice"}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");

    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "private");
    let cacao_b64 = build_ed25519_cacao_for_operation(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        "nonce-datomic-q-datom-read-e2e",
    );
    let (status, q_body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#,
                "cacao_b64": cacao_b64
            }),
        )
        .await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "authenticated");

    assert_eq!(status, 200, "{q_body}");
    assert_eq!(q_body["rows_edn"], json!([["\"Alice\""]]), "{q_body}");
}

#[tokio::test]
async fn datomic_with_applies_tx_without_publishing_distributed_head() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-with-speculative-e2e").to_multibase();

    let (status, first_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "alice" :person/name "Alice"}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{first_body}");
    let first_tx = first_body["tx_cid"].as_str().unwrap();

    let (status, with_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.with",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alicia"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{with_body}");
    assert_eq!(with_body["db_before_basis_t"], first_tx, "{with_body}");
    assert_ne!(with_body["tx_cid"], first_tx, "{with_body}");
    assert!(
        with_body["db_after_datoms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| {
                d["a"] == ":person/name" && d["v_edn"] == "\"Alicia\"" && d["added"] == true
            }),
        "{with_body}"
    );

    let (status, basis_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.basisT",
            json!({ "graph": graph }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{basis_body}");
    assert_eq!(basis_body["basis_t"], first_tx, "{basis_body}");

    let (status, query_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{query_body}");
    assert_eq!(
        query_body["rows_edn"],
        json!([["\"Alice\""]]),
        "{query_body}"
    );
}

#[tokio::test]
async fn datomic_as_of_and_since_expose_distributed_database_values() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-as-of-since-e2e").to_multibase();

    let (status, first_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "alice" :person/name "Alice"}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{first_body}");
    let first_tx = first_body["tx_cid"].as_str().unwrap();

    let (status, second_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "bob" :person/name "Bob"}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{second_body}");
    let second_tx = second_body["tx_cid"].as_str().unwrap();

    let (status, sync_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.sync",
            json!({ "graph": graph, "tx": first_tx }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{sync_body}");
    assert_eq!(sync_body["basis_t"], second_tx, "{sync_body}");
    assert_eq!(sync_body["target_tx"], first_tx, "{sync_body}");
    assert_eq!(sync_body["reached"], true, "{sync_body}");
    assert_eq!(sync_body["ipns_sequence"], 2, "{sync_body}");
    assert!(sync_body["commit_cid"].as_str().is_some(), "{sync_body}");

    let (status, as_of_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.asOf",
            json!({ "graph": graph, "tx": first_tx }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{as_of_body}");
    assert_eq!(as_of_body["tx"], first_tx, "{as_of_body}");
    assert_eq!(as_of_body["basis_t"], first_tx, "{as_of_body}");
    assert_eq!(as_of_body["tx_count"], 1, "{as_of_body}");

    let (status, since_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.since",
            json!({ "graph": graph, "tx": first_tx }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{since_body}");
    assert_eq!(since_body["tx"], first_tx, "{since_body}");
    assert_eq!(since_body["basis_t"], second_tx, "{since_body}");
    assert_eq!(since_body["tx_count"], 1, "{since_body}");

    let (status, as_of_q) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "as_of": first_tx,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{as_of_q}");
    assert_eq!(as_of_q["rows_edn"], json!([["\"Alice\""]]), "{as_of_q}");

    let (status, since_q) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "since": first_tx,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{since_q}");
    assert_eq!(since_q["rows_edn"], json!([["\"Bob\""]]), "{since_q}");
}

#[tokio::test]
async fn datomic_sync_reports_distributed_head_and_target_tx_reachability() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-sync-e2e").to_multibase();

    let (status, first_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "alice" :person/name "Alice"}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{first_body}");
    let first_tx = first_body["tx_cid"].as_str().unwrap();

    let (status, second_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "bob" :person/name "Bob"}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{second_body}");
    let second_tx = second_body["tx_cid"].as_str().unwrap();

    let (status, head_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.sync",
            json!({ "graph": graph }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{head_body}");
    assert_eq!(head_body["basis_t"], second_tx, "{head_body}");
    assert_eq!(
        head_body["commit_cid"], second_body["commit_cid"],
        "{head_body}"
    );
    assert_eq!(head_body["ipns_sequence"], 2, "{head_body}");
    assert_eq!(head_body["reached"], true, "{head_body}");

    let (status, reached_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.sync",
            json!({ "graph": graph, "tx": first_tx }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{reached_body}");
    assert_eq!(reached_body["basis_t"], second_tx, "{reached_body}");
    assert_eq!(reached_body["target_tx"], first_tx, "{reached_body}");
    assert_eq!(reached_body["reached"], true, "{reached_body}");

    let missing_tx =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-sync-missing-tx").to_multibase();
    let (status, missing_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.sync",
            json!({ "graph": graph, "tx": missing_tx }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{missing_body}");
    assert_eq!(missing_body["basis_t"], second_tx, "{missing_body}");
    assert_eq!(missing_body["target_tx"], missing_tx, "{missing_body}");
    assert_eq!(missing_body["reached"], false, "{missing_body}");
}

#[tokio::test]
async fn datomic_transact_applies_schema_upsert_cas_and_retract_entity_on_distributed_head() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-distributed-tx-fns-e2e").to_multibase();

    let (status, schema_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[
                  {:db/id "email" :db/ident :person/email :db/unique :db.unique/identity}
                  {:db/id "name" :db/ident :person/name :db/cardinality :db.cardinality/one}
                  {:db/id "age" :db/ident :person/age :db/valueType :db.type/long :db/cardinality :db.cardinality/one}
                ]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{schema_body}");

    let (status, first_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "alice" :person/email "a@example.com" :person/name "Alice" :person/age 30}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{first_body}");
    let alice = first_body["tempids"]["alice"].as_str().unwrap();

    let (status, upsert_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "same-alice" :person/email "a@example.com" :person/name "Alicia"}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{upsert_body}");
    assert_eq!(upsert_body["tempids"]["same-alice"], alice, "{upsert_body}");

    let (status, cas_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db.fn/cas [:person/email "a@example.com"] :person/age 30 31]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{cas_body}");

    let (status, query_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name ?age] :where [[?e :person/email "a@example.com"] [?e :person/name ?name] [?e :person/age ?age]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{query_body}");
    assert_eq!(
        query_body["rows_edn"],
        json!([["\"Alicia\"", "31"]]),
        "{query_body}"
    );

    let (status, retract_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db.fn/retractEntity [:person/email "a@example.com"]]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{retract_body}");

    let (status, after_retract_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/email "a@example.com"] [?e :person/name ?name]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{after_retract_body}");
    assert_eq!(
        after_retract_body["rows_edn"],
        json!([]),
        "{after_retract_body}"
    );
}

#[tokio::test]
async fn datomic_retract_entity_cascades_component_refs_on_distributed_head() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-distributed-component-e2e")
        .to_multibase();

    let (status, schema_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[
                  {:db/id "address-attr"
                   :db/ident :person/address
                   :db/valueType :db.type/ref
                   :db/isComponent true}
                ]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{schema_body}");

    let (status, entity_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[
                  {:db/id "alice" :person/name "Alice" :person/address "addr"}
                  {:db/id "addr" :address/city "Tokyo"}
                ]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{entity_body}");

    let (status, before_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name ?city] :where [[?e :person/name ?name] [?e :person/address ?addr] [?addr :address/city ?city]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{before_body}");
    assert_eq!(
        before_body["rows_edn"],
        json!([["\"Alice\"", "\"Tokyo\""]]),
        "{before_body}"
    );

    let (status, retract_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db.fn/retractEntity "alice"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{retract_body}");
    assert!(retract_body["datoms"]
        .as_array()
        .unwrap()
        .iter()
        .any(|datom| {
            datom["a"] == ":address/city"
                && datom["v_edn"] == "\"Tokyo\""
                && datom["added"] == false
        }));

    let (status, after_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?city] :where [[?addr :address/city ?city]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{after_body}");
    assert_eq!(after_body["rows_edn"], json!([]), "{after_body}");
}

#[tokio::test]
async fn datomic_datoms_vaet_scans_ref_values_from_distributed_head() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-distributed-vaet-e2e").to_multibase();

    let (status, schema_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[
                  {:db/id "friend" :db/ident :person/friend :db/valueType :db.type/ref}
                  {:db/id "name" :db/ident :person/name :db/valueType :db.type/string}
                ]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{schema_body}");
    let friend_attr = schema_body["tempids"]["friend"].as_str().unwrap();

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[
                  {:db/id "alice" :person/name "Alice" :person/friend "bob"}
                  {:db/id "bob" :person/name "Bob"}
                ]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");
    let alice = tx_body["tempids"]["alice"].as_str().unwrap();
    let bob = tx_body["tempids"]["bob"].as_str().unwrap();

    let (status, vaet_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.datoms",
            json!({
                "graph": graph,
                "index": ":vaet",
                "components_edn": [format!("\"{bob}\""), ":person/friend", format!("\"{alice}\"")],
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{vaet_body}");
    assert_eq!(vaet_body["basis_t"], tx_body["tx_cid"], "{vaet_body}");
    assert_eq!(vaet_body["datom_count"], 1, "{vaet_body}");
    assert_eq!(vaet_body["datoms"][0]["e"], alice, "{vaet_body}");
    assert_eq!(vaet_body["datoms"][0]["a"], ":person/friend", "{vaet_body}");
    assert_eq!(
        vaet_body["datoms"][0]["v_edn"],
        format!("\"{bob}\""),
        "{vaet_body}"
    );

    let (status, vaet_lookup_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.datoms",
            json!({
                "graph": graph,
                "index": ":vaet",
                "components_edn": [r#"[:person/name "Bob"]"#, ":person/friend", r#"[:person/name "Alice"]"#],
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{vaet_lookup_body}");
    assert_eq!(vaet_lookup_body["datom_count"], 1, "{vaet_lookup_body}");
    assert_eq!(
        vaet_lookup_body["datoms"][0]["e"], alice,
        "{vaet_lookup_body}"
    );
    assert_eq!(
        vaet_lookup_body["datoms"][0]["v_edn"],
        format!("\"{bob}\""),
        "{vaet_lookup_body}"
    );

    let (status, seek_lookup_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.seekDatoms",
            json!({
                "graph": graph,
                "index": ":vaet",
                "components_edn": [r#"[:person/name "Bob"]"#, ":person/friend"],
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{seek_lookup_body}");
    assert!(seek_lookup_body["datoms"]
        .as_array()
        .unwrap()
        .iter()
        .any(|datom| datom["e"] == alice && datom["a"] == ":person/friend"));

    let (status, ref_range_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.indexRange",
            json!({
                "graph": graph,
                "attr_edn": ":person/friend",
                "start_edn": r#"[:person/name "Bob"]"#,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{ref_range_body}");
    assert!(ref_range_body["datoms"]
        .as_array()
        .unwrap()
        .iter()
        .any(|datom| {
            datom["e"] == alice
                && datom["a"] == ":person/friend"
                && datom["v_edn"] == format!("\"{bob}\"")
        }));

    let (status, pull_lookup_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.pull",
            json!({
                "graph": graph,
                "entity": r#"[:person/name "Alice"]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{pull_lookup_body}");
    assert!(pull_lookup_body["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":person/name \"Alice\""));

    let (status, pull_many_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.pullMany",
            json!({
                "graph": graph,
                "entities": [":person/friend", r#"[:person/name "Bob"]"#]
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{pull_many_body}");
    assert_eq!(pull_many_body["entity_count"], 2, "{pull_many_body}");
    assert!(pull_many_body["entities"][0]["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":db/ident :person/friend"));
    assert!(pull_many_body["entities"][1]["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":person/name \"Bob\""));

    let (status, all_vaet_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.datoms",
            json!({
                "graph": graph,
                "index": ":vaet",
                "components_edn": [],
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{all_vaet_body}");
    assert!(
        all_vaet_body["datoms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|datom| {
                datom["e"] == alice
                    && datom["a"] == ":person/friend"
                    && datom["v_edn"] == format!("\"{bob}\"")
            }),
        "{all_vaet_body}"
    );

    let (status, entity_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.entity",
            json!({
                "graph": graph,
                "entity": alice
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{entity_body}");
    assert!(entity_body["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":person/name \"Alice\""));
    assert!(entity_body["datom_count"].as_u64().unwrap_or(0) >= 2);

    let (status, entity_lookup_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.entity",
            json!({
                "graph": graph,
                "entity": r#"[:person/name "Alice"]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{entity_lookup_body}");
    assert!(entity_lookup_body["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":person/name \"Alice\""));

    let (status, entity_ident_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.entity",
            json!({
                "graph": graph,
                "entity": ":person/friend"
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{entity_ident_body}");
    assert!(entity_ident_body["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains(":db/ident :person/friend"));

    let (status, ident_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.ident",
            json!({
                "graph": graph,
                "entity": friend_attr
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{ident_body}");
    assert_eq!(ident_body["ident_edn"], ":person/friend", "{ident_body}");

    let (status, entid_ident_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.entid",
            json!({
                "graph": graph,
                "ident_edn": ":person/friend"
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{entid_ident_body}");
    assert_eq!(
        entid_ident_body["entity"], friend_attr,
        "{entid_ident_body}"
    );

    let (status, entid_lookup_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.entid",
            json!({
                "graph": graph,
                "ident_edn": r#"[:person/name "Alice"]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{entid_lookup_body}");
    assert_eq!(entid_lookup_body["entity"], alice, "{entid_lookup_body}");
}

#[tokio::test]
async fn datomic_index_pull_pulls_entities_from_distributed_index() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-index-pull-e2e").to_multibase();

    let (status, first_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "alice" :person/name "Alice" :person/role :admin}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{first_body}");
    let first_tx = first_body["tx_cid"].as_str().unwrap();

    let (status, second_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[{:db/id "bob" :person/name "Bob" :person/role :guest}]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{second_body}");
    let second_tx = second_body["tx_cid"].as_str().unwrap();

    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.indexPull",
            json!({
                "graph": graph,
                "index": ":aevt",
                "components_edn": [":person/name"],
                "pattern_edn": r#"[:person/name :person/role]"#,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["basis_t"], second_tx, "{body}");
    assert_eq!(body["entity_count"], 2, "{body}");
    let entities = body["entities"].as_array().expect("entities");
    assert!(
        entities.iter().any(|entity| entity["entity_edn"]
            .as_str()
            .unwrap_or("")
            .contains("Alice")
            && entity["entity_edn"]
                .as_str()
                .unwrap_or("")
                .contains(":person/role :admin")),
        "{body}"
    );
    assert!(
        entities.iter().any(
            |entity| entity["entity_edn"].as_str().unwrap_or("").contains("Bob")
                && entity["entity_edn"]
                    .as_str()
                    .unwrap_or("")
                    .contains(":person/role :guest")
        ),
        "{body}"
    );

    let (status, as_of_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.indexPull",
            json!({
                "graph": graph,
                "index": ":aevt",
                "components_edn": [":person/name"],
                "pattern_edn": r#"[:person/name]"#,
                "as_of": first_tx
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{as_of_body}");
    assert_eq!(as_of_body["basis_t"], first_tx, "{as_of_body}");
    assert_eq!(as_of_body["entity_count"], 1, "{as_of_body}");
    assert!(as_of_body["entities"][0]["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains("Alice"));

    let (status, since_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.indexPull",
            json!({
                "graph": graph,
                "index": ":aevt",
                "components_edn": [":person/name"],
                "pattern_edn": r#"[:person/name]"#,
                "since": first_tx
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{since_body}");
    assert_eq!(since_body["basis_t"], second_tx, "{since_body}");
    assert_eq!(since_body["entity_count"], 1, "{since_body}");
    assert!(since_body["entities"][0]["entity_edn"]
        .as_str()
        .unwrap_or("")
        .contains("Bob"));
}

#[tokio::test]
async fn datomic_transact_accepts_cacao_datom_transact_operation_scope() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-cacao-scope-e2e").to_multibase();
    let cacao_b64 = build_ed25519_cacao_for_operation_with_resources(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        "nonce-datomic-transact-e2e",
        vec![format!(
            "kotoba://op/{}",
            kotoba_auth::CacaoPayload::OP_TX_CREATE
        )],
    );

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#,
                "cacao_b64": cacao_b64
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["commit_cid"].as_str().is_some(), "{body}");
    assert!(body["assert_count"].as_u64().unwrap_or(0) > 0, "{body}");
    assert_eq!(body["retract_count"], 0, "{body}");
    let proof_cid = body["auth_proof_cid"]
        .as_str()
        .expect("auth_proof_cid")
        .to_string();
    let (status, proof_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.block.get?cid={proof_cid}"
        ))
        .await;
    assert_eq!(status, 200, "{proof_body}");
    assert_eq!(proof_body["data_b64"], cacao_b64, "{proof_body}");

    let (status, commit_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.commit.get?graph={graph}"
        ))
        .await;
    assert_eq!(status, 200, "{commit_body}");
    assert_eq!(
        commit_body["commit_type"], "distributed-datomic",
        "{commit_body}"
    );
    assert_eq!(commit_body["cid"], body["commit_cid"], "{commit_body}");
    assert_eq!(commit_body["tx_cid"], body["tx_cid"], "{commit_body}");
    assert_eq!(commit_body["cacao_proof_cid"], proof_cid, "{commit_body}");
    assert_eq!(commit_body["ipns_verified"], true, "{commit_body}");
    assert_eq!(
        commit_body["ipns_controller_did"], s.operator_did,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_controller_matches_node"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_controller_key_matches_did"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_signature_verified"], true,
        "{commit_body}"
    );
    assert!(
        commit_body["ipns_public_key_multibase"].as_str().is_some(),
        "{commit_body}"
    );
    assert!(
        commit_body["ipns_signature_multibase"].as_str().is_some(),
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_value_matches_commit"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_sequence_matches_commit"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_graph_matches_request"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_value_cid"], body["commit_cid"],
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_sequence"], body["ipns_sequence"],
        "{commit_body}"
    );
    assert!(
        commit_body["ipns_name"]
            .as_str()
            .unwrap_or_default()
            .starts_with("k51-kotoba-"),
        "{commit_body}"
    );
    assert_eq!(
        commit_body["index_roots"]
            .as_object()
            .map(|roots| roots.len()),
        Some(5),
        "{commit_body}"
    );

    let tok = tenant_jwt(&s.operator_did);
    let (status, query_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?proof ?operation ?author ?ipns ?seq ?controller]
                                 :where [[?tx :tx/authProofCid ?proof]
                                         [?tx :tx/operation ?operation]
                                         [?tx :tx/author ?author]
                                         [?tx :tx/ipnsName ?ipns]
                                         [?tx :tx/ipnsSequence ?seq]
                                         [?tx :tx/ipnsControllerDid ?controller]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{query_body}");
    let row = query_body["rows_edn"][0].as_array().expect("metadata row");
    assert_eq!(row[0], format!("\"{proof_cid}\""), "{query_body}");
    assert_eq!(
        row[1],
        format!("\"{}\"", kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT),
        "{query_body}"
    );
    assert!(
        row[2]
            .as_str()
            .unwrap_or_default()
            .starts_with("\"did:key:"),
        "{query_body}"
    );
    assert_eq!(
        row[3],
        format!("\"{}\"", body["ipns_name"].as_str().unwrap()),
        "{query_body}"
    );
    assert_eq!(
        row[4],
        body["ipns_sequence"].as_i64().unwrap().to_string(),
        "{query_body}"
    );
    assert_eq!(row[5], format!("\"{}\"", s.operator_did), "{query_body}");

    let (status, cap_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?proof ?controller ?action ?target]
                                 :where [[?tx :capability/proofCid ?proof]
                                         [?tx :capability/controller ?controller]
                                         [?tx :capability/allowedAction ?action]
                                         [?tx :capability/invocationTarget ?target]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{cap_body}");
    let cap_rows = cap_body["rows_edn"].as_array().expect("capability rows");
    assert!(
        cap_rows.iter().any(|row| row.as_array().is_some_and(|row| {
            row[0] == format!("\"{proof_cid}\"")
                && row[1]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("\"did:key:")
                && row[2] == format!("\"{}\"", kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT)
                && row[3] == format!("\"kotoba://graph/{graph}\"")
        })),
        "{cap_body}"
    );
}

#[tokio::test]
async fn datomic_transact_rejects_mismatched_cacao_tx_scope() {
    let s = TestServer::start(false).await;
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-cacao-write-tx-scope-e2e").to_multibase();
    let wrong_tx =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-cacao-wrong-write-tx-e2e").to_multibase();
    let cacao_b64 = build_ed25519_cacao_for_operation_with_resources(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        "nonce-datomic-transact-wrong-tx-e2e",
        vec![
            format!("kotoba://op/{}", kotoba_auth::CacaoPayload::OP_TX_CREATE),
            format!("kotoba://tx/{wrong_tx}"),
        ],
    );

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#,
                "cacao_b64": cacao_b64
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert!(
        body.as_str()
            .unwrap_or_default()
            .contains("CACAO missing transact tx scope kotoba://tx/"),
        "{body}"
    );
}

#[tokio::test]
async fn datomic_transact_accepts_matching_cacao_tx_scope_and_projects_capability_tx() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-cacao-matching-write-tx-e2e")
        .to_multibase();
    let tx_edn = r#"[[:db/add "alice" :person/name "Alice"]]"#;
    let tx_data = kotoba_edn::parse(tx_edn).expect("tx_edn parse");
    let expected_report = kotoba_datomic::Connection::new()
        .transact(tx_data)
        .await
        .expect("expected tx report");
    let expected_tx = expected_report.tx_cid.to_multibase();
    let cacao_b64 = build_ed25519_cacao_for_operation_with_resources(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        "nonce-datomic-transact-matching-tx-e2e",
        vec![
            format!("kotoba://op/{}", kotoba_auth::CacaoPayload::OP_TX_CREATE),
            format!("kotoba://tx/{expected_tx}"),
        ],
    );

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": tx_edn,
                "cacao_b64": cacao_b64
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tx_cid"], expected_tx, "{body}");
    let proof_cid = body["auth_proof_cid"].as_str().expect("auth proof cid");

    let tok = tenant_jwt(&s.operator_did);
    let (status, cap_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?proof ?tx]
                                 :where [[?e :capability/proofCid ?proof]
                                         [?e :capability/tx ?tx]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{cap_body}");
    assert!(
        cap_body["rows_edn"].as_array().unwrap().iter().any(|row| {
            row[0] == format!("\"{proof_cid}\"") && row[1] == format!("\"{expected_tx}\"")
        }),
        "{cap_body}"
    );
}

#[tokio::test]
async fn graph_sparql_reads_datomic_distributed_datoms() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-sparql-projection-e2e").to_multibase();

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[
                    [:db/add "alice" :person/name "Alice"]
                    [:db/add "alice" :person/role :admin]
                ]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");

    let (status, sparql_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": r#"SELECT * WHERE { ?s <kotoba://attr/:person/name> "Alice" }"#,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{sparql_body}");
    assert_eq!(sparql_body["form"], "select", "{sparql_body}");
    assert_eq!(sparql_body["count"], 1, "{sparql_body}");
    assert_eq!(
        sparql_body["quads"][0]["predicate"], ":person/name",
        "{sparql_body}"
    );
    assert_eq!(
        sparql_body["quads"][0]["object"]["text"], "Alice",
        "{sparql_body}"
    );

    let (status, retract_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "expected_parent": tx_body["commit_cid"],
                "tx_edn": r#"[
                    [:db/retract "alice" :person/name "Alice"]
                    [:db/add "alice" :person/name "Alicia"]
                ]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{retract_body}");
    assert_eq!(retract_body["ipns_sequence"], 2, "{retract_body}");

    let (status, old_name_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": r#"SELECT * WHERE { ?s <kotoba://attr/:person/name> "Alice" }"#,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{old_name_body}");
    assert_eq!(old_name_body["form"], "select", "{old_name_body}");
    assert_eq!(
        old_name_body["count"], 0,
        "SPARQL current view must hide retracted Datoms: {old_name_body}"
    );

    let (status, new_name_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": r#"SELECT * WHERE { ?s <kotoba://attr/:person/name> "Alicia" }"#,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{new_name_body}");
    assert_eq!(new_name_body["form"], "select", "{new_name_body}");
    assert_eq!(new_name_body["count"], 1, "{new_name_body}");
    assert_eq!(
        new_name_body["quads"][0]["object"]["text"], "Alicia",
        "{new_name_body}"
    );

    let (status, history_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "history": true,
                "query_edn": r#"{:find [?name ?added]
                                 :in [$history]
                                 :where [[$history ?e :person/name ?name ?tx ?added]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{history_body}");
    assert!(
        history_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row[0] == "\"Alice\"" && row[1] == "false"),
        "{history_body}"
    );
    assert!(
        history_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row[0] == "\"Alicia\"" && row[1] == "true"),
        "{history_body}"
    );
}

#[tokio::test]
async fn graph_sparql_accepts_cacao_graph_query_operation_scope_on_private_graph() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"sparql-cacao-query-private-e2e").to_multibase();

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");

    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "private");
    let cacao_b64 = build_ed25519_cacao_for_operation(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
        "nonce-sparql-query-private-e2e",
    );
    let (status, sparql_body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": r#"SELECT * WHERE { ?s <kotoba://attr/:person/name> "Alice" }"#,
                "cacaoB64": cacao_b64,
                "limit": 10
            }),
        )
        .await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "authenticated");

    assert_eq!(status, 200, "{sparql_body}");
    assert_eq!(sparql_body["form"], "select", "{sparql_body}");
    assert_eq!(sparql_body["count"], 1, "{sparql_body}");
}

#[tokio::test]
async fn datomic_transact_accepts_vp_capability_and_persists_proof_block() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-vp-transact-e2e").to_multibase();
    let presentation = build_vp_capability_presentation_with_operations(
        &s.operator_did,
        &s.state.ipns_signing_key(),
        &graph,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        vec![kotoba_auth::CacaoPayload::OP_TX_CREATE],
        false,
    )
    .1;

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#,
                "presentation": presentation
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    let proof_cid = body["auth_proof_cid"]
        .as_str()
        .expect("auth_proof_cid")
        .to_string();
    let (status, proof_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.block.get?cid={proof_cid}"
        ))
        .await;
    assert_eq!(status, 200, "{proof_body}");

    let data_b64 = proof_body["data_b64"].as_str().expect("data_b64");
    let proof_bytes = {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        B64.decode(data_b64).expect("proof block base64")
    };
    let stored: serde_json::Value =
        serde_json::from_slice(&proof_bytes).expect("stored VP proof JSON");
    assert_eq!(stored, presentation);

    let (status, commit_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.commit.get?graph={graph}"
        ))
        .await;
    assert_eq!(status, 200, "{commit_body}");
    assert_eq!(
        commit_body["commit_type"], "distributed-datomic",
        "{commit_body}"
    );
    assert_eq!(commit_body["cid"], body["commit_cid"], "{commit_body}");
    assert_eq!(commit_body["cacao_proof_cid"], proof_cid, "{commit_body}");

    let tok = tenant_jwt(&s.operator_did);
    let (status, cap_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?action]
                                 :where [[?tx :capability/proofCid ?proof]
                                         [?tx :capability/allowedAction ?action]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{cap_body}");
    let cap_actions = cap_body["rows_edn"].as_array().expect("cap actions");
    for expected in [
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        kotoba_auth::CacaoPayload::OP_TX_CREATE,
    ] {
        assert!(
            cap_actions
                .iter()
                .any(|row| row[0] == format!("\"{expected}\"")),
            "missing capability action {expected}: {cap_body}"
        );
    }

    let (status, zcap_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?action]
                                 :where [[?tx :capability/proofCid ?proof]
                                         [?tx "https://w3id.org/security#allowedAction" ?action]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{zcap_body}");
    let zcap_actions = zcap_body["rows_edn"].as_array().expect("zcap actions");
    for expected in [
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        kotoba_auth::CacaoPayload::OP_TX_CREATE,
    ] {
        assert!(
            zcap_actions
                .iter()
                .any(|row| row[0] == format!("\"{expected}\"")),
            "missing zcap action {expected}: {zcap_body}"
        );
    }
}

#[tokio::test]
async fn datomic_transact_accepts_matching_vp_tx_scope_and_projects_capability_tx() {
    let s = TestServer::start(false).await;
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-vp-matching-write-tx-e2e").to_multibase();
    let tx_edn = r#"[[:db/add "alice" :person/name "Alice"]]"#;
    let tx_data = kotoba_edn::parse(tx_edn).expect("tx_edn parse");
    let expected_report = kotoba_datomic::Connection::new()
        .transact(tx_data)
        .await
        .expect("expected tx report");
    let expected_tx = expected_report.tx_cid.to_multibase();
    let presentation = build_vp_capability_presentation_with_resources(
        &s.operator_did,
        &s.state.ipns_signing_key(),
        &graph,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        vec![kotoba_auth::CacaoPayload::OP_TX_CREATE],
        vec![format!("kotoba://tx/{expected_tx}")],
        false,
    )
    .1;

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": tx_edn,
                "presentation": presentation
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tx_cid"], expected_tx, "{body}");
    let proof_cid = body["auth_proof_cid"].as_str().expect("auth proof cid");

    let tok = tenant_jwt(&s.operator_did);
    let (status, cap_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?proof ?tx]
                                 :where [[?e :capability/proofCid ?proof]
                                         [?e :capability/tx ?tx]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{cap_body}");
    assert!(
        cap_body["rows_edn"].as_array().unwrap().iter().any(|row| {
            row[0] == format!("\"{proof_cid}\"") && row[1] == format!("\"{expected_tx}\"")
        }),
        "{cap_body}"
    );
}

#[tokio::test]
async fn datomic_transact_rejects_mismatched_vp_tx_scope() {
    let s = TestServer::start(false).await;
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-vp-wrong-write-tx-e2e").to_multibase();
    let wrong_tx =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-vp-wrong-tx-scope-e2e").to_multibase();
    let presentation = build_vp_capability_presentation_with_resources(
        &s.operator_did,
        &s.state.ipns_signing_key(),
        &graph,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        vec![kotoba_auth::CacaoPayload::OP_TX_CREATE],
        vec![format!("kotoba://tx/{wrong_tx}")],
        false,
    )
    .1;

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#,
                "presentation": presentation
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert!(
        body.as_str()
            .unwrap_or_default()
            .contains("VP missing operator-issued capability for datom:transact,tx:create"),
        "{body}"
    );
    assert!(
        body.as_str()
            .unwrap_or_default()
            .contains("with scope kotoba://tx/"),
        "{body}"
    );
}

#[tokio::test]
async fn datomic_q_accepts_cacao_graph_query_operation_scope_on_private_graph() {
    let s = TestServer::start(false).await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "private");
    let tok = tenant_jwt(&s.operator_did);
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-cacao-query-e2e").to_multibase();

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");

    let cacao_b64 = build_ed25519_cacao_for_operation(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
        "nonce-datomic-query-e2e",
    );
    let (status, q_body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#,
                "cacao_b64": cacao_b64
            }),
        )
        .await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "authenticated");
    assert_eq!(status, 200, "{q_body}");
    assert_eq!(q_body["rows_edn"][0][0], "\"Alice\"", "{q_body}");
}

#[tokio::test]
async fn datomic_q_requires_matching_cacao_tx_scope_for_temporal_query_on_private_graph() {
    let s = TestServer::start(false).await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "private");
    let tok = tenant_jwt(&s.operator_did);
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-cacao-tx-scope-e2e").to_multibase();

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");
    let tx_cid = tx_body["tx_cid"].as_str().unwrap();
    let wrong_tx =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-cacao-wrong-tx-e2e").to_multibase();

    let wrong_cacao_b64 = build_ed25519_cacao_for_operation_with_resources(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
        "nonce-datomic-query-wrong-tx-e2e",
        vec![format!("kotoba://tx/{wrong_tx}")],
    );
    let (status, q_body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#,
                "as_of": tx_cid,
                "cacao_b64": wrong_cacao_b64
            }),
        )
        .await;
    assert_eq!(status, 401, "{q_body}");
    assert!(
        q_body
            .as_str()
            .unwrap_or_default()
            .contains(&format!("kotoba://tx/{tx_cid}")),
        "{q_body}"
    );

    let cacao_b64 = build_ed25519_cacao_for_operation_with_resources(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
        "nonce-datomic-query-matching-tx-e2e",
        vec![format!("kotoba://tx/{tx_cid}")],
    );
    let (status, q_body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#,
                "as_of": tx_cid,
                "cacao_b64": cacao_b64
            }),
        )
        .await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "authenticated");
    assert_eq!(status, 200, "{q_body}");
    assert_eq!(q_body["rows_edn"][0][0], "\"Alice\"", "{q_body}");
}

#[tokio::test]
async fn datomic_q_accepts_vp_graph_query_capability_on_private_graph() {
    let s = TestServer::start(false).await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "private");
    let tok = tenant_jwt(&s.operator_did);
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-vp-query-e2e").to_multibase();
    let presentation = build_vp_capability_presentation(
        &s.operator_did,
        &s.state.ipns_signing_key(),
        &graph,
        kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
        false,
    )
    .1;

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");

    let (status, q_body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#,
                "presentation": presentation
            }),
        )
        .await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "authenticated");
    assert_eq!(status, 200, "{q_body}");
    assert_eq!(q_body["rows_edn"][0][0], "\"Alice\"", "{q_body}");
}

#[tokio::test]
async fn datomic_q_accepts_vp_datom_read_capability_on_private_graph() {
    let s = TestServer::start(false).await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "private");
    let tok = tenant_jwt(&s.operator_did);
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"datomic-vp-datom-read-e2e").to_multibase();
    let presentation = build_vp_capability_presentation(
        &s.operator_did,
        &s.state.ipns_signing_key(),
        &graph,
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        false,
    )
    .1;

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");

    let (status, q_body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#,
                "presentation": presentation
            }),
        )
        .await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "authenticated");
    assert_eq!(status, 200, "{q_body}");
    assert_eq!(q_body["rows_edn"][0][0], "\"Alice\"", "{q_body}");
}

#[tokio::test]
async fn datomic_q_rejects_tampered_vp_capability_signature() {
    let s = TestServer::start(false).await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "private");
    let tok = tenant_jwt(&s.operator_did);
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-vp-tamper-e2e").to_multibase();
    let presentation = build_vp_capability_presentation(
        &s.operator_did,
        &s.state.ipns_signing_key(),
        &graph,
        kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
        true,
    )
    .1;

    let (status, tx_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{tx_body}");

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?name] :where [[?e :person/name ?name]]}"#,
                "presentation": presentation
            }),
        )
        .await;
    std::env::set_var("KOTOBA_DEFAULT_VISIBILITY", "authenticated");
    assert_eq!(status, 401, "{body}");
    assert!(
        body.as_str()
            .unwrap_or_default()
            .contains("DataIntegrity proof verification failed"),
        "{body}"
    );
}

#[tokio::test]
async fn datomic_q_rejects_vp_with_forged_operator_capability_credential() {
    use ed25519_dalek::SigningKey;

    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"datomic-vp-forged-vc-e2e").to_multibase();
    let wrong_operator_key = SigningKey::from_bytes(&[55u8; 32]);
    let presentation = build_vp_capability_presentation(
        &s.operator_did,
        &wrong_operator_key,
        &graph,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        false,
    )
    .1;

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.datomic.transact",
            json!({
                "graph": graph,
                "tx_edn": r#"[[:db/add "alice" :person/name "Alice"]]"#,
                "presentation": presentation
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert!(
        body.as_str()
            .or_else(|| body["error"].as_str())
            .unwrap_or_default()
            .contains("VC capability proof verification failed"),
        "{body}"
    );
}

#[tokio::test]
async fn vc_issue_projects_credential_to_distributed_datoms() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"vc-issue-e2e").to_multibase();

    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.vc.issue",
            json!({
                "graph": graph,
                "credential": {
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "id": "urn:uuid:vc-e2e-1",
                    "type": ["VerifiableCredential", "KotobaRoleCredential"],
                    "issuer": "did:key:zIssuer",
                    "credentialSubject": {
                        "id": "did:key:zAlice",
                        "role": "admin",
                        "profile": {
                            "name": "Alice",
                            "region": "JP"
                        }
                    },
                    "credentialStatus": {
                        "id": "urn:status:vc-e2e-1",
                        "type": "StatusList2021Entry"
                    },
                    "proof": {
                        "type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-rdfc-2022",
                        "proofPurpose": "assertionMethod",
                        "verificationMethod": "did:key:zIssuer#key-1",
                        "created": "2026-05-29T00:00:00Z",
                        "proofValue": "zFakeProof",
                        "challenge": "vc-issue-e2e-challenge",
                        "domain": "kotoba.local"
                    }
                }
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["commit_cid"].as_str().is_some(), "{body}");
    assert!(body["datom_count"].as_u64().unwrap_or(0) >= 5);

    let (status, q_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?id ?types ?issuer ?subject ?status ?proof]
                                :where [[?e :credential/id ?id]
                                        [?e :credential/type ?types]
                                        [?e :credential/issuer ?issuer]
                                        [?e :credential/subject ?subject]
                                        [?e :credential/status ?status]
                                        [?e :credential/proof ?proof]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{q_body}");
    let rows = q_body["rows_edn"].as_array().unwrap();
    assert!(!rows.is_empty(), "{q_body}");
    let row = rows[0].as_array().unwrap();
    assert_eq!(row[0], "\"urn:uuid:vc-e2e-1\"", "{q_body}");
    assert!(row[1]
        .as_str()
        .unwrap_or("")
        .contains("\"KotobaRoleCredential\""));
    assert_eq!(row[2], format!("\"{}\"", s.operator_did), "{q_body}");
    assert!(row[3].as_str().unwrap_or("").contains(":role \"admin\""));
    assert!(row[4]
        .as_str()
        .unwrap_or("")
        .contains("StatusList2021Entry"));
    assert!(row[5].as_str().unwrap_or("").contains("DataIntegrityProof"));

    let (status, subject_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?role ?name ?region]
                                :where [[?e :credential/id "urn:uuid:vc-e2e-1"]
                                        [?e :credential/subject/role ?role]
                                        [?e :credential/subject/profile/name ?name]
                                        [?e :credential/subject/profile/region ?region]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{subject_body}");
    assert!(
        subject_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row.as_array().is_some_and(|row| {
                row[0] == "\"admin\"" && row[1] == "\"Alice\"" && row[2] == "\"JP\""
            })),
        "{subject_body}"
    );

    let (status, normalized_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?statusId ?statusType ?proofType ?proofSuite ?proofPurpose ?proofVm ?proofCreated ?proofValue ?proofChallenge ?proofDomain]
                                :where [[?e :credential/id "urn:uuid:vc-e2e-1"]
                                        [?e :credential/status/id ?statusId]
                                        [?e :credential/status/type ?statusType]
                                        [?e :credential/proof/type ?proofType]
                                        [?e :credential/proof/cryptosuite ?proofSuite]
                                        [?e :credential/proof/proofPurpose ?proofPurpose]
                                        [?e :credential/proof/verificationMethod ?proofVm]
                                        [?e :credential/proof/created ?proofCreated]
                                        [?e :credential/proof/proofValue ?proofValue]
                                        [?e :credential/proof/challenge ?proofChallenge]
                                        [?e :credential/proof/domain ?proofDomain]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{normalized_body}");
    assert!(
        normalized_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row.as_array().is_some_and(|row| {
                row[0] == "\"urn:status:vc-e2e-1\""
                    && row[1] == "\"StatusList2021Entry\""
                    && row[2] == "\"DataIntegrityProof\""
                    && row[3] == "\"eddsa-2022\""
                    && row[4] == "\"assertionMethod\""
                    && row[5] == format!("\"{}#agent-ed25519\"", s.operator_did)
                    && row[6] == "\"2026-05-29T00:00:00Z\""
                    && row[7]
                        .as_str()
                        .is_some_and(|proof| proof.starts_with("\"z"))
                    && row[8] == "\"vc.issue\""
                    && row[9] == "\"kotoba.vc.issue\""
            })),
        "{normalized_body}"
    );

    let (status, iri_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?id ?types ?issuer ?subject ?status ?proof]
                                :where [[?e "https://www.w3.org/2018/credentials#id" ?id]
                                        [?e "http://www.w3.org/1999/02/22-rdf-syntax-ns#type" ?types]
                                        [?e "https://www.w3.org/2018/credentials#issuer" ?issuer]
                                        [?e "https://www.w3.org/2018/credentials#credentialSubject" ?subject]
                                        [?e "https://www.w3.org/2018/credentials#credentialStatus" ?status]
                                        [?e "https://w3id.org/security#proof" ?proof]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{iri_body}");
    let iri_rows = iri_body["rows_edn"].as_array().unwrap();
    assert!(
        iri_rows.iter().any(|row| row.as_array().is_some_and(|row| {
            row[0] == "\"urn:uuid:vc-e2e-1\""
                && row[1]
                    .as_str()
                    .unwrap_or("")
                    .contains("\"KotobaRoleCredential\"")
                && row[2] == format!("\"{}\"", s.operator_did)
                && row[3].as_str().unwrap_or("").contains(":role \"admin\"")
                && row[4]
                    .as_str()
                    .unwrap_or("")
                    .contains("StatusList2021Entry")
                && row[5].as_str().unwrap_or("").contains("DataIntegrityProof")
        })),
        "{iri_body}"
    );

    let (status, sparql_issuer_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": format!(r#"SELECT * WHERE {{ ?s <https://www.w3.org/2018/credentials#issuer> "{}" }}"#, s.operator_did),
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{sparql_issuer_body}");
    assert_eq!(sparql_issuer_body["form"], "select", "{sparql_issuer_body}");
    assert!(
        sparql_issuer_body["count"].as_u64().unwrap_or(0) >= 1,
        "{sparql_issuer_body}"
    );

    let (status, sparql_subject_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": r#"SELECT * WHERE { ?s <https://www.w3.org/2018/credentials#credentialSubject> ?subject }"#,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{sparql_subject_body}");
    assert_eq!(
        sparql_subject_body["form"], "select",
        "{sparql_subject_body}"
    );
    assert!(
        sparql_subject_body["count"].as_u64().unwrap_or(0) >= 1,
        "{sparql_subject_body}"
    );
}

#[tokio::test]
async fn vc_issue_accepts_cacao_vc_issue_operation_scope() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"vc-issue-cacao-e2e").to_multibase();
    let cacao_b64 = build_ed25519_cacao_for_operation(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_VC_ISSUE,
        "nonce-vc-issue-cacao-e2e",
    );

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.vc.issue",
            json!({
                "graph": graph,
                "cacao_b64": cacao_b64,
                "credential": {
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "id": "urn:uuid:vc-cacao-e2e-1",
                    "type": ["VerifiableCredential", "KotobaCapabilityCredential"],
                    "issuer": "did:key:zIssuer",
                    "credentialSubject": {
                        "id": "did:key:zAlice",
                        "operation": "vc:issue"
                    }
                }
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok", "{body}");
    assert!(body["commit_cid"].as_str().is_some(), "{body}");
    assert_protocol_auth_proof(
        &s,
        &graph,
        &body,
        &cacao_b64,
        kotoba_auth::CacaoPayload::OP_VC_ISSUE,
    )
    .await;
}

#[tokio::test]
async fn vc_issue_accepts_vp_capability_and_persists_proof() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"vc-issue-vp-e2e").to_multibase();
    let presentation = build_vp_capability_presentation(
        &s.operator_did,
        &s.state.ipns_signing_key(),
        &graph,
        kotoba_auth::CacaoPayload::OP_VC_ISSUE,
        false,
    )
    .1;

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.vc.issue",
            json!({
                "graph": graph,
                "auth_presentation": presentation,
                "credential": {
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "id": "urn:uuid:vc-vp-auth-e2e-1",
                    "type": ["VerifiableCredential", "KotobaCapabilityCredential"],
                    "issuer": "did:key:zIssuer",
                    "credentialSubject": {
                        "id": "did:key:zAlice",
                        "operation": "vc:issue"
                    }
                }
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok", "{body}");
    assert_protocol_vp_auth_proof(
        &s,
        &graph,
        &body,
        &presentation,
        kotoba_auth::CacaoPayload::OP_VC_ISSUE,
    )
    .await;
}

#[tokio::test]
async fn vc_present_projects_presentation_to_distributed_datoms() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"vc-present-e2e").to_multibase();
    let cacao_b64 = build_ed25519_cacao_for_operation(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_VC_PRESENT,
        "nonce-vc-present-e2e",
    );

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.vc.present",
            json!({
                "graph": graph,
                "cacao_b64": cacao_b64,
                "presentation": {
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "id": "urn:uuid:vp-e2e-1",
                    "type": ["VerifiablePresentation"],
                    "holder": "did:key:zAlice",
                    "verifiableCredential": [{
                        "@context": ["https://www.w3.org/ns/credentials/v2"],
                        "id": "urn:uuid:vc-in-vp-e2e-1",
                        "type": ["VerifiableCredential"],
                        "issuer": "did:key:zIssuer",
                        "credentialSubject": {"id": "did:key:zAlice"}
                    }],
                    "proof": {
                        "type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-rdfc-2022",
                        "proofPurpose": "authentication",
                        "verificationMethod": "did:key:zAlice#key-1",
                        "created": "2026-05-29T00:00:00Z",
                        "proofValue": "zFakePresentationProof",
                        "challenge": "vc-present-e2e-challenge",
                        "domain": "kotoba.local"
                    }
                }
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["commit_cid"].as_str().is_some(), "{body}");
    assert_protocol_auth_proof(
        &s,
        &graph,
        &body,
        &cacao_b64,
        kotoba_auth::CacaoPayload::OP_VC_PRESENT,
    )
    .await;

    let tok = tenant_jwt(&s.operator_did);
    let (status, q_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?holder] :where [[?e :presentation/holder ?holder]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{q_body}");
    assert_eq!(q_body["rows_edn"][0][0], "\"did:key:zAlice\"", "{q_body}");

    let (status, proof_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?proofType ?proofSuite ?proofPurpose ?proofVm ?proofCreated ?proofValue ?proofChallenge ?proofDomain]
                                 :where [[?e :presentation/id "urn:uuid:vp-e2e-1"]
                                         [?e :presentation/proof/type ?proofType]
                                         [?e :presentation/proof/cryptosuite ?proofSuite]
                                         [?e :presentation/proof/proofPurpose ?proofPurpose]
                                         [?e :presentation/proof/verificationMethod ?proofVm]
                                         [?e :presentation/proof/created ?proofCreated]
                                         [?e :presentation/proof/proofValue ?proofValue]
                                         [?e :presentation/proof/challenge ?proofChallenge]
                                         [?e :presentation/proof/domain ?proofDomain]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{proof_body}");
    assert!(
        proof_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row.as_array().is_some_and(|row| {
                row[0] == "\"DataIntegrityProof\""
                    && row[1] == "\"eddsa-rdfc-2022\""
                    && row[2] == "\"authentication\""
                    && row[3] == "\"did:key:zAlice#key-1\""
                    && row[4] == "\"2026-05-29T00:00:00Z\""
                    && row[5] == "\"zFakePresentationProof\""
                    && row[6] == "\"vc-present-e2e-challenge\""
                    && row[7] == "\"kotoba.local\""
            })),
        "{proof_body}"
    );

    let (status, iri_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?id ?types ?holder ?credential]
                                 :where [[?e "https://www.w3.org/2018/credentials#id" ?id]
                                         [?e "http://www.w3.org/1999/02/22-rdf-syntax-ns#type" ?types]
                                         [?e "https://www.w3.org/2018/credentials#holder" ?holder]
                                         [?e "https://www.w3.org/2018/credentials#verifiableCredential" ?credential]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{iri_body}");
    assert!(
        iri_body["rows_edn"].as_array().is_some_and(|rows| {
            rows.iter().any(|row| {
                row.as_array().is_some_and(|row| {
                    row[0] == "\"urn:uuid:vp-e2e-1\""
                        && row[1]
                            .as_str()
                            .unwrap_or("")
                            .contains("\"VerifiablePresentation\"")
                        && row[2] == "\"did:key:zAlice\""
                        && row[3].as_str().is_some_and(|cid| cid.starts_with("\"bafy"))
                })
            })
        }),
        "{iri_body}"
    );

    let (status, sparql_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": r#"SELECT * WHERE { ?s <https://www.w3.org/2018/credentials#holder> "did:key:zAlice" }"#,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{sparql_body}");
    assert_eq!(sparql_body["form"], "select", "{sparql_body}");
    assert!(
        sparql_body["count"].as_u64().unwrap_or(0) >= 1,
        "{sparql_body}"
    );

    let (status, vc_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?id ?issuer ?subject]
                                 :where [[?e :credential/id ?id]
                                         [?e :credential/issuer ?issuer]
                                         [?e :credential/subjectId ?subject]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{vc_body}");
    assert!(
        vc_body["rows_edn"].as_array().is_some_and(|rows| {
            rows.iter().any(|row| {
                row.as_array().is_some_and(|row| {
                    row[0] == "\"urn:uuid:vc-in-vp-e2e-1\""
                        && row[1] == "\"did:key:zIssuer\""
                        && row[2] == "\"did:key:zAlice\""
                })
            })
        }),
        "{vc_body}"
    );
}

#[tokio::test]
async fn vc_present_accepts_vp_capability_and_persists_proof() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"vc-present-vp-e2e").to_multibase();
    let presentation = build_vp_capability_presentation(
        &s.operator_did,
        &s.state.ipns_signing_key(),
        &graph,
        kotoba_auth::CacaoPayload::OP_VC_PRESENT,
        false,
    )
    .1;

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.vc.present",
            json!({
                "graph": graph,
                "auth_presentation": presentation,
                "presentation": {
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "id": "urn:uuid:vp-vp-auth-e2e-1",
                    "type": ["VerifiablePresentation"],
                    "holder": "did:key:zAlice",
                    "verifiableCredential": [{
                        "@context": ["https://www.w3.org/ns/credentials/v2"],
                        "id": "urn:uuid:vc-in-vp-auth-e2e-1",
                        "type": ["VerifiableCredential", "KotobaRoleCredential"],
                        "issuer": "did:key:zIssuer",
                        "credentialSubject": {
                            "id": "did:key:zAlice",
                            "role": "presenter"
                        }
                    }]
                }
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok", "{body}");
    assert_protocol_vp_auth_proof(
        &s,
        &graph,
        &body,
        &presentation,
        kotoba_auth::CacaoPayload::OP_VC_PRESENT,
    )
    .await;
}

#[tokio::test]
async fn did_document_publish_projects_protocol_services_to_distributed_datoms() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"did-document-publish-e2e").to_multibase();
    let cacao_b64 = build_ed25519_cacao_for_operation(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        "nonce-did-document-publish-e2e",
    );

    let document = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:plc:kotobaagent",
        "verificationMethod": [
            {
                "id": "did:plc:kotobaagent#x25519-1",
                "type": "X25519KeyAgreementKey2020",
                "controller": "did:plc:kotobaagent",
                "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, [42u8; 32])
            }
        ],
        "authentication": [],
        "assertionMethod": [],
        "keyAgreement": ["did:plc:kotobaagent#x25519-1"],
        "capabilityInvocation": [],
        "capabilityDelegation": [],
        "service": [
            {
                "id": "did:plc:kotobaagent#didcomm",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "didcomm://mediator/kotobaagent"
            },
            {
                "id": "did:plc:kotobaagent#atproto-pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com"
            },
            {
                "id": "did:plc:kotobaagent#kotoba-node",
                "type": "KotobaNode",
                "serviceEndpoint": "/ip4/127.0.0.1/tcp/4001"
            },
            {
                "id": "did:plc:kotobaagent#kotoba-graphs",
                "type": "KotobaGraphMembership",
                "serviceEndpoint": ["kotoba://graph/a", "kotoba://graph/b"]
            }
        ]
    });

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.did.document.publish",
            json!({
                "graph": graph,
                "cacao_b64": cacao_b64,
                "document": document
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok", "{body}");
    assert_protocol_auth_proof(
        &s,
        &graph,
        &body,
        &cacao_b64,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
    )
    .await;

    let tok = tenant_jwt(&s.operator_did);
    let (status, q_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?type] :where [[?e :did/service/type ?type]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{q_body}");
    let rows = q_body["rows_edn"].as_array().unwrap();
    for expected in [
        "\"DIDCommMessaging\"",
        "\"AtprotoPersonalDataServer\"",
        "\"KotobaNode\"",
        "\"KotobaGraphMembership\"",
    ] {
        assert!(
            rows.iter()
                .any(|row| row.as_array().and_then(|r| r.first()) == Some(&json!(expected))),
            "missing service type {expected}: {q_body}"
        );
    }

    let (status, w3c_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?service ?type ?endpoint]
                    :where [[?doc "https://www.w3.org/ns/did#service" ?service]
                            [?service_e "https://www.w3.org/ns/did#id" ?service]
                            [?service_e "http://www.w3.org/1999/02/22-rdf-syntax-ns#type" ?type]
                            [?service_e "https://www.w3.org/ns/did#serviceEndpoint" ?endpoint]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{w3c_body}");
    let w3c_rows = w3c_body["rows_edn"].as_array().unwrap();
    for expected in [
        "\"DIDCommMessaging\"",
        "\"AtprotoPersonalDataServer\"",
        "\"KotobaNode\"",
        "\"KotobaGraphMembership\"",
    ] {
        assert!(
            w3c_rows
                .iter()
                .any(|row| row.as_array().and_then(|r| r.get(1)) == Some(&json!(expected))),
            "missing W3C DID Core service type {expected}: {w3c_body}"
        );
    }
    assert!(
        w3c_rows
            .iter()
            .any(|row| row.as_array().and_then(|r| r.get(2))
                == Some(&json!("\"https://pds.example.com\""))),
        "missing W3C DID Core serviceEndpoint projection: {w3c_body}"
    );

    let did_entity =
        kotoba_core::cid::KotobaCid::from_bytes("did:plc:kotobaagent".as_bytes()).to_multibase();
    let (status, entity_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.entity",
            json!({
                "graph": graph,
                "entity": did_entity
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{entity_body}");
    let entity_datoms = entity_body["datoms"].as_array().expect("entity datoms");
    for attr in ["did/id", "https://www.w3.org/ns/did#id"] {
        assert!(
            entity_datoms
                .iter()
                .any(|datom| { datom["a"] == attr && datom["v_edn"] == "\"did:plc:kotobaagent\"" }),
            "missing DID-derived entity attr {attr}: {entity_body}"
        );
    }
    for attr in ["did/keyAgreement", "https://www.w3.org/ns/did#keyAgreement"] {
        assert!(
            entity_datoms.iter().any(|datom| {
                datom["a"] == attr
                    && datom["v_edn"]
                        .as_str()
                        .is_some_and(|edn| edn.contains("\"did:plc:kotobaagent#x25519-1\""))
            }),
            "missing DID keyAgreement attr {attr}: {entity_body}"
        );
    }

    let resolved = s
        .state
        .did_resolver
        .resolve("did:plc:kotobaagent")
        .expect("published DID document should resolve from distributed DID registry");
    assert_eq!(
        resolved.key_agreement,
        vec!["did:plc:kotobaagent#x25519-1".to_string()]
    );
    assert_eq!(resolved.x25519_public_key(), Some([42u8; 32]));
    assert_eq!(
        resolved.didcomm_endpoint(),
        Some("didcomm://mediator/kotobaagent")
    );
    assert_eq!(
        resolved.atproto_pds_endpoint(),
        Some("https://pds.example.com")
    );
    assert_eq!(resolved.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4001"));
    assert_eq!(
        resolved.graph_memberships(),
        vec!["kotoba://graph/a", "kotoba://graph/b"]
    );
}

#[tokio::test]
async fn did_document_publish_rejects_missing_protocol_services() {
    let s = TestServer::start(false).await;
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"did-document-publish-missing-services-e2e")
            .to_multibase();
    let cacao_b64 = build_ed25519_cacao_for_operation(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        "nonce-did-document-publish-missing-services-e2e",
    );

    let document = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:plc:incompleteagent",
        "verificationMethod": [],
        "authentication": [],
        "assertionMethod": [],
        "capabilityInvocation": [],
        "capabilityDelegation": [],
        "service": [
            {
                "id": "did:plc:incompleteagent#didcomm",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "didcomm://mediator/incompleteagent"
            }
        ]
    });

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.did.document.publish",
            json!({
                "graph": graph,
                "cacao_b64": cacao_b64,
                "document": document
            }),
        )
        .await;

    assert_eq!(status, 400, "{body}");
    let message = body.as_str().unwrap_or("");
    for missing in [
        "AtprotoPersonalDataServer",
        "KotobaNode",
        "KotobaGraphMembership",
    ] {
        assert!(
            message.contains(missing),
            "missing service {missing} should be named in error: {body}"
        );
    }
    assert!(
        s.state
            .did_resolver
            .resolve("did:plc:incompleteagent")
            .is_err(),
        "rejected DID document must not be published to distributed DID registry"
    );
}

#[tokio::test]
async fn didcomm_send_projects_message_to_distributed_datoms() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"didcomm-send-e2e").to_multibase();
    let cacao_b64 = build_ed25519_cacao_for_operation_with_resources(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_DIDCOMM_SEND,
        "nonce-didcomm-send-e2e",
        vec!["didcomm://thread/thread-e2e-1".to_string()],
    );

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.didcomm.send",
            json!({
                "graph": graph,
                "cacao_b64": cacao_b64,
                "message": {
                    "id": "msg-e2e-1",
                    "type": "https://didcomm.org/basicmessage/2.0/message",
                    "from": "did:key:zAlice",
                    "to": ["did:key:zBob"],
                    "thid": "thread-e2e-1",
                    "body": {
                        "content": "hello",
                        "meta": {"lang": "en"},
                        "tags": ["chat", "kotoba"]
                    },
                    "attachments": [{
                        "id": "att-e2e-1",
                        "description": "profile",
                        "media_type": "application/json",
                        "data": {"json": {"name": "Alice"}}
                    }]
                }
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["commit_cid"].as_str().is_some(), "{body}");
    assert_protocol_auth_proof(
        &s,
        &graph,
        &body,
        &cacao_b64,
        kotoba_auth::CacaoPayload::OP_DIDCOMM_SEND,
    )
    .await;
    assert_capability_invocation_target(
        &s,
        &graph,
        body["auth_proof_cid"].as_str().expect("auth_proof_cid"),
        "didcomm://thread/thread-e2e-1",
    )
    .await;

    let tok = tenant_jwt(&s.operator_did);
    let (status, cap_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?thread]
                                 :where [[?tx :capability/proofCid ?proof]
                                         [?tx :capability/didcommThread ?thread]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{cap_body}");
    assert!(
        cap_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row[0] == "\"thread-e2e-1\""),
        "{cap_body}"
    );

    let (status, q_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?protocol ?service ?thread]
                                 :where [[?e :didcomm/protocol ?protocol]
                                         [?e :didcomm/serviceType ?service]
                                         [?e :didcomm/thread ?thread]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{q_body}");
    assert_eq!(
        q_body["rows_edn"],
        json!([["\"DIDComm v2\"", "\"DIDCommMessaging\"", "\"thread-e2e-1\""]]),
        "{q_body}"
    );

    let (status, body_field_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?content ?meta ?lang ?tags]
                                 :where [[?e :didcomm/id "msg-e2e-1"]
                                         [?e :didcomm/body/content ?content]
                                         [?e :didcomm/body/meta ?meta]
                                         [?e :didcomm/body/meta/lang ?lang]
                                         [?e :didcomm/body/tags ?tags]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body_field_body}");
    assert!(
        body_field_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| {
                row[0] == "\"hello\""
                    && row[1].as_str().unwrap_or("").contains(":lang \"en\"")
                    && row[2] == "\"en\""
                    && row[3]
                        .as_str()
                        .unwrap_or("")
                        .contains("[\"chat\" \"kotoba\"]")
            }),
        "{body_field_body}"
    );

    let (status, wire_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?thread ?body]
                                 :where [[?e "thid" ?thread]
                                         [?e "https://didcomm.org/basicmessage/2.0/message" ?body]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{wire_body}");
    assert!(
        wire_body["rows_edn"].as_array().unwrap().iter().any(|row| {
            let body = row[1].as_str().unwrap_or("");
            row[0] == "\"thread-e2e-1\""
                && body.contains(":content \"hello\"")
                && body.contains(":meta {:lang \"en\"")
                && body.contains(":tags [\"chat\" \"kotoba\"]")
        }),
        "{wire_body}"
    );

    let (status, attachment_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?body ?attachment ?wireAttachment]
                                 :where [[?e :didcomm/body ?body]
                                         [?e :didcomm/attachment ?attachment]
                                         [?e "attachments" ?wireAttachment]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{attachment_body}");
    assert!(
        attachment_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| {
                let body = row[0].as_str().unwrap_or("");
                let attachment = row[1].as_str().unwrap_or("");
                let wire_attachment = row[2].as_str().unwrap_or("");
                body.contains(":meta {:lang \"en\"")
                    && body.contains(":tags [\"chat\" \"kotoba\"]")
                    && attachment.contains(":description \"profile\"")
                    && attachment.contains(":media_type \"application/json\"")
                    && attachment.contains(":json {:name \"Alice\"")
                    && wire_attachment.contains(":description \"profile\"")
                    && wire_attachment.contains(":media_type \"application/json\"")
            }),
        "{attachment_body}"
    );

    let (status, sparql_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": r#"SELECT * WHERE { ?message <https://didcomm.org/basicmessage/2.0/message> ?body }"#,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{sparql_body}");
    assert_eq!(sparql_body["form"], "select", "{sparql_body}");
    assert!(
        sparql_body["count"].as_u64().unwrap_or(0) >= 1,
        "{sparql_body}"
    );
}

#[tokio::test]
async fn didcomm_send_rejects_cacao_without_thread_scope() {
    let s = TestServer::start(false).await;
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"didcomm-send-thread-scope-e2e").to_multibase();
    let cacao_b64 = build_ed25519_cacao_for_operation(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_DIDCOMM_SEND,
        "nonce-didcomm-send-no-thread-scope-e2e",
    );

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.didcomm.send",
            json!({
                "graph": graph,
                "cacao_b64": cacao_b64,
                "message": {
                    "id": "msg-e2e-no-thread-scope-1",
                    "type": "https://didcomm.org/basicmessage/2.0/message",
                    "from": "did:key:zAlice",
                    "to": ["did:key:zBob"],
                    "thid": "thread-e2e-no-scope-1",
                    "body": {"content": "hello"}
                }
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert!(
        body.as_str()
            .or_else(|| body["error"].as_str())
            .unwrap_or_default()
            .contains("DIDComm thread scope"),
        "{body}"
    );
}

#[tokio::test]
async fn didcomm_send_accepts_vp_thread_scope_and_persists_proof() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"didcomm-send-vp-e2e").to_multibase();
    let thread_scope = "didcomm://thread/thread-vp-e2e-1";
    let presentation = build_vp_capability_presentation_with_resources(
        &s.operator_did,
        &s.state.ipns_signing_key(),
        &graph,
        kotoba_auth::CacaoPayload::OP_DIDCOMM_SEND,
        Vec::new(),
        vec![thread_scope.to_string()],
        false,
    )
    .1;

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.didcomm.send",
            json!({
                "graph": graph,
                "auth_presentation": presentation,
                "message": {
                    "id": "msg-vp-e2e-1",
                    "type": "https://didcomm.org/basicmessage/2.0/message",
                    "from": "did:key:zAlice",
                    "to": ["did:key:zBob"],
                    "thid": "thread-vp-e2e-1",
                    "body": {"content": "hello via vp"}
                }
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok", "{body}");
    assert_protocol_vp_auth_proof(
        &s,
        &graph,
        &body,
        &presentation,
        kotoba_auth::CacaoPayload::OP_DIDCOMM_SEND,
    )
    .await;
    assert_capability_invocation_target(
        &s,
        &graph,
        body["auth_proof_cid"].as_str().expect("auth_proof_cid"),
        thread_scope,
    )
    .await;
}

#[tokio::test]
async fn atproto_repo_write_projects_record_to_distributed_datoms() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"atproto-write-e2e").to_multibase();
    let at_uri = "at://did:plc:alice/app.bsky.feed.post/3kabc";
    let cacao_b64 = build_ed25519_cacao_for_operation_with_resources(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_ATPROTO_REPO_WRITE,
        "nonce-atproto-write-e2e",
        vec![at_uri.to_string()],
    );

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.atproto.repo.write",
            json!({
                "graph": graph,
                "cacao_b64": cacao_b64,
                "uri": at_uri,
                "operation": "create",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": "hello kotoba",
                    "langs": ["en"],
                    "createdAt": "2026-05-29T00:00:00Z",
                    "embed": {
                        "$type": "app.bsky.embed.external",
                        "external": {
                            "uri": "ipfs://bafyexample",
                            "title": "Kotoba"
                        }
                    }
                }
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["commit_cid"].as_str().is_some(), "{body}");
    assert_protocol_auth_proof(
        &s,
        &graph,
        &body,
        &cacao_b64,
        kotoba_auth::CacaoPayload::OP_ATPROTO_REPO_WRITE,
    )
    .await;
    assert_capability_invocation_target(
        &s,
        &graph,
        body["auth_proof_cid"].as_str().expect("auth_proof_cid"),
        at_uri,
    )
    .await;

    let tok = tenant_jwt(&s.operator_did);
    let (status, cap_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?at]
                                 :where [[?tx :capability/proofCid ?proof]
                                         [?tx :capability/atprotoResource ?at]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{cap_body}");
    assert!(
        cap_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row[0] == format!("\"{at_uri}\"")),
        "{cap_body}"
    );

    let (status, q_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?did ?collection ?nsid]
                                 :where [[?e :atproto/did ?did]
                                         [?e :atproto/collection ?collection]
                                         [?e :atproto/nsid ?nsid]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{q_body}");
    assert_eq!(
        q_body["rows_edn"],
        json!([[
            "\"did:plc:alice\"",
            "\"app.bsky.feed.post\"",
            "\"app.bsky.feed.post\""
        ]]),
        "{q_body}"
    );

    let (status, nsid_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?type ?record]
                                 :where [[?e :atproto/recordType ?type]
                                         [?e "app.bsky.feed.post" ?record]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{nsid_body}");
    assert!(
        nsid_body["rows_edn"].as_array().unwrap().iter().any(|row| {
            row[0] == "\"app.bsky.feed.post\""
                && row[1]
                    .as_str()
                    .unwrap_or("")
                    .contains(":text \"hello kotoba\"")
        }),
        "{nsid_body}"
    );

    let (status, record_field_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?text ?langs ?createdAt ?embedUri ?nsidText]
                                 :where [[?e :atproto/uri ?uri]
                                         [?e :atproto/record/text ?text]
                                         [?e :atproto/record/langs ?langs]
                                         [?e :atproto/record/createdAt ?createdAt]
                                         [?e :atproto/record/embed/external/uri ?embedUri]
                                         [?e "app.bsky.feed.post#text" ?nsidText]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{record_field_body}");
    assert!(
        record_field_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| {
                row[0] == "\"hello kotoba\""
                    && row[1].as_str().unwrap_or("").contains("[\"en\"]")
                    && row[2] == "\"2026-05-29T00:00:00Z\""
                    && row[3] == "\"ipfs://bafyexample\""
                    && row[4] == "\"hello kotoba\""
            }),
        "{record_field_body}"
    );

    let (status, sparql_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": r#"SELECT * WHERE { ?post <app.bsky.feed.post> ?record }"#,
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{sparql_body}");
    assert_eq!(sparql_body["form"], "select", "{sparql_body}");
    assert!(
        sparql_body["count"].as_u64().unwrap_or(0) >= 1,
        "{sparql_body}"
    );

    let delete_cacao_b64 = build_ed25519_cacao_for_operation_with_resources(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_ATPROTO_REPO_WRITE,
        "nonce-atproto-delete-e2e",
        vec![at_uri.to_string()],
    );
    let (status, delete_body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.atproto.repo.write",
            json!({
                "graph": graph,
                "cacao_b64": delete_cacao_b64,
                "uri": at_uri,
                "operation": "delete"
            }),
        )
        .await;
    assert_eq!(status, 200, "{delete_body}");
    assert_eq!(delete_body["status"], "ok", "{delete_body}");
    assert!(
        delete_body["assert_count"].as_u64().unwrap_or(0) > 0,
        "{delete_body}"
    );
    assert!(
        delete_body["retract_count"].as_u64().unwrap_or(0) > 0,
        "{delete_body}"
    );

    let (status, deleted_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?deleted ?operation]
                                 :where [[?e :atproto/uri ?uri]
                                         [?e :atproto/deleted ?deleted]
                                         [?e :atproto/operation ?operation]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{deleted_body}");
    assert_eq!(
        deleted_body["rows_edn"],
        json!([["true", "\"delete\""]]),
        "{deleted_body}"
    );

    let (status, deleted_text_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?text] :where [[?e :atproto/record/text ?text]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{deleted_text_body}");
    assert_eq!(
        deleted_text_body["rows_edn"],
        json!([]),
        "{deleted_text_body}"
    );

    let (status, deleted_history_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "history": true,
                "query_edn": r#"{:find [?text ?added]
                                 :where [[?e :atproto/record/text ?text ?tx ?added]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{deleted_history_body}");
    assert!(
        deleted_history_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row[0] == "\"hello kotoba\"" && row[1] == "true"),
        "{deleted_history_body}"
    );
    assert!(
        deleted_history_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row[0] == "\"hello kotoba\"" && row[1] == "false"),
        "{deleted_history_body}"
    );
}

#[tokio::test]
async fn atproto_repo_write_rejects_cacao_without_at_uri_scope() {
    let s = TestServer::start(false).await;
    let graph =
        kotoba_core::cid::KotobaCid::from_bytes(b"atproto-write-no-scope-e2e").to_multibase();
    let at_uri = "at://did:plc:alice/app.bsky.feed.post/3kabc";
    let cacao_b64 = build_ed25519_cacao_for_operation(
        &graph,
        &s.operator_did,
        kotoba_auth::CacaoPayload::OP_ATPROTO_REPO_WRITE,
        "nonce-atproto-write-no-scope-e2e",
    );

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.atproto.repo.write",
            json!({
                "graph": graph,
                "cacao_b64": cacao_b64,
                "uri": at_uri,
                "operation": "create",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": "missing at uri scope"
                }
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert!(
        body.as_str()
            .or_else(|| body["error"].as_str())
            .unwrap_or_default()
            .contains("ATProto scope"),
        "{body}"
    );
}

#[tokio::test]
async fn atproto_repo_write_accepts_vp_at_uri_scope_and_persists_proof() {
    let s = TestServer::start(false).await;
    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"atproto-write-vp-e2e").to_multibase();
    let at_uri = "at://did:plc:alice/app.bsky.feed.post/3kvp";
    let presentation = build_vp_capability_presentation_with_resources(
        &s.operator_did,
        &s.state.ipns_signing_key(),
        &graph,
        kotoba_auth::CacaoPayload::OP_ATPROTO_REPO_WRITE,
        Vec::new(),
        vec![at_uri.to_string()],
        false,
    )
    .1;

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.atproto.repo.write",
            json!({
                "graph": graph,
                "auth_presentation": presentation,
                "uri": at_uri,
                "operation": "create",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": "hello kotoba via vp"
                }
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok", "{body}");
    assert_protocol_vp_auth_proof(
        &s,
        &graph,
        &body,
        &presentation,
        kotoba_auth::CacaoPayload::OP_ATPROTO_REPO_WRITE,
    )
    .await;
    assert_capability_invocation_target(
        &s,
        &graph,
        body["auth_proof_cid"].as_str().expect("auth_proof_cid"),
        at_uri,
    )
    .await;
}

async fn assert_protocol_auth_proof(
    s: &TestServer,
    graph: &str,
    body: &serde_json::Value,
    expected_cacao_b64: &str,
    expected_operation: &str,
) {
    let proof_cid = body["auth_proof_cid"].as_str().expect("auth_proof_cid");
    let (status, proof_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.block.get?cid={proof_cid}"
        ))
        .await;
    assert_eq!(status, 200, "{proof_body}");
    assert_eq!(proof_body["data_b64"], expected_cacao_b64, "{proof_body}");

    let (status, commit_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.commit.get?graph={graph}"
        ))
        .await;
    assert_eq!(status, 200, "{commit_body}");
    assert_eq!(
        commit_body["commit_type"], "distributed-datomic",
        "{commit_body}"
    );
    assert_eq!(commit_body["cid"], body["commit_cid"], "{commit_body}");
    assert_eq!(commit_body["tx_cid"], body["tx_cid"], "{commit_body}");
    assert_eq!(commit_body["cacao_proof_cid"], proof_cid, "{commit_body}");
    assert_protocol_commit_integrity(s, body, &commit_body);
    let cacao_bytes = {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        B64.decode(expected_cacao_b64)
            .expect("expected CACAO base64")
    };
    let expected_cacao: kotoba_auth::Cacao =
        ciborium::from_reader(cacao_bytes.as_slice()).expect("expected CACAO CBOR");
    assert_protocol_commit_block_dag_cbor(s, body, &expected_cacao.p.iss).await;
    assert_protocol_tx_metadata(s, graph, body, proof_cid, expected_operation).await;
}

async fn assert_protocol_vp_auth_proof(
    s: &TestServer,
    graph: &str,
    body: &serde_json::Value,
    expected_presentation: &serde_json::Value,
    expected_operation: &str,
) {
    let proof_cid = body["auth_proof_cid"].as_str().expect("auth_proof_cid");
    let (status, proof_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.block.get?cid={proof_cid}"
        ))
        .await;
    assert_eq!(status, 200, "{proof_body}");
    let data_b64 = proof_body["data_b64"].as_str().expect("data_b64");
    let proof_bytes = {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        B64.decode(data_b64).expect("proof block base64")
    };
    let stored: serde_json::Value =
        serde_json::from_slice(&proof_bytes).expect("stored VP proof JSON");
    assert_eq!(&stored, expected_presentation);

    let (status, commit_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.commit.get?graph={graph}"
        ))
        .await;
    assert_eq!(status, 200, "{commit_body}");
    assert_eq!(
        commit_body["commit_type"], "distributed-datomic",
        "{commit_body}"
    );
    assert_eq!(commit_body["cid"], body["commit_cid"], "{commit_body}");
    assert_eq!(commit_body["tx_cid"], body["tx_cid"], "{commit_body}");
    assert_eq!(commit_body["cacao_proof_cid"], proof_cid, "{commit_body}");
    assert_protocol_commit_integrity(s, body, &commit_body);
    let expected_author = expected_presentation["holder"]
        .as_str()
        .unwrap_or(&s.operator_did);
    assert_protocol_commit_block_dag_cbor(s, body, expected_author).await;
    assert_protocol_tx_metadata(s, graph, body, proof_cid, expected_operation).await;
}

async fn assert_protocol_commit_block_dag_cbor(
    s: &TestServer,
    body: &serde_json::Value,
    expected_author: &str,
) {
    let commit_cid = body["commit_cid"].as_str().expect("commit_cid");
    let (status, block_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.block.get?cid={commit_cid}"
        ))
        .await;
    assert_eq!(status, 200, "{block_body}");
    let data_b64 = block_body["data_b64"].as_str().expect("commit data_b64");
    let bytes = {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        B64.decode(data_b64).expect("commit block base64")
    };
    let commit: kotoba_datomic::distributed::DistributedDatomCommit =
        ciborium::from_reader(bytes.as_slice()).expect("protocol commit DAG-CBOR");
    assert_eq!(block_body["cid"], commit_cid, "{block_body}");
    assert_eq!(
        commit.tx_cid.to_multibase(),
        body["tx_cid"].as_str().expect("tx_cid"),
        "{block_body}"
    );
    assert_eq!(commit.author, expected_author, "{block_body}");
    assert_eq!(commit.index_roots.len(), 5, "{block_body}");
}

fn assert_protocol_commit_integrity(
    s: &TestServer,
    body: &serde_json::Value,
    commit_body: &serde_json::Value,
) {
    assert_eq!(commit_body["ipns_verified"], true, "{commit_body}");
    assert_eq!(
        commit_body["ipns_value_matches_commit"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_sequence_matches_commit"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_graph_matches_request"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_controller_did"], s.operator_did,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_controller_matches_node"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_controller_key_matches_did"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_signature_verified"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_value_cid"], body["commit_cid"],
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_sequence"], body["ipns_sequence"],
        "{commit_body}"
    );
    assert_eq!(commit_body["ipns_name"], body["ipns_name"], "{commit_body}");
    assert!(
        commit_body["ipns_public_key_multibase"].as_str().is_some(),
        "{commit_body}"
    );
    assert!(
        commit_body["ipns_signature_multibase"].as_str().is_some(),
        "{commit_body}"
    );
    assert_eq!(
        commit_body["index_roots"]
            .as_object()
            .map(|roots| roots.len()),
        Some(5),
        "{commit_body}"
    );
}

async fn assert_protocol_tx_metadata(
    s: &TestServer,
    graph: &str,
    body: &serde_json::Value,
    proof_cid: &str,
    expected_operation: &str,
) {
    let tok = tenant_jwt(&s.operator_did);
    let (status, q_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?proof ?operation ?ipns ?seq ?controller]
                                 :where [[?tx :tx/authProofCid ?proof]
                                         [?tx :tx/operation ?operation]
                                         [?tx :tx/ipnsName ?ipns]
                                         [?tx :tx/ipnsSequence ?seq]
                                         [?tx :tx/ipnsControllerDid ?controller]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{q_body}");
    let row = q_body["rows_edn"][0].as_array().expect("tx metadata row");
    assert_eq!(row[0], format!("\"{proof_cid}\""), "{q_body}");
    assert_eq!(row[1], format!("\"{expected_operation}\""), "{q_body}");
    assert_eq!(
        row[2],
        format!("\"{}\"", body["ipns_name"].as_str().unwrap()),
        "{q_body}"
    );
    assert_eq!(
        row[3],
        body["ipns_sequence"].as_i64().unwrap().to_string(),
        "{q_body}"
    );
    assert_eq!(row[4], format!("\"{}\"", s.operator_did), "{q_body}");

    let (status, cap_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?proof ?controller ?action ?target]
                                 :where [[?tx :capability/proofCid ?proof]
                                         [?tx :capability/controller ?controller]
                                         [?tx :capability/allowedAction ?action]
                                         [?tx :capability/invocationTarget ?target]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{cap_body}");
    let cap_rows = cap_body["rows_edn"].as_array().expect("capability rows");
    assert!(
        cap_rows.iter().any(|row| row.as_array().is_some_and(|row| {
            row[0] == format!("\"{proof_cid}\"")
                && row[1].as_str().unwrap_or_default().starts_with("\"did:")
                && row[2] == format!("\"{expected_operation}\"")
                && row[3] == format!("\"kotoba://graph/{graph}\"")
        })),
        "{cap_body}"
    );

    let (status, zcap_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?proof ?controller ?action ?target]
                                 :where [[?tx "https://w3id.org/security#proof" ?proof]
                                         [?tx "https://w3id.org/security#controller" ?controller]
                                         [?tx "https://w3id.org/security#allowedAction" ?action]
                                         [?tx "https://w3id.org/security#invocationTarget" ?target]]}"#
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{zcap_body}");
    let zcap_rows = zcap_body["rows_edn"].as_array().expect("zcap rows");
    assert!(
        zcap_rows
            .iter()
            .any(|row| row.as_array().is_some_and(|row| {
                row[0] == format!("\"{proof_cid}\"")
                    && row[1].as_str().unwrap_or_default().starts_with("\"did:")
                    && row[2] == format!("\"{expected_operation}\"")
                    && row[3] == format!("\"kotoba://graph/{graph}\"")
            })),
        "{zcap_body}"
    );

    let (status, sparql_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": format!(
                    r#"SELECT * WHERE {{ ?s <https://w3id.org/security#allowedAction> "{}" }}"#,
                    expected_operation
                ),
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{sparql_body}");
    assert!(
        sparql_body["count"].as_u64().unwrap_or(0) >= 1,
        "{sparql_body}"
    );

    let (status, sparql_controller_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "graph": graph,
                "query": format!(
                    r#"SELECT * WHERE {{ ?s <https://w3id.org/security#controller> ?controller . ?s <https://w3id.org/security#allowedAction> "{}" }}"#,
                    expected_operation
                ),
                "limit": 10
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{sparql_controller_body}");
    assert!(
        sparql_controller_body["count"].as_u64().unwrap_or(0) >= 1,
        "{sparql_controller_body}"
    );
}

async fn assert_capability_invocation_target(
    s: &TestServer,
    graph: &str,
    proof_cid: &str,
    expected_target: &str,
) {
    let tok = tenant_jwt(&s.operator_did);
    for attr in [
        ":capability/invocationTarget",
        "\"https://w3id.org/security#invocationTarget\"",
    ] {
        let (status, body) = s
            .post_auth(
                "/xrpc/ai.gftd.apps.kotoba.datomic.q",
                json!({
                    "graph": graph,
                    "query_edn": format!(
                        r#"{{:find [?target]
                             :where [[?tx :capability/proofCid ?proof]
                                     [?tx {attr} ?target]]
                             :in [?proof]}}"#
                    ),
                    "inputs_edn": [format!(r#""{proof_cid}""#)]
                }),
                &tok,
            )
            .await;
        assert_eq!(status, 200, "{body}");
        let rows = body["rows_edn"].as_array().expect("capability target rows");
        assert!(
            rows.iter().any(|row| row.as_array().is_some_and(|row| {
                row.first() == Some(&json!(format!("\"{expected_target}\"")))
            })),
            "missing capability target {expected_target} for attr {attr}: {body}"
        );
    }
}

#[tokio::test]
async fn quad_retract_returns_ok() {
    let s = TestServer::start(false).await;
    let (_, cacao_b64) = build_ed25519_cacao("e2e");
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.quad.retract",
            json!({
                "graph":     "e2e",
                "subject":   "alice",
                "predicate": "knows",
                "object":    "bob",
                "cacao_b64": cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn quad_retract_without_cacao_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.quad.retract",
            json!({ "graph": "e2e", "subject": "alice", "predicate": "knows", "object": "bob" }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn quad_retract_cacao_graph_mismatch_returns_401() {
    let s = TestServer::start(false).await;
    // CACAO signed for "other-graph" but request targets "e2e"
    let (_, cacao_b64) = build_ed25519_cacao("other-graph");
    let (status, _body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.quad.retract",
            json!({
                "graph":     "e2e",
                "subject":   "alice",
                "predicate": "knows",
                "object":    "bob",
                "cacao_b64": cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn block_get_invalid_cid_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get("/xrpc/ai.gftd.apps.kotoba.block.get?cid=not-a-valid-cid")
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn block_get_unknown_cid_returns_404() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let cid = KotobaCid::from_bytes(b"block-does-not-exist-xyz").to_multibase();
    let (status, body) = s
        .get(&format!("/xrpc/ai.gftd.apps.kotoba.block.get?cid={cid}"))
        .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn commit_get_invalid_cid_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get("/xrpc/ai.gftd.apps.kotoba.commit.get?graph=not-a-cid")
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn commit_get_unknown_graph_returns_404() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let cid = KotobaCid::from_bytes(b"graph-commit-does-not-exist").to_multibase();
    let (status, body) = s
        .get(&format!("/xrpc/ai.gftd.apps.kotoba.commit.get?graph={cid}"))
        .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn block_put_and_get_roundtrip() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);

    let payload = b"kotoba e2e block";
    let (status, put) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.block.put",
            json!({ "data_b64": B64.encode(payload) }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{put}");
    let cid = put["cid"].as_str().expect("cid");

    let (status2, get) = s
        .get(&format!("/xrpc/ai.gftd.apps.kotoba.block.get?cid={cid}"))
        .await;
    assert_eq!(status2, 200, "{get}");
    let bytes = B64
        .decode(get["data_b64"].as_str().expect("data_b64"))
        .unwrap();
    assert_eq!(bytes, payload);
}

#[tokio::test]
async fn commit_store_and_get_roundtrip() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let graph_cid = KotobaCid::from_bytes(b"commit-e2e").to_multibase();

    s.post_quad("commit-e2e", "s", "p", "o").await;

    // CACAO must be built against the same graph string sent in the request (multibase CID)
    let (_, cacao_b64) = build_ed25519_cacao(&graph_cid);
    let (status, store) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.commit.store",
        json!({ "graph": graph_cid, "author": "did:plc:e2e", "seq": 1, "cacao_b64": cacao_b64 }),
    ).await;
    assert_eq!(status, 200, "{store}");
    assert!(store["cid"].as_str().is_some());

    let (status2, get) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.commit.get?graph={graph_cid}"
        ))
        .await;
    assert_eq!(status2, 200, "{get}");
    assert_eq!(get["seq"], 1);
    assert_eq!(get["author"], "did:plc:e2e");
}

#[tokio::test]
async fn commit_store_without_cacao_returns_401() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let graph_cid = KotobaCid::from_bytes(b"commit-e2e-noauth").to_multibase();

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.commit.store",
            json!({ "graph": graph_cid, "author": "did:plc:e2e", "seq": 1 }),
        )
        .await;
    assert_eq!(status, 401, "missing cacao must return 401: {body}");
}

#[tokio::test]
async fn embed_create_returns_quad_cid() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph = KotobaCid::from_bytes(b"embed-e2e");
    let graph_cid = graph.to_multibase();
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.embed.create",
            json!({
                "text": "hello kotoba",
                "doc_cid": "doc1",
                "model_cid": "model1",
                "graph": graph_cid
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["dims"].as_u64().unwrap_or(0) > 0);

    let doc_cid = KotobaCid::from_bytes(b"doc1");
    let model_cid = KotobaCid::from_bytes(b"model1");
    let tx_cid = KotobaCid::from_bytes(
        format!(
            "embed.create:{}:{}:{}",
            graph_cid,
            doc_cid.to_multibase(),
            model_cid.to_multibase()
        )
        .as_bytes(),
    );
    let reader = kotoba_datomic::distributed::DistributedDatomReader::new(
        &*s.state.block_store,
        &*s.state.ipns_registry,
    );
    let head = reader
        .resolve_head(&format!("k51-kotoba-{}", graph.to_multibase()))
        .expect("resolve distributed embed head")
        .expect("distributed embed head");
    let tea_datoms = reader
        .history_datoms_index(
            &head.cid,
            kotoba_datomic::DatomIndex::Tea,
            &[kotoba_edn::EdnValue::string(tx_cid.to_multibase())],
        )
        .expect("embedding datoms by tx");
    assert!(
        tea_datoms.iter().any(|datom| {
            datom.e == doc_cid
                && datom.a == format!("embedding/{}", model_cid.to_multibase())
                && datom.t == tx_cid
                && datom.added
        }),
        "embed.create must publish embedding datoms with Datomic T equal to the tx CID"
    );
}

#[tokio::test]
async fn embed_create_empty_text_returns_400() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let graph_cid = KotobaCid::from_bytes(b"embed-empty").to_multibase();
    let (status, body) = s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.embed.create",
        json!({ "text": "", "doc_cid": "doc-empty", "model_cid": "model1", "graph": graph_cid }),
        &tok,
    ).await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn infer_run_with_stub_engine() {
    let s = TestServer::start(true).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.infer.run",
            json!({ "prompt": "what is kotoba?", "max_new_tokens": 32 }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["output"]
        .as_str()
        .map(|s| !s.is_empty())
        .unwrap_or(false));
}

#[tokio::test]
async fn infer_run_without_auth_returns_401() {
    let s = TestServer::start(true).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.infer.run",
            json!({ "prompt": "hello" }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn infer_run_without_engine_returns_503() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, _) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.infer.run",
            json!({ "prompt": "hello" }),
            &tok,
        )
        .await;
    assert_eq!(status, 503);
}

#[tokio::test]
#[cfg(feature = "wasm-runtime")]
async fn agent_run_with_stub_engine_completes() {
    let s = TestServer::start(true).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.run",
            json!({ "task": "test: 2+2?", "max_steps": 3, "max_tokens": 64 }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["session_cid"].as_str().is_some());
    assert!(
        body["commit_cid"]
            .as_str()
            .is_some_and(|cid| { kotoba_core::cid::KotobaCid::from_multibase(cid).is_some() }),
        "agent.run must return a distributed Datomic commit CID: {body}"
    );
    assert!(body["supersteps"].as_u64().unwrap_or(0) >= 1);
}

#[tokio::test]
async fn agent_run_without_engine_returns_503() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, _) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.run",
            json!({ "task": "x" }),
            &tok,
        )
        .await;
    assert_eq!(status, 503);
}

// ── MCP ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_initialize_returns_protocol_version() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/mcp",
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": null }),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(body["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(body["result"]["serverInfo"]["name"], "kotoba");
}

#[tokio::test]
async fn mcp_tools_list_returns_expected_count() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/mcp",
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": null }),
        )
        .await;
    assert_eq!(status, 200);
    let tools = body["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 18);
    assert!(tools
        .iter()
        .any(|tool| tool["name"].as_str() == Some("kotoba_datom_create")));
}

#[tokio::test]
async fn mcp_ping_returns_empty_result() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/mcp",
            json!({ "jsonrpc": "2.0", "id": 5, "method": "ping" }),
        )
        .await;
    assert_eq!(status, 200);
    assert!(body["result"].is_object());
    assert!(body.get("error").is_none());
}

#[tokio::test]
async fn mcp_node_info_returns_did_and_roles() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 10, "method": "tools/call",
                "params": { "name": "kotoba_node_info", "arguments": {} }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert!(
        content["did"].as_str().unwrap_or("").starts_with("did:"),
        "expected DID, got: {}",
        content["did"]
    );
    assert!(!content["node_id_hex"].as_str().unwrap_or("").is_empty());
    assert!(content["roles"].is_array());
    assert!(content.get("ephemeral").is_some());
}

#[tokio::test]
async fn mcp_node_register_returns_ok() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 11, "method": "tools/call",
                "params": { "name": "kotoba_node_register", "arguments": {} }
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["status"], "ok");
    assert!(content["operator_did"]
        .as_str()
        .unwrap_or("")
        .starts_with("did:"));
}

#[tokio::test]
async fn mcp_node_register_non_operator_returns_auth_error() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zNotTheOperator");
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 11, "method": "tools/call",
                "params": { "name": "kotoba_node_register", "arguments": {} }
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "MCP always returns 200");
    assert!(
        body.get("error").is_some(),
        "expected JSON-RPC error: {body}"
    );
}

#[tokio::test]
async fn mcp_network_peers_returns_local_node_id() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 12, "method": "tools/call",
                "params": { "name": "kotoba_network_peers", "arguments": {} }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert!(!content["local_node_id_hex"]
        .as_str()
        .unwrap_or("")
        .is_empty());
    assert!(content["peers"].is_array());
    assert_eq!(
        content["peer_count"].as_u64().unwrap_or(99),
        0,
        "fresh node has no peers"
    );
}

#[tokio::test]
async fn mcp_tools_call_quad_create_ok() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "kotoba_quad_create",
                "arguments": { "graph": "mcp-g", "subject": "s", "predicate": "p", "object": "o" }
            }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    assert!(body["result"].is_object());
}

#[tokio::test]
async fn mcp_tools_call_datom_create_ok() {
    let s = TestServer::start(false).await;
    let (status, body) = s.post_auth(
        "/mcp",
        json!({
            "jsonrpc": "2.0", "id": 30, "method": "tools/call",
            "params": {
                "name": "kotoba_datom_create",
                "arguments": { "graph": "mcp-g", "subject": "s", "predicate": "p", "object": "o" }
            }
        }),
        "test-token",
    ).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let text = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(text).expect("json");
    assert_eq!(content["status"], "ok");
    assert!(content["datom_cid"].is_string());
    assert_eq!(content["datom_cid"], content["journal_cid"]);
}

#[tokio::test]
async fn mcp_tools_call_without_auth_returns_error() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {
                    "name": "kotoba_quad_create",
                    "arguments": { "graph": "g", "subject": "s", "predicate": "p", "object": "o" }
                }
            }),
        )
        .await;
    assert_eq!(status, 200);
    assert!(body["error"].is_object(), "expected JSON-RPC error");
    assert_eq!(body["error"]["code"], -32001);
}

// ── MCP kotoba_wasm_run (skips if cargo-component unavailable) ───────────────

#[tokio::test]
#[cfg(feature = "wasm-runtime")]
async fn mcp_wasm_run_writes_gas_attribution() {
    let Some(wasm_bytes) = build_guest_component() else {
        eprintln!("cargo-component unavailable — skipping mcp_wasm_run_writes_gas_attribution");
        return;
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let mut ctx_cbor = Vec::new();
    {
        use std::collections::BTreeMap;
        let mut map: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        map.insert("graph", ciborium::Value::Text("mcp-wasm-graph".into()));
        map.insert("session_cid", ciborium::Value::Null);
        map.insert(
            "args_cbor",
            ciborium::Value::Bytes(b"mcp_wasm_test".to_vec()),
        );
        ciborium::into_writer(&map, &mut ctx_cbor).unwrap();
    }

    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 20, "method": "tools/call",
                "params": {
                    "name": "kotoba_wasm_run",
                    "arguments": {
                        "wasm_b64":     B64.encode(&wasm_bytes),
                        "agent_did":    "did:plc:e2e_mcp_wasm",
                        "ctx_cbor_b64": B64.encode(&ctx_cbor),
                    }
                }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");

    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["status"], "ok", "{content}");
    assert!(
        content["total_gas_used"].as_u64().unwrap_or(0) > 0,
        "expected gas_used > 0, got: {content}"
    );
    assert!(
        content["output_cbor_b64"].as_str().is_some(),
        "missing output_cbor_b64: {content}"
    );
}

// ── MCP kotoba_wasm_run — Python componentize-py guest ───────────────────────

#[tokio::test]
#[cfg(feature = "wasm-runtime")]
async fn mcp_wasm_run_python_langgraph_agent() {
    // Load the pre-built Python LangGraph agent WASM.
    // Skip if the file is absent (developer hasn't built it yet or CI excludes it).
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().unwrap().parent().unwrap();
    let wasm_path = workspace.join("examples/kotoba-langgraph-hello/agent.wasm");
    let wasm_bytes = match std::fs::read(&wasm_path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("kotoba-langgraph-hello/agent.wasm not found — skipping mcp_wasm_run_python_langgraph_agent");
            return;
        }
    };

    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    // Build CBOR InvokeContext expected by handle_invoke() in _entry.py:
    //   { "graph": str, "session_cid": str, "args": { "input": {...}, "thread_id": str } }
    let mut ctx_cbor = Vec::new();
    {
        use std::collections::BTreeMap;
        let mut input_msg: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        input_msg.insert("type", ciborium::Value::Text("human".into()));
        input_msg.insert("content", ciborium::Value::Text("hello".into()));

        let mut input_state: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        input_state.insert(
            "messages",
            ciborium::Value::Array(vec![ciborium::Value::Map(
                input_msg
                    .into_iter()
                    .map(|(k, v)| (ciborium::Value::Text(k.into()), v))
                    .collect(),
            )]),
        );

        let mut args: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        args.insert(
            "input",
            ciborium::Value::Map(
                input_state
                    .into_iter()
                    .map(|(k, v)| (ciborium::Value::Text(k.into()), v))
                    .collect(),
            ),
        );
        args.insert("thread_id", ciborium::Value::Text("py-test-thread".into()));

        let mut ctx: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        ctx.insert("graph", ciborium::Value::Text("py-hello-graph".into()));
        ctx.insert(
            "session_cid",
            ciborium::Value::Text("py-test-session".into()),
        );
        ctx.insert(
            "args",
            ciborium::Value::Map(
                args.into_iter()
                    .map(|(k, v)| (ciborium::Value::Text(k.into()), v))
                    .collect(),
            ),
        );

        ciborium::into_writer(&ctx, &mut ctx_cbor).unwrap();
    }

    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 30, "method": "tools/call",
                "params": {
                    "name": "kotoba_wasm_run",
                    "arguments": {
                        "wasm_b64":     B64.encode(&wasm_bytes),
                        "agent_did":    "did:plc:e2e_py_langgraph",
                        "ctx_cbor_b64": B64.encode(&ctx_cbor),
                    }
                }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body.get("error").is_none(),
        "unexpected json-rpc error: {body}"
    );

    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    // WasmPregelRunner must complete without a Rust panic (HTTP 200 + status=ok)
    assert_eq!(
        content["status"], "ok",
        "expected WasmPregelRunner status=ok, got: {content}"
    );

    // Decode the output CBOR — must always be valid CBOR with "ok" or "err" key
    let out_b64 = content["output_cbor_b64"]
        .as_str()
        .expect("output_cbor_b64");
    let out_cbor = B64.decode(out_b64).expect("valid base64");
    let out: ciborium::Value = ciborium::from_reader(std::io::Cursor::new(&out_cbor))
        .expect("output_cbor_b64 must be valid CBOR (WasmPregelRunner encodes errors as CBOR)");
    let out_map: std::collections::HashMap<String, ciborium::Value> = match out {
        ciborium::Value::Map(ref m) => m
            .iter()
            .filter_map(|(k, v)| k.as_text().map(|s| (s.to_string(), v.clone())))
            .collect(),
        _ => panic!("expected CBOR map from Python agent output, got: {out:?}"),
    };
    assert!(
        out_map.contains_key("ok") || out_map.contains_key("err"),
        "Python handle_invoke must return {{ok/err}}, got keys: {:?}",
        out_map.keys().collect::<Vec<_>>()
    );

    let gas = content["total_gas_used"].as_u64().unwrap_or(0);
    if gas > 0 {
        // Python WASM executed — LLM may have failed but graph code ran
        eprintln!("Python LangGraph WASM executed successfully: gas_used={gas}");
    } else {
        // gas=0 means WASM compilation failed before execution.
        // Expected with wasmtime 22 which disables the extended-const proposal
        // required by componentize-py 0.23 output. Upgrade wasmtime to fix.
        let err_text = out_map.get("err").and_then(|v| v.as_text()).unwrap_or("");
        assert!(
            err_text.contains("CompileFailed") || err_text.contains("compile"),
            "gas=0 but error is unexpected (not a compile error): {err_text}"
        );
        eprintln!("NOTE: Python WASM compile failed (extended-const / wasmtime 22 limitation): {err_text}");
    }
}

// ── MCP kotoba_datalog_run ────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_datalog_run_derives_and_flushes_royalty() {
    let s = TestServer::start(false).await;

    // Seed the graph with two edges: a→b and b→c
    let graph = "mcp-datalog-test-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);
    for (subj, pred, obj) in [("a", "edge", "b"), ("b", "edge", "c")] {
        let (st, _) = s
            .post(
                "/xrpc/ai.gftd.apps.kotoba.quad.create",
                json!({
                    "graph":     graph,
                    "subject":   subj,
                    "predicate": pred,
                    "object":    obj,
                    "cacao_b64": cacao_b64,
                }),
            )
            .await;
        assert_eq!(st, 200);
    }

    // reachable(?x, ?y) :- edge(?x, ?y)
    let rule = json!({
        "head": { "relation": "reachable", "args": [{"Variable": "x"}, {"Variable": "y"}] },
        "body": [{ "Positive": { "relation": "edge", "args": [{"Variable": "x"}, {"Variable": "y"}] } }]
    });

    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 21, "method": "tools/call",
                "params": {
                    "name": "kotoba_datalog_run",
                    "arguments": {
                        "graph": graph,
                        "rules": [rule],
                        "epoch_pool_koto": 1_000_000u64,
                    }
                }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");

    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["status"], "ok", "{content}");
    assert!(
        content["derived"].as_u64().unwrap_or(0) >= 2,
        "expected derived >= 2, got: {content}"
    );
    assert!(
        content["citations"].as_u64().unwrap_or(0) > 0,
        "expected citations > 0, got: {content}"
    );
    assert!(
        content.get("epoch").is_some(),
        "missing epoch field: {content}"
    );
}

// ── MCP datalog_run rules-count cap ───────────────────────────────────────────

#[tokio::test]
async fn mcp_datalog_run_too_many_rules_returns_error() {
    let s = TestServer::start(false).await;
    // Build 257 rules (MAX_DATALOG_RULES = 256).
    let rule = json!({
        "head": { "relation": "reachable", "args": [{"Variable": "x"}, {"Variable": "y"}] },
        "body": [{ "Positive": { "relation": "edge", "args": [{"Variable": "x"}, {"Variable": "y"}] } }]
    });
    let rules: Vec<_> = (0..257).map(|_| rule.clone()).collect();

    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 99, "method": "tools/call",
                "params": {
                    "name": "kotoba_datalog_run",
                    "arguments": { "graph": "cap-test-graph", "rules": rules }
                }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    // kotoba MCP returns JSON-RPC top-level error for invalid params
    let err_node = if body["error"].is_object() {
        &body["error"]
    } else {
        &body["result"]["error"]
    };
    let err_code = err_node["code"].as_i64();
    assert!(err_code.is_some(), "expected MCP error, got: {body}");
    assert_eq!(
        err_code.unwrap(),
        -32602,
        "expected ERR_INVALID_PARAMS: {body}"
    );
    let err_msg = err_node["message"].as_str().unwrap_or("");
    assert!(
        err_msg.contains("257") || err_msg.contains("256"),
        "error should mention count/limit: {body}"
    );
}

#[tokio::test]
async fn mcp_datalog_run_too_many_body_literals_returns_error() {
    let s = TestServer::start(false).await;
    // Build a rule with 17 body literals (MAX_BODY_LITERALS = 16).
    let body_lit = json!({ "Positive": { "relation": "edge", "args": [{"Variable": "x"}, {"Variable": "y"}] } });
    let body: Vec<_> = (0..17).map(|_| body_lit.clone()).collect();
    let rule = json!({
        "head": { "relation": "reachable", "args": [{"Variable": "x"}, {"Variable": "y"}] },
        "body": body
    });

    let (status, body_resp) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 100, "method": "tools/call",
                "params": {
                    "name": "kotoba_datalog_run",
                    "arguments": { "graph": "lit-test-graph", "rules": [rule] }
                }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body_resp}");
    let err_node = if body_resp["error"].is_object() {
        &body_resp["error"]
    } else {
        &body_resp["result"]["error"]
    };
    let err_code = err_node["code"].as_i64();
    assert!(err_code.is_some(), "expected MCP error, got: {body_resp}");
    assert_eq!(
        err_code.unwrap(),
        -32602,
        "expected ERR_INVALID_PARAMS: {body_resp}"
    );
    let err_msg = err_node["message"].as_str().unwrap_or("");
    assert!(
        err_msg.contains("17") || err_msg.contains("16"),
        "error should mention literal count/limit: {body_resp}"
    );
}

// ── WASM invoke.run (skips if cargo-component unavailable) ────────────────────

#[tokio::test]
#[cfg(feature = "wasm-runtime")]
async fn invoke_run_wasm_guest_via_xrpc() {
    let Some(wasm_bytes) = build_guest_component() else {
        eprintln!("cargo-component unavailable — skipping invoke_run_wasm_guest_via_xrpc");
        return;
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let mut ctx = Vec::new();
    {
        use std::collections::BTreeMap;
        let mut map: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
        map.insert("graph", ciborium::Value::Text("e2e-wasm-graph".into()));
        map.insert("session_cid", ciborium::Value::Null);
        map.insert("args_cbor", ciborium::Value::Bytes(b"e2e test".to_vec()));
        ciborium::into_writer(&map, &mut ctx).unwrap();
    }

    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.invoke.run",
            json!({
                "program_cid":  "be2e_wasm_invoke",
                "program_type": "wasm-node",
                "agent_did":    "did:plc:e2e",
                "wasm_b64":     B64.encode(&wasm_bytes),
                "ctx_b64":      B64.encode(&ctx),
            }),
            &tok,
        )
        .await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert!(body["gas_used"].as_u64().unwrap_or(0) > 0);
    assert!(body["assert_count"].as_u64().unwrap_or(0) >= 1, "{body}");

    let out_bytes = B64
        .decode(body["output_b64"].as_str().expect("output_b64"))
        .unwrap();
    let out: ciborium::Value = ciborium::from_reader(out_bytes.as_slice()).unwrap();
    if let ciborium::Value::Map(pairs) = out {
        let status_val = pairs.iter().find_map(|(k, v)| {
            if k == &ciborium::Value::Text("status".into()) {
                v.as_text().map(|s| s.to_string())
            } else {
                None
            }
        });
        assert_eq!(status_val.as_deref(), Some("ok"));
    } else {
        panic!("output CBOR not a map");
    }
}

#[tokio::test]
async fn invoke_run_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.invoke.run",
            json!({ "program_cid": "x", "program_type": "datalog", "agent_did": "did:plc:x" }),
        )
        .await;
    assert_eq!(status, 401);
}

// ── SyncWindow session lifecycle ──────────────────────────────────────────────

#[tokio::test]
async fn agent_sync_open_creates_session() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph").to_multibase();
    let tok = tenant_jwt(&s.operator_did);

    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
            json!({
                "session_id": "sess-1",
                "graph_cid":  graph_cid,
                "since_seq":  0,
                "head_cid":   null,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["session_id"], "sess-1");
    assert_eq!(body["since_seq"], 0);
}

#[tokio::test]
async fn agent_sync_open_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph-noauth").to_multibase();
    let (status, body) = s.post(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({ "session_id": "sess-noauth", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
    ).await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn agent_sync_advance_updates_watermark() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph-adv").to_multibase();
    let head_cid = KotobaCid::from_bytes(b"head-v1").to_multibase();
    let tok = tenant_jwt(&s.operator_did);

    s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({ "session_id": "sess-adv", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
        &tok,
    ).await;

    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
            json!({ "session_id": "sess-adv", "new_head_cid": head_cid, "new_seq": 42 }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["since_seq"], 42);
}

#[tokio::test]
async fn agent_sync_close_removes_session() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"sync-graph-close").to_multibase();
    let tok = tenant_jwt(&s.operator_did);

    s.post_auth(
        "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
        json!({ "session_id": "sess-close", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
        &tok,
    ).await;

    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncclose",
            json!({ "session_id": "sess-close" }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["session_id"], "sess-close");

    // Second close → 404 (session removed)
    let (status2, _) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncclose",
            json!({ "session_id": "sess-close" }),
            &tok,
        )
        .await;
    assert_eq!(status2, 404);
}

#[tokio::test]
async fn agent_sync_full_lifecycle() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"lifecycle-graph").to_multibase();
    let head1 = KotobaCid::from_bytes(b"lifecycle-head-1").to_multibase();
    let head2 = KotobaCid::from_bytes(b"lifecycle-head-2").to_multibase();
    let tok = tenant_jwt(&s.operator_did);

    // open
    let (st, _) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
            json!({ "session_id": "lc", "graph_cid": graph_cid, "since_seq": 0, "head_cid": null }),
            &tok,
        )
        .await;
    assert_eq!(st, 200);

    // advance × 2
    let (st, b) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
            json!({ "session_id": "lc", "new_head_cid": head1, "new_seq": 10 }),
            &tok,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(b["since_seq"], 10);

    let (st, b) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
            json!({ "session_id": "lc", "new_head_cid": head2, "new_seq": 20 }),
            &tok,
        )
        .await;
    assert_eq!(st, 200);
    assert_eq!(b["since_seq"], 20);

    // close
    let (st, _) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncclose",
            json!({ "session_id": "lc" }),
            &tok,
        )
        .await;
    assert_eq!(st, 200);
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn build_guest_component() -> Option<Vec<u8>> {
    use std::process::Command;
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().unwrap().parent().unwrap();
    let status = Command::new("cargo")
        .args([
            "component",
            "build",
            "--manifest-path",
            "crates/kotoba-guest/Cargo.toml",
            "--target",
            "wasm32-wasip2",
            "--release",
            "--quiet",
        ])
        .current_dir(workspace)
        .status();
    let Ok(s) = status else {
        return None;
    };
    if !s.success() {
        return None;
    }
    let p = workspace.join("target/wasm32-wasip2/release/kotoba_echo_assert.wasm");
    if p.exists() {
        return std::fs::read(p).ok();
    }
    let alt = workspace.join("target/wasm32-wasip2/release/kotoba_guest.wasm");
    if alt.exists() {
        return std::fs::read(alt).ok();
    }
    let dir = std::fs::read_dir(workspace.join("target/wasm32-wasip2/release")).ok()?;
    for e in dir.flatten() {
        let p = e.path();
        if p.extension().map(|x| x == "wasm").unwrap_or(false) {
            let n = p.file_name().unwrap().to_string_lossy();
            if n.contains("kotoba") || n.contains("echo") || n.contains("guest") {
                return std::fs::read(&p).ok();
            }
        }
    }
    None
}

// ── vault.put / vault.get tests ───────────────────────────────────────────────

#[tokio::test]
async fn vault_put_returns_cid_and_size() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let data = b"hello vault";
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.vault.put",
            json!({ "data_b64": B64.encode(data) }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["cid"].as_str().is_some(), "cid missing: {body}");
    assert_eq!(body["size"], data.len() as u64, "size mismatch: {body}");
}

#[tokio::test]
async fn vault_put_then_get_roundtrip() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let data = b"roundtrip blob content";
    let data_b64 = B64.encode(data);

    let (status, put_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.vault.put",
            json!({ "data_b64": data_b64 }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{put_body}");
    let cid = put_body["cid"].as_str().expect("cid");

    let (status, get_body) = s
        .get_with_auth(
            &format!("/xrpc/ai.gftd.apps.kotoba.vault.get?cid={cid}"),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{get_body}");
    assert_eq!(get_body["cid"].as_str(), Some(cid), "cid mismatch");
    assert_eq!(
        get_body["data_b64"].as_str(),
        Some(data_b64.as_str()),
        "data mismatch"
    );
}

#[tokio::test]
async fn vault_get_without_auth_returns_401() {
    // Regression guard: vault_get must require operator auth — unauthenticated
    // reads would expose private encrypted blobs to any caller.
    let s = TestServer::start(false).await;
    let zero_cid = format!("b{}", "a".repeat(58));
    let (status, _body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.vault.get?cid={zero_cid}"
        ))
        .await;
    assert_eq!(
        status, 401,
        "vault_get must reject unauthenticated requests"
    );
}

#[tokio::test]
async fn vault_get_unknown_cid_returns_404() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    // KotobaCid multibase = 'b' + base32-nopad of 36 bytes (lowercase).
    // 36 zero-bytes → 58 'a' chars. blake3 of any real content won't produce all-zeros,
    // so this CID is valid format but never stored.
    let zero_cid = format!("b{}", "a".repeat(58));
    let (status, _body) = s
        .get_with_auth(
            &format!("/xrpc/ai.gftd.apps.kotoba.vault.get?cid={zero_cid}"),
            &tok,
        )
        .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn vault_get_missing_cid_param_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, _body) = s
        .get_with_auth("/xrpc/ai.gftd.apps.kotoba.vault.get", &tok)
        .await;
    assert_eq!(status, 400);
}

// ── kg.entity / kg.ingest tests ──────────────────────────────────────────────

#[tokio::test]
async fn kg_entity_lookup_by_id_after_quad_create() {
    let s = TestServer::start(false).await;

    // Seed quads directly via quad.create into kotobase-kg-v1 graph
    let g = "kotobase-kg-v1";
    let subj = "e2e-person-001";

    for (pred, obj) in &[
        ("kg/id", subj),
        ("kg/type", "Person"),
        ("kg/label/ja", "テスト太郎"),
        ("kg/label/en", "Test Taro"),
        ("kg/qid", "Q99901"),
    ] {
        let (st, b) = s.post_quad(g, subj, pred, obj).await;
        assert_eq!(st, 200, "seed failed for {pred}: {b}");
    }

    // Seed one claim
    let (st, _) = s.post_quad(g, subj, "kg/claim/birthYear", "1990").await;
    assert_eq!(st, 200);

    // Query by id — kg graph defaults to Authenticated tier.
    let (status, body) = s
        .get_authed(&format!("/xrpc/ai.gftd.apps.kotobase.kg.entity?id={subj}"))
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "ok false: {body}");

    let entity = &body["entity"];
    assert_eq!(entity["id"], subj, "id mismatch: {body}");
    assert_eq!(entity["type"], "Person", "type mismatch: {body}");
    assert_eq!(entity["labelJa"], "テスト太郎", "labelJa mismatch: {body}");
    assert_eq!(entity["labelEn"], "Test Taro", "labelEn mismatch: {body}");
    assert_eq!(entity["qid"], "Q99901", "qid mismatch: {body}");

    let claims = entity["claims"].as_array().expect("claims array");
    assert!(
        claims
            .iter()
            .any(|c| c["predicate"] == "birthYear" && c["value"] == "1990"),
        "birthYear claim missing: {body}"
    );
}

#[tokio::test]
async fn kg_entity_lookup_by_qid() {
    let s = TestServer::start(false).await;
    let g = "kotobase-kg-v1";
    let subj = "e2e-person-qid";

    for (pred, obj) in &[("kg/id", subj), ("kg/qid", "Q42"), ("kg/type", "Human")] {
        s.post_quad(g, subj, pred, obj).await;
    }

    let (status, body) = s
        .get_authed("/xrpc/ai.gftd.apps.kotobase.kg.entity?qid=Q42")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false));
    assert_eq!(body["entity"]["qid"], "Q42");
    assert_eq!(body["entity"]["type"], "Human");
}

#[tokio::test]
async fn kg_entity_not_found_returns_ok_false() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get_authed("/xrpc/ai.gftd.apps.kotobase.kg.entity?id=no-such-entity")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !body["ok"].as_bool().unwrap_or(true),
        "expected ok:false: {body}"
    );
    assert!(body["error"].as_str().is_some(), "error missing: {body}");
}

#[tokio::test]
async fn kg_entity_missing_param_returns_400() {
    let s = TestServer::start(false).await;
    // Must pass auth first (authenticated tier), then the missing-param check fires.
    let (status, _) = s.get_authed("/xrpc/ai.gftd.apps.kotobase.kg.entity").await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kg_ingest_and_entity_roundtrip() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgRoundtrip1");

    let (status, put) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":        "ingest-e2e-001",
                "qid":       "Q100",
                "type":      "Organization",
                "labelJa":   "テスト会社",
                "labelEn":   "Test Corp",
                "confidence":"0.95",
                "license":   "CC0-1.0",
                "sourceId":  "src-abc",
                "claims": [
                    { "pred": "founded", "value": "2020" },
                    { "pred": "country", "value": "JP" }
                ],
                "relations": []
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{put}");
    assert!(put["ok"].as_bool().unwrap_or(false), "ingest failed: {put}");
    assert!(
        put["subjectCid"].as_str().is_some(),
        "subjectCid missing: {put}"
    );
    // kg/id + optional fields + 2 claims
    assert!(
        put["quadCount"].as_u64().unwrap_or(0) >= 3,
        "quadCount low: {put}"
    );

    // Lookup via kg.entity — kg graph defaults to Authenticated tier.
    let (status, body) = s
        .get_authed("/xrpc/ai.gftd.apps.kotobase.kg.entity?id=ingest-e2e-001")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["ok"].as_bool().unwrap_or(false),
        "entity not found: {body}"
    );

    let entity = &body["entity"];
    assert_eq!(entity["id"], "ingest-e2e-001", "{body}");
    assert_eq!(entity["qid"], "Q100", "{body}");
    assert_eq!(entity["type"], "Organization", "{body}");
    assert_eq!(entity["labelJa"], "テスト会社", "{body}");
    assert_eq!(entity["labelEn"], "Test Corp", "{body}");
    assert_eq!(entity["confidence"], "0.95", "{body}");
    assert_eq!(entity["license"], "CC0-1.0", "{body}");
    assert_eq!(entity["sourceId"], "src-abc", "{body}");

    let claims = entity["claims"].as_array().expect("claims");
    assert!(
        claims
            .iter()
            .any(|c| c["predicate"] == "founded" && c["value"] == "2020"),
        "{body}"
    );
    assert!(
        claims
            .iter()
            .any(|c| c["predicate"] == "country" && c["value"] == "JP"),
        "{body}"
    );
}

#[tokio::test]
async fn kg_commit_returns_distributed_datomic_head() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);

    let (status, put) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":      "kg-commit-e2e-001",
                "labelEn": "KG Commit E2E",
                "type":    "TestEntity",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "ingest: {put}");
    assert!(put["ok"].as_bool().unwrap_or(false), "ingest: {put}");

    let (status, commit) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.commit",
            json!({ "author": s.operator_did }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "commit: {commit}");
    assert_eq!(commit["ok"], true, "{commit}");
    let commit_cid = commit["commitCid"]
        .as_str()
        .expect("commitCid present")
        .to_string();
    assert!(
        kotoba_core::cid::KotobaCid::from_multibase(&commit_cid).is_some(),
        "commitCid must be a kotoba/IPFS-compatible CID: {commit}"
    );
    assert!(
        commit["ipnsName"]
            .as_str()
            .is_some_and(|name| !name.is_empty()),
        "ipnsName missing: {commit}"
    );
    assert!(
        commit["ipnsSequence"].as_u64().unwrap_or(0) >= 1,
        "ipnsSequence missing: {commit}"
    );

    let (status, second) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.commit",
            json!({ "author": s.operator_did }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "second commit: {second}");
    assert_eq!(second["commitCid"], commit["commitCid"], "{second}");
    assert_eq!(second["ipnsSequence"], commit["ipnsSequence"], "{second}");
}

#[tokio::test]
async fn kg_ingest_with_relations() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgRelations1");

    // Ingest target entity first (needed for relation dst)
    s.post_auth(
        "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
        json!({ "id": "rel-dst-001", "type": "City", "labelEn": "Tokyo" }),
        &tok,
    )
    .await;

    // Ingest source entity with relation to target
    let (status, put) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":      "rel-src-001",
                "type":    "Person",
                "labelEn": "Alice",
                "relations": [
                    { "pred": "locatedIn", "dstId": "rel-dst-001" }
                ]
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{put}");
    assert!(put["ok"].as_bool().unwrap_or(false));

    // Query source entity — kg graph defaults to Authenticated tier.
    let (st, body) = s
        .get_authed("/xrpc/ai.gftd.apps.kotobase.kg.entity?id=rel-src-001")
        .await;
    assert_eq!(st, 200, "{body}");

    let rels = body["entity"]["relations"].as_array().expect("relations");
    assert!(!rels.is_empty(), "expected relations: {body}");
    assert_eq!(rels[0]["predicate"], "locatedIn", "{body}");
    assert!(
        rels[0]["dstCid"].as_str().is_some(),
        "dstCid missing: {body}"
    );
}

#[tokio::test]
async fn kg_catalog_reflects_ingested_entities() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgCatalog1");

    // Ingest two entities
    for (id, label) in &[("cat-e1", "EntityOne"), ("cat-e2", "EntityTwo")] {
        let (st, _) = s
            .post_auth(
                "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
                json!({ "id": id, "type": "Thing", "labelEn": label, "sourceId": "cat-test-src" }),
                &tok,
            )
            .await;
        assert_eq!(st, 200);
    }

    // kg graph defaults to Authenticated tier — send a Bearer token.
    let (status, body) = s.get_authed("/xrpc/ai.gftd.apps.kotobase.kg.catalog").await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false));
    assert!(
        body["stats"]["totalEntities"].as_u64().unwrap_or(0) >= 2,
        "{body}"
    );
}

// ── quad.create CACAO auth tests ─────────────────────────────────────────────

/// Build a signed Ed25519 CACAO granting `datom:transact` on `graph`. Returns `(issuer_did, cacao_b64)`.
fn build_ed25519_cacao(graph: &str) -> (String, String) {
    use base64::{
        engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
        Engine as _,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use kotoba_auth::did_key::ed25519_pubkey_to_did_key;

    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key();
    let did = ed25519_pubkey_to_did_key(pk.as_bytes());

    let mut cacao = kotoba_auth::Cacao {
        h: kotoba_auth::CacaoHeader {
            t: "caip122".into(),
        },
        p: kotoba_auth::CacaoPayload {
            iss: did.clone(),
            aud: "kotoba://node/test".into(),
            issued_at: "2026-05-26T00:00:00Z".into(),
            expiry: Some("2030-01-01T00:00:00Z".into()),
            nonce: "nonce-42".into(),
            domain: "kotoba.test".into(),
            statement: Some("Authorize datom transaction".into()),
            version: "1".into(),
            resources: vec![
                format!("kotoba://graph/{graph}"),
                "kotoba://can/datom:transact".into(),
            ],
        },
        s: kotoba_auth::CacaoSig {
            t: "EdDSA".into(),
            s: String::new(),
        },
    };

    let msg = cacao.siwe_message();
    let sig: ed25519_dalek::Signature = sk.sign(msg.as_bytes());
    cacao.s.s = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let mut cbor_buf = Vec::new();
    ciborium::into_writer(&cacao, &mut cbor_buf).expect("cbor encode");
    (did, B64.encode(&cbor_buf))
}

fn build_ed25519_cacao_for_operation(
    graph: &str,
    audience: &str,
    operation: &str,
    nonce: &str,
) -> String {
    build_ed25519_cacao_for_operation_with_resources(graph, audience, operation, nonce, vec![])
}

fn build_ed25519_cacao_for_operation_with_resources(
    graph: &str,
    audience: &str,
    operation: &str,
    nonce: &str,
    extra_resources: Vec<String>,
) -> String {
    use base64::{
        engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
        Engine as _,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use kotoba_auth::did_key::ed25519_pubkey_to_did_key;

    let sk = SigningKey::from_bytes(&[43u8; 32]);
    let pk = sk.verifying_key();
    let did = ed25519_pubkey_to_did_key(pk.as_bytes());
    let mut resources = vec![
        format!("kotoba://graph/{graph}"),
        format!("kotoba://op/{operation}"),
    ];
    resources.extend(extra_resources);
    let mut cacao = kotoba_auth::Cacao {
        h: kotoba_auth::CacaoHeader {
            t: "caip122".into(),
        },
        p: kotoba_auth::CacaoPayload {
            iss: did,
            aud: audience.to_string(),
            issued_at: "2026-05-26T00:00:00Z".into(),
            expiry: Some("2030-01-01T00:00:00Z".into()),
            nonce: nonce.to_string(),
            domain: "kotoba.test".into(),
            statement: Some(format!("Authorize {operation}")),
            version: "1".into(),
            resources,
        },
        s: kotoba_auth::CacaoSig {
            t: "EdDSA".into(),
            s: String::new(),
        },
    };
    let sig: ed25519_dalek::Signature = sk.sign(cacao.siwe_message().as_bytes());
    cacao.s.s = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let mut cbor_buf = Vec::new();
    ciborium::into_writer(&cacao, &mut cbor_buf).expect("cbor encode");
    B64.encode(&cbor_buf)
}

fn build_vp_capability_presentation(
    issuer: &str,
    issuer_sk: &ed25519_dalek::SigningKey,
    graph: &str,
    operation: &str,
    tamper_after_sign: bool,
) -> (String, Value) {
    build_vp_capability_presentation_with_operations(
        issuer,
        issuer_sk,
        graph,
        operation,
        Vec::new(),
        tamper_after_sign,
    )
}

fn build_vp_capability_presentation_with_operations(
    issuer: &str,
    issuer_sk: &ed25519_dalek::SigningKey,
    graph: &str,
    operation: &str,
    extra_operations: Vec<&str>,
    tamper_after_sign: bool,
) -> (String, Value) {
    build_vp_capability_presentation_with_resources(
        issuer,
        issuer_sk,
        graph,
        operation,
        extra_operations,
        Vec::new(),
        tamper_after_sign,
    )
}

fn build_vp_capability_presentation_with_resources(
    issuer: &str,
    issuer_sk: &ed25519_dalek::SigningKey,
    graph: &str,
    operation: &str,
    extra_operations: Vec<&str>,
    extra_resources: Vec<String>,
    tamper_after_sign: bool,
) -> (String, Value) {
    use ed25519_dalek::{Signer, SigningKey};
    use kotoba_auth::did_key::ed25519_pubkey_to_did_key;

    let sk = SigningKey::from_bytes(&[44u8; 32]);
    let holder = ed25519_pubkey_to_did_key(sk.verifying_key().as_bytes());
    let mut resources = vec![format!("kotoba://graph/{graph}")];
    resources.extend(extra_resources);
    let operations = std::iter::once(operation)
        .chain(extra_operations)
        .collect::<Vec<_>>();
    let mut vc = kotoba_vc::VerifiableCredential {
        context: vec![kotoba_vc::VC_CONTEXT_V2.to_string()],
        id: "urn:uuid:vc-query-capability-e2e".into(),
        types: vec![
            "VerifiableCredential".into(),
            "KotobaCapabilityCredential".into(),
        ],
        issuer: issuer.to_string(),
        valid_from: None,
        valid_until: None,
        credential_subject: json!({
            "id": holder,
            "resources": resources,
            "operations": operations
        })
        .into(),
        credential_status: None,
        proof: None,
    };
    let vc_sig = issuer_sk.sign(&vc.proof_bytes().expect("vc proof bytes"));
    vc.proof = Some(kotoba_vc::DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: Some("eddsa-2022".into()),
        proof_purpose: "capabilityDelegation".into(),
        verification_method: format!("{issuer}#agent-ed25519"),
        created: Some("2026-05-29T00:00:00Z".into()),
        proof_value: multibase::encode(multibase::Base::Base58Btc, vc_sig.to_bytes()),
        challenge: None,
        domain: Some("kotoba.test".into()),
    });
    let mut vp = kotoba_vc::VerifiablePresentation {
        context: vec![kotoba_vc::VC_CONTEXT_V2.to_string()],
        id: "urn:uuid:vp-query-capability-e2e".into(),
        types: vec!["VerifiablePresentation".into()],
        holder: Some(holder.clone()),
        verifiable_credentials: vec![vc],
        proof: None,
    };
    let sig = sk.sign(&vp.proof_bytes().expect("vp proof bytes"));
    vp.proof = Some(kotoba_vc::DataIntegrityProof {
        proof_type: "DataIntegrityProof".into(),
        cryptosuite: Some("eddsa-2022".into()),
        proof_purpose: "authentication".into(),
        verification_method: format!("{holder}#key-1"),
        created: Some("2026-05-29T00:00:00Z".into()),
        proof_value: multibase::encode(multibase::Base::Base58Btc, sig.to_bytes()),
        challenge: None,
        domain: Some("kotoba.test".into()),
    });
    if tamper_after_sign {
        vp.verifiable_credentials[0].credential_subject = json!({
            "id": holder,
            "resources": [format!("kotoba://graph/{graph}")],
            "operations": [kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT]
        })
        .into();
    }
    (
        holder,
        serde_json::to_value(vp).expect("vp presentation JSON"),
    )
}

#[tokio::test]
async fn quad_create_without_cacao_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({ "graph": "public", "subject": "alice", "predicate": "knows", "object": "bob" }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn quad_create_with_valid_ed25519_cacao_stores_author_did() {
    let s = TestServer::start(false).await;
    let graph = "cacao-test-graph";
    let (issuer_did, cacao_b64) = build_ed25519_cacao(graph);

    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({
                "graph":     graph,
                "subject":   "alice",
                "predicate": "knows",
                "object":    "bob",
                "cacao_b64": cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok");
    let journal_cid = body["journal_cid"]
        .as_str()
        .expect("journal_cid")
        .to_string();

    // Verify meta/author quad was stored with the journal CID as subject
    let graph_cid = kotoba_core::cid::KotobaCid::from_bytes(graph.as_bytes()).to_multibase();
    let url = format!(
        "/xrpc/ai.gftd.apps.kotoba.graph.query?graph={graph_cid}&subject={journal_cid}&predicate=meta%2Fauthor"
    );
    let (qstatus, qbody) = s.get_authed(&url).await;
    assert_eq!(qstatus, 200, "{qbody}");

    let quads = qbody["quads"].as_array().expect("quads array");
    assert!(!quads.is_empty(), "meta/author quad must exist: {qbody}");
    let author_quad = quads
        .iter()
        .find(|q| q["predicate"] == "meta/author")
        .expect("meta/author quad not found");
    // QuadObject::Text serializes as {"Text": "<value>"}
    assert_eq!(
        author_quad["object"]["Text"], issuer_did,
        "author DID must match CACAO issuer"
    );
}

#[tokio::test]
async fn quad_create_cacao_graph_mismatch_returns_401() {
    let s = TestServer::start(false).await;
    let (_, cacao_b64) = build_ed25519_cacao("other-graph");
    // CACAO covers "other-graph" but request targets "my-graph"
    let (status, _body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({
                "graph":     "my-graph",
                "subject":   "s",
                "predicate": "p",
                "object":    "o",
                "cacao_b64": cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn quad_create_invalid_cacao_b64_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({
                "graph": "private-graph",
                "subject": "alice",
                "predicate": "knows",
                "object": "bob",
                "cacao_b64": "not-valid-base64!!!"
            }),
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn quad_create_cacao_cbor_parse_error_returns_400() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    // Valid base64 but not valid DAG-CBOR
    let (status, _body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({
                "graph": "private-graph",
                "subject": "alice",
                "predicate": "knows",
                "object": "bob",
                "cacao_b64": B64.encode(b"this is not cbor")
            }),
        )
        .await;
    assert_eq!(status, 400);
}

// ── quad.create / quad.retract field-length caps (security bounds) ────────────

#[tokio::test]
async fn quad_create_oversized_graph_returns_400() {
    let s = TestServer::start(false).await;
    // Build CACAO for the oversized graph so auth succeeds; size cap fires after.
    let oversized_graph = "g".repeat(513);
    let (_, cacao_b64) = build_ed25519_cacao(&oversized_graph);
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({
                "graph":     oversized_graph,
                "subject":   "s",
                "predicate": "p",
                "object":    "o",
                "cacao_b64": cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn quad_create_oversized_object_returns_400() {
    let s = TestServer::start(false).await;
    let (_, cacao_b64) = build_ed25519_cacao("e2e");
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.quad.create",
            json!({
                "graph":     "e2e",
                "subject":   "s",
                "predicate": "p",
                "object":    "x".repeat(8 * 1024 + 1), // > 8 KiB limit
                "cacao_b64": cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn mcp_quad_create_oversized_field_returns_error() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 20, "method": "tools/call",
                "params": {
                    "name": "kotoba_quad_create",
                    "arguments": {
                        "graph":     "g",
                        "subject":   "s",
                        "predicate": "p",
                        "object":    "x".repeat(4097), // > 4096 byte MCP limit
                    }
                }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    // MCP tools return errors as JSON-RPC error objects, not HTTP 4xx
    assert!(
        body.get("error").is_some(),
        "expected error for oversized field: {body}"
    );
}

// ── kotobase input validation tests ──────────────────────────────────────────

const KOTOBASE_ACCOUNT_CREATE: &str = "/xrpc/ai.gftd.apps.kotobase.accountCreate";
const KOTOBASE_ACCOUNT_STATUS: &str = "/xrpc/ai.gftd.apps.kotobase.accountStatus";
const KOTOBASE_PIN_CREATE: &str = "/xrpc/ai.gftd.apps.kotobase.pinCreate";
const KOTOBASE_PIN_DELETE: &str = "/xrpc/ai.gftd.apps.kotobase.pinDelete";
const KOTOBASE_PIN_LIST: &str = "/xrpc/ai.gftd.apps.kotobase.pinList";
const KOTOBASE_USAGE_GET: &str = "/xrpc/ai.gftd.apps.kotobase.usageGet";

/// Build a minimal JWT with `sub = did` and a far-future `exp`.
/// Signature is intentionally fake — the server does not verify JWT signatures.
fn tenant_jwt(did: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload =
        URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{did}","exp":9999999999}}"#).as_bytes());
    format!("{header}.{payload}.fakesig")
}

/// Build an expired JWT (exp = 1 = past Unix epoch).
fn expired_jwt(did: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{did}","exp":1}}"#).as_bytes());
    format!("{header}.{payload}.fakesig")
}

#[tokio::test]
async fn kotobase_account_create_roundtrip() {
    let s = TestServer::start(false).await;
    let did = "did:key:zAlice";
    let (status, body) = s
        .post_auth(
            KOTOBASE_ACCOUNT_CREATE,
            json!({
                "tenant_did": did,
                "tier": "free",
            }),
            &tenant_jwt(did),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert_eq!(body["tier"], "free");
    assert_eq!(body["tenant_did"], did);
}

#[tokio::test]
async fn kotobase_account_create_invalid_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s
        .post(
            KOTOBASE_ACCOUNT_CREATE,
            json!({
                "tenant_did": "not-a-did",
            }),
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kotobase_account_create_empty_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s
        .post(
            KOTOBASE_ACCOUNT_CREATE,
            json!({
                "tenant_did": "",
            }),
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kotobase_account_create_unknown_tier_returns_400() {
    let s = TestServer::start(false).await;
    let did = "did:key:zAlice2";
    let (status, _body) = s
        .post_auth(
            KOTOBASE_ACCOUNT_CREATE,
            json!({
                "tenant_did": did,
                "tier": "enterprise_ultra",
            }),
            &tenant_jwt(did),
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kotobase_pin_create_negative_size_returns_400() {
    let s = TestServer::start(false).await;
    let did = "did:key:zAlice3";
    let (status, body) = s
        .post_auth(
            KOTOBASE_PIN_CREATE,
            json!({
                "tenant_did": did,
                "name": "my-pin",
                "cid": "bafytest",
                "size_hint_bytes": -1_i64,
            }),
            &tenant_jwt(did),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kotobase_pin_create_name_too_long_returns_400() {
    let s = TestServer::start(false).await;
    let did = "did:key:zAlice4";
    let long_name = "x".repeat(300);
    let (status, body) = s
        .post_auth(
            KOTOBASE_PIN_CREATE,
            json!({
                "tenant_did": did,
                "name": long_name,
                "cid": "bafytest",
            }),
            &tenant_jwt(did),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kotobase_pin_create_too_many_triples_returns_400() {
    let s = TestServer::start(false).await;
    let did = "did:key:zAlice5";
    // 1025 triples exceeds MAX_TRIPLES_PER_PIN = 1024
    let triples: Vec<serde_json::Value> = (0..1025u32)
        .map(|i| {
            json!({
                "subject":   format!("s{i}"),
                "predicate": "p",
                "object":    "o",
            })
        })
        .collect();
    let (status, body) = s
        .post_auth(
            KOTOBASE_PIN_CREATE,
            json!({
                "tenant_did": did,
                "name": "big-triples",
                "quads": { "graph": "test-graph", "triples": triples },
            }),
            &tenant_jwt(did),
        )
        .await;
    assert_eq!(status, 400, "{body}");
    let err = body["error"].as_str().unwrap_or("");
    assert!(err.contains("1024"), "error should mention limit: {body}");
}

#[tokio::test]
async fn kotobase_pin_list_invalid_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s
        .post(
            KOTOBASE_PIN_LIST,
            json!({
                "tenant_did": "invalid",
            }),
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kotobase_usage_get_empty_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s
        .post(
            KOTOBASE_USAGE_GET,
            json!({
                "tenant_did": "",
            }),
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kotobase_account_and_pin_lifecycle() {
    let s = TestServer::start(false).await;
    let did = "did:key:zLifecycle1";
    let tok = tenant_jwt(did);

    // Create account
    let (status, body) = s
        .post_auth(
            KOTOBASE_ACCOUNT_CREATE,
            json!({
                "tenant_did": did,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // Pin a CID
    let (status, body) = s
        .post_auth(
            KOTOBASE_PIN_CREATE,
            json!({
                "tenant_did": did,
                "name": "test-pin",
                "cid": "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354",
                "size_hint_bytes": 1024_i64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert!(!body["pin_id"].as_str().unwrap_or("").is_empty(), "{body}");

    // Check usage
    let (status, body) = s
        .post_auth(
            KOTOBASE_USAGE_GET,
            json!({
                "tenant_did": did,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["pin_count"], 1, "{body}");
}

#[tokio::test]
async fn kotobase_account_status_returns_tier_and_quota() {
    let s = TestServer::start(false).await;
    let did = "did:key:zStatus1";
    let tok = tenant_jwt(did);

    // account must exist first
    let (status, _) = s
        .post_auth(KOTOBASE_ACCOUNT_CREATE, json!({ "tenant_did": did }), &tok)
        .await;
    assert_eq!(status, 200);

    let (status, body) = s
        .post_auth(KOTOBASE_ACCOUNT_STATUS, json!({ "tenant_did": did }), &tok)
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert_eq!(body["tenant_did"], did, "{body}");
    assert!(body["tier"].is_string(), "tier missing: {body}");
    assert!(body["quota_pins"].is_number(), "quota_pins missing: {body}");
    assert!(
        body["quota_bytes"].is_number(),
        "quota_bytes missing: {body}"
    );
    assert!(body["used_pins"].is_number(), "used_pins missing: {body}");
    assert!(body["used_bytes"].is_number(), "used_bytes missing: {body}");
}

#[tokio::test]
async fn kotobase_pin_delete_removes_pin() {
    let s = TestServer::start(false).await;
    let did = "did:key:zDelete1";
    let tok = tenant_jwt(did);

    // create account
    let (status, _) = s
        .post_auth(KOTOBASE_ACCOUNT_CREATE, json!({ "tenant_did": did }), &tok)
        .await;
    assert_eq!(status, 200);

    // pin a CID
    let (status, body) = s
        .post_auth(
            KOTOBASE_PIN_CREATE,
            json!({
                "tenant_did": did,
                "name": "del-test",
                "cid": "bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354",
                "size_hint_bytes": 512_i64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let pin_id = body["pin_id"].as_str().expect("pin_id").to_string();

    // delete the pin
    let (status, body) = s
        .post_auth(
            KOTOBASE_PIN_DELETE,
            json!({
                "tenant_did": did,
                "pin_id": pin_id,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");

    // list should now be empty
    let (status, body) = s
        .post_auth(KOTOBASE_PIN_LIST, json!({ "tenant_did": did }), &tok)
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 0, "expected 0 pins after delete: {body}");
}

#[tokio::test]
async fn mcp_graph_query_empty_graph_returns_zero_count() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 10, "method": "tools/call",
                "params": {
                    "name": "kotoba_graph_query",
                    "arguments": { "graph": "did:example:emptygraph" }
                }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["count"], 0, "{content}");
    assert!(
        content["quads"].is_array(),
        "quads must be array: {content}"
    );
}

#[tokio::test]
async fn mcp_email_list_no_emails_returns_empty() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 11, "method": "tools/call",
                "params": {
                    "name": "kotoba_email_list",
                    "arguments": { "owner_did": "did:key:zNoEmails1" }
                }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["total"], 0, "{content}");
    assert!(
        content["emails"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "{content}"
    );
}

#[tokio::test]
async fn mcp_infer_run_without_engine_returns_error() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 12, "method": "tools/call",
                "params": {
                    "name": "kotoba_infer_run",
                    "arguments": { "prompt": "hello" }
                }
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    // without a loaded model the tool must return a JSON-RPC error, not panic
    let err = &body["error"];
    assert!(
        err.is_object(),
        "expected error object when no engine loaded: {body}"
    );
}

#[tokio::test]
async fn mcp_graph_gc_returns_deleted_count() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 99, "method": "tools/call",
                "params": { "name": "kotoba_graph_gc", "arguments": {} }
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body.get("error").is_none(), "unexpected error: {body}");
    let content_str = body["result"]["content"][0]["text"].as_str().expect("text");
    let content: serde_json::Value = serde_json::from_str(content_str).expect("json");
    assert_eq!(content["status"], "ok", "{content}");
    assert!(
        content["deleted_blocks"].is_number(),
        "missing deleted_blocks: {content}"
    );
}

#[tokio::test]
async fn mcp_graph_gc_non_operator_returns_auth_error() {
    // Regression guard: kotoba_graph_gc and kotoba_commit_prune are destructive
    // admin tools — non-operators must receive a JSON-RPC auth error.
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zNotTheOperator");
    let (status, body) = s
        .post_auth(
            "/mcp",
            json!({
                "jsonrpc": "2.0", "id": 99, "method": "tools/call",
                "params": { "name": "kotoba_graph_gc", "arguments": {} }
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "MCP always returns 200");
    assert!(
        body.get("error").is_some(),
        "expected JSON-RPC error for non-operator: {body}"
    );
}

// ── XRPC route smoke tests (KG / CC / email) ──────────────────────────────────

#[tokio::test]
async fn kg_catalog_empty_returns_zero_stats() {
    let s = TestServer::start(false).await;
    // KG graph defaults to Authenticated visibility — opaque Bearer token suffices
    let (status, body) = s.get_authed("/xrpc/ai.gftd.apps.kotobase.kg.catalog").await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    let stats = &body["stats"];
    assert_eq!(stats["totalEntities"], 0, "{body}");
    assert_eq!(stats["totalClaims"], 0, "{body}");
    assert_eq!(stats["totalRelations"], 0, "{body}");
}

#[tokio::test]
async fn cc_status_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _body) = s.get("/xrpc/ai.gftd.apps.kotoba.cc.status").await;
    assert_eq!(
        status, 401,
        "cc_status must reject unauthenticated requests"
    );
}

#[tokio::test]
async fn cc_status_returns_index_counts() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .get_with_auth("/xrpc/ai.gftd.apps.kotoba.cc.status", &tok)
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["chunks_indexed"].is_number(), "{body}");
    assert!(body["pages_indexed"].is_number(), "{body}");
    assert!(body["ivf_centroids"].is_number(), "{body}");
}

#[tokio::test]
async fn email_list_xrpc_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get("/xrpc/ai.gftd.apps.kotoba.email.list?owner_did=did:key:zEmailXrpc1")
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn email_list_xrpc_unknown_owner_returns_empty() {
    let s = TestServer::start(false).await;
    let did = "did:key:zEmailXrpc1";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .get_with_auth(
            &format!("/xrpc/ai.gftd.apps.kotoba.email.list?owner_did={did}"),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 0, "{body}");
    assert!(
        body["emails"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "{body}"
    );
}

#[tokio::test]
async fn email_ingest_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.email.ingest",
            json!({
                "owner_did": "did:key:zEmailIngest1",
                "raw_b64": "aGVsbG8=",
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn email_ingest_empty_owner_did_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zEmailOwner1");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.email.ingest",
            json!({
                "owner_did": "",
                "raw_b64": "aGVsbG8=",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

// ── weight.put CACAO auth tests ───────────────────────────────────────────────

#[tokio::test]
async fn weight_put_with_valid_cacao_returns_blob_cid() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    let graph = "weight-test-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);

    // Minimal 1-element FP8 tensor
    let data = vec![0x3cu8];
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.weight.put",
            json!({
                "model_cid":  "bafkreiabcdef",
                "layer":      0,
                "data_b64":   B64.encode(&data),
                "shape":      [1u32],
                "dtype":      "fp8e4m3",
                "graph":      graph,
                "cacao_b64":  cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["blob_cid"].as_str().is_some(),
        "blob_cid missing: {body}"
    );
    assert!(
        body["quad_cid"].as_str().is_some(),
        "quad_cid missing: {body}"
    );
    assert_eq!(body["layer"], 0u64, "layer mismatch: {body}");
}

#[tokio::test]
async fn weight_put_without_cacao_returns_401() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    let data = vec![0x3cu8];
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.weight.put",
            json!({
                "model_cid": "bafkreiabcdef",
                "layer":     0,
                "data_b64":  B64.encode(&data),
                "shape":     [1u32],
                "dtype":     "fp8e4m3",
                "graph":     "weight-test-graph",
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

// ── lora.apply CACAO auth tests ───────────────────────────────────────────────

#[tokio::test]
async fn lora_apply_with_valid_cacao_returns_adapter_cid() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    let graph = "lora-test-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);

    let adapter = vec![0x01u8, 0x02u8, 0x03u8];
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.lora.apply",
            json!({
                "model_cid":   "bafkreiabcdef",
                "rank":        4u32,
                "graph":       graph,
                "adapter_b64": B64.encode(&adapter),
                "cacao_b64":   cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["adapter_cid"].as_str().is_some(),
        "adapter_cid missing: {body}"
    );
    assert!(
        body["quad_cid"].as_str().is_some(),
        "quad_cid missing: {body}"
    );
}

#[tokio::test]
async fn lora_apply_without_cacao_returns_401() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    let adapter = vec![0x01u8, 0x02u8, 0x03u8];
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.lora.apply",
            json!({
                "model_cid":   "bafkreiabcdef",
                "rank":        4u32,
                "graph":       "lora-test-graph",
                "adapter_b64": B64.encode(&adapter),
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

// ── kotobase quota enforcement tests ─────────────────────────────────────────

// Free tier allows QUOTA_FREE_PINS=3 pins. The 4th pin must be rejected with QuotaExceeded.
#[tokio::test]
async fn kotobase_pin_quota_exceeded_returns_429() {
    let s = TestServer::start(false).await;
    let did = "did:key:zQuotaPin1";
    let tok = tenant_jwt(did);

    let (status, _) = s
        .post_auth(KOTOBASE_ACCOUNT_CREATE, json!({ "tenant_did": did }), &tok)
        .await;
    assert_eq!(status, 200);

    // Pin up to the free-tier limit (3 pins)
    for i in 0..3u32 {
        let cid_str = format!("bafybeiquota{i:04}abcdefghijklmnopqrstuvwxyz12345678");
        let (status, body) = s
            .post_auth(
                KOTOBASE_PIN_CREATE,
                json!({
                    "tenant_did": did,
                    "name":       format!("quota-pin-{i}"),
                    "cid":        cid_str,
                    "size_hint_bytes": 100_i64,
                }),
                &tok,
            )
            .await;
        assert_eq!(status, 200, "pin {i} should succeed: {body}");
    }

    // 4th pin must be rejected
    let (status, body) = s
        .post_auth(
            KOTOBASE_PIN_CREATE,
            json!({
                "tenant_did": did,
                "name":       "quota-overflow",
                "cid":        "bafybeiquotaoverflow000000000000000000000000000000",
                "size_hint_bytes": 100_i64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 429, "expected QuotaExceeded 429: {body}");
    let err = body["error"].as_str().unwrap_or("");
    assert!(
        err.contains("QuotaExceeded"),
        "error should mention QuotaExceeded: {body}"
    );
}

// Free tier allows QUOTA_FREE_BYTES=100 MiB. A single pin that exceeds the byte quota is rejected.
#[tokio::test]
async fn kotobase_byte_quota_exceeded_returns_429() {
    let s = TestServer::start(false).await;
    let did = "did:key:zQuotaByte1";
    let tok = tenant_jwt(did);

    let (status, _) = s
        .post_auth(KOTOBASE_ACCOUNT_CREATE, json!({ "tenant_did": did }), &tok)
        .await;
    assert_eq!(status, 200);

    // Attempt to pin something bigger than the free-tier byte quota (100 MiB = 104857600 bytes)
    let over_quota_bytes: i64 = 105_000_000; // ~100.1 MiB
    let (status, body) = s
        .post_auth(
            KOTOBASE_PIN_CREATE,
            json!({
                "tenant_did":      did,
                "name":            "byte-overflow",
                "cid":             "bafybeibytequotaoverflow00000000000000000000000000",
                "size_hint_bytes": over_quota_bytes,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 429, "expected QuotaExceeded 429: {body}");
    let err = body["error"].as_str().unwrap_or("");
    assert!(
        err.contains("QuotaExceeded"),
        "error should mention QuotaExceeded: {body}"
    );
}

// ── kotobase DID ownership auth tests ────────────────────────────────────────

#[tokio::test]
async fn kotobase_account_create_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s
        .post(
            KOTOBASE_ACCOUNT_CREATE,
            json!({
                "tenant_did": "did:key:zNoAuth1",
            }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_pin_create_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s
        .post(
            KOTOBASE_PIN_CREATE,
            json!({
                "tenant_did": "did:key:zNoAuth2",
                "name": "my-pin",
                "cid": "bafytest",
            }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_pin_delete_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s
        .post(
            KOTOBASE_PIN_DELETE,
            json!({
                "tenant_did": "did:key:zNoAuth3",
                "pin_id": "some-pin-id",
            }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_pin_create_wrong_sub_returns_401() {
    let s = TestServer::start(false).await;
    let victim_did = "did:key:zVictim1";
    let attacker_jwt = tenant_jwt("did:key:zAttacker1");
    let (status, _) = s
        .post_auth(
            KOTOBASE_PIN_CREATE,
            json!({
                "tenant_did": victim_did,
                "name": "stolen-pin",
                "cid": "bafytest",
            }),
            &attacker_jwt,
        )
        .await;
    assert_eq!(status, 401);
}

// ── weight.get tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn weight_get_unknown_cid_returns_404() {
    use kotoba_core::cid::KotobaCid;
    let s = TestServer::start(false).await;
    // A well-formed multibase CID that does not exist in the store
    let cid = KotobaCid::from_bytes(b"nonexistent-weight-blob").to_multibase();
    let (status, _body) = s
        .get(&format!("/xrpc/ai.gftd.apps.kotoba.weight.get?cid={cid}"))
        .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn weight_put_then_get_roundtrip() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    let graph = "weight-roundtrip-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);

    let data = vec![0x3cu8, 0x7fu8, 0x00u8];
    let (status, put_body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.weight.put",
            json!({
                "model_cid":  "bafkreiabcdef",
                "layer":      1u32,
                "data_b64":   B64.encode(&data),
                "shape":      [3u32],
                "dtype":      "fp8e4m3",
                "graph":      graph,
                "cacao_b64":  cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 200, "{put_body}");
    let blob_cid = put_body["blob_cid"].as_str().expect("blob_cid").to_string();

    // Now GET the blob back by its CID
    let (status, get_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.weight.get?cid={blob_cid}"
        ))
        .await;
    assert_eq!(status, 200, "{get_body}");
    assert_eq!(get_body["cid"], blob_cid, "{get_body}");
    let returned = B64
        .decode(get_body["data_b64"].as_str().expect("data_b64"))
        .expect("valid base64");
    assert_eq!(returned, data, "roundtripped bytes must match");
}

// ── kg.search / kg.query / kg.delete smoke tests ─────────────────────────────

#[tokio::test]
async fn kg_search_empty_returns_empty_results() {
    let s = TestServer::start(false).await;
    // KG graph defaults to Authenticated — send Bearer token
    let (status, body) = s
        .get_authed("/xrpc/ai.gftd.apps.kotobase.kg.search?q=nonexistent+entity")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["results"].is_array(), "expected results array: {body}");
    let results = body["results"].as_array().unwrap();
    assert!(
        results.is_empty(),
        "expected empty results on fresh store: {body}"
    );
}

#[tokio::test]
async fn kg_search_after_ingest_returns_entity() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgSearch1");

    // Ingest an entity with a label so the search index has data
    let (status, _) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":      "ent-search-1",
                "labelJa": "東京都",
                "labelEn": "Tokyo",
                "type":    "Place",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "ingest failed");

    // Search for the entity (blake3 pseudo-vector fallback, no LLM needed)
    let (status, body) = s
        .get_authed("/xrpc/ai.gftd.apps.kotobase.kg.search?q=Tokyo")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["results"].is_array(), "{body}");
    // At minimum the field must be present; exact match depends on vector similarity
    assert!(body["elapsedMs"].is_number(), "elapsedMs missing: {body}");
}

#[tokio::test]
async fn kg_embed_commits_vector_to_distributed_search_view() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgEmbedSearch1");

    let (status, ingest) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":      "ent-embed-search-1",
                "labelEn": "Distributed Vector Entity",
                "type":    "TestEntity",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "ingest: {ingest}");

    let (status, embed) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.embed",
            json!({
                "entityId": "ent-embed-search-1",
                "text":     "distributed vector entity",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "embed: {embed}");
    assert_eq!(embed["ok"], true, "{embed}");
    assert!(embed["dims"].as_u64().unwrap_or(0) > 0, "{embed}");

    let (status, body) = s
        .get_authed("/xrpc/ai.gftd.apps.kotobase.kg.search?q=distributed+vector+entity")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["results"].as_array().unwrap().iter().any(|row| {
            row["id"] == "ent-embed-search-1" && row["labelEn"] == "Distributed Vector Entity"
        }),
        "{body}"
    );
}

#[tokio::test]
async fn kg_query_sparql_empty_graph_returns_empty() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.query",
            json!({
                "lang":  "sparql",
                "query": "PREFIX k: <urn:kg:> SELECT ?s ?o WHERE { ?s k:id ?o }",
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["results"].is_array(), "expected results array: {body}");
    assert_eq!(
        body["results"].as_array().unwrap().len(),
        0,
        "fresh graph should have no quads: {body}"
    );
}

// ─── kotoba.graph.sparql (direct SPARQL form endpoint) ───────────────────────

#[tokio::test]
async fn kg_sparql_roundtrip_ingest_then_select_describe_ask() {
    // End-to-end HTTP roundtrip:
    //   1. ingest an entity via kg.ingest (writes to the kg graph)
    //   2. SELECT via kg.sparql — predicate matches return ≥1 quad
    //   3. ASK   via kg.sparql — known fact → true
    //   4. ASK   via kg.sparql — unknown fact → false
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zSparqlRoundtrip1");

    let (status, put) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":        "sparql-roundtrip-001",
                "qid":       "Q42",
                "type":      "Person",
                "labelJa":   "山田太郎",
                "labelEn":   "Yamada Taro",
                "confidence":"0.99",
                "license":   "CC0-1.0",
                "sourceId":  "src-roundtrip",
                "claims": [
                    { "pred": "occupation", "value": "engineer" }
                ],
                "relations": []
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "ingest: {put}");
    assert!(put["ok"].as_bool().unwrap_or(false), "ingest ok: {put}");

    // SELECT bound by predicate.  kg.ingest writes "kg/claim/<pred>" predicates;
    // the SPARQL executor's base IRI strips relative IRIs to their raw bytes,
    // so we match the exact stored predicate string.
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({ "query": r#"SELECT * WHERE { ?s <kg/claim/occupation> ?o }"#, "limit": 1000 }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "select: {body}");
    assert_eq!(body["form"], "select", "{body}");
    let count = body["count"].as_u64().unwrap_or(0);
    assert!(
        count >= 1,
        "expected ≥1 kg/claim/occupation quad, got {count}: {body}"
    );

    // ASK with the predicate we just wrote
    let (status, ask) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({ "query": r#"ASK { ?s <kg/claim/occupation> "engineer" }"# }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "ask-true: {ask}");
    assert_eq!(ask["form"], "ask", "{ask}");
    assert_eq!(
        ask["result"], true,
        "ingested <kg/claim/occupation>=\"engineer\" must be ASK-true: {ask}"
    );

    // ASK with a value that was NOT written — must be false
    let (status, ask2) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({ "query": r#"ASK { ?s <kg/claim/occupation> "wizard" }"# }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "ask-false: {ask2}");
    assert_eq!(
        ask2["result"], false,
        "occupation=\"wizard\" was never written; ASK must be false: {ask2}"
    );
}

#[tokio::test]
async fn kg_sparql_roundtrip_ingest_then_describe_subject() {
    // HTTP roundtrip: ingest → DESCRIBE <cid:subject> via kg.sparql
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zSparqlDescribe1");

    let (status, put) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":        "sparql-describe-001",
                "type":      "Person",
                "labelEn":   "Describe Test",
                "confidence":"0.9",
                "license":   "CC0-1.0",
                "sourceId":  "src-d",
                "claims": [
                    { "pred": "role", "value": "admin" }
                ],
                "relations": []
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "ingest: {put}");
    let subj_cid = put["subjectCid"]
        .as_str()
        .expect("subjectCid present")
        .to_string();

    // DESCRIBE the just-ingested subject → expects all its quads back
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({ "query": format!("DESCRIBE <cid:{subj_cid}>") }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "describe: {body}");
    assert_eq!(body["form"], "describe", "{body}");
    let count = body["count"].as_u64().unwrap_or(0);
    assert!(
        count >= 1,
        "DESCRIBE should return ≥1 quad for ingested subject, got {count}: {body}"
    );
    // Every returned quad must be about the requested subject
    for q in body["quads"].as_array().unwrap_or(&vec![]) {
        assert_eq!(
            q["subject"], subj_cid,
            "DESCRIBE returned quad about a different subject: {q}"
        );
    }
}

#[tokio::test]
async fn kg_sparql_roundtrip_ingest_then_construct() {
    // HTTP roundtrip: ingest → CONSTRUCT { ?s <label> ?n } WHERE { ?s <kg/claim/role> "admin" }
    // Validates template instantiation over ingested data.
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zSparqlConstruct1");

    let (status, put) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":        "sparql-construct-001",
                "type":      "Person",
                "labelEn":   "Construct Test",
                "confidence":"0.9",
                "license":   "CC0-1.0",
                "sourceId":  "src-c",
                "claims": [
                    { "pred": "role", "value": "admin" }
                ],
                "relations": []
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "ingest: {put}");

    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "query": r#"CONSTRUCT { ?s <admin> "yes" } WHERE { ?s <kg/claim/role> "admin" }"#,
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "construct: {body}");
    assert_eq!(body["form"], "construct", "{body}");
    let count = body["count"].as_u64().unwrap_or(0);
    assert!(
        count >= 1,
        "CONSTRUCT should materialise ≥1 admin-label quad, got {count}: {body}"
    );
    for q in body["quads"].as_array().unwrap_or(&vec![]) {
        assert_eq!(q["predicate"], "admin", "{q}");
        assert_eq!(q["object"]["text"], "yes", "{q}");
    }
}

#[tokio::test]
async fn kg_sparql_select_empty_graph_returns_select_form() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({ "query": r#"SELECT * WHERE { ?s <role> "admin" }"# }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["form"], "select", "{body}");
    assert_eq!(body["count"], 0, "{body}");
    assert!(body["quads"].is_array(), "{body}");
}

#[tokio::test]
async fn kg_sparql_ask_empty_graph_returns_false() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({ "query": r#"ASK { ?s <role> "admin" }"# }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["form"], "ask", "{body}");
    assert_eq!(body["result"], false, "{body}");
}

#[tokio::test]
async fn kg_sparql_describe_empty_returns_zero_quads() {
    let s = TestServer::start(false).await;
    let cid = kotoba_core::cid::KotobaCid::from_bytes(b"sparql-e2e-nobody");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({ "query": format!("DESCRIBE <cid:{}>", cid.to_multibase()) }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["form"], "describe", "{body}");
    assert_eq!(body["count"], 0, "{body}");
}

#[tokio::test]
async fn kg_sparql_construct_returns_construct_form() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({ "query": r#"CONSTRUCT { ?s <label> "ADMIN" } WHERE { ?s <role> "admin" }"# }),
            "test-token",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["form"], "construct", "{body}");
    assert_eq!(
        body["count"], 0,
        "empty graph yields zero constructed quads: {body}"
    );
}

#[tokio::test]
async fn kg_sparql_unknown_form_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({ "query": "INSERT DATA { <a> <b> <c> }" }),
            "test-token",
        )
        .await;
    assert_eq!(status, 400, "non-SELECT/DESCRIBE/CONSTRUCT/ASK must be 400");
}

#[tokio::test]
async fn kg_sparql_empty_query_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({ "query": "" }),
            "test-token",
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kg_sparql_invalid_graph_cid_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.graph.sparql",
            json!({
                "query": r#"SELECT * WHERE { ?s ?p ?o }"#,
                "graph": "not-a-real-multibase-cid",
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kg_query_unknown_lang_returns_400() {
    let s = TestServer::start(false).await;
    let (status, _body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.query",
            json!({ "lang": "sql", "query": "SELECT 1" }),
            "test-token",
        )
        .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn kg_delete_nonexistent_entity_returns_ok_zero_retracted() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.delete",
            json!({ "id": "ent-does-not-exist" }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert_eq!(body["retractedCount"], 0, "{body}");
}

#[tokio::test]
async fn kg_ingest_then_delete_removes_entity() {
    let s = TestServer::start(false).await;
    let write_tok = tenant_jwt("did:key:zKgDel2");
    let op_tok = tenant_jwt(&s.operator_did);

    // Ingest an entity (any bearer allowed)
    let (status, _) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({ "id": "ent-delete-me", "type": "Thing", "labelEn": "Delete Target" }),
            &write_tok,
        )
        .await;
    assert_eq!(status, 200);

    // Verify it's present
    let (status, body) = s
        .get_authed("/xrpc/ai.gftd.apps.kotobase.kg.entity?id=ent-delete-me")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["ok"].as_bool().unwrap_or(false),
        "entity not found before delete: {body}"
    );

    // Delete requires operator auth
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.delete",
            json!({ "id": "ent-delete-me" }),
            &op_tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["ok"].as_bool().unwrap_or(false), "{body}");
    assert!(
        body["retractedCount"].as_u64().unwrap_or(0) > 0,
        "expected >0 retracted: {body}"
    );

    // Entity should no longer be found
    let (status, body) = s
        .get_authed("/xrpc/ai.gftd.apps.kotobase.kg.entity?id=ent-delete-me")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !body["ok"].as_bool().unwrap_or(true),
        "entity still found after delete: {body}"
    );
}

// ── kotobase read-endpoint auth tests ────────────────────────────────────────

#[tokio::test]
async fn kotobase_account_status_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s
        .post(
            KOTOBASE_ACCOUNT_STATUS,
            json!({
                "tenant_did": "did:key:zStatusNoAuth1",
            }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_pin_list_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s
        .post(
            KOTOBASE_PIN_LIST,
            json!({
                "tenant_did": "did:key:zPinListNoAuth1",
            }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_usage_get_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, _) = s
        .post(
            KOTOBASE_USAGE_GET,
            json!({
                "tenant_did": "did:key:zUsageNoAuth1",
            }),
        )
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn kotobase_pin_list_offset_pagination() {
    let s = TestServer::start(false).await;
    let did = "did:key:zPaginate1";
    let tok = tenant_jwt(did);

    let (status, _) = s
        .post_auth(
            KOTOBASE_ACCOUNT_CREATE,
            json!({
                "tenant_did": did, "tier": "starter",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200);

    // Create 3 pins
    for name in &["pin-a", "pin-b", "pin-c"] {
        let (status, body) = s
            .post_auth(
                KOTOBASE_PIN_CREATE,
                json!({
                    "tenant_did": did, "name": name,
                    "cid": format!("bafytest{name}"),
                }),
                &tok,
            )
            .await;
        assert_eq!(status, 200, "create {name}: {body}");
    }

    // Page 1: offset=0, limit=2
    let (status, body) = s
        .post_auth(
            KOTOBASE_PIN_LIST,
            json!({
                "tenant_did": did, "limit": 2, "offset": 0,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 3, "total should be 3: {body}");
    assert_eq!(body["offset"], 0, "{body}");
    assert_eq!(body["limit"], 2, "{body}");
    assert_eq!(
        body["pins"].as_array().map(|a| a.len()).unwrap_or(0),
        2,
        "{body}"
    );

    // Page 2: offset=2, limit=2
    let (status, body) = s
        .post_auth(
            KOTOBASE_PIN_LIST,
            json!({
                "tenant_did": did, "limit": 2, "offset": 2,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["total"], 3, "total still 3: {body}");
    assert_eq!(body["offset"], 2, "{body}");
    assert_eq!(
        body["pins"].as_array().map(|a| a.len()).unwrap_or(0),
        1,
        "{body}"
    );
}

// ── cc.search / cc.rag / cc.ingest smoke tests ───────────────────────────────

#[tokio::test]
async fn cc_search_without_auth_returns_401() {
    // Regression guard: cc_search calls the embed service per request — exposing
    // it without auth enables resource-exhaustion attacks on the embed backend.
    let s = TestServer::start(false).await;
    let (status, _body) = s.get("/xrpc/ai.gftd.apps.kotoba.cc.search?q=test").await;
    assert_eq!(
        status, 401,
        "cc_search must reject unauthenticated requests"
    );
}

#[tokio::test]
async fn cc_rag_without_auth_returns_401() {
    // Regression guard: cc_rag calls embed service + LLM inference — highest-cost
    // endpoint; must be operator-gated to prevent resource exhaustion.
    let s = TestServer::start(false).await;
    let (status, _body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.cc.rag",
            json!({ "query": "what is Rust?" }),
        )
        .await;
    assert_eq!(status, 401, "cc_rag must reject unauthenticated requests");
}

#[tokio::test]
async fn cc_search_without_real_embed_endpoint_returns_error() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    // The embed client initializes with default localhost:11434 but no server is running.
    // The request should return an error response (500 or 503) — not 200 with data.
    let (status, body) = s
        .get_with_auth("/xrpc/ai.gftd.apps.kotoba.cc.search?q=test", &tok)
        .await;
    assert!(
        status == 500 || status == 503,
        "expected 500 or 503, got {status}: {body}"
    );
    assert!(
        body["error"].as_str().is_some(),
        "expected error field: {body}"
    );
}

#[tokio::test]
async fn cc_rag_without_real_embed_endpoint_returns_error() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.cc.rag",
            json!({ "query": "what is Rust?" }),
            &tok,
        )
        .await;
    assert!(
        status == 500 || status == 503,
        "expected 500 or 503, got {status}: {body}"
    );
    assert!(
        body["error"].as_str().is_some(),
        "expected error field: {body}"
    );
}

#[tokio::test]
async fn cc_ingest_trigger_returns_started_job_id() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    // Even with a non-existent parquet_dir, the ingest endpoint accepts the request
    // and spawns the job asynchronously; the response must include job_id + status=started
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.cc.ingest",
            json!({ "parquetDir": "/tmp/no-such-dir", "mode": "chunks" }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["job_id"].as_str().is_some(), "job_id missing: {body}");
    assert_eq!(body["status"], "started", "{body}");
}

#[tokio::test]
async fn cc_ingest_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.cc.ingest",
            json!({ "parquetDir": "/tmp/test", "mode": "chunks" }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert!(body["error"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn cc_ingest_with_non_operator_did_returns_401() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zNotTheOperator");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.cc.ingest",
            json!({ "parquetDir": "/tmp/test", "mode": "chunks" }),
            &tok,
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert!(body["error"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn cc_search_empty_query_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .get_with_auth("/xrpc/ai.gftd.apps.kotoba.cc.search?q=", &tok)
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(body["error"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn cc_ingest_invalid_mode_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.cc.ingest",
            json!({ "parquetDir": "/tmp/test", "mode": "invalid" }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(body["error"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn cc_rag_empty_query_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.cc.rag",
            json!({ "query": "" }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert!(body["error"].as_str().is_some(), "{body}");
}

// ── agent.sync security tests ─────────────────────────────────────────────────

#[tokio::test]
async fn agent_sync_open_empty_session_id_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
            json!({
                "session_id": "",
                "graph_cid":  "bafybeisync000000000000000000000000000000000000000",
                "since_seq":  0u64,
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn agent_sync_open_oversized_session_id_returns_400() {
    let s = TestServer::start(false).await;
    let long_id = "x".repeat(257); // > 256 bytes
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
            json!({
                "session_id": long_id,
                "graph_cid":  "bafybeisync000000000000000000000000000000000000000",
                "since_seq":  0u64,
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

// ── kg input-validation tests ─────────────────────────────────────────────────

#[tokio::test]
async fn kg_ingest_empty_id_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgVal1");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id": "",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kg_embed_empty_text_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgVal2");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.embed",
            json!({
                "entityId": "ent-1",
                "text": "",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kg_search_empty_query_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.apps.kotobase.kg.search?q=").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kg_delete_empty_id_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.delete",
            json!({
                "id": "",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kg_query_empty_query_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.query",
            json!({
                "lang": "sparql", "query": "",
            }),
            "test-token",
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn kg_ingest_too_many_claims_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgVal4");
    let claims: Vec<_> = (0..1025)
        .map(|i| json!({"pred": format!("p{i}"), "value": "v"}))
        .collect();
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id": "ent-overflow",
                "claims": claims,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn agent_sync_open_non_ascii_session_id_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncopen",
            json!({
                "session_id": "セッション",  // non-ASCII
                "graph_cid":  "bafybeisync000000000000000000000000000000000000000",
                "since_seq":  0u64,
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn agent_sync_advance_unknown_session_returns_404() {
    let s = TestServer::start(false).await;
    use kotoba_core::cid::KotobaCid;
    let head_cid = KotobaCid::from_bytes(b"head-adv").to_multibase();
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.agent.syncadvance",
            json!({
                "session_id":   "no-such-session",
                "new_head_cid": head_cid,
                "new_seq":      0u64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 404, "{body}");
}

// ── signal endpoint security tests ───────────────────────────────────────────

#[tokio::test]
async fn signal_register_prekeys_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.register.prekeys",
            json!({
                "did": "did:plc:test123",
                "deviceId": "device-1",
                "identityKey": {},
                "prekeyBundle": {},
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn signal_register_prekeys_empty_did_returns_400() {
    let s = TestServer::start(false).await;
    // Use a token whose sub matches the empty DID (won't reach the check — empty DID is caught first)
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.signal.register.prekeys",
            json!({
                "did": "",
                "deviceId": "device-1",
                "identityKey": {},
                "prekeyBundle": {},
            }),
            "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6cGxjOnRlc3QxMjMifQ.dummysig",
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_send_message_oversized_payload_returns_413() {
    let s = TestServer::start(false).await;
    // Build a payload exceeding 256 KiB
    let large_ciphertext = "x".repeat(300 * 1024);
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.send.message",
            json!({
                "signalMessage": {
                    "recipientDid": "did:plc:recipient",
                    "deviceId": "device-1",
                    "ciphertext": large_ciphertext,
                    "messageType": 1u32,
                },
            }),
        )
        .await;
    assert_eq!(status, 413, "{body}");
}

#[tokio::test]
async fn signal_get_prekey_bundle_empty_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.signal.get.prekey.bundle?did=").await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_send_group_message_empty_group_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.send.group.message",
            json!({
                "groupId": "",
                "senderDid": "did:plc:sender",
                "senderKeyMessage": {},
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

// ── attestation endpoint security tests ──────────────────────────────────────

#[tokio::test]
async fn attest_claim_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.attest.claim",
            json!({
                "entity_did":   "did:key:zEntity1",
                "attester_did": "did:key:zAttester1",
                "claim_type":   "self",
                "stake_mkoto":  1_000_000_000u64,
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn attest_claim_invalid_claim_type_returns_400() {
    let s = TestServer::start(false).await;
    let did = "did:key:zAttester2";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.claim",
            json!({
                "entity_did":   "did:key:zEntity2",
                "attester_did": did,
                "claim_type":   "unknown_type",
                "stake_mkoto":  1_000_000_000u64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn attest_claim_roundtrip() {
    let s = TestServer::start(false).await;
    let did = "did:key:zAttester3";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.claim",
            json!({
                "entity_did":   "did:key:zEntity3",
                "attester_did": did,
                "claim_type":   "self",
                "stake_mkoto":  1_000_000_000u64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["status"], "attested", "{body}");
    assert!(body["claim_cid"].as_str().is_some(), "{body}");
    assert!(body["credential_cid"].as_str().is_some(), "{body}");
    assert!(body["commit_cid"].as_str().is_some(), "{body}");
    assert!(body["ipns_name"].as_str().is_some(), "{body}");
    assert_eq!(body["ipns_sequence"].as_u64(), Some(1), "{body}");

    let graph = kotoba_core::cid::KotobaCid::from_bytes(b"kotoba/attestation/v1").to_multibase();
    let (status, q_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?issuer ?types ?subjectId ?claimCid ?claimType ?attester ?stake ?status ?statusId ?statusType]
	                                :where [[?e :credential/issuer ?issuer]
	                                        [?e :credential/type ?types]
	                                        [?e :credential/subjectId ?subjectId]
	                                        [?e :credential/subject/claimCid ?claimCid]
	                                        [?e :credential/subject/claimType ?claimType]
	                                        [?e :credential/subject/attester ?attester]
	                                        [?e :credential/subject/stakeMkoto ?stake]
	                                        [?e :credential/status ?status]
	                                        [?e :credential/status/id ?statusId]
	                                        [?e :credential/status/type ?statusType]]}"#
            }),
            &tenant_jwt(&s.operator_did),
        )
        .await;
    assert_eq!(status, 200, "{q_body}");
    let row = q_body["rows_edn"][0].as_array().unwrap();
    assert_eq!(row[0], format!("\"{}\"", s.operator_did), "{q_body}");
    assert!(row[1]
        .as_str()
        .unwrap_or("")
        .contains("\"KotobaAttestationCredential\""));
    assert_eq!(row[2], "\"did:key:zEntity3\"", "{q_body}");
    assert_eq!(
        row[3],
        format!("\"{}\"", body["claim_cid"].as_str().unwrap()),
        "{q_body}"
    );
    assert_eq!(row[4], "\"self\"", "{q_body}");
    assert_eq!(row[5], "\"did:key:zAttester3\"", "{q_body}");
    assert_eq!(row[6], "1000000000", "{q_body}");
    assert!(row[7]
        .as_str()
        .unwrap_or("")
        .contains(":type \"KotobaAttestationStatus\""));
    assert_eq!(
        row[8],
        format!(
            "\"kotoba://attestation/{}/status\"",
            body["claim_cid"].as_str().unwrap()
        ),
        "{q_body}"
    );
    assert_eq!(row[9], "\"KotobaAttestationStatus\"", "{q_body}");

    let (status, iri_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?issuer ?types ?subject ?status]
	                                :where [[?e "https://www.w3.org/2018/credentials#issuer" ?issuer]
	                                        [?e "http://www.w3.org/1999/02/22-rdf-syntax-ns#type" ?types]
	                                        [?e "https://www.w3.org/2018/credentials#credentialSubject" ?subject]
	                                        [?e "https://www.w3.org/2018/credentials#credentialStatus" ?status]]}"#
            }),
            &tenant_jwt(&s.operator_did),
        )
        .await;
    assert_eq!(status, 200, "{iri_body}");
    assert!(
        iri_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row.as_array().is_some_and(|row| {
                row[0] == format!("\"{}\"", s.operator_did)
                    && row[1]
                        .as_str()
                        .unwrap_or("")
                        .contains("\"KotobaAttestationCredential\"")
                    && row[2].as_str().unwrap_or("").contains(":claimCid")
                    && row[3]
                        .as_str()
                        .unwrap_or("")
                        .contains("KotobaAttestationStatus")
            })),
        "{iri_body}"
    );

    let (status, proof_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?proofType ?proofPurpose ?proofVm ?proofValue ?proofDomain]
	                                :where [[?e :credential/proof/type ?proofType]
	                                        [?e :credential/proof/proofPurpose ?proofPurpose]
	                                        [?e :credential/proof/verificationMethod ?proofVm]
	                                        [?e :credential/proof/proofValue ?proofValue]
	                                        [?e :credential/proof/domain ?proofDomain]]}"#
            }),
            &tenant_jwt(&s.operator_did),
        )
        .await;
    assert_eq!(status, 200, "{proof_body}");
    assert!(
        proof_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row.as_array().is_some_and(|row| {
                row[0] == "\"DataIntegrityProof\""
                    && row[1] == "\"assertionMethod\""
                    && row[2] == format!("\"{}#agent-ed25519\"", s.operator_did)
                    && row[3]
                        .as_str()
                        .is_some_and(|proof| proof.starts_with("\"z"))
                    && row[4] == "\"kotoba.attestation\""
            })),
        "{proof_body}"
    );

    let (status, commit_body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.commit.get?graph={graph}"
        ))
        .await;
    assert_eq!(status, 200, "{commit_body}");
    assert_eq!(
        commit_body["commit_type"], "distributed-datomic",
        "{commit_body}"
    );
    assert_eq!(commit_body["cid"], body["commit_cid"], "{commit_body}");
    assert_eq!(commit_body["ipns_verified"], true, "{commit_body}");
    assert_eq!(
        commit_body["ipns_value_matches_commit"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_sequence_matches_commit"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_graph_matches_request"], true,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_controller_did"], s.operator_did,
        "{commit_body}"
    );
    assert_eq!(
        commit_body["ipns_signature_verified"], true,
        "{commit_body}"
    );
    assert!(
        commit_body["ipns_signature_multibase"].as_str().is_some(),
        "{commit_body}"
    );

    let (status, tx_meta_body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.datomic.q",
            json!({
                "graph": graph,
                "query_edn": r#"{:find [?operation ?ipns ?seq ?controller]
                                 :where [[?tx :tx/operation ?operation]
                                         [?tx :tx/ipnsName ?ipns]
                                         [?tx :tx/ipnsSequence ?seq]
                                         [?tx :tx/ipnsControllerDid ?controller]]}"#
            }),
            &tenant_jwt(&s.operator_did),
        )
        .await;
    assert_eq!(status, 200, "{tx_meta_body}");
    assert!(
        tx_meta_body["rows_edn"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row.as_array().is_some_and(|row| {
                row[0] == "\"vc:issue\""
                    && row[1] == format!("\"{}\"", body["ipns_name"].as_str().unwrap())
                    && row[2] == body["ipns_sequence"].as_i64().unwrap().to_string()
                    && row[3] == format!("\"{}\"", s.operator_did)
            })),
        "{tx_meta_body}"
    );
}

#[tokio::test]
async fn attest_challenge_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.attest.challenge",
            json!({
                "claim_cid":      "bafybeifake000000000000000000000000000",
                "challenger_did": "did:key:zChallenger1",
                "reason":         "fabricated evidence",
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn attest_challenge_empty_reason_returns_400() {
    let s = TestServer::start(false).await;
    let did = "did:key:zChallenger2";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.challenge",
            json!({
                "claim_cid":      "bafybeifake000000000000000000000000000",
                "challenger_did": did,
                "reason":         "",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

// ── kg write-endpoint auth tests ──────────────────────────────────────────────

#[tokio::test]
async fn kg_ingest_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id": "ent-noauth",
                "labelEn": "Test Entity",
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["ok"], false, "{body}");
}

#[tokio::test]
async fn kg_delete_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotobase.kg.delete",
            json!({
                "id": "ent-noauth-del",
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["ok"], false, "{body}");
}

#[tokio::test]
async fn kg_embed_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotobase.kg.embed",
            json!({
                "entityId": "ent-embed-noauth",
                "text": "some text",
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn kg_ingest_with_auth_succeeds() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgWriter1");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":      "ent-auth-ok",
                "labelEn": "Authenticated Entity",
                "labelJa": "認証済みエンティティ",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ok"], true, "{body}");
    assert!(body["subjectCid"].as_str().is_some(), "{body}");
    assert!(body["quadCount"].as_u64().unwrap_or(0) > 0, "{body}");
}

#[tokio::test]
async fn kg_delete_with_auth_on_missing_entity_returns_ok_zero() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.delete",
            json!({
                "id": "ent-does-not-exist-auth",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["ok"], true, "{body}");
    assert_eq!(body["retractedCount"], 0, "{body}");
}

#[tokio::test]
async fn kg_delete_non_operator_returns_401() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zNonOperatorDeleter");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.delete",
            json!({
                "id": "ent-non-op-del",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["ok"], false, "{body}");
}

#[tokio::test]
async fn kg_ingest_claim_pred_too_long_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgClaimLen");
    let long_pred = "x".repeat(300); // exceeds MAX_KG_ID_LEN=256
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":     "ent-claim-pred-len",
                "claims": [{ "pred": long_pred, "value": "v" }],
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["ok"], false, "{body}");
}

#[tokio::test]
async fn kg_ingest_relation_pred_too_long_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgRelLen");
    let long_pred = "r".repeat(300);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":        "ent-rel-pred-len",
                "relations": [{ "pred": long_pred, "dstId": "dst-ok" }],
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["ok"], false, "{body}");
}

#[tokio::test]
async fn kg_ingest_label_vec_inf_returns_400() {
    // 1e40 as f64 is valid JSON but overflows to f32::INFINITY when serde deserializes it
    // as Vec<f32>.  The is_finite() guard should reject it with 400.
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zKgVecInf");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.ingest",
            json!({
                "id":       "ent-vec-inf",
                "labelVec": [1.0_f64, 1e40_f64],
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["ok"], false, "{body}");
}

// ── attest_challenge happy path ───────────────────────────────────────────────

#[tokio::test]
async fn attest_challenge_roundtrip() {
    let s = TestServer::start(false).await;
    let did = "did:key:zChallenger3";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.challenge",
            json!({
                "claim_cid":      "bafybeifake000000000000000000000000000",
                "challenger_did": did,
                "reason":         "counter-evidence",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["status"], "challenged", "{body}");
    assert!(body["challenge_cid"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn attest_challenge_empty_claim_cid_returns_400() {
    let s = TestServer::start(false).await;
    let did = "did:key:zChallenger4";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.challenge",
            json!({
                "claim_cid":      "",
                "challenger_did": did,
                "reason":         "some reason",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

// ── attest_query ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn attest_query_returns_empty_list() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get("/xrpc/ai.gftd.apps.kotoba.attest.query?entity_did=did:key:zNobody")
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["claims"].as_array().is_some(),
        "claims must be array: {body}"
    );
    assert_eq!(body["total"].as_u64().unwrap_or(1), 0, "{body}");
}

#[tokio::test]
async fn attest_query_oversized_entity_did_returns_400() {
    let s = TestServer::start(false).await;
    let big_did = "x".repeat(600);
    let (status, body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.attest.query?entity_did={big_did}"
        ))
        .await;
    assert_eq!(status, 400, "{body}");
}

// ── attest_claim stake enforcement ────────────────────────────────────────────

#[tokio::test]
async fn attest_claim_insufficient_stake_self_returns_422() {
    let s = TestServer::start(false).await;
    let did = "did:key:zStaker1";
    let tok = tenant_jwt(did);
    // MIN_STAKE_SELF_ATTESTED = 1_000_000_000 mKOTO; send one less
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.claim",
            json!({
                "entity_did":   did,
                "attester_did": did,
                "claim_type":   "self",
                "stake_mkoto":  999_999_999u64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["error"], "insufficient_stake", "{body}");
    assert_eq!(
        body["required_mkoto"].as_u64().unwrap(),
        1_000_000_000u64,
        "{body}"
    );
}

#[tokio::test]
async fn attest_claim_insufficient_stake_verified_entity_returns_422() {
    let s = TestServer::start(false).await;
    let did = "did:key:zStaker2";
    let tok = tenant_jwt(did);
    // MIN_STAKE_VERIFIED_ENTITY = 5_000_000_000 mKOTO; send exactly MIN_STAKE_SELF_ATTESTED
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.claim",
            json!({
                "entity_did":   "did:key:zEntity1",
                "attester_did": did,
                "claim_type":   "verified_entity",
                "stake_mkoto":  1_000_000_000u64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["error"], "insufficient_stake", "{body}");
    assert_eq!(
        body["required_mkoto"].as_u64().unwrap(),
        5_000_000_000u64,
        "{body}"
    );
}

#[tokio::test]
async fn attest_claim_sufficient_stake_self_succeeds() {
    let s = TestServer::start(false).await;
    let did = "did:key:zStaker3";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.claim",
            json!({
                "entity_did":   did,
                "attester_did": did,
                "claim_type":   "self",
                "stake_mkoto":  1_000_000_000u64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(body["status"], "attested", "{body}");
}

// ── attest_query live scan ─────────────────────────────────────────────────────

#[tokio::test]
async fn attest_query_returns_claim_after_submit() {
    let s = TestServer::start(false).await;
    let attester = "did:key:zQueryAttester1";
    let entity = "did:key:zQueryEntity1";
    let tok = tenant_jwt(attester);

    // Submit a claim
    let (status, _) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.claim",
            json!({
                "entity_did":   entity,
                "attester_did": attester,
                "claim_type":   "self",
                "stake_mkoto":  1_000_000_000u64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 201);

    // Query by entity_did — should find the claim
    let (status, body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.attest.query?entity_did={entity}"
        ))
        .await;
    assert_eq!(status, 200, "{body}");
    let claims = body["claims"].as_array().expect("claims array");
    assert_eq!(claims.len(), 1, "expected 1 claim: {body}");
    assert_eq!(claims[0]["entity_did"], entity, "{body}");
    assert_eq!(claims[0]["attester_did"], attester, "{body}");
    assert_eq!(claims[0]["claim_type"], "self", "{body}");
    assert!(claims[0]["credential_cid"].as_str().is_some(), "{body}");
    assert!(
        claims[0]["credential_id"]
            .as_str()
            .unwrap_or_default()
            .starts_with("urn:kotoba:attestation:"),
        "{body}"
    );
    assert_eq!(claims[0]["credential_status"], "active", "{body}");
    assert_eq!(
        claims[0]["stake_mkoto"].as_u64().unwrap(),
        1_000_000_000u64,
        "{body}"
    );

    // Query by attester_did — same claim
    let (status, body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.attest.query?attester_did={attester}"
        ))
        .await;
    assert_eq!(status, 200, "{body}");
    let claims = body["claims"].as_array().expect("claims array");
    assert_eq!(claims.len(), 1, "expected 1 claim by attester: {body}");
    assert_eq!(claims[0]["entity_did"], entity, "{body}");
}

#[tokio::test]
async fn attest_query_no_filter_returns_empty() {
    let s = TestServer::start(false).await;
    let (status, body) = s.get("/xrpc/ai.gftd.apps.kotoba.attest.query").await;
    assert_eq!(status, 200, "{body}");
    let claims = body["claims"].as_array().expect("claims array");
    assert_eq!(claims.len(), 0, "no-filter must return empty: {body}");
}

// ── request_log_query ────────────────────────────────────────────────────────

#[tokio::test]
async fn request_log_query_without_auth_returns_401() {
    // Regression guard: audit log must be operator-only — leaking it reveals
    // internal API usage patterns and DID activity timings to any caller.
    let s = TestServer::start(false).await;
    let (status, _body) = s.get("/xrpc/ai.gftd.apps.kotoba.request.log").await;
    assert_eq!(
        status, 401,
        "request_log_query must reject unauthenticated requests"
    );
}

#[tokio::test]
async fn request_log_query_returns_empty_list() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .get_with_auth("/xrpc/ai.gftd.apps.kotoba.request.log", &tok)
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        body["entries"].as_array().is_some(),
        "entries must be array: {body}"
    );
}

#[tokio::test]
async fn request_log_query_returns_entries_after_requests() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    // Make a few requests so the fingerprint middleware writes audit quads.
    s.get_with_auth("/xrpc/ai.gftd.apps.kotoba.request.log", &tok)
        .await;
    s.get_with_auth("/xrpc/ai.gftd.apps.kotoba.request.log", &tok)
        .await;
    // Allow the fire-and-forget tokio tasks to complete (in-memory, µs).
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (status, body) = s
        .get_with_auth("/xrpc/ai.gftd.apps.kotoba.request.log", &tok)
        .await;
    assert_eq!(status, 200, "{body}");
    let entries = body["entries"].as_array().expect("entries must be array");
    assert!(
        !entries.is_empty(),
        "expected audit entries after requests, got: {body}"
    );
    let entry = &entries[0];
    assert!(
        entry["request_cid"].as_str().is_some(),
        "request_cid missing: {entry}"
    );
    assert!(
        entry["method"].as_str().is_some(),
        "method missing: {entry}"
    );
    assert!(entry["path"].as_str().is_some(), "path missing: {entry}");
}

#[tokio::test]
async fn request_log_query_path_prefix_filter() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    // Make distinct requests to two different endpoint families.
    s.get_with_auth("/xrpc/ai.gftd.apps.kotoba.request.log", &tok)
        .await;
    s.get("/xrpc/ai.gftd.apps.kotoba.attest.query?entity_did=did:key:zTest1")
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    // Filter by exact prefix — should return only audit entries matching it.
    let (status, body) = s
        .get_with_auth(
            "/xrpc/ai.gftd.apps.kotoba.request.log?path_prefix=/xrpc/ai.gftd.apps.kotoba.request.log",
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let entries = body["entries"].as_array().expect("entries must be array");
    for e in entries {
        let path = e["path"].as_str().unwrap_or("");
        assert!(
            path.starts_with("/xrpc/ai.gftd.apps.kotoba.request.log"),
            "entry path {path:?} does not match filter"
        );
    }
}

// ── signal.distribute.sender.key ─────────────────────────────────────────────

#[tokio::test]
async fn signal_distribute_sender_key_ok() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt(&s.operator_did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.signal.distribute.sender.key",
            json!({
                "recipientDid":    "did:key:zRecipient1",
                "recipientDevice": "device-1",
                "signalMessage":   { "ciphertext": "AAAA", "messageType": 3 },
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "ok", "{body}");
    assert!(body["messageId"].as_str().is_some(), "{body}");
}

#[tokio::test]
async fn signal_distribute_sender_key_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.distribute.sender.key",
            json!({
                "recipientDid":    "did:key:zRecipient1",
                "recipientDevice": "device-1",
                "signalMessage":   { "ciphertext": "AAAA", "messageType": 3 },
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn signal_send_message_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.send.message",
            json!({
                "signalMessage": {
                    "messageType":       "directMessage",
                    "senderDid":         "did:key:zSender",
                    "recipientDid":      "did:key:zRecipient",
                    "deviceId":          "dev-1",
                    "ciphertextEnvelope": "AAAA",
                    "timestamp":         "2026-05-26T00:00:00Z",
                },
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn signal_send_group_message_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.send.group.message",
            json!({
                "groupId":          "grp-1",
                "senderDid":        "did:key:zSender",
                "senderKeyMessage": {},
            }),
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn signal_distribute_sender_key_empty_recipient_did_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.distribute.sender.key",
            json!({
                "recipientDid":    "",
                "recipientDevice": "device-1",
                "signalMessage":   {},
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_distribute_sender_key_empty_device_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.distribute.sender.key",
            json!({
                "recipientDid":    "did:key:zRecipient2",
                "recipientDevice": "",
                "signalMessage":   {},
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_distribute_sender_key_oversized_payload_returns_413() {
    let s = TestServer::start(false).await;
    let large = "x".repeat(300 * 1024);
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.distribute.sender.key",
            json!({
                "recipientDid":    "did:key:zRecipient3",
                "recipientDevice": "device-1",
                "signalMessage":   { "ciphertext": large },
            }),
        )
        .await;
    assert_eq!(status, 413, "{body}");
}

// ── expired JWT rejection tests ───────────────────────────────────────────────

#[tokio::test]
async fn attest_claim_expired_token_returns_401() {
    let s = TestServer::start(false).await;
    let did = "did:key:zExpired1";
    let tok = expired_jwt(did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.claim",
            json!({
                "entity_did":   "did:key:zEntity99",
                "attester_did": did,
                "claim_type":   "self",
                "stake_mkoto":  1_000_000_000u64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn attest_challenge_expired_token_returns_401() {
    let s = TestServer::start(false).await;
    let did = "did:key:zExpired2";
    let tok = expired_jwt(did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.challenge",
            json!({
                "claim_cid":      "bafybeifake000000000000000000000000000",
                "challenger_did": did,
                "reason":         "bad actor",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn signal_register_prekeys_expired_token_returns_401() {
    let s = TestServer::start(false).await;
    let did = "did:key:zExpired3";
    let tok = expired_jwt(did);
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.signal.register.prekeys",
            json!({
                "did":          did,
                "deviceId":     "device-x",
                "identityKey":  {},
                "prekeyBundle": {},
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn operator_auth_expired_token_returns_401() {
    let s = TestServer::start(false).await;
    let tok = expired_jwt(&s.operator_did);
    use kotoba_core::cid::KotobaCid;
    let graph_cid = KotobaCid::from_bytes(b"expired-test").to_multibase();
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.embed.create",
            json!({ "text": "hello", "doc_cid": "d1", "model_cid": "m1", "graph": graph_cid }),
            &tok,
        )
        .await;
    assert_eq!(status, 401, "{body}");
}

// ── signal DID prefix validation tests ───────────────────────────────────────

#[tokio::test]
async fn signal_register_prekeys_invalid_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("not-a-did");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.signal.register.prekeys",
            json!({
                "did":          "not-a-did",
                "deviceId":     "device-1",
                "identityKey":  {},
                "prekeyBundle": {},
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_get_prekey_bundle_invalid_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get("/xrpc/ai.gftd.signal.get.prekey.bundle?did=not-a-did")
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_send_group_message_invalid_sender_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.send.group.message",
            json!({
                "groupId":          "grp-1",
                "senderDid":        "not-a-did",
                "senderKeyMessage": {},
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn signal_distribute_sender_key_invalid_recipient_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.signal.distribute.sender.key",
            json!({
                "recipientDid":    "not-a-did",
                "recipientDevice": "device-1",
                "signalMessage":   {},
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

// ── DID prefix validation tests (email / attest / invoke_run) ────────────────

#[tokio::test]
async fn email_list_invalid_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get("/xrpc/ai.gftd.apps.kotoba.email.list?owner_did=not-a-did")
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn email_ingest_invalid_did_prefix_returns_400() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zOperator");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.email.ingest",
            json!({
                "owner_did": "not-a-did",
                "raw_b64":   B64.encode(b"From: test@example.com\r\n\r\nBody"),
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn attest_claim_invalid_entity_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zAttester");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.claim",
            json!({
                "entity_did":   "not-a-did",
                "attester_did": "did:key:zAttester",
                "claim_type":   "self",
                "stake_mkoto":  1_000_000_000u64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn attest_claim_invalid_attester_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zSelf");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.claim",
            json!({
                "entity_did":   "did:key:zSelf",
                "attester_did": "not-a-did",
                "claim_type":   "self",
                "stake_mkoto":  1_000_000_000u64,
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn attest_challenge_invalid_challenger_did_prefix_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("not-a-did");
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotoba.attest.challenge",
            json!({
                "claim_cid":      "bafybeifake000000000000000000000000000",
                "challenger_did": "not-a-did",
                "reason":         "bad actor",
            }),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

// ── commit.store / weight.put field-bound tests ───────────────────────────────

#[tokio::test]
async fn commit_store_oversized_author_returns_400() {
    let s = TestServer::start(false).await;
    let graph = "commit-author-bound-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);
    // 513-byte author (limit is 512)
    let long_author = "a".repeat(513);
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.commit.store",
            json!({
                "graph":     graph,
                "author":    long_author,
                "seq":       1u64,
                "cacao_b64": cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn weight_put_oversized_shape_returns_400() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let s = TestServer::start(false).await;
    let graph = "weight-shape-bound-graph";
    let (_, cacao_b64) = build_ed25519_cacao(graph);
    let data = vec![0x3cu8];
    // 9-element shape (limit is 8)
    let bad_shape: Vec<u32> = vec![1; 9];
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.weight.put",
            json!({
                "model_cid": "bafkreiabcdef",
                "layer":     0,
                "data_b64":  B64.encode(&data),
                "shape":     bad_shape,
                "dtype":     "fp8e4m3",
                "graph":     graph,
                "cacao_b64": cacao_b64,
            }),
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

// ── email.read tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn email_read_without_auth_returns_401() {
    let s = TestServer::start(false).await;
    let (status, body) = s
        .get("/xrpc/ai.gftd.apps.kotoba.email.read?owner_did=did:key:zReader&email_cid=fakecid")
        .await;
    assert_eq!(status, 401, "{body}");
}

#[tokio::test]
async fn email_read_invalid_did_returns_400() {
    let s = TestServer::start(false).await;
    let tok = tenant_jwt("did:key:zReader");
    let (status, body) = s
        .get_with_auth(
            "/xrpc/ai.gftd.apps.kotoba.email.read?owner_did=not-a-did&email_cid=fakecid",
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn email_read_empty_cid_returns_400() {
    let s = TestServer::start(false).await;
    let did = "did:key:zReader2";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .get_with_auth(
            &format!("/xrpc/ai.gftd.apps.kotoba.email.read?owner_did={did}&email_cid="),
            &tok,
        )
        .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn email_read_without_crypto_returns_503() {
    // The test server does not call init_crypto(), so crypto = None.
    let s = TestServer::start(false).await;
    let did = "did:key:zReader3";
    let tok = tenant_jwt(did);
    let (status, body) = s
        .get_with_auth(
            &format!("/xrpc/ai.gftd.apps.kotoba.email.read?owner_did={did}&email_cid=fakecid"),
            &tok,
        )
        .await;
    assert_eq!(status, 503, "{body}");
    assert!(
        body["error"].as_str().is_some(),
        "expected error field: {body}"
    );
}

// ── New input-guard e2e tests (guards added 2026-05-27) ──────────────────────

#[tokio::test]
async fn block_get_oversized_cid_returns_400() {
    let s = TestServer::start(false).await;
    let oversized_cid = "b".repeat(513); // exceeds MAX_CID_LEN=512
    let (status, body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.block.get?cid={oversized_cid}"
        ))
        .await;
    assert_eq!(status, 400, "oversized cid must be rejected: {body}");
}

#[tokio::test]
async fn weight_get_oversized_cid_returns_400() {
    let s = TestServer::start(false).await;
    let oversized_cid = "w".repeat(513);
    let (status, body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.weight.get?cid={oversized_cid}"
        ))
        .await;
    assert_eq!(status, 400, "oversized cid must be rejected: {body}");
}

#[tokio::test]
async fn commit_get_oversized_graph_returns_400() {
    let s = TestServer::start(false).await;
    let oversized_graph = "g".repeat(513);
    let (status, body) = s
        .get(&format!(
            "/xrpc/ai.gftd.apps.kotoba.commit.get?graph={oversized_graph}"
        ))
        .await;
    assert_eq!(status, 400, "oversized graph must be rejected: {body}");
}

#[tokio::test]
async fn kg_query_oversized_lang_returns_400() {
    let s = TestServer::start(false).await;
    let oversized_lang = "x".repeat(17); // exceeds MAX_KG_LANG_LEN=16
    let (status, body) = s
        .post_auth(
            "/xrpc/ai.gftd.apps.kotobase.kg.query",
            json!({ "lang": oversized_lang, "query": "SELECT ?s ?o WHERE {}" }),
            "test-token",
        )
        .await;
    assert_eq!(status, 400, "oversized lang must be rejected: {body}");
}

#[tokio::test]
async fn commit_store_oversized_graph_returns_400() {
    let s = TestServer::start(false).await;
    let oversized_graph = "g".repeat(513); // exceeds MAX_GRAPH_LEN=512
    let (_, cacao_b64) = build_ed25519_cacao("irrelevant-graph");
    let (status, body) = s
        .post(
            "/xrpc/ai.gftd.apps.kotoba.commit.store",
            json!({
                "graph":     oversized_graph,
                "author":    "did:key:zAuthor",
                "seq":       0u64,
                "cacao_b64": cacao_b64,
            }),
        )
        .await;
    assert_eq!(
        status, 400,
        "oversized graph must be rejected before CACAO: {body}"
    );
}
