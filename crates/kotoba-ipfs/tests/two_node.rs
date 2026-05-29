/// Two-node block exchange: A stores a block, B fetches it via `/kotoba/ipfs/1.0.0`.
use ciborium::value::Value as CborValue;
use ipld_core::ipld::Ipld;
use kotoba_ipfs::{
    cid_for_bytes, raw_cid, IpfsConfig, Multiaddr, CODEC_DAG_CBOR, CODEC_DAG_PB, CODEC_RAW,
};
use serde::{Deserialize, Serialize};
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn two_node_block_exchange() {
    tracing_subscriber::fmt()
        .with_env_filter("kotoba_ipfs=debug")
        .try_init()
        .ok();

    let data = b"hello kotoba-ipfs block exchange".to_vec();

    // Node A on a fixed port so B can dial it.
    let node_a = IpfsConfig::new()
        .with_listen("/ip4/127.0.0.1/tcp/17011".parse().unwrap())
        .start()
        .await
        .expect("node A start");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let cid = node_a.put_raw_block(&data).await.expect("put_raw_block");
    let peer_a = node_a.peer_id();
    eprintln!("node A peer_id: {peer_a}");
    eprintln!("stored CID:     {cid}");

    let peer_a_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/17011/p2p/{peer_a}")
        .parse()
        .unwrap();
    // Node B on ephemeral port, seeded with A as a bootstrap peer.
    let node_b = IpfsConfig::new()
        .with_bootstrap(vec![peer_a_addr.clone()])
        .start()
        .await
        .expect("node B start");
    assert_eq!(
        node_b.bootstrap_list().await.expect("bootstrap/list"),
        vec![peer_a_addr.clone()]
    );
    assert_eq!(
        node_b
            .bootstrap_add(peer_a_addr.clone())
            .await
            .expect("bootstrap/add"),
        vec![peer_a_addr.clone()]
    );
    let connected = node_b
        .swarm_connect(peer_a_addr.clone())
        .await
        .expect("swarm/connect");
    assert_eq!(connected.peer, peer_a);
    assert_eq!(connected.addr, peer_a_addr);

    // Wait for connection to establish.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let peers = node_b.connected_peers().await.expect("peers");
    eprintln!("B connected peers: {peers:?}");
    assert!(peers.contains(&peer_a), "B should be connected to A");
    assert_eq!(node_b.swarm_peers().await.expect("swarm/peers").len(), 1);
    assert_eq!(
        node_b
            .dht_find_peer(peer_a)
            .await
            .expect("dht/findpeer")
            .len(),
        1
    );
    node_a.dht_provide(&cid).await.expect("dht/provide");
    let providers = node_a
        .dht_find_providers(&cid)
        .await
        .expect("dht/findprovs");
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].peer, peer_a);
    assert!(!providers[0].addrs.is_empty());

    // B fetches the block from A.
    let fetched = timeout(Duration::from_secs(5), node_b.fetch_block(&cid, peer_a))
        .await
        .expect("timed out waiting for block")
        .expect("get_block failed");

    assert_eq!(fetched, data, "fetched data must match original");
    let bw_a = node_a.stats_bw();
    let bw_b = node_b.stats_bw();
    assert!(bw_a.total_out >= data.len() as u64);
    assert!(bw_b.total_in >= data.len() as u64);
    let bitswap_b = node_b.stats_bitswap().await.expect("stats/bitswap");
    assert!(bitswap_b.blocks_received >= 1);
    assert!(bitswap_b.data_received >= data.len() as u64);
    assert_eq!(bitswap_b.peers, vec![peer_a]);
    let disconnected = node_b
        .swarm_disconnect(peer_a)
        .await
        .expect("swarm/disconnect")
        .expect("peer removed");
    assert_eq!(disconnected.peer, peer_a);
    assert!(node_b
        .swarm_disconnect(peer_a)
        .await
        .expect("swarm/disconnect idempotent")
        .is_none());
    assert_eq!(
        node_b
            .bootstrap_rm(&peer_a_addr)
            .await
            .expect("bootstrap/rm"),
        vec![peer_a_addr.clone()]
    );
    assert!(node_b
        .bootstrap_clear()
        .await
        .expect("bootstrap/rm all")
        .is_empty());
    eprintln!("two-node block exchange: PASS");
}

#[tokio::test]
async fn repo_persists_blocks_and_pins() {
    let temp = tempfile::tempdir().expect("tempdir");
    let data = b"persistent block".to_vec();

    let node = IpfsConfig::new()
        .with_repo_path(temp.path())
        .start()
        .await
        .expect("node start");
    let cid = node.put_raw_block(&data).await.expect("put");
    let direct_cid = node
        .put_raw_block(b"persistent direct pin")
        .await
        .expect("put direct");
    node.pin(&cid).await.expect("pin");
    node.pin_add_direct(&direct_cid).await.expect("pin direct");
    node.files_write_bytes("/persisted/file.txt", &data, true)
        .await
        .expect("files/write bytes");
    node.name_publish("k51-kotoba-persisted", &cid, "2026-05-29T00:00:00Z")
        .await
        .expect("name/publish");
    assert_eq!(
        node.block_stat(&cid).await.expect("stat").size,
        data.len() as u64
    );
    let blocks = node.list_blocks().await.expect("blocks");
    assert!(blocks.contains(&cid));
    assert!(blocks.contains(&direct_cid));
    let pins = node.pin_ls().await.expect("pin/ls persisted");
    assert!(pins
        .iter()
        .any(|entry| entry.cid == cid && entry.kind == kotoba_ipfs::PinKind::Recursive));
    assert!(pins
        .iter()
        .any(|entry| entry.cid == direct_cid && entry.kind == kotoba_ipfs::PinKind::Direct));
    node.shutdown().await;

    let restarted = IpfsConfig::new()
        .with_repo_path(temp.path())
        .start()
        .await
        .expect("restart");
    assert_eq!(restarted.get_block(&cid).await.expect("get"), data);
    assert!(restarted.is_pinned(&cid).await.expect("is pinned"));
    assert!(restarted
        .is_pinned(&direct_cid)
        .await
        .expect("direct is pinned"));
    assert!(restarted
        .pin_ls()
        .await
        .expect("pin/ls restarted")
        .iter()
        .any(|entry| entry.cid == direct_cid && entry.kind == kotoba_ipfs::PinKind::Direct));
    assert_eq!(
        restarted
            .files_read("/persisted/file.txt")
            .await
            .expect("files/read persisted"),
        b"persistent block"[..]
    );
    assert_eq!(
        restarted
            .name_resolve("k51-kotoba-persisted")
            .await
            .expect("name/resolve persisted")
            .cid,
        cid
    );
}

#[tokio::test]
async fn gc_removes_unpinned_blocks_and_keeps_pinned() {
    let temp = tempfile::tempdir().expect("tempdir");
    let node = IpfsConfig::new()
        .with_repo_path(temp.path())
        .start()
        .await
        .expect("node start");

    let pinned = node.put_raw_block(b"pinned").await.expect("put pinned");
    let loose = node.put_raw_block(b"loose").await.expect("put loose");
    node.pin(&pinned).await.expect("pin");

    let removed = node.gc().await.expect("gc");
    assert_eq!(removed, vec![loose]);
    assert!(node.has_block(&pinned).await.expect("has pinned"));
    assert!(!node.has_block(&loose).await.expect("has loose"));
}

#[tokio::test]
async fn kubo_compatible_local_api_surface() {
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Doc {
        title: String,
        n: u64,
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let node = IpfsConfig::new()
        .with_repo_path(temp.path())
        .start()
        .await
        .expect("node start");

    let raw = node.add(b"hello").await.expect("add");
    assert_eq!(node.block_get(&raw).await.expect("block/get"), b"hello"[..]);
    assert_eq!(node.cat(&raw).await.expect("cat"), b"hello"[..]);
    let unixfs = node
        .add_unixfs_file(b"hello")
        .await
        .expect("add unixfs file");
    assert_eq!(unixfs.codec(), CODEC_DAG_PB);
    assert_eq!(
        unixfs.to_string(),
        "bafybeid3weurg3gvyoi7nisadzolomlvoxoppe2sesktnpvdve3256n5tq"
    );
    assert_eq!(
        node.cat(&unixfs).await.expect("cat unixfs file"),
        b"hello"[..]
    );
    assert_eq!(
        node.cat_path(format!("/ipfs/{unixfs}"))
            .await
            .expect("cat /ipfs unixfs file"),
        b"hello"[..]
    );
    assert_eq!(
        node.resolve_path(format!("/ipfs/{raw}"))
            .await
            .expect("resolve /ipfs raw")
            .cid,
        raw
    );
    assert_eq!(
        node.cat_path(format!("/ipfs/{raw}"))
            .await
            .expect("cat /ipfs raw"),
        b"hello"[..]
    );
    assert!(node
        .dht_find_providers(&raw)
        .await
        .expect("dht/findprovs empty")
        .is_empty());
    node.dht_provide(&raw).await.expect("dht/provide");
    let providers = node.dht_find_providers(&raw).await.expect("dht/findprovs");
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].peer, node.peer_id());
    let codec_put = node
        .block_put_codec(CODEC_RAW, b"hello codec")
        .await
        .expect("block/put codec");
    assert_eq!(codec_put.cid, raw_cid(b"hello codec"));
    assert_eq!(codec_put.size, 11);
    assert_eq!(
        node.block_get(&codec_put.cid)
            .await
            .expect("block/get codec"),
        b"hello codec"[..]
    );
    let raw_object = node.object_stat(&raw).await.expect("object/stat raw");
    assert_eq!(raw_object.cid, raw);
    assert_eq!(raw_object.codec, CODEC_RAW);
    assert_eq!(raw_object.block_size, 5);
    assert_eq!(raw_object.cumulative_size, 5);

    let doc = Doc {
        title: "kotoba".into(),
        n: 42,
    };
    let dag = node.dag_put(&doc).await.expect("dag/put");
    let decoded: Doc = node.dag_get(&dag).await.expect("dag/get");
    assert_eq!(decoded, doc);
    let dag_object = node.object_stat(&dag).await.expect("object/stat dag");
    assert_eq!(dag_object.cid, dag);
    assert_eq!(dag_object.codec, CODEC_DAG_CBOR);
    assert!(dag_object.block_size > 0);
    assert_eq!(dag_object.block_size, dag_object.cumulative_size);
    let dag_stat = node.dag_stat(&dag).await.expect("dag/stat");
    assert_eq!(dag_stat.cid, dag);
    assert_eq!(dag_stat.codec, CODEC_DAG_CBOR);
    assert_eq!(dag_stat.size, dag_object.block_size);
    assert!(node.dag_stat(&raw).await.is_err());
    let root_resolve = node.dag_resolve(&dag, "").await.expect("dag/resolve root");
    assert_eq!(root_resolve.cid, dag);
    assert_eq!(root_resolve.rem_path, "");

    let leaf = put_cbor_value(&node, CborValue::Text("leaf".into()))
        .await
        .expect("dag leaf");
    let mut leaf_bytes = vec![0];
    leaf_bytes.extend(leaf.to_bytes());
    let child = put_cbor_value(
        &node,
        CborValue::Map(vec![(
            CborValue::Text("leaf".into()),
            CborValue::Tag(42, Box::new(CborValue::Bytes(leaf_bytes))),
        )]),
    )
    .await
    .expect("dag child");
    let mut link_bytes = vec![0];
    link_bytes.extend(child.to_bytes());
    let linked_doc = CborValue::Map(vec![(
        CborValue::Text("child".into()),
        CborValue::Tag(42, Box::new(CborValue::Bytes(link_bytes))),
    )]);
    let linked = put_cbor_value(&node, linked_doc.clone())
        .await
        .expect("dag linked");
    assert_eq!(node.refs(&linked, false).await.expect("refs"), vec![child]);
    assert_eq!(
        node.object_links(&linked).await.expect("object/links"),
        vec![kotoba_ipfs::ObjectLink {
            name: String::new(),
            cid: child,
        }]
    );
    let pb_dir_block = dag_pb_node_with_link("hello.txt", &raw, 5);
    let pb_dir = cid_for_bytes(CODEC_DAG_PB, &pb_dir_block);
    node.block_put(&pb_dir, &pb_dir_block)
        .await
        .expect("block/put dag-pb dir");
    assert_eq!(
        node.object_data(&pb_dir).await.expect("object/data"),
        b""[..]
    );
    let object = node.object_get(&pb_dir).await.expect("object/get dag-pb");
    assert_eq!(object.cid, pb_dir);
    assert_eq!(object.data, Vec::<u8>::new());
    assert_eq!(
        object.links,
        vec![kotoba_ipfs::ObjectLink {
            name: "hello.txt".into(),
            cid: raw,
        }]
    );
    assert_eq!(
        node.object_links(&pb_dir)
            .await
            .expect("object/links dag-pb"),
        object.links
    );
    let pb_ipld = node.dag_get_ipld(&pb_dir).await.expect("dag/get dag-pb");
    let Ipld::Map(pb_map) = pb_ipld else {
        panic!("dag-pb root should decode as IPLD map");
    };
    assert!(matches!(pb_map.get("Data"), Some(Ipld::Bytes(data)) if data.is_empty()));
    let Some(Ipld::List(pb_links)) = pb_map.get("Links") else {
        panic!("dag-pb root should expose Links");
    };
    assert_eq!(pb_links.len(), 1);
    let Ipld::Map(pb_link) = &pb_links[0] else {
        panic!("dag-pb Link should decode as IPLD map");
    };
    assert!(matches!(pb_link.get("Hash"), Some(Ipld::Link(link)) if link == &raw));
    assert!(matches!(pb_link.get("Name"), Some(Ipld::String(name)) if name == "hello.txt"));
    assert!(matches!(pb_link.get("Tsize"), Some(Ipld::Integer(size)) if *size == 5));
    let pb_stat = node.dag_stat(&pb_dir).await.expect("dag/stat dag-pb");
    assert_eq!(pb_stat.cid, pb_dir);
    assert_eq!(pb_stat.codec, CODEC_DAG_PB);
    assert_eq!(pb_stat.size, pb_dir_block.len() as u64);
    assert_eq!(
        node.resolve_path(format!("/ipfs/{pb_dir}/hello.txt"))
            .await
            .expect("resolve dag-pb named link")
            .cid,
        raw
    );
    assert_eq!(
        node.dag_resolve(&pb_dir, "0")
            .await
            .expect("dag/resolve dag-pb link index")
            .cid,
        raw
    );
    assert_eq!(
        node.resolve_path(format!("/ipfs/{pb_dir}/0"))
            .await
            .expect("resolve dag-pb link index path")
            .cid,
        raw
    );
    assert_eq!(
        node.cat_path(format!("/ipfs/{pb_dir}/hello.txt"))
            .await
            .expect("cat dag-pb named link"),
        b"hello"[..]
    );
    assert_eq!(
        node.refs(&linked, true).await.expect("recursive refs"),
        vec![child, leaf]
    );
    let ipld = node.dag_get_ipld(&linked).await.expect("dag/get ipld");
    let Ipld::Map(map) = ipld else {
        panic!("linked dag-cbor root should decode as IPLD map");
    };
    assert!(matches!(map.get("child"), Some(Ipld::Link(link)) if link == &child));
    let link_resolve = node
        .dag_resolve(&linked, "/child")
        .await
        .expect("dag/resolve link");
    assert_eq!(link_resolve.cid, child);
    assert_eq!(link_resolve.rem_path, "");
    let path_resolve = node
        .resolve_path(format!("/ipfs/{linked}/child"))
        .await
        .expect("resolve /ipfs dag link path");
    assert_eq!(path_resolve.cid, child);
    assert_eq!(path_resolve.rem_path, "");
    let car = node
        .dag_export(&linked, true)
        .await
        .expect("dag/export recursive CAR");
    let import_temp = tempfile::tempdir().expect("import tempdir");
    let import_node = IpfsConfig::new()
        .with_repo_path(import_temp.path())
        .start()
        .await
        .expect("import node start");
    let imported = import_node.dag_import(&car).await.expect("dag/import CAR");
    assert_eq!(imported.roots, vec![linked]);
    assert_eq!(imported.blocks, vec![child, leaf, linked]);
    assert!(import_node
        .has_block(&linked)
        .await
        .expect("has imported root"));
    assert!(import_node
        .has_block(&child)
        .await
        .expect("has imported child"));
    assert!(import_node
        .has_block(&leaf)
        .await
        .expect("has imported leaf"));
    assert_eq!(
        import_node
            .refs(&linked, true)
            .await
            .expect("refs imported CAR"),
        vec![child, leaf]
    );

    let updated_pin = node.add(b"hello v2").await.expect("add updated pin");
    node.pin_add(&raw).await.expect("pin/add");
    assert!(node.is_pinned(&raw).await.expect("is pinned"));
    assert_eq!(
        node.pin_ls().await.expect("pin/ls"),
        vec![kotoba_ipfs::PinLsEntry {
            cid: raw,
            kind: kotoba_ipfs::PinKind::Recursive,
        }]
    );
    assert!(node
        .pin_ls()
        .await
        .expect("pin/ls kind")
        .iter()
        .all(|entry| entry.kind.as_str() == "recursive"));
    assert_eq!(
        node.pin_verify().await.expect("pin/verify"),
        vec![kotoba_ipfs::PinVerify {
            cid: raw,
            ok: true,
            error: None,
        }]
    );
    node.pin_update(&raw, &updated_pin)
        .await
        .expect("pin/update");
    assert!(!node.is_pinned(&raw).await.expect("old pin removed"));
    assert!(node
        .is_pinned(&updated_pin)
        .await
        .expect("new pin inserted"));
    node.pin_rm(&updated_pin).await.expect("pin/rm updated");
    assert!(!node
        .is_pinned(&updated_pin)
        .await
        .expect("updated pin after rm"));
    node.pin_add(&raw).await.expect("pin/add raw again");
    node.pin_rm(&raw).await.expect("pin/rm");
    assert!(!node.is_pinned(&raw).await.expect("is pinned after rm"));
    node.pin_add(&linked).await.expect("pin/add recursive dag");
    let dag_pins = node.pin_ls().await.expect("pin/ls recursive dag");
    assert!(dag_pins
        .iter()
        .any(|entry| { entry.cid == linked && entry.kind == kotoba_ipfs::PinKind::Recursive }));
    assert!(dag_pins
        .iter()
        .any(|entry| entry.cid == child && entry.kind == kotoba_ipfs::PinKind::Indirect));
    assert!(dag_pins
        .iter()
        .any(|entry| entry.cid == leaf && entry.kind == kotoba_ipfs::PinKind::Indirect));
    assert!(node.block_rm(&linked).await.is_err());
    assert!(node.block_rm(&child).await.is_err());
    assert!(node
        .pin_verify()
        .await
        .expect("pin/verify recursive dag")
        .iter()
        .any(|entry| entry.cid == linked && entry.ok));
    node.pin_rm(&linked)
        .await
        .expect("pin/rm recursive before direct");
    node.pin_add_direct(&linked)
        .await
        .expect("pin/add direct dag");
    let direct_pins = node.pin_ls().await.expect("pin/ls direct dag");
    assert!(direct_pins
        .iter()
        .any(|entry| entry.cid == linked && entry.kind == kotoba_ipfs::PinKind::Direct));
    assert!(!direct_pins
        .iter()
        .any(|entry| entry.cid == child && entry.kind == kotoba_ipfs::PinKind::Indirect));
    assert!(node.block_rm(&linked).await.is_err());
    assert!(node
        .block_rm(&child)
        .await
        .expect("direct pin does not protect child"));
    assert!(!node
        .has_block(&child)
        .await
        .expect("child removed under direct pin"));
    assert!(node
        .pin_verify()
        .await
        .expect("pin/verify direct dag")
        .iter()
        .any(|entry| entry.cid == linked && entry.ok));
    assert_eq!(
        put_cbor_value(
            &node,
            CborValue::Map(vec![(
                CborValue::Text("leaf".into()),
                CborValue::Tag(
                    42,
                    Box::new(CborValue::Bytes({
                        let mut bytes = vec![0];
                        bytes.extend(leaf.to_bytes());
                        bytes
                    }))
                ),
            )])
        )
        .await
        .expect("re-add child after direct pin test"),
        child
    );
    node.pin_rm(&linked).await.expect("pin/rm direct dag");
    node.pin_add(&linked)
        .await
        .expect("pin/add recursive dag again");
    let dag_gc = node.repo_gc().await.expect("repo/gc pinned dag");
    assert!(!dag_gc.contains(&linked));
    assert!(!dag_gc.contains(&child));
    assert!(!dag_gc.contains(&leaf));
    assert!(node.has_block(&linked).await.expect("has linked after gc"));
    assert!(node.has_block(&child).await.expect("has child after gc"));
    assert!(node.has_block(&leaf).await.expect("has leaf after gc"));
    node.pin_rm(&linked).await.expect("pin/rm recursive dag");
    assert!(node
        .block_rm(&linked)
        .await
        .expect("block/rm unpinned root"));
    assert!(!node
        .has_block(&linked)
        .await
        .expect("has root after block/rm"));
    assert_eq!(
        put_cbor_value(&node, linked_doc.clone())
            .await
            .expect("re-add linked"),
        linked
    );
    node.pin_add(&linked)
        .await
        .expect("pin/add linked for force rm");
    assert!(node
        .block_rm_force(&linked)
        .await
        .expect("block/rm force pinned root"));
    assert!(!node
        .is_pinned(&linked)
        .await
        .expect("forced root pin removed"));
    assert_eq!(
        put_cbor_value(&node, linked_doc.clone())
            .await
            .expect("re-add linked"),
        linked
    );
    assert_eq!(node.add(b"hello").await.expect("re-add raw"), raw);
    assert_eq!(node.dag_put(&doc).await.expect("re-add dag"), dag);
    assert_eq!(
        node.add_unixfs_file(b"hello").await.expect("re-add unixfs"),
        unixfs
    );

    node.files_write("/docs/hello.txt", &raw)
        .await
        .expect("files/write");
    node.files_write("/unixfs/hello.txt", &unixfs)
        .await
        .expect("files/write unixfs");
    assert_eq!(
        node.files_read("/unixfs/hello.txt")
            .await
            .expect("files/read unixfs"),
        b"hello"[..]
    );
    let unixfs_stat = node
        .files_stat("/unixfs/hello.txt")
        .await
        .expect("files/stat unixfs");
    assert_eq!(unixfs_stat.cid, Some(unixfs));
    assert_eq!(unixfs_stat.kind, kotoba_ipfs::MfsKind::File);
    assert_eq!(unixfs_stat.size, 5);
    assert_eq!(unixfs_stat.blocks, 1);
    assert!(
        unixfs_stat.cumulative_size >= unixfs_stat.size,
        "{unixfs_stat:?}"
    );
    assert_eq!(
        node.files_du("/unixfs/hello.txt", false)
            .await
            .expect("files/du unixfs file"),
        5
    );
    assert_eq!(
        node.files_rm("/unixfs/hello.txt", false)
            .await
            .expect("files/rm unixfs"),
        1
    );
    let write_bytes_stat = node
        .files_write_bytes("/docs/generated.txt", b"generated", true)
        .await
        .expect("files/write bytes");
    assert_eq!(write_bytes_stat.path, "/docs/generated.txt");
    assert_eq!(write_bytes_stat.size, 9);
    assert_eq!(
        node.files_read("/docs/generated.txt")
            .await
            .expect("files/read generated"),
        b"generated"[..]
    );
    let touched = node
        .files_touch("/docs/empty.txt", true)
        .await
        .expect("files/touch");
    assert_eq!(touched.path, "/docs/empty.txt");
    assert_eq!(touched.size, 0);
    assert_eq!(
        node.files_touch("/docs/empty.txt", false)
            .await
            .expect("files/touch idempotent"),
        touched
    );
    assert_eq!(
        node.files_read("/docs/hello.txt")
            .await
            .expect("files/read"),
        b"hello"[..]
    );
    let file_stat = node
        .files_stat("/docs/hello.txt")
        .await
        .expect("files/stat");
    assert_eq!(file_stat.path, "/docs/hello.txt");
    assert_eq!(file_stat.cid, Some(raw));
    assert_eq!(file_stat.kind, kotoba_ipfs::MfsKind::File);
    assert_eq!(file_stat.kind.as_str(), "file");
    assert_eq!(file_stat.size, 5);
    assert_eq!(file_stat.cumulative_size, 5);
    assert_eq!(file_stat.blocks, 1);
    assert_eq!(
        node.files_flush("/docs/hello.txt")
            .await
            .expect("files/flush"),
        file_stat
    );
    let files = node.files_ls("/docs").await.expect("files/ls");
    assert_eq!(files.len(), 3);
    assert!(files
        .iter()
        .any(|entry| entry.path == "/docs/hello.txt" && entry.cid == Some(raw)));
    assert!(files
        .iter()
        .any(|entry| entry.path == "/docs/generated.txt" && entry.cid == write_bytes_stat.cid));
    assert!(files
        .iter()
        .any(|entry| entry.path == "/docs/empty.txt" && entry.cid == touched.cid));
    assert_eq!(
        node.files_ls("/").await.expect("files/ls root"),
        vec![kotoba_ipfs::MfsEntry {
            path: "/docs".into(),
            cid: None,
        }]
    );
    let docs_stat = node.files_stat("/docs").await.expect("files/stat dir");
    assert_eq!(docs_stat.path, "/docs");
    assert_eq!(docs_stat.cid, None);
    assert_eq!(docs_stat.kind, kotoba_ipfs::MfsKind::Directory);
    assert_eq!(docs_stat.kind.as_str(), "directory");
    assert_eq!(docs_stat.size, 14);
    assert_eq!(docs_stat.cumulative_size, 14);
    assert_eq!(docs_stat.blocks, 3);
    assert_eq!(
        node.files_du("/docs/hello.txt", false)
            .await
            .expect("files/du file"),
        5
    );
    assert_eq!(
        node.files_du("/docs", true)
            .await
            .expect("files/du recursive"),
        14
    );

    node.files_mkdir("/docs/archive", true)
        .await
        .expect("files/mkdir");
    let docs_after_mkdir = node.files_ls("/docs").await.expect("files/ls mkdir");
    assert!(docs_after_mkdir
        .iter()
        .any(|entry| entry.path == "/docs/archive" && entry.cid.is_none()));
    node.files_mkdir("/docs/empty-dir", true)
        .await
        .expect("files/mkdir empty-dir");
    assert_eq!(
        node.files_rm("/docs/empty-dir", false)
            .await
            .expect("files/rm empty dir"),
        1
    );
    assert!(node.files_rm("/docs", false).await.is_err());
    assert!(node.files_read("/docs/hello.txt").await.is_ok());
    node.files_cp("/docs/hello.txt", "/docs/archive/hello-copy.txt")
        .await
        .expect("files/cp");
    let docs_after_copy = node.files_ls("/docs").await.expect("files/ls after copy");
    assert!(docs_after_copy
        .iter()
        .any(|entry| entry.path == "/docs/archive" && entry.cid.is_none()));
    assert!(!docs_after_copy
        .iter()
        .any(|entry| entry.path == "/docs/archive/hello-copy.txt"));
    assert_eq!(
        node.files_read("/docs/archive/hello-copy.txt")
            .await
            .expect("files/read copy"),
        b"hello"[..]
    );
    let copy_stat = node
        .files_stat("/docs/archive/hello-copy.txt")
        .await
        .expect("files/stat copy");
    assert_eq!(copy_stat.cid, Some(raw));
    assert_eq!(copy_stat.kind, kotoba_ipfs::MfsKind::File);
    assert_eq!(copy_stat.size, 5);
    node.files_cp(format!("/ipfs/{raw}"), "/docs/from-ipfs.txt")
        .await
        .expect("files/cp /ipfs source");
    assert_eq!(
        node.files_read("/docs/from-ipfs.txt")
            .await
            .expect("files/read /ipfs copy"),
        b"hello"[..]
    );
    node.block_put(&pb_dir, &pb_dir_block)
        .await
        .expect("re-add dag-pb dir before files/cp path source");
    node.files_cp(
        format!("/ipfs/{pb_dir}/hello.txt"),
        "/docs/from-ipfs-path.txt",
    )
    .await
    .expect("files/cp resolved /ipfs path source");
    assert_eq!(
        node.files_read("/docs/from-ipfs-path.txt")
            .await
            .expect("files/read resolved /ipfs path copy"),
        b"hello"[..]
    );
    node.files_mv("/docs/from-ipfs.txt", "/docs/archive/from-ipfs-moved.txt")
        .await
        .expect("files/mv file");
    assert_eq!(
        node.files_read("/docs/archive/from-ipfs-moved.txt")
            .await
            .expect("files/read moved file"),
        b"hello"[..]
    );
    assert!(node.files_read("/docs/from-ipfs.txt").await.is_err());
    node.files_mkdir("/docs/move-src", true)
        .await
        .expect("files/mkdir move-src");
    node.files_cp(format!("/ipfs/{raw}"), "/docs/move-src/nested.txt")
        .await
        .expect("files/cp nested /ipfs source");
    node.files_mv("/docs/move-src", "/docs/archive/moved-dir")
        .await
        .expect("files/mv dir");
    assert_eq!(
        node.files_read("/docs/archive/moved-dir/nested.txt")
            .await
            .expect("files/read moved dir child"),
        b"hello"[..]
    );
    node.files_cp("/docs/archive", "/docs/archive-copy")
        .await
        .expect("files/cp directory");
    assert_eq!(
        node.files_read("/docs/archive-copy/hello-copy.txt")
            .await
            .expect("files/read copied dir file"),
        b"hello"[..]
    );
    assert_eq!(
        node.files_read("/docs/archive-copy/moved-dir/nested.txt")
            .await
            .expect("files/read copied nested dir file"),
        b"hello"[..]
    );
    assert!(node
        .files_cp("/docs/archive", "/docs/archive-copy")
        .await
        .is_err());
    assert!(node.files_cp("/docs", "/docs/archive/self").await.is_err());

    let refs = node.refs_local().await.expect("refs/local");
    assert!(refs.contains(&raw));
    assert!(refs.contains(&dag));

    let published = node
        .name_publish("k51-kotoba-local", &raw, "2026-05-29T00:00:00Z")
        .await
        .expect("name/publish");
    assert_eq!(published.value, raw.to_string());
    assert_eq!(published.sequence, 1);
    let resolved = node
        .name_resolve("k51-kotoba-local")
        .await
        .expect("name/resolve");
    assert_eq!(resolved.cid, raw);
    assert_eq!(resolved.path, format!("/ipfs/{raw}"));
    assert_eq!(resolved.record, published);
    assert_eq!(
        node.resolve_path("/ipns/k51-kotoba-local")
            .await
            .expect("resolve /ipns")
            .cid,
        raw
    );
    assert_eq!(
        node.cat_path("/ipns/k51-kotoba-local")
            .await
            .expect("cat /ipns"),
        b"hello"[..]
    );
    let republished = node
        .name_publish("k51-kotoba-local", &dag, "2026-05-29T00:01:00Z")
        .await
        .expect("name/publish sequence");
    assert_eq!(republished.sequence, 2);
    assert_eq!(
        node.name_resolve("k51-kotoba-local")
            .await
            .expect("name/resolve updated")
            .cid,
        dag
    );

    let stat = node.repo_stat().await.expect("repo/stat");
    assert_eq!(
        stat.num_objects,
        node.list_blocks().await.expect("list blocks").len() as u64
    );
    assert!(stat.num_objects >= 6);
    assert!(stat.repo_size >= 5);
    let verify = node.repo_verify().await.expect("repo/verify");
    assert_eq!(verify.checked, stat.num_objects);
    assert!(verify.ok, "repo/verify errors: {:?}", verify.errors);
    let bw = node.stats_bw();
    assert_eq!(bw.total_in, 0);
    let bitswap = node.stats_bitswap().await.expect("stats/bitswap");
    assert_eq!(bitswap.blocks_received, stat.num_objects);
    assert_eq!(bitswap.data_received, stat.repo_size);
    assert!(bitswap.provide_buf_len >= 1);
    assert!(bitswap.wantlist.is_empty());

    assert!(!node
        .repo_gc()
        .await
        .expect("repo/gc mfs root")
        .contains(&raw));
    assert!(node.has_block(&raw).await.expect("has raw under mfs"));
    assert!(!node.has_block(&dag).await.expect("has dag after gc"));
    assert_eq!(node.files_rm("/docs", true).await.expect("files/rm"), 15);
    assert!(node
        .files_ls("/docs")
        .await
        .expect("files/ls empty")
        .is_empty());

    assert!(node.repo_gc().await.expect("repo/gc").contains(&raw));
    assert!(!node.has_block(&raw).await.expect("has raw"));
}

#[tokio::test]
async fn block_put_rejects_cid_data_mismatch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let node = IpfsConfig::new()
        .with_repo_path(temp.path())
        .start()
        .await
        .expect("node start");

    let cid = raw_cid(b"expected bytes");
    let err = node
        .block_put(&cid, b"different bytes")
        .await
        .expect_err("block/put must reject data that does not hash to the CID");

    assert!(
        err.to_string().contains("cid/data mismatch"),
        "unexpected error: {err}"
    );
    assert!(!node.has_block(&cid).await.expect("has_block"));
}

async fn put_cbor_value(
    node: &kotoba_ipfs::KotobaIpfsNode,
    value: CborValue,
) -> anyhow::Result<kotoba_ipfs::IpldCid> {
    let mut data = Vec::new();
    ciborium::into_writer(&value, &mut data)?;
    node.put_codec_block(CODEC_DAG_CBOR, &data).await
}

fn dag_pb_node_with_link(name: &str, cid: &kotoba_ipfs::IpldCid, tsize: u64) -> Vec<u8> {
    let mut link = Vec::new();
    write_pb_bytes(&mut link, 1, &cid.to_bytes());
    write_pb_bytes(&mut link, 2, name.as_bytes());
    write_pb_varint(&mut link, 3, tsize);

    let mut node = Vec::new();
    write_pb_bytes(&mut node, 2, &link);
    node
}

fn write_pb_bytes(out: &mut Vec<u8>, field: u64, bytes: &[u8]) {
    write_pb_key(out, field, 2);
    write_pb_raw_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn write_pb_varint(out: &mut Vec<u8>, field: u64, value: u64) {
    write_pb_key(out, field, 0);
    write_pb_raw_varint(out, value);
}

fn write_pb_key(out: &mut Vec<u8>, field: u64, wire: u64) {
    write_pb_raw_varint(out, (field << 3) | wire);
}

fn write_pb_raw_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
