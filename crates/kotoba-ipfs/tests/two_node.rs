/// Two-node block exchange: A stores a block, B fetches it via `/kotoba/ipfs/1.0.0`.
use kotoba_ipfs::IpfsConfig;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn two_node_block_exchange() {
    tracing_subscriber::fmt()
        .with_env_filter("kotoba_ipfs=debug")
        .try_init()
        .ok();

    let data = b"hello kotoba-ipfs block exchange".to_vec();

    // Node A on a fixed port so B can dial it.
    let node_a = IpfsConfig {
        listen: "/ip4/127.0.0.1/tcp/17011".parse().unwrap(),
    }
    .start()
    .await
    .expect("node A start");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let cid = node_a.put_block(data.clone()).await.expect("put_block");
    let peer_a = node_a.peer_id();
    eprintln!("node A peer_id: {peer_a}");
    eprintln!("stored CID:     {cid}");

    // Node B on ephemeral port, dials A.
    let node_b = IpfsConfig::new().start().await.expect("node B start");
    node_b
        .dial(format!("/ip4/127.0.0.1/tcp/17011/p2p/{peer_a}").parse().unwrap())
        .expect("dial");

    // Wait for connection to establish.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let peers = node_b.connected_peers().await.expect("peers");
    eprintln!("B connected peers: {peers:?}");
    assert!(peers.contains(&peer_a), "B should be connected to A");

    // B fetches the block from A.
    let fetched = timeout(
        Duration::from_secs(5),
        node_b.get_block(cid, peer_a),
    )
    .await
    .expect("timed out waiting for block")
    .expect("get_block failed");

    assert_eq!(fetched, data, "fetched data must match original");
    eprintln!("two-node block exchange: PASS");
}
