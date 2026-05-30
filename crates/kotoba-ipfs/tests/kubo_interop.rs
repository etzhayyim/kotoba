use kotoba_ipfs::{
    dag_pb_object_block, decode_dag_pb_node, raw_cid, unixfs_file_block, DagPbLink, IpfsConfig,
    IpldCid, CODEC_DAG_PB, CODEC_RAW,
};
use reqwest::blocking::{multipart, Client};
use serde_json::Value;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

struct KuboContainer {
    id: String,
    api: String,
}

impl Drop for KuboContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn start_kubo() -> KuboContainer {
    let image =
        std::env::var("KOTOBA_KUBO_IMAGE").unwrap_or_else(|_| "ipfs/kubo:v0.41.0".to_string());
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "-p",
            "127.0.0.1::5001",
            &image,
            "daemon",
            "--migrate=true",
            "--agent-version-suffix=kotoba-interop",
        ])
        .output()
        .expect("start kubo docker container");
    assert!(
        output.status.success(),
        "docker run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let id = String::from_utf8(output.stdout)
        .expect("container id utf8")
        .trim()
        .to_string();
    let client = Client::new();
    for _ in 0..90 {
        let port = Command::new("docker")
            .args(["port", &id, "5001/tcp"])
            .output()
            .ok()
            .and_then(|output| {
                output.status.success().then(|| {
                    String::from_utf8_lossy(&output.stdout)
                        .trim()
                        .rsplit(':')
                        .next()
                        .unwrap_or_default()
                        .to_string()
                })
            })
            .filter(|port| !port.is_empty());
        if let Some(port) = port {
            let api = format!("http://127.0.0.1:{port}/api/v0");
            if client
                .post(format!("{api}/version"))
                .send()
                .is_ok_and(|resp| resp.status().is_success())
            {
                return KuboContainer { id, api };
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
    panic!("kubo API did not become ready");
}

fn kubo_add(client: &Client, api: &str, data: &'static [u8], raw_leaves: bool) -> Value {
    let form =
        multipart::Form::new().part("file", multipart::Part::bytes(data).file_name("hello.txt"));
    client
        .post(format!("{api}/add"))
        .query(&[
            ("cid-version", "1"),
            ("pin", "false"),
            ("raw-leaves", if raw_leaves { "true" } else { "false" }),
        ])
        .multipart(form)
        .send()
        .expect("kubo add")
        .error_for_status()
        .expect("kubo add status")
        .json()
        .expect("kubo add json")
}

fn kubo_add_with_chunker(client: &Client, api: &str, data: &'static [u8], chunker: &str) -> Value {
    let form =
        multipart::Form::new().part("file", multipart::Part::bytes(data).file_name("big.txt"));
    client
        .post(format!("{api}/add"))
        .query(&[
            ("cid-version", "1"),
            ("pin", "false"),
            ("raw-leaves", "true"),
            ("chunker", chunker),
        ])
        .multipart(form)
        .send()
        .expect("kubo chunked add")
        .error_for_status()
        .expect("kubo chunked add status")
        .json()
        .expect("kubo chunked add json")
}

fn kubo_block_get(client: &Client, api: &str, cid: &IpldCid) -> Vec<u8> {
    client
        .post(format!("{api}/block/get"))
        .query(&[("arg", cid.to_string())])
        .send()
        .expect("kubo block/get")
        .error_for_status()
        .expect("kubo block/get status")
        .bytes()
        .expect("kubo block/get bytes")
        .to_vec()
}

fn kubo_cat(client: &Client, api: &str, cid: &IpldCid) -> Vec<u8> {
    client
        .post(format!("{api}/cat"))
        .query(&[("arg", cid.to_string())])
        .send()
        .expect("kubo cat")
        .error_for_status()
        .expect("kubo cat status")
        .bytes()
        .expect("kubo cat bytes")
        .to_vec()
}

fn kubo_block_put(client: &Client, api: &str, codec: &str, block: Vec<u8>) -> Value {
    let form =
        multipart::Form::new().part("file", multipart::Part::bytes(block).file_name("block.bin"));
    client
        .post(format!("{api}/block/put"))
        .query(&[("cid-codec", codec), ("mhtype", "sha2-256")])
        .multipart(form)
        .send()
        .expect("kubo block/put")
        .error_for_status()
        .expect("kubo block/put status")
        .json()
        .expect("kubo block/put json")
}

fn kubo_refs(client: &Client, api: &str, cid: &IpldCid) -> Vec<IpldCid> {
    let body = client
        .post(format!("{api}/refs"))
        .query(&[("arg", cid.to_string()), ("recursive", "false".into())])
        .send()
        .expect("kubo refs")
        .error_for_status()
        .expect("kubo refs status")
        .text()
        .expect("kubo refs body");
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let value: Value = serde_json::from_str(line).expect("kubo refs json line");
            assert!(
                value
                    .get("Err")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .is_empty(),
                "kubo refs error: {value}"
            );
            value["Ref"]
                .as_str()
                .expect("refs Ref")
                .parse()
                .expect("refs cid")
        })
        .collect()
}

#[test]
#[ignore = "requires Docker and a local Kubo image; run with --ignored"]
fn kubo_raw_and_unixfs_blocks_roundtrip_with_kotoba() {
    let kubo = start_kubo();
    let client = Client::new();
    let data = b"hello";
    let expected_raw = raw_cid(data);
    let (expected_unixfs, unixfs_block) = unixfs_file_block(data);

    let raw_add = kubo_add(&client, &kubo.api, data, true);
    assert_eq!(raw_add["Hash"], expected_raw.to_string());
    assert_eq!(kubo_cat(&client, &kubo.api, &expected_raw), data);

    let unixfs_add = kubo_add(&client, &kubo.api, data, false);
    assert_eq!(unixfs_add["Hash"], expected_unixfs.to_string());
    assert_eq!(expected_unixfs.codec(), CODEC_DAG_PB);
    assert_eq!(kubo_cat(&client, &kubo.api, &expected_unixfs), data);

    let raw_from_kubo = kubo_block_get(&client, &kubo.api, &expected_raw);
    let unixfs_from_kubo = kubo_block_get(&client, &kubo.api, &expected_unixfs);
    assert_eq!(raw_from_kubo, data);
    assert_eq!(unixfs_from_kubo, unixfs_block);

    let node = tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(async {
            let temp = tempfile::tempdir().expect("tempdir");
            let node = IpfsConfig::new()
                .with_repo_path(temp.path())
                .start()
                .await
                .expect("kotoba node");
            node.put_block(&expected_raw, &raw_from_kubo)
                .await
                .expect("put raw from kubo");
            node.put_block(&expected_unixfs, &unixfs_from_kubo)
                .await
                .expect("put unixfs from kubo");
            assert_eq!(node.cat(&expected_raw).await.expect("cat raw"), data[..]);
            assert_eq!(
                node.cat(&expected_unixfs).await.expect("cat unixfs"),
                data[..]
            );
            node
        });
    drop(node);

    let raw_put = kubo_block_put(&client, &kubo.api, "raw", data.to_vec());
    assert_eq!(raw_put["Key"], expected_raw.to_string());
    let unixfs_put = kubo_block_put(&client, &kubo.api, "dag-pb", unixfs_block);
    assert_eq!(unixfs_put["Key"], expected_unixfs.to_string());
    assert_eq!(kubo_cat(&client, &kubo.api, &expected_unixfs), data);
    assert_eq!(expected_raw.codec(), CODEC_RAW);
}

#[test]
#[ignore = "requires Docker and a local Kubo image; run with --ignored"]
fn kotoba_dag_pb_object_links_are_kubo_refs_compatible() {
    let kubo = start_kubo();
    let client = Client::new();
    let child_data = b"linked object payload";
    let child = raw_cid(child_data);
    let child_put = kubo_block_put(&client, &kubo.api, "raw", child_data.to_vec());
    assert_eq!(child_put["Key"], child.to_string());

    let (parent, parent_block) = dag_pb_object_block(
        b"object metadata",
        &[DagPbLink {
            name: "payload.bin".into(),
            cid: child,
            tsize: Some(child_data.len() as u64),
        }],
    );
    assert_eq!(parent.codec(), CODEC_DAG_PB);
    let parent_put = kubo_block_put(&client, &kubo.api, "dag-pb", parent_block.clone());
    assert_eq!(parent_put["Key"], parent.to_string());

    assert_eq!(kubo_block_get(&client, &kubo.api, &parent), parent_block);
    assert_eq!(kubo_refs(&client, &kubo.api, &parent), vec![child]);
    assert_eq!(kubo_cat(&client, &kubo.api, &child), child_data);
}

#[test]
#[ignore = "requires Docker and a local Kubo image; run with --ignored"]
fn kubo_chunked_unixfs_file_cats_through_kotoba_dag_pb_links() {
    let kubo = start_kubo();
    let client = Client::new();
    let data = b"abcdefghijklmnopqrstuvwxyz";
    let add = kubo_add_with_chunker(&client, &kubo.api, data, "size-5");
    let root: IpldCid = add["Hash"]
        .as_str()
        .expect("root hash")
        .parse()
        .expect("root cid");
    assert_eq!(root.codec(), CODEC_DAG_PB);

    let root_block = kubo_block_get(&client, &kubo.api, &root);
    let root_node = decode_dag_pb_node(&root_block).expect("decode kubo dag-pb root");
    assert!(root_node.links.len() > 1, "{root_node:?}");
    let linked_blocks = root_node
        .links
        .iter()
        .map(|link| (link.cid, kubo_block_get(&client, &kubo.api, &link.cid)))
        .collect::<Vec<_>>();

    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .expect("tokio runtime")
            .block_on(async {
                let temp = tempfile::tempdir().expect("tempdir");
                let node = IpfsConfig::new()
                    .with_repo_path(temp.path())
                    .start()
                    .await
                    .expect("kotoba node");
                node.put_block(&root, &root_block)
                    .await
                    .expect("put root from kubo");
                for (cid, block) in &linked_blocks {
                    node.put_block(cid, block)
                        .await
                        .expect("put linked block from kubo");
                }
                assert_eq!(
                    node.refs(&root, false).await.expect("refs"),
                    root_node
                        .links
                        .iter()
                        .map(|link| link.cid)
                        .collect::<Vec<_>>()
                );
                assert_eq!(node.cat(&root).await.expect("cat chunked unixfs"), data[..]);
                assert_eq!(
                    node.cat_path(format!("/ipfs/{root}"))
                        .await
                        .expect("cat path chunked unixfs"),
                    data[..]
                );
                let object = node.object_stat(&root).await.expect("object/stat root");
                assert!(object.cumulative_size > object.block_size);
                node.shutdown().await;
            })
    })
    .join()
    .expect("kotoba runtime thread");
}
