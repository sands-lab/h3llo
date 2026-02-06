//! Throughput end-to-end tests using iperf3 inside Docker containers.
//!
//! Measures TCP throughput through VPN tunnels to verify data-plane
//! forwarding works beyond simple ping connectivity. Covers both
//! BareUDP and HTTP/3 transports.

use std::time::Duration;
use testcontainers::core::{ContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use super::common::{
    ensure_image_exists, ensure_network_exists, format_throughput, parse_iperf3_bps, TEST_IMAGE,
    TEST_NETWORK, TEST_TAG,
};
use super::h3::{generate_test_certs, h3_node_config};

/// iperf3 test duration in seconds.
const IPERF_DURATION_SECS: u32 = 5;

/// BareUDP node A config for throughput testing.
const THROUGHPUT_NODE_A_CONFIG: &str = r#"
local:
  id: node-a-tp
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.1
    mtu: 1400
  dns:
    server: udp://127.0.0.11:53
    refresh: 1
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-b-tp
    enabled: true
    bare:
      endpoint: "udp://node-b-tp.h3llo-test-net:5353"
    tun:
      allowedIPs:
        - 10.0.0.2/32
"#;

/// BareUDP node B config for throughput testing.
const THROUGHPUT_NODE_B_CONFIG: &str = r#"
local:
  id: node-b-tp
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.2
    mtu: 1400
  dns:
    server: udp://127.0.0.11:53
    refresh: 1
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-a-tp
    enabled: true
    bare:
      endpoint: "udp://node-a-tp.h3llo-test-net:5353"
    tun:
      allowedIPs:
        - 10.0.0.1/32
"#;

/// BareUDP TCP throughput test.
///
/// 1. Starts two h3llo containers with BareUDP tunnel
/// 2. Runs iperf3 server on node B (via VPN IP 10.0.0.2)
/// 3. Runs iperf3 client on node A targeting 10.0.0.2
/// 4. Parses JSON output and asserts throughput > 0
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_bareudp_tcp_throughput() {
    if !ensure_image_exists() {
        eprintln!(
            "Docker image {}:{} not found. Build with:",
            TEST_IMAGE, TEST_TAG
        );
        eprintln!(
            "  docker build --target test -t {}:{} .",
            TEST_IMAGE, TEST_TAG
        );
        panic!("Missing Docker image");
    }

    ensure_network_exists();

    let temp_dir = tempfile::tempdir().expect("create temp dir");

    let node_a_config_path = temp_dir.path().join("node-a-tp.yaml");
    let node_b_config_path = temp_dir.path().join("node-b-tp.yaml");
    std::fs::write(&node_a_config_path, THROUGHPUT_NODE_A_CONFIG).expect("write node-a config");
    std::fs::write(&node_b_config_path, THROUGHPUT_NODE_B_CONFIG).expect("write node-b config");

    let node_a = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-a-tp")
        .with_network(TEST_NETWORK)
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            node_a_config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .start()
        .await
        .expect("start node-a-tp");

    let node_b = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-b-tp")
        .with_network(TEST_NETWORK)
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            node_b_config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .start()
        .await
        .expect("start node-b-tp");

    // Wait for DNS refresh and tunnel establishment
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Start iperf3 server on node B (daemon mode, -1 = exit after single client)
    let server = node_b
        .exec(testcontainers::core::ExecCommand::new([
            "iperf3", "-s", "-D", "-1",
        ]))
        .await
        .expect("start iperf3 server");
    let server_exit = server.exit_code().await.unwrap();
    assert_eq!(server_exit, Some(0), "iperf3 server failed to start");

    // Brief pause for server readiness
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Run iperf3 client on node A -> node B via tunnel
    let mut client = node_a
        .exec(testcontainers::core::ExecCommand::new([
            "iperf3",
            "-c",
            "10.0.0.2",
            "-t",
            &IPERF_DURATION_SECS.to_string(),
            "-J", // JSON output
        ]))
        .await
        .expect("run iperf3 client");

    let client_out = client.stdout_to_vec().await.unwrap();
    let client_exit = client.exit_code().await.unwrap();
    let json_output = String::from_utf8_lossy(&client_out);

    println!(
        "iperf3 client output (raw JSON length: {} bytes)",
        json_output.len()
    );

    assert_eq!(
        client_exit,
        Some(0),
        "iperf3 client failed (exit={client_exit:?})\nOutput: {json_output}"
    );

    let bps = parse_iperf3_bps(&json_output).expect("failed to parse iperf3 JSON output");

    println!("BareUDP tunnel throughput: {}", format_throughput(bps));

    assert!(bps > 0.0, "Expected measurable throughput, got {bps} bps");

    drop(node_b);
    drop(node_a);
    drop(temp_dir);
}

/// HTTP/3 TCP throughput test.
///
/// 1. Generates self-signed certificates for both nodes
/// 2. Starts two h3llo containers with HTTP/3 tunnel
/// 3. Runs iperf3 server on node B (via VPN IP 10.0.0.2)
/// 4. Runs iperf3 client on node A targeting 10.0.0.2
/// 5. Parses JSON output and asserts throughput > 0
#[tokio::test]
#[ignore = "requires Docker and pre-built image with H3 support"]
async fn test_h3_tcp_throughput() {
    if !ensure_image_exists() {
        eprintln!(
            "Docker image {}:{} not found. Build with:",
            TEST_IMAGE, TEST_TAG
        );
        eprintln!(
            "  docker build --target test -t {}:{} .",
            TEST_IMAGE, TEST_TAG
        );
        panic!("Missing Docker image");
    }

    ensure_network_exists();

    let temp_dir = tempfile::tempdir().expect("create temp dir");

    // Generate certificates for both nodes
    let (node_a_cert, node_a_key) = generate_test_certs(temp_dir.path(), "node-a-tp-h3");
    let (node_b_cert, node_b_key) = generate_test_certs(temp_dir.path(), "node-b-tp-h3");

    let shared_secret = "throughput-test-secret";
    let node_a_config = h3_node_config(
        "node-a-tp-h3",
        "10.0.0.1",
        "node-b-tp-h3",
        "https://node-b-tp-h3.h3llo-test-net:443/",
        shared_secret,
        "10.0.0.2/32",
        "/certs/cert.pem",
        "/certs/key.pem",
    );
    let node_b_config = h3_node_config(
        "node-b-tp-h3",
        "10.0.0.2",
        "node-a-tp-h3",
        "https://node-a-tp-h3.h3llo-test-net:443/",
        shared_secret,
        "10.0.0.1/32",
        "/certs/cert.pem",
        "/certs/key.pem",
    );

    let node_a_config_path = temp_dir.path().join("node-a-tp-h3.yaml");
    let node_b_config_path = temp_dir.path().join("node-b-tp-h3.yaml");
    std::fs::write(&node_a_config_path, &node_a_config).expect("write node-a config");
    std::fs::write(&node_b_config_path, &node_b_config).expect("write node-b config");

    let node_a = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(443))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-a-tp-h3")
        .with_network(TEST_NETWORK)
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            node_a_config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .with_mount(Mount::bind_mount(
            node_a_cert.to_str().unwrap(),
            "/certs/cert.pem",
        ))
        .with_mount(Mount::bind_mount(
            node_a_key.to_str().unwrap(),
            "/certs/key.pem",
        ))
        .start()
        .await
        .expect("start node-a-tp-h3");

    let node_b = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(443))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-b-tp-h3")
        .with_network(TEST_NETWORK)
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            node_b_config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .with_mount(Mount::bind_mount(
            node_b_cert.to_str().unwrap(),
            "/certs/cert.pem",
        ))
        .with_mount(Mount::bind_mount(
            node_b_key.to_str().unwrap(),
            "/certs/key.pem",
        ))
        .start()
        .await
        .expect("start node-b-tp-h3");

    // Wait for DNS refresh cycles and H3 handshake
    tokio::time::sleep(Duration::from_secs(8)).await;

    // Start iperf3 server on node B (daemon mode, -1 = exit after single client)
    let server = node_b
        .exec(testcontainers::core::ExecCommand::new([
            "iperf3", "-s", "-D", "-1",
        ]))
        .await
        .expect("start iperf3 server");
    let server_exit = server.exit_code().await.unwrap();
    assert_eq!(server_exit, Some(0), "iperf3 server failed to start");

    // Brief pause for server readiness
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Run iperf3 client on node A -> node B via tunnel
    let mut client = node_a
        .exec(testcontainers::core::ExecCommand::new([
            "iperf3",
            "-c",
            "10.0.0.2",
            "-t",
            &IPERF_DURATION_SECS.to_string(),
            "-J", // JSON output
        ]))
        .await
        .expect("run iperf3 client");

    let client_out = client.stdout_to_vec().await.unwrap();
    let client_exit = client.exit_code().await.unwrap();
    let json_output = String::from_utf8_lossy(&client_out);

    println!(
        "iperf3 client output (raw JSON length: {} bytes)",
        json_output.len()
    );

    assert_eq!(
        client_exit,
        Some(0),
        "iperf3 client failed (exit={client_exit:?})\nOutput: {json_output}"
    );

    let bps = parse_iperf3_bps(&json_output).expect("failed to parse iperf3 JSON output");

    println!("H3 tunnel throughput: {}", format_throughput(bps));

    assert!(bps > 0.0, "Expected measurable throughput, got {bps} bps");

    drop(node_b);
    drop(node_a);
    drop(temp_dir);
}
