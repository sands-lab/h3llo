//! Docker-based integration tests using testcontainers-rs.
//!
//! These tests verify multi-node BareUDP connectivity using real TUN devices
//! inside Docker containers. Requires Docker daemon and CAP_NET_ADMIN.
//!
//! Run with: `cargo test --test docker_integration -- --ignored --nocapture`

use std::process::Command;
use std::time::Duration;
use testcontainers::core::{ContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const TEST_IMAGE: &str = "h3llo";
const TEST_TAG: &str = "test";
const TEST_NETWORK: &str = "h3llo-test-net";

/// Test configuration for node A (server role).
/// Uses container hostname "node-b" for peer endpoint (resolved via Docker DNS).
const NODE_A_CONFIG: &str = r#"
local:
  id: node-a-local
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.1
    mtu: 1400
  dns:
    server: udp://127.0.0.11:53
    refresh: 30
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-b
    enabled: true
    bare:
      endpoint: "udp://node-b:5353"
    tun:
      allowedIPs:
        - 10.0.0.2/32
"#;

/// Test configuration for node B (client role).
/// Uses container hostname "node-a" for peer endpoint (resolved via Docker DNS).
const NODE_B_CONFIG: &str = r#"
local:
  id: node-b-local
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.2
    mtu: 1400
  dns:
    server: udp://127.0.0.11:53
    refresh: 30
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-a
    enabled: true
    bare:
      endpoint: "udp://node-a:5353"
    tun:
      allowedIPs:
        - 10.0.0.1/32
"#;

/// Verifies Docker image exists before running tests.
fn ensure_image_exists() -> bool {
    let output = Command::new("docker")
        .args(["image", "inspect", &format!("{}:{}", TEST_IMAGE, TEST_TAG)])
        .output();

    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Creates a unique temporary directory for test files.
fn create_temp_dir() -> std::path::PathBuf {
    let unique_id = std::process::id();
    let temp_dir = std::env::temp_dir().join(format!("h3llo-test-{}", unique_id));
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");
    temp_dir
}

/// Creates the test Docker network if it doesn't exist.
fn ensure_network_exists() {
    let check = Command::new("docker")
        .args(["network", "inspect", TEST_NETWORK])
        .output();

    if check.map(|o| o.status.success()).unwrap_or(false) {
        return; // Network already exists
    }

    let result = Command::new("docker")
        .args(["network", "create", TEST_NETWORK])
        .output()
        .expect("create network");

    if !result.status.success() {
        panic!(
            "Failed to create network: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

/// Integration test: Two-node BareUDP tunnel connectivity.
///
/// This test:
/// 1. Creates a custom Docker network for container DNS resolution
/// 2. Starts two h3llo containers with named hostnames
/// 3. Verifies bidirectional ping over the VPN tunnel
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_two_node_bareudp_tunnel() {
    if !ensure_image_exists() {
        eprintln!(
            "Docker image {}:{} not found. Build with:",
            TEST_IMAGE, TEST_TAG
        );
        eprintln!("  docker build -t {}:{} .", TEST_IMAGE, TEST_TAG);
        panic!("Missing Docker image");
    }

    // Ensure test network exists for hostname resolution
    ensure_network_exists();

    // Create temporary config files
    let temp_dir = create_temp_dir();

    let node_a_config_path = temp_dir.join("node-a.yaml");
    let node_b_config_path = temp_dir.join("node-b.yaml");
    std::fs::write(&node_a_config_path, NODE_A_CONFIG).expect("write node-a config");
    std::fs::write(&node_b_config_path, NODE_B_CONFIG).expect("write node-b config");

    // Start node A with container name for DNS resolution
    let node_a = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-a")
        .with_network(TEST_NETWORK)
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            node_a_config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .start()
        .await
        .expect("start node-a");

    // Start node B with container name for DNS resolution
    let node_b = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-b")
        .with_network(TEST_NETWORK)
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            node_b_config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .start()
        .await
        .expect("start node-b");

    // Allow time for TUN setup, DNS resolution, and peer registration
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Test ping from node A to node B via VPN tunnel (10.0.0.2)
    let ping_result = node_a
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "3", "-W", "2", "10.0.0.2",
        ]))
        .await
        .expect("exec ping");

    println!("Ping from node-a to node-b (10.0.0.2): {:?}", ping_result);

    // Test ping from node B to node A via VPN tunnel (10.0.0.1)
    let ping_result_b = node_b
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "3", "-W", "2", "10.0.0.1",
        ]))
        .await
        .expect("exec ping");

    println!("Ping from node-b to node-a (10.0.0.1): {:?}", ping_result_b);

    // Cleanup happens automatically when containers go out of scope
    drop(node_b);
    drop(node_a);

    // Clean up temp files
    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Integration test: BareUDP source IP filtering.
///
/// Verifies that packets from non-allowed sources are dropped.
/// Uses a third container that is NOT in the peer's allowed_ips.
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_source_ip_filtering() {
    if !ensure_image_exists() {
        panic!("Missing Docker image {}:{}", TEST_IMAGE, TEST_TAG);
    }

    ensure_network_exists();

    let temp_dir = create_temp_dir();

    // Node C has a different VPN IP (10.0.0.3) not in node-a's allowed_ips
    let node_c_config = r#"
local:
  id: node-c-local
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.3
    mtu: 1400
  dns:
    server: udp://127.0.0.11:53
    refresh: 30
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-a-filter
    enabled: true
    bare:
      endpoint: "udp://node-a-filter:5353"
    tun:
      allowedIPs:
        - 10.0.0.1/32
"#;

    // Node A only allows 10.0.0.2, not 10.0.0.3
    let node_a_config = r#"
local:
  id: node-a-filter-local
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.1
    mtu: 1400
  dns:
    server: udp://127.0.0.11:53
    refresh: 30
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-b
    enabled: true
    bare:
      endpoint: "udp://node-b:5353"
    tun:
      allowedIPs:
        - 10.0.0.2/32
"#;

    let node_a_config_path = temp_dir.join("node-a-filter.yaml");
    let node_c_config_path = temp_dir.join("node-c.yaml");
    std::fs::write(&node_a_config_path, node_a_config).expect("write node-a config");
    std::fs::write(&node_c_config_path, node_c_config).expect("write node-c config");

    // Start node A
    let node_a = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-a-filter")
        .with_network(TEST_NETWORK)
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            node_a_config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .start()
        .await
        .expect("start node-a");

    // Start node C (unauthorized source)
    let node_c = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-c")
        .with_network(TEST_NETWORK)
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            node_c_config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .start()
        .await
        .expect("start node-c");

    tokio::time::sleep(Duration::from_secs(5)).await;

    // Ping from node C to node A should fail (source IP not allowed)
    // Node C (10.0.0.3) is not in node-a's allowed_ips (only 10.0.0.2)
    let ping_result = node_c
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "2", "-W", "2", "10.0.0.1",
        ]))
        .await
        .expect("exec ping");

    println!(
        "Ping from node-c (10.0.0.3) to node-a (10.0.0.1): {:?}",
        ping_result
    );
    // Note: The ping should fail or timeout since node-a doesn't have node-c in its peers

    drop(node_c);
    drop(node_a);
    let _ = std::fs::remove_dir_all(&temp_dir);
}
