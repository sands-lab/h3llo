//! BareUDP end-to-end integration tests using testcontainers-rs.
//!
//! These tests verify multi-node BareUDP VPN connectivity, source IP filtering,
//! and MTU boundary behavior using real TUN devices inside Docker containers.
//! Requires Docker daemon and CAP_NET_ADMIN.
//!
//! Run with: `cargo test --test e2e -- --ignored --nocapture`

use std::time::Duration;
use testcontainers::core::{ContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use super::common::{require_image_and_network, TEST_IMAGE, TEST_NETWORK, TEST_TAG};

/// Test configuration for node A (server role).
/// Uses FQDN container hostname for peer endpoint (Docker DNS requires FQDN format).
/// Short `tuning.dns_refresh_interval` (1s) handles startup order automatically.
const NODE_A_CONFIG: &str = r#"
local:
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.1/32
  dns:
    server: udp://127.0.0.11:53
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-b
    bare:
      endpoint: "udp://node-b.h3llo-test-net:5353"
    tun:
      allowed_ips:
        - 10.0.0.2/32
tuning:
  dns_refresh_interval: 1
"#;

/// Test configuration for node B (client role).
/// Uses FQDN container hostname for peer endpoint (Docker DNS requires FQDN format).
/// Short `tuning.dns_refresh_interval` (1s) handles startup order automatically.
const NODE_B_CONFIG: &str = r#"
local:
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.2/32
  dns:
    server: udp://127.0.0.11:53
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-a
    bare:
      endpoint: "udp://node-a.h3llo-test-net:5353"
    tun:
      allowed_ips:
        - 10.0.0.1/32
tuning:
  dns_refresh_interval: 1
"#;

/// Integration test: Two-node BareUDP tunnel connectivity.
///
/// This test:
/// 1. Creates a custom Docker network for container DNS resolution
/// 2. Starts two h3llo containers with named hostnames
/// 3. Verifies bidirectional ping over the VPN tunnel
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_two_node_bareudp_tunnel() {
    require_image_and_network();

    // Create temporary config files (TempDir auto-cleans on drop)
    let temp_dir = tempfile::tempdir().expect("create temp dir");

    let node_a_config_path = temp_dir.path().join("node-a.yaml");
    let node_b_config_path = temp_dir.path().join("node-b.yaml");
    std::fs::write(&node_a_config_path, NODE_A_CONFIG).expect("write node-a config");
    std::fs::write(&node_b_config_path, NODE_B_CONFIG).expect("write node-b config");

    // Start both nodes - h3llo handles DNS resolution timing via refresh interval.
    // No need to control startup order; DNS refresh (1s) ensures eventual resolution.
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

    // Wait for DNS refresh cycles to resolve both peers (1s interval + buffer)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Test ping from node A to node B via VPN tunnel (10.0.0.2)
    let mut ping_ab = node_a
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "3", "-W", "2", "10.0.0.2",
        ]))
        .await
        .expect("exec ping a->b");

    let ping_ab_out = ping_ab.stdout_to_vec().await.unwrap();
    let ping_ab_exit = ping_ab.exit_code().await.unwrap();
    println!(
        "Ping node-a -> node-b (10.0.0.2):\n{}",
        String::from_utf8_lossy(&ping_ab_out)
    );
    assert_eq!(
        ping_ab_exit,
        Some(0),
        "ping a->b failed (exit={ping_ab_exit:?})"
    );

    // Test ping from node B to node A via VPN tunnel (10.0.0.1)
    let mut ping_ba = node_b
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "3", "-W", "2", "10.0.0.1",
        ]))
        .await
        .expect("exec ping b->a");

    let ping_ba_out = ping_ba.stdout_to_vec().await.unwrap();
    let ping_ba_exit = ping_ba.exit_code().await.unwrap();
    println!(
        "Ping node-b -> node-a (10.0.0.1):\n{}",
        String::from_utf8_lossy(&ping_ba_out)
    );
    assert_eq!(
        ping_ba_exit,
        Some(0),
        "ping b->a failed (exit={ping_ba_exit:?})"
    );

    // Cleanup happens automatically when containers and temp_dir go out of scope
    drop(node_b);
    drop(node_a);
    drop(temp_dir);
}

/// Integration test: BareUDP source IP filtering.
///
/// Verifies that packets from non-allowed sources are dropped.
/// Uses a third container that is NOT in the peer's allowed_ips.
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_source_ip_filtering() {
    require_image_and_network();

    let temp_dir = tempfile::tempdir().expect("create temp dir");

    // Node C has a different VPN IP (10.0.0.3) not in node-a's allowed_ips
    let node_c_config = r#"
local:
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.3/32
  dns:
    server: udp://127.0.0.11:53
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-a-filter
    bare:
      endpoint: "udp://node-a-filter.h3llo-test-net:5353"
    tun:
      allowed_ips:
        - 10.0.0.1/32
tuning:
  dns_refresh_interval: 1
"#;

    // Node A only allows 10.0.0.2, not 10.0.0.3
    let node_a_config = r#"
local:
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.1/32
  dns:
    server: udp://127.0.0.11:53
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-b
    bare:
      endpoint: "udp://node-b.h3llo-test-net:5353"
    tun:
      allowed_ips:
        - 10.0.0.2/32
tuning:
  dns_refresh_interval: 1
"#;

    let node_a_config_path = temp_dir.path().join("node-a-filter.yaml");
    let node_c_config_path = temp_dir.path().join("node-c.yaml");
    std::fs::write(&node_a_config_path, node_a_config).expect("write node-a config");
    std::fs::write(&node_c_config_path, node_c_config).expect("write node-c config");

    // Start both nodes - h3llo handles DNS resolution timing via refresh interval.
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

    // Wait for DNS refresh cycles (1s interval + buffer)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Ping from node C to node A should fail (source IP not allowed)
    // Node C (10.0.0.3) is not in node-a's allowed_ips (only 10.0.0.2)
    let mut ping_ca = node_c
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "2", "-W", "2", "10.0.0.1",
        ]))
        .await
        .expect("exec ping c->a");

    let ping_ca_out = ping_ca.stdout_to_vec().await.unwrap();
    let ping_ca_exit = ping_ca.exit_code().await.unwrap();
    println!(
        "Ping node-c -> node-a (10.0.0.3 -> 10.0.0.1, should fail):\n{}",
        String::from_utf8_lossy(&ping_ca_out)
    );
    assert_ne!(
        ping_ca_exit,
        Some(0),
        "ping c->a should have failed but exit={ping_ca_exit:?}"
    );

    drop(node_c);
    drop(node_a);
    drop(temp_dir);
}

/// Integration test: MTU boundary checks.
///
/// Verifies that packets at the default MTU pass through while oversized
/// packets are dropped when DF (Don't Fragment) is set.
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_mtu_boundary_drop() {
    require_image_and_network();

    // Dedicated configs with container names matching the endpoints.
    // Short `tuning.dns_refresh_interval` (1s) handles startup order automatically.
    let node_a_mtu_config = r#"
local:
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.1/32
  dns:
    server: udp://127.0.0.11:53
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-b-mtu
    bare:
      endpoint: "udp://node-b-mtu.h3llo-test-net:5353"
    tun:
      allowed_ips:
        - 10.0.0.2/32
tuning:
  dns_refresh_interval: 1
"#;

    let node_b_mtu_config = r#"
local:
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.2/32
  dns:
    server: udp://127.0.0.11:53
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: node-a-mtu
    bare:
      endpoint: "udp://node-a-mtu.h3llo-test-net:5353"
    tun:
      allowed_ips:
        - 10.0.0.1/32
tuning:
  dns_refresh_interval: 1
"#;

    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let node_a_config_path = temp_dir.path().join("node-a-mtu.yaml");
    let node_b_config_path = temp_dir.path().join("node-b-mtu.yaml");
    std::fs::write(&node_a_config_path, node_a_mtu_config).expect("write node-a config");
    std::fs::write(&node_b_config_path, node_b_mtu_config).expect("write node-b config");

    // Start both nodes - h3llo handles DNS resolution timing via refresh interval.
    // No need to control startup order; DNS refresh (1s) ensures eventual resolution.
    let node_a = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-a-mtu")
        .with_network(TEST_NETWORK)
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            node_a_config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .start()
        .await
        .expect("start node-a-mtu");

    let node_b = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-b-mtu")
        .with_network(TEST_NETWORK)
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            node_b_config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .start()
        .await
        .expect("start node-b-mtu");

    // Wait for DNS refresh cycles to resolve both peers (1s interval + buffer)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Compute ping payload sizes from default MTU.
    // Max payload = MTU - 20 (IP hdr) - 8 (ICMP hdr).
    let mtu = h3llo::config::default_mtu() as u16;
    let ok_payload = (mtu - 20 - 8).to_string();
    let exceed_payload = mtu.to_string();

    let mut ping_ok = node_a
        .exec(testcontainers::core::ExecCommand::new([
            "ping",
            "-c",
            "2",
            "-W",
            "2",
            "-s",
            ok_payload.as_str(),
            "-M",
            "do",
            "10.0.0.2",
        ]))
        .await
        .expect("exec ping mtu-ok");
    let ping_ok_out = ping_ok.stdout_to_vec().await.unwrap();
    let exit_ok = ping_ok.exit_code().await.unwrap();
    println!(
        "Ping MTU-ok ({ok_payload} bytes payload):\n{}",
        String::from_utf8_lossy(&ping_ok_out)
    );
    assert_eq!(
        exit_ok,
        Some(0),
        "ping with MTU-fitting payload should succeed"
    );

    // Ping with payload exceeding MTU (DF set, should be dropped)
    let mut ping_big = node_a
        .exec(testcontainers::core::ExecCommand::new([
            "ping",
            "-c",
            "2",
            "-W",
            "2",
            "-s",
            exceed_payload.as_str(),
            "-M",
            "do",
            "10.0.0.2",
        ]))
        .await
        .expect("exec ping mtu-exceed");
    let ping_big_out = ping_big.stdout_to_vec().await.unwrap();
    let exit_big = ping_big.exit_code().await.unwrap();
    println!(
        "Ping MTU-exceed ({exceed_payload} bytes payload, should fail):\n{}",
        String::from_utf8_lossy(&ping_big_out)
    );
    assert_ne!(
        exit_big,
        Some(0),
        "ping exceeding MTU should fail with DF set"
    );

    drop(node_b);
    drop(node_a);
    drop(temp_dir);
}
