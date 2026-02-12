//! Multipath end-to-end integration test.
//!
//! Verifies that h3llo can route different subnets through different transport
//! peers. This test uses a topology where Node A and Node B each have two TUN
//! addresses, with BareUDP handling one subnet and HTTP/3 handling another.
//!
//! Topology:
//! - Node A: TUN with 10.0.0.1/24 and 10.0.1.1/24
//!   - Peer B-bare (BareUDP): allowed_ips 10.0.0.0/24
//!   - Peer B-h3 (HTTP/3): allowed_ips 10.0.1.0/24
//! - Node B: TUN with 10.0.0.2/24 and 10.0.1.2/24
//!   - Peer A-bare (BareUDP): allowed_ips 10.0.0.0/24
//!   - Peer A-h3 (HTTP/3): allowed_ips 10.0.1.0/24
//!
//! Run with: `cargo test --test e2e -- --ignored --nocapture`

use std::time::Duration;
use testcontainers::core::{ContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use super::common::{require_image_and_network, TEST_IMAGE, TEST_NETWORK, TEST_TAG};
use super::h3::generate_test_certs;

/// Node A multipath config: dual transport (BareUDP + H3) with different subnets.
fn node_a_multipath_config(cert_path: &str, key_path: &str) -> String {
    format!(
        r#"
local:
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.1/24
      - 10.0.1.1/24
  dns:
    server: udp://127.0.0.11:53
  bare:
    listen: "udp://0.0.0.0:5353"
  h3:
    listen: "https://0.0.0.0:443/"
    cert: {cert_path}
    key: {key_path}
peers:
  - id: node-b-mp-bare
    bare:
      endpoint: "udp://node-b-mp.h3llo-test-net:5353"
    tun:
      allowed_ips:
        - 10.0.0.0/24
  - id: node-b-mp-h3
    h3:
      endpoint: "https://node-b-mp.h3llo-test-net:443/"
      token: multipath-token-12ch
      insecure: true
    tun:
      allowed_ips:
        - 10.0.1.0/24
tuning:
  dns_refresh_interval: 1
"#
    )
}

/// Node B multipath config: dual transport (BareUDP + H3) with different subnets.
fn node_b_multipath_config(cert_path: &str, key_path: &str) -> String {
    format!(
        r#"
local:
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.2/24
      - 10.0.1.2/24
  dns:
    server: udp://127.0.0.11:53
  bare:
    listen: "udp://0.0.0.0:5353"
  h3:
    listen: "https://0.0.0.0:443/"
    cert: {cert_path}
    key: {key_path}
peers:
  - id: node-a-mp-bare
    bare:
      endpoint: "udp://node-a-mp.h3llo-test-net:5353"
    tun:
      allowed_ips:
        - 10.0.0.0/24
  - id: node-a-mp-h3
    h3:
      endpoint: "https://node-a-mp.h3llo-test-net:443/"
      token: multipath-token-12ch
      insecure: true
    tun:
      allowed_ips:
        - 10.0.1.0/24
tuning:
  dns_refresh_interval: 1
"#
    )
}

/// Multipath end-to-end test: dual-subnet mixed transport.
///
/// This test verifies:
/// 1. Subnet 10.0.0.0/24 routes through BareUDP transport
/// 2. Subnet 10.0.1.0/24 routes through HTTP/3 transport
/// 3. Both paths can operate concurrently
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_multipath_dual_subnet_mixed_transport() {
    require_image_and_network();

    let temp_dir = tempfile::tempdir().expect("create temp dir");

    // Generate TLS certificates for both nodes
    let (node_a_cert, node_a_key) = generate_test_certs(temp_dir.path(), "node-a-mp");
    let (node_b_cert, node_b_key) = generate_test_certs(temp_dir.path(), "node-b-mp");

    // Create config files
    let node_a_config = node_a_multipath_config("/certs/cert.pem", "/certs/key.pem");
    let node_b_config = node_b_multipath_config("/certs/cert.pem", "/certs/key.pem");

    let node_a_config_path = temp_dir.path().join("node-a-mp.yaml");
    let node_b_config_path = temp_dir.path().join("node-b-mp.yaml");
    std::fs::write(&node_a_config_path, &node_a_config).expect("write node-a config");
    std::fs::write(&node_b_config_path, &node_b_config).expect("write node-b config");

    // Start Node A
    let node_a = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_exposed_port(ContainerPort::Udp(443))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-a-mp")
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
        .expect("start node-a");

    // Start Node B
    let node_b = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_exposed_port(ContainerPort::Udp(443))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name("node-b-mp")
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
        .expect("start node-b");

    // Wait for DNS refresh cycles and H3 handshake
    // Need extra time for both BareUDP and H3 to establish
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Test 1: Ping via BareUDP path (10.0.0.x subnet)
    let mut ping_bare_ab = node_a
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "3", "-W", "2", "10.0.0.2",
        ]))
        .await
        .expect("exec ping bareudp a->b");

    let ping_bare_ab_out = ping_bare_ab.stdout_to_vec().await.unwrap();
    let ping_bare_ab_exit = ping_bare_ab.exit_code().await.unwrap();
    println!(
        "Ping node-a -> node-b (10.0.0.2 via BareUDP):\n{}",
        String::from_utf8_lossy(&ping_bare_ab_out)
    );
    assert_eq!(
        ping_bare_ab_exit,
        Some(0),
        "BareUDP ping a->b failed (exit={ping_bare_ab_exit:?})"
    );

    // Test 2: Ping via H3 path (10.0.1.x subnet)
    let mut ping_h3_ab = node_a
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "3", "-W", "2", "10.0.1.2",
        ]))
        .await
        .expect("exec ping h3 a->b");

    let ping_h3_ab_out = ping_h3_ab.stdout_to_vec().await.unwrap();
    let ping_h3_ab_exit = ping_h3_ab.exit_code().await.unwrap();
    println!(
        "Ping node-a -> node-b (10.0.1.2 via H3):\n{}",
        String::from_utf8_lossy(&ping_h3_ab_out)
    );
    assert_eq!(
        ping_h3_ab_exit,
        Some(0),
        "H3 ping a->b failed (exit={ping_h3_ab_exit:?})"
    );

    // Test 3: Reverse direction - BareUDP path
    let mut ping_bare_ba = node_b
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "3", "-W", "2", "10.0.0.1",
        ]))
        .await
        .expect("exec ping bareudp b->a");

    let ping_bare_ba_out = ping_bare_ba.stdout_to_vec().await.unwrap();
    let ping_bare_ba_exit = ping_bare_ba.exit_code().await.unwrap();
    println!(
        "Ping node-b -> node-a (10.0.0.1 via BareUDP):\n{}",
        String::from_utf8_lossy(&ping_bare_ba_out)
    );
    assert_eq!(
        ping_bare_ba_exit,
        Some(0),
        "BareUDP ping b->a failed (exit={ping_bare_ba_exit:?})"
    );

    // Test 4: Reverse direction - H3 path
    let mut ping_h3_ba = node_b
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "3", "-W", "2", "10.0.1.1",
        ]))
        .await
        .expect("exec ping h3 b->a");

    let ping_h3_ba_out = ping_h3_ba.stdout_to_vec().await.unwrap();
    let ping_h3_ba_exit = ping_h3_ba.exit_code().await.unwrap();
    println!(
        "Ping node-b -> node-a (10.0.1.1 via H3):\n{}",
        String::from_utf8_lossy(&ping_h3_ba_out)
    );
    assert_eq!(
        ping_h3_ba_exit,
        Some(0),
        "H3 ping b->a failed (exit={ping_h3_ba_exit:?})"
    );

    // Cleanup
    drop(node_b);
    drop(node_a);
    drop(temp_dir);
}
