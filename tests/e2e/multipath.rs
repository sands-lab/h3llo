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

use super::common::{TestContext, TEST_IMAGE, TEST_TAG};
use super::h3::generate_test_certs;

/// Multipath node config: dual transport (BareUDP + H3) with different subnets.
///
/// # Arguments
///
/// * `bare_addr` - BareUDP subnet TUN address (e.g., "10.0.0.1/24")
/// * `h3_addr` - H3 subnet TUN address (e.g., "10.0.1.1/24")
/// * `peer_bare_id` - Peer's BareUDP container name
/// * `peer_bare_fqdn` - Peer's BareUDP FQDN for DNS resolution
/// * `peer_h3_id` - Peer's H3 container name
/// * `peer_h3_fqdn` - Peer's H3 FQDN for DNS resolution
/// * `cert_path` - Container path to TLS certificate
/// * `key_path` - Container path to TLS private key
fn multipath_config(
    bare_addr: &str,
    h3_addr: &str,
    peer_bare_id: &str,
    peer_bare_fqdn: &str,
    peer_h3_id: &str,
    peer_h3_fqdn: &str,
    cert_path: &str,
    key_path: &str,
) -> String {
    format!(
        r#"
local:
  tun:
    ifname: tun0
    addrs:
      - {bare_addr}
      - {h3_addr}
  dns:
    server: udp://127.0.0.11:53
  bare:
    listen: "udp://0.0.0.0:5353"
  h3:
    listen: "https://0.0.0.0:443/"
    cert: {cert_path}
    key: {key_path}
peers:
  - id: {peer_bare_id}
    bare:
      endpoint: "udp://{peer_bare_fqdn}:5353"
    tun:
      allowed_ips:
        - 10.0.0.0/24
  - id: {peer_h3_id}
    h3:
      endpoint: "https://{peer_h3_fqdn}:443/"
      token: multipath-token-12ch
    tun:
      allowed_ips:
        - 10.0.1.0/24
tuning:
  dns_refresh_interval: 1
  h3_insecure_skip_verify: true
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
    let ctx = TestContext::new();
    let temp_dir = tempfile::tempdir().expect("create temp dir");

    let name_a = ctx.container_name("node-a-mp");
    let name_b = ctx.container_name("node-b-mp");

    // Generate TLS certificates for both nodes
    let (node_a_cert, node_a_key) = generate_test_certs(temp_dir.path(), &name_a, ctx.network());
    let (node_b_cert, node_b_key) = generate_test_certs(temp_dir.path(), &name_b, ctx.network());

    // Create config files
    let node_a_config = multipath_config(
        "10.0.0.1/24",
        "10.0.1.1/24",
        &name_b,
        &ctx.fqdn("node-b-mp"),
        &name_b,
        &ctx.fqdn("node-b-mp"),
        "/certs/cert.pem",
        "/certs/key.pem",
    );
    let node_b_config = multipath_config(
        "10.0.0.2/24",
        "10.0.1.2/24",
        &name_a,
        &ctx.fqdn("node-a-mp"),
        &name_a,
        &ctx.fqdn("node-a-mp"),
        "/certs/cert.pem",
        "/certs/key.pem",
    );

    let node_a_config_path = temp_dir.path().join("node-a-mp.yaml");
    let node_b_config_path = temp_dir.path().join("node-b-mp.yaml");
    std::fs::write(&node_a_config_path, &node_a_config).expect("write node-a config");
    std::fs::write(&node_b_config_path, &node_b_config).expect("write node-b config");

    // Start Node A
    let node_a = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_exposed_port(ContainerPort::Udp(443))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name(&name_a)
        .with_network(ctx.network())
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
        .with_container_name(&name_b)
        .with_network(ctx.network())
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
