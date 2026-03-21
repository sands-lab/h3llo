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
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use super::common::{assert_ping, TestContext, TEST_IMAGE, TEST_TAG};
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
#[allow(clippy::too_many_arguments)]
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

    let name_a = ctx.container_name("node-a-mp");
    let name_b = ctx.container_name("node-b-mp");

    // Generate TLS certificates for both nodes
    let (node_a_cert, node_a_key) = generate_test_certs(&name_a, ctx.network());
    let (node_b_cert, node_b_key) = generate_test_certs(&name_b, ctx.network());

    // Peer IDs must be unique within a config. Use "-bare"/"-h3" suffixes to
    // distinguish the two transport peers pointing at the same container.
    let peer_b_bare = format!("{name_b}-bare");
    let peer_b_h3 = format!("{name_b}-h3");
    let peer_a_bare = format!("{name_a}-bare");
    let peer_a_h3 = format!("{name_a}-h3");

    // Create config files
    let node_a_config = multipath_config(
        "10.0.0.1/24",
        "10.0.1.1/24",
        &peer_b_bare,
        &ctx.fqdn("node-b-mp"),
        &peer_b_h3,
        &ctx.fqdn("node-b-mp"),
        "/certs/cert.pem",
        "/certs/key.pem",
    );
    let node_b_config = multipath_config(
        "10.0.0.2/24",
        "10.0.1.2/24",
        &peer_a_bare,
        &ctx.fqdn("node-a-mp"),
        &peer_a_h3,
        &ctx.fqdn("node-a-mp"),
        "/certs/cert.pem",
        "/certs/key.pem",
    );

    // Start Node A
    let node_a = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_exposed_port(ContainerPort::Udp(443))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name(&name_a)
        .with_network(ctx.network())
        .with_privileged(true)
        .with_copy_to("/etc/h3llo/config.yaml", node_a_config.into_bytes())
        .with_copy_to("/certs/cert.pem", node_a_cert)
        .with_copy_to("/certs/key.pem", node_a_key)
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
        .with_copy_to("/etc/h3llo/config.yaml", node_b_config.into_bytes())
        .with_copy_to("/certs/cert.pem", node_b_cert)
        .with_copy_to("/certs/key.pem", node_b_key)
        .start()
        .await
        .expect("start node-b");

    // Wait for DNS refresh cycles and H3 handshake
    // Need extra time for both BareUDP and H3 to establish
    tokio::time::sleep(Duration::from_secs(10)).await;

    assert_ping(&node_a, "10.0.0.2", "bareudp a->b").await;
    assert_ping(&node_a, "10.0.1.2", "h3 a->b").await;
    assert_ping(&node_b, "10.0.0.1", "bareudp b->a").await;
    assert_ping(&node_b, "10.0.1.1", "h3 b->a").await;

    drop(node_b);
    drop(node_a);
}
