//! HTTP/3 end-to-end integration tests using testcontainers-rs.
//!
//! These tests verify multi-node HTTP/3 VPN connectivity using real TUN devices
//! inside Docker containers with self-signed certificates.
//!
//! Run with: `cargo test --test e2e -- --ignored --nocapture`

use std::time::Duration;
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use super::common::{assert_ping, TestContext, TEST_IMAGE, TEST_TAG};

/// Generates self-signed certificate and key PEM bytes for testing.
///
/// # Arguments
///
/// * `hostname` - Primary hostname for the certificate
/// * `network` - Docker network name for FQDN SAN entry
///
/// # Returns
///
/// Tuple of `(cert_pem_bytes, key_pem_bytes)`.
pub(super) fn generate_test_certs(hostname: &str, network: &str) -> (Vec<u8>, Vec<u8>) {
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    let subject_alt_names = vec![
        hostname.to_string(),
        format!("{}.{}", hostname, network),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names).expect("cert generation");

    (
        cert.pem().into_bytes(),
        signing_key.serialize_pem().into_bytes(),
    )
}

/// Test configuration template for H3 node.
///
/// # Arguments
///
/// * `tun_addr` - VPN tunnel IP address (e.g., "10.0.0.1")
/// * `peer_id` - Remote peer identifier
/// * `peer_endpoint` - HTTPS endpoint URL for peer (FQDN format)
/// * `peer_token` - Peer authentication token (>= 12 characters)
/// * `peer_allowed_ip` - CIDR allowed IP for peer traffic
/// * `cert_path` - Container path to TLS certificate
/// * `key_path` - Container path to TLS private key
pub(super) fn h3_node_config(
    tun_addr: &str,
    peer_id: &str,
    peer_endpoint: &str,
    peer_token: &str,
    peer_allowed_ip: &str,
    cert_path: &str,
    key_path: &str,
) -> String {
    format!(
        r#"
local:
  tun:
    ifname: tun0
    addrs:
      - {tun_addr}
  dns:
    server: udp://127.0.0.11:53
  h3:
    listen: "https://0.0.0.0:443/"
    cert: {cert_path}
    key: {key_path}
peers:
  - id: {peer_id}
    h3:
      endpoint: {peer_endpoint}
      token: {peer_token}
    tun:
      allowed_ips:
        - {peer_allowed_ip}
tuning:
  dns_refresh_interval: 1
  h3_insecure_skip_verify: true
"#
    )
}

/// Integration test: Two-node HTTP/3 tunnel connectivity.
///
/// This test:
/// 1. Generates self-signed certificates for both nodes
/// 2. Creates a per-test Docker network for container DNS resolution
/// 3. Starts two h3llo containers with H3 transport
/// 4. Verifies bidirectional ping over the VPN tunnel
#[tokio::test]
#[ignore = "requires Docker and pre-built image with H3 support"]
async fn test_two_node_h3_tunnel() {
    let ctx = TestContext::new().await;

    let name_a = ctx.container_name("node-a-h3");
    let name_b = ctx.container_name("node-b-h3");

    // Generate certificates for both nodes
    let (node_a_cert, node_a_key) = generate_test_certs(&name_a, ctx.network());
    let (node_b_cert, node_b_key) = generate_test_certs(&name_b, ctx.network());

    // Create config files
    // The token must match cross-wise: Node_A.peers[B].token == Node_B.peers[A].token
    // This is because client sends peers[target].token, server validates with peers[client].token
    let shared_secret = "shared-tunnel-secret";
    let node_a_config = h3_node_config(
        "10.0.0.1/32",
        &name_b,
        &format!("https://{}:443/", ctx.fqdn("node-b-h3")),
        shared_secret,
        "10.0.0.2/32",
        "/certs/cert.pem",
        "/certs/key.pem",
    );

    let node_b_config = h3_node_config(
        "10.0.0.2/32",
        &name_a,
        &format!("https://{}:443/", ctx.fqdn("node-a-h3")),
        shared_secret,
        "10.0.0.1/32",
        "/certs/cert.pem",
        "/certs/key.pem",
    );

    // Start both nodes
    let node_a = GenericImage::new(TEST_IMAGE, TEST_TAG)
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

    let node_b = GenericImage::new(TEST_IMAGE, TEST_TAG)
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
    tokio::time::sleep(Duration::from_secs(8)).await;

    assert_ping(&node_a, "10.0.0.2", "h3 a->b").await;
    assert_ping(&node_b, "10.0.0.1", "h3 b->a").await;

    drop(node_b);
    drop(node_a);
}
