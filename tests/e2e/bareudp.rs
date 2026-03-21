//! BareUDP end-to-end integration tests using testcontainers-rs.
//!
//! These tests verify multi-node BareUDP VPN connectivity, source IP filtering,
//! and MTU boundary behavior using real TUN devices inside Docker containers.
//! Requires Docker daemon and CAP_NET_ADMIN.
//!
//! Run with: `cargo test --test e2e -- --ignored --nocapture`

use std::time::Duration;

use super::common::{assert_ping, bareudp_config, start_bareudp_node, BareUdpPeer, TestContext};

/// Integration test: Two-node BareUDP tunnel connectivity.
///
/// This test:
/// 1. Creates a per-test Docker network for container DNS resolution
/// 2. Starts two h3llo containers with named hostnames
/// 3. Verifies bidirectional ping over the VPN tunnel
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_two_node_bareudp_tunnel() {
    let ctx = TestContext::new();

    let name_a = ctx.container_name("node-a");
    let name_b = ctx.container_name("node-b");
    let fqdn_a = ctx.fqdn("node-a");
    let fqdn_b = ctx.fqdn("node-b");

    let cfg_a = bareudp_config(
        "10.0.0.1/32",
        &[BareUdpPeer {
            id: &name_b,
            fqdn: &fqdn_b,
            allowed_ips: &["10.0.0.2/32"],
        }],
    );
    let cfg_b = bareudp_config(
        "10.0.0.2/32",
        &[BareUdpPeer {
            id: &name_a,
            fqdn: &fqdn_a,
            allowed_ips: &["10.0.0.1/32"],
        }],
    );

    let node_a = start_bareudp_node(&ctx, "node-a", &cfg_a).await;
    let node_b = start_bareudp_node(&ctx, "node-b", &cfg_b).await;

    // Wait for DNS refresh cycles to resolve both peers (1s interval + buffer)
    tokio::time::sleep(Duration::from_secs(5)).await;

    assert_ping(&node_a, "10.0.0.2", "a->b").await;
    assert_ping(&node_b, "10.0.0.1", "b->a").await;

    drop(node_b);
    drop(node_a);
}

/// Integration test: BareUDP source IP filtering.
///
/// Verifies that packets from non-allowed sources are dropped.
/// Uses a third container that is NOT in the peer's allowed_ips.
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_source_ip_filtering() {
    let ctx = TestContext::new();

    let name_a = ctx.container_name("node-a-filter");
    let fqdn_a = ctx.fqdn("node-a-filter");
    let fake_peer = ctx.container_name("node-b");
    let fqdn_fake = ctx.fqdn("node-b");

    // Node A only allows 10.0.0.2 (non-existent node-b); not 10.0.0.3.
    let cfg_a = bareudp_config(
        "10.0.0.1/32",
        &[BareUdpPeer {
            id: &fake_peer,
            fqdn: &fqdn_fake,
            allowed_ips: &["10.0.0.2/32"],
        }],
    );
    // Node C peers with A but has IP 10.0.0.3 (not in A's allowed_ips).
    let cfg_c = bareudp_config(
        "10.0.0.3/32",
        &[BareUdpPeer {
            id: &name_a,
            fqdn: &fqdn_a,
            allowed_ips: &["10.0.0.1/32"],
        }],
    );

    let node_a = start_bareudp_node(&ctx, "node-a-filter", &cfg_a).await;
    let node_c = start_bareudp_node(&ctx, "node-c", &cfg_c).await;

    // Wait for DNS refresh cycles (1s interval + buffer)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Ping from node C to node A should fail: source 10.0.0.3 not in A's allowed_ips.
    let mut result = node_c
        .exec(testcontainers::core::ExecCommand::new([
            "ping", "-c", "2", "-W", "2", "10.0.0.1",
        ]))
        .await
        .expect("exec ping c->a");
    let stdout = result.stdout_to_vec().await.unwrap();
    let stderr = result.stderr_to_vec().await.unwrap();
    let exit = result.exit_code().await.unwrap();
    println!(
        "Ping c->a (expected failure):\n{}",
        String::from_utf8_lossy(&stdout)
    );
    assert_ne!(
        exit,
        Some(0),
        "ping c->a should have failed (exit={exit:?})\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );

    drop(node_c);
    drop(node_a);
}

/// Integration test: MTU boundary checks.
///
/// Verifies that packets at the default MTU pass through while oversized
/// packets are dropped when DF (Don't Fragment) is set.
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_mtu_boundary_drop() {
    let ctx = TestContext::new();

    let name_a = ctx.container_name("node-a-mtu");
    let name_b = ctx.container_name("node-b-mtu");
    let fqdn_a = ctx.fqdn("node-a-mtu");
    let fqdn_b = ctx.fqdn("node-b-mtu");

    let cfg_a = bareudp_config(
        "10.0.0.1/32",
        &[BareUdpPeer {
            id: &name_b,
            fqdn: &fqdn_b,
            allowed_ips: &["10.0.0.2/32"],
        }],
    );
    let cfg_b = bareudp_config(
        "10.0.0.2/32",
        &[BareUdpPeer {
            id: &name_a,
            fqdn: &fqdn_a,
            allowed_ips: &["10.0.0.1/32"],
        }],
    );

    let node_a = start_bareudp_node(&ctx, "node-a-mtu", &cfg_a).await;
    let node_b = start_bareudp_node(&ctx, "node-b-mtu", &cfg_b).await;

    // Wait for DNS refresh cycles to resolve both peers (1s interval + buffer)
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Compute ping payload sizes from default MTU.
    // Max payload = MTU - 20 (IP hdr) - 8 (ICMP hdr).
    let mtu = h3llo::config::default_mtu();
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
}
