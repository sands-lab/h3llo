//! Three-node BareUDP userspace forwarding end-to-end test.
//!
//! Topology:
//!   Node A (10.0.0.1) <─BareUDP─> Relay B (10.0.0.2) <─BareUDP─> Node C (10.0.0.3)
//!
//! Run with: `cargo test --test e2e -- --ignored --nocapture forwarding`

use std::time::Duration;

use super::common::{assert_ping, bareudp_config, start_bareudp_node, BareUdpPeer, TestContext};

/// Three-node BareUDP userspace forwarding test.
///
/// Proves relay Node B forwards packets between edge nodes A and C
/// via `handle_transport_batch` (LPM lookup + TTL decrement).
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_three_node_bareudp_forwarding() {
    let ctx = TestContext::new().await;

    let name_a = ctx.container_name("node-a-fwd");
    let fqdn_a = ctx.fqdn("node-a-fwd");
    let name_relay = ctx.container_name("relay-fwd");
    let fqdn_relay = ctx.fqdn("relay-fwd");
    let name_c = ctx.container_name("node-c-fwd");
    let fqdn_c = ctx.fqdn("node-c-fwd");

    // Node A: all 10.0.0.0/24 traffic goes through relay B.
    let cfg_a = bareudp_config(
        "10.0.0.1/32",
        &[BareUdpPeer {
            id: &name_relay,
            fqdn: &fqdn_relay,
            allowed_ips: &["10.0.0.0/24"],
        }],
    );

    // Relay B: routes A's IP to A, C's IP to C.
    let cfg_relay = bareudp_config(
        "10.0.0.2/32",
        &[
            BareUdpPeer {
                id: &name_a,
                fqdn: &fqdn_a,
                allowed_ips: &["10.0.0.1/32"],
            },
            BareUdpPeer {
                id: &name_c,
                fqdn: &fqdn_c,
                allowed_ips: &["10.0.0.3/32"],
            },
        ],
    );

    // Node C: mirrors A — all 10.0.0.0/24 traffic goes through relay B.
    let cfg_c = bareudp_config(
        "10.0.0.3/32",
        &[BareUdpPeer {
            id: &name_relay,
            fqdn: &fqdn_relay,
            allowed_ips: &["10.0.0.0/24"],
        }],
    );

    let node_a = start_bareudp_node(&ctx, "node-a-fwd", &cfg_a).await;
    let relay = start_bareudp_node(&ctx, "relay-fwd", &cfg_relay).await;
    let node_c = start_bareudp_node(&ctx, "node-c-fwd", &cfg_c).await;

    // Wait for DNS refresh cycles to resolve all peers (1s interval + buffer).
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Precondition: direct peer connectivity (one per link).
    assert_ping(&node_a, "10.0.0.2", "a->relay (direct)").await;
    assert_ping(&relay, "10.0.0.3", "relay->c (direct)").await;

    // Main assertion: forwarded connectivity through relay.
    assert_ping(&node_a, "10.0.0.3", "a->c (forwarded via relay)").await;
    assert_ping(&node_c, "10.0.0.1", "c->a (forwarded via relay)").await;

    drop(node_c);
    drop(relay);
    drop(node_a);
}
