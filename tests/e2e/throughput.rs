//! Throughput end-to-end tests using iperf3 inside Docker containers.
//!
//! Measures TCP throughput through VPN tunnels to verify data-plane
//! forwarding works beyond simple ping connectivity. Covers both
//! BareUDP and HTTP/3 transports.

use std::time::Duration;
use testcontainers::core::{ContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::common::{
    bareudp_config, format_throughput, parse_iperf3_bps, TestContext, TEST_IMAGE, TEST_TAG,
};
use super::h3::{generate_test_certs, h3_node_config};

/// iperf3 test duration in seconds.
const IPERF_DURATION_SECS: u32 = 5;

/// Runs iperf3 between two containers and returns measured throughput in bps.
///
/// Starts an iperf3 server (daemon, single-client mode) on `server`, then
/// runs an iperf3 client on `client` targeting `target_ip`. Parses JSON
/// output and asserts throughput > 0.
async fn run_iperf3_throughput(
    server: &ContainerAsync<GenericImage>,
    client: &ContainerAsync<GenericImage>,
    target_ip: &str,
    label: &str,
) -> f64 {
    // Start iperf3 server (-1 = exit after single client).
    // Don't use -D (daemon) as it forks, which breaks exit_code() in container exec.
    // exec() returns immediately, so the server runs in the background.
    let _srv = server
        .exec(testcontainers::core::ExecCommand::new([
            "iperf3", "-s", "-1",
        ]))
        .await
        .expect("start iperf3 server");

    // Brief pause for server readiness
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Run iperf3 client targeting the server via tunnel
    let mut cli = client
        .exec(testcontainers::core::ExecCommand::new([
            "iperf3",
            "-c",
            target_ip,
            "-t",
            &IPERF_DURATION_SECS.to_string(),
            "-J", // JSON output
        ]))
        .await
        .expect("run iperf3 client");

    let cli_out = cli.stdout_to_vec().await.unwrap();
    let cli_exit = cli.exit_code().await.unwrap();
    let json_output = String::from_utf8_lossy(&cli_out);

    println!(
        "iperf3 client output (raw JSON length: {} bytes)",
        json_output.len()
    );

    assert_eq!(
        cli_exit,
        Some(0),
        "iperf3 client failed (exit={cli_exit:?})\nOutput: {json_output}"
    );

    let bps = parse_iperf3_bps(&json_output).expect("failed to parse iperf3 JSON output");

    println!("{label} throughput: {}", format_throughput(bps));

    assert!(bps > 0.0, "Expected measurable throughput, got {bps} bps");

    bps
}

/// BareUDP TCP throughput test.
///
/// 1. Starts two h3llo containers with BareUDP tunnel
/// 2. Runs iperf3 through the tunnel and asserts throughput > 0
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_bareudp_tcp_throughput() {
    let ctx = TestContext::new();
    let temp_dir = tempfile::tempdir().expect("create temp dir");

    let name_a = ctx.container_name("node-a-tp");
    let name_b = ctx.container_name("node-b-tp");

    let node_a_cfg = bareudp_config(
        "10.0.0.1/32",
        &name_b,
        &ctx.fqdn("node-b-tp"),
        "10.0.0.2/32",
    );
    let node_b_cfg = bareudp_config(
        "10.0.0.2/32",
        &name_a,
        &ctx.fqdn("node-a-tp"),
        "10.0.0.1/32",
    );

    let node_a_config_path = temp_dir.path().join("node-a-tp.yaml");
    let node_b_config_path = temp_dir.path().join("node-b-tp.yaml");
    std::fs::write(&node_a_config_path, &node_a_cfg).expect("write node-a config");
    std::fs::write(&node_b_config_path, &node_b_cfg).expect("write node-b config");

    let node_a = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(2))
        .with_container_name(&name_a)
        .with_network(ctx.network())
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
        .with_container_name(&name_b)
        .with_network(ctx.network())
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

    run_iperf3_throughput(&node_b, &node_a, "10.0.0.2", "BareUDP tunnel").await;

    drop(node_b);
    drop(node_a);
    drop(temp_dir);
}

/// HTTP/3 TCP throughput test.
///
/// 1. Starts two h3llo containers with HTTP/3 tunnel
/// 2. Runs iperf3 through the tunnel and asserts throughput > 0
#[tokio::test]
#[ignore = "requires Docker and pre-built image with H3 support"]
async fn test_h3_tcp_throughput() {
    let ctx = TestContext::new();
    let temp_dir = tempfile::tempdir().expect("create temp dir");

    let name_a = ctx.container_name("node-a-tp-h3");
    let name_b = ctx.container_name("node-b-tp-h3");

    // Generate certificates for both nodes
    let (node_a_cert, node_a_key) = generate_test_certs(temp_dir.path(), &name_a, ctx.network());
    let (node_b_cert, node_b_key) = generate_test_certs(temp_dir.path(), &name_b, ctx.network());

    let shared_secret = "throughput-test-secret";
    let node_a_config = h3_node_config(
        "10.0.0.1/32",
        &name_b,
        &format!("https://{}:443/", ctx.fqdn("node-b-tp-h3")),
        shared_secret,
        "10.0.0.2/32",
        "/certs/cert.pem",
        "/certs/key.pem",
    );
    let node_b_config = h3_node_config(
        "10.0.0.2/32",
        &name_a,
        &format!("https://{}:443/", ctx.fqdn("node-a-tp-h3")),
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
        .expect("start node-a-tp-h3");

    let node_b = GenericImage::new(TEST_IMAGE, TEST_TAG)
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
        .expect("start node-b-tp-h3");

    // Wait for DNS refresh cycles and H3 handshake
    tokio::time::sleep(Duration::from_secs(8)).await;

    run_iperf3_throughput(&node_b, &node_a, "10.0.0.2", "H3 tunnel").await;

    drop(node_b);
    drop(node_a);
    drop(temp_dir);
}
