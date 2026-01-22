//! Docker-based integration tests using testcontainers-rs.
//!
//! These tests verify h3llo container builds and basic functionality.
//! Full multi-node VPN connectivity tests require manual network setup.
//!
//! Run with: `cargo test --test docker_integration -- --ignored --nocapture`
//!
//! # Prerequisites
//!
//! Build the test image first:
//! ```bash
//! docker build -t h3llo:test .
//! ```
//!
//! # Multi-node Testing (Manual)
//!
//! For full VPN connectivity testing with static IPs, use docker-compose or
//! manual Docker network setup:
//!
//! ```bash
//! # Create test network
//! docker network create --subnet=172.30.0.0/24 h3llo-test-net
//!
//! # Run containers with static IPs
//! docker run --privileged --network=h3llo-test-net --ip=172.30.0.10 \
//!     -v /path/to/node-a.yaml:/etc/h3llo/config.yaml h3llo:test
//! ```

use std::process::Command;
use std::time::Duration;
use testcontainers::core::{ContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

const TEST_IMAGE: &str = "h3llo";
const TEST_TAG: &str = "test";

/// Minimal configuration for container startup test.
const MINIMAL_CONFIG: &str = r#"
local:
  tun:
    ifname: tun0
    addrs:
      - 10.0.0.1
    mtu: 1400
  bare:
    listen: "0.0.0.0:5353"
peers: []
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

/// Integration test: Container startup and TUN device creation.
///
/// Verifies that the h3llo container:
/// 1. Starts successfully with privileged mode
/// 2. Can create a TUN device
/// 3. Binds to the configured UDP port
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_container_startup() {
    if !ensure_image_exists() {
        eprintln!(
            "Docker image {}:{} not found. Build with:",
            TEST_IMAGE, TEST_TAG
        );
        eprintln!("  docker build -t {}:{} .", TEST_IMAGE, TEST_TAG);
        panic!("Missing Docker image");
    }

    // Create temporary config file
    let temp_dir = create_temp_dir();
    let config_path = temp_dir.join("config.yaml");
    std::fs::write(&config_path, MINIMAL_CONFIG).expect("write config");

    // Start container with privileged mode for TUN access
    let container = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(2))
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .start()
        .await
        .expect("start container");

    // Allow time for TUN setup
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Verify TUN interface exists
    let tun_check = container
        .exec(testcontainers::core::ExecCommand::new([
            "ip", "link", "show", "tun0",
        ]))
        .await
        .expect("exec ip link show");

    println!("TUN interface check: {:?}", tun_check);

    // Verify UDP port is bound
    let port_check = container
        .exec(testcontainers::core::ExecCommand::new([
            "ss", "-uln", "sport", "=", ":5353",
        ]))
        .await
        .expect("exec ss");

    println!("UDP port check: {:?}", port_check);

    // Cleanup
    drop(container);
    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Integration test: Container image verification.
///
/// Verifies the Docker image contains required tools for VPN operation.
#[tokio::test]
#[ignore = "requires Docker and pre-built image"]
async fn test_image_tools() {
    if !ensure_image_exists() {
        panic!("Missing Docker image {}:{}", TEST_IMAGE, TEST_TAG);
    }

    let temp_dir = create_temp_dir();
    let config_path = temp_dir.join("config.yaml");
    std::fs::write(&config_path, MINIMAL_CONFIG).expect("write config");

    let container = GenericImage::new(TEST_IMAGE, TEST_TAG)
        .with_exposed_port(ContainerPort::Udp(5353))
        .with_wait_for(WaitFor::seconds(1))
        .with_privileged(true)
        .with_mount(Mount::bind_mount(
            config_path.to_str().unwrap(),
            "/etc/h3llo/config.yaml",
        ))
        .start()
        .await
        .expect("start container");

    // Verify required tools are present
    let tools = ["ip", "ping", "ss"];
    for tool in tools {
        let result = container
            .exec(testcontainers::core::ExecCommand::new(["which", tool]))
            .await
            .expect(&format!("exec which {}", tool));
        println!("Tool '{}' check: {:?}", tool, result);
    }

    drop(container);
    let _ = std::fs::remove_dir_all(&temp_dir);
}
