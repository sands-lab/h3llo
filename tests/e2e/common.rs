//! Shared utilities for E2E integration tests.
//!
//! Provides common constants, Docker helpers, per-test isolation context,
//! and iperf3 output parsing shared across all E2E test modules.

use std::process::Command;

/// Default test image name.
pub const TEST_IMAGE: &str = "h3llo";

/// Default test image tag.
pub const TEST_TAG: &str = "test";

/// Per-test isolation context providing unique container names and Docker network.
///
/// Each E2E test creates a `TestContext` that generates a unique suffix,
/// creates an isolated Docker network, and provides helpers for deriving
/// globally-unique container names and their FQDNs within the network.
/// The Docker network is removed when the context is dropped.
///
/// # Examples
///
/// ```ignore
/// let ctx = TestContext::new();
/// let name_a = ctx.container_name("node-a");  // e.g. "node-a-a1b2c3d4"
/// let fqdn_a = ctx.fqdn("node-a");            // e.g. "node-a-a1b2c3d4.h3llo-e2e-a1b2c3d4"
/// ```
pub struct TestContext {
    suffix: String,
    network: String,
}

impl TestContext {
    /// Creates a new test context with unique suffix, verifies the Docker image,
    /// and creates an isolated Docker network.
    ///
    /// # Panics
    ///
    /// Panics if the Docker test image is not found or the network cannot be created.
    pub fn new() -> Self {
        if !ensure_image_exists() {
            eprintln!(
                "Docker image {}:{} not found. Build with:",
                TEST_IMAGE, TEST_TAG
            );
            eprintln!(
                "  docker buildx build --target test -t {}:{} --load .",
                TEST_IMAGE, TEST_TAG
            );
            panic!("Missing Docker image");
        }

        let suffix = format!("{:08x}", rand::random::<u32>());
        let network = format!("h3llo-e2e-{suffix}");

        let result = Command::new("docker")
            .args(["network", "create", &network])
            .output()
            .expect("create network");

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr);
            panic!("Failed to create network {network}: {stderr}");
        }

        Self { suffix, network }
    }

    /// Returns the Docker network name for this test.
    pub fn network(&self) -> &str {
        &self.network
    }

    /// Generates a globally-unique container name from a logical role name.
    pub fn container_name(&self, role: &str) -> String {
        format!("{role}-{}", self.suffix)
    }

    /// Generates the FQDN for a container within this test's Docker network.
    ///
    /// Docker user-defined bridge networks resolve `{container_name}.{network_name}`
    /// via the embedded DNS server.
    pub fn fqdn(&self, role: &str) -> String {
        format!("{}-{}.{}", role, self.suffix, self.network)
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .output();
    }
}

/// Checks if the Docker test image exists locally.
fn ensure_image_exists() -> bool {
    let output = Command::new("docker")
        .args(["image", "inspect", &format!("{}:{}", TEST_IMAGE, TEST_TAG)])
        .output();
    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Generates a BareUDP node config with dynamic peer endpoint FQDN.
///
/// # Arguments
///
/// * `tun_addr` - Local TUN IP address (e.g., "10.0.0.1/32")
/// * `peer_id` - Peer's container name (used as peer ID)
/// * `peer_fqdn` - Peer's FQDN for DNS resolution in Docker network
/// * `peer_allowed_ip` - CIDR for peer traffic
pub fn bareudp_config(
    tun_addr: &str,
    peer_id: &str,
    peer_fqdn: &str,
    peer_allowed_ip: &str,
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
  bare:
    listen: "udp://0.0.0.0:5353"
peers:
  - id: {peer_id}
    bare:
      endpoint: "udp://{peer_fqdn}:5353"
    tun:
      allowed_ips:
        - {peer_allowed_ip}
tuning:
  dns_refresh_interval: 1
"#
    )
}

/// Parses iperf3 JSON output to extract received throughput in bits/second.
///
/// Returns `None` if parsing fails or the expected field is missing.
pub fn parse_iperf3_bps(json: &str) -> Option<f64> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v["end"]["sum_received"]["bits_per_second"].as_f64()
}

/// Formats throughput in human-readable form (e.g., "123.45 Mbps").
pub fn format_throughput(bps: f64) -> String {
    if bps >= 1_000_000_000.0 {
        format!("{:.2} Gbps", bps / 1_000_000_000.0)
    } else if bps >= 1_000_000.0 {
        format!("{:.2} Mbps", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.2} Kbps", bps / 1_000.0)
    } else {
        format!("{:.0} bps", bps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iperf3_bps_valid() {
        let json = r#"{"end":{"sum_received":{"bits_per_second":1234567.89}}}"#;
        assert!((parse_iperf3_bps(json).unwrap() - 1234567.89).abs() < 0.01);
    }

    #[test]
    fn test_parse_iperf3_bps_invalid() {
        assert!(parse_iperf3_bps("not json").is_none());
        assert!(parse_iperf3_bps(r#"{"end":{}}"#).is_none());
    }

    #[test]
    fn test_format_throughput_gbps() {
        assert_eq!(format_throughput(2_500_000_000.0), "2.50 Gbps");
    }

    #[test]
    fn test_format_throughput_mbps() {
        assert_eq!(format_throughput(123_456_789.0), "123.46 Mbps");
    }

    #[test]
    fn test_format_throughput_kbps() {
        assert_eq!(format_throughput(45_678.0), "45.68 Kbps");
    }

    #[test]
    fn test_format_throughput_bps() {
        assert_eq!(format_throughput(999.0), "999 bps");
    }
}
