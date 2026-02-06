//! Shared utilities for E2E integration tests.
//!
//! Provides common constants, Docker helpers, and iperf3 output parsing
//! shared across all E2E test modules.

use std::process::Command;

/// Default test image name.
pub const TEST_IMAGE: &str = "h3llo";

/// Default test image tag.
pub const TEST_TAG: &str = "test";

/// Docker network for E2E tests.
pub const TEST_NETWORK: &str = "h3llo-test-net";

/// Checks if the Docker test image exists locally.
pub fn ensure_image_exists() -> bool {
    let output = Command::new("docker")
        .args(["image", "inspect", &format!("{}:{}", TEST_IMAGE, TEST_TAG)])
        .output();
    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Creates the test Docker network if it doesn't exist.
///
/// Handles race conditions when multiple tests run in parallel.
pub fn ensure_network_exists() {
    let check = Command::new("docker")
        .args(["network", "inspect", TEST_NETWORK])
        .output();

    if check.map(|o| o.status.success()).unwrap_or(false) {
        return;
    }

    let result = Command::new("docker")
        .args(["network", "create", TEST_NETWORK])
        .output()
        .expect("create network");

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        if stderr.contains("already exists") {
            return;
        }
        panic!("Failed to create network: {}", stderr);
    }
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
}
