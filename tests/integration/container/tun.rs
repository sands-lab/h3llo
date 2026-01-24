//! Standalone TUN integration test binary for Docker container execution.
//!
//! Exercises `h3llo::tun::from_config()` with real TUN devices requiring
//! CAP_NET_ADMIN. Designed to run inside a privileged Docker container
//! via the native orchestrator (`tests/integration/native/tun.rs`).
//!
//! Exit code 0 = all checks passed, 1 = failure.

use std::process::Command;

fn main() {
    // Skip gracefully when not running with CAP_NET_ADMIN (e.g., during `cargo test`
    // on the host). The orchestrator in native/tun.rs runs this inside a privileged
    // container where TUN creation succeeds.
    if !has_net_admin() {
        eprintln!("SKIP: CAP_NET_ADMIN not available (not in privileged container)");
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    if let Err(e) = rt.block_on(run_checks()) {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
    eprintln!("OK: all TUN checks passed");
}

/// Checks whether the process has CAP_NET_ADMIN by reading effective capabilities.
fn has_net_admin() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:\t") {
            let Ok(caps) = u64::from_str_radix(hex.trim(), 16) else {
                return false;
            };
            // CAP_NET_ADMIN is bit 12
            return caps & (1 << 12) != 0;
        }
    }
    false
}

async fn run_checks() -> Result<(), String> {
    check_device_creation().await?;
    check_multi_address().await?;
    check_mtu_configuration().await?;
    Ok(())
}

/// Verifies TUN device creation via `from_config()` and interface visibility.
async fn check_device_creation() -> Result<(), String> {
    let local_tun = h3llo::config::LocalTun {
        ifname: "itun0".to_string(),
        addrs: vec!["10.99.0.1".to_string()],
        mtu: 1400,
    };

    let (_reader, _writer) = h3llo::tun::from_config(&local_tun)
        .await
        .map_err(|e| format!("device_creation: from_config failed: {e}"))?;

    let output = Command::new("ip")
        .args(["link", "show", "itun0"])
        .output()
        .map_err(|e| format!("device_creation: ip command failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "device_creation: interface itun0 not visible: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("itun0") {
        return Err("device_creation: ip link output missing itun0".to_string());
    }

    eprintln!("  check_device_creation: PASS");
    Ok(())
}

/// Verifies multiple IPv4 and IPv6 addresses are assigned correctly.
async fn check_multi_address() -> Result<(), String> {
    let local_tun = h3llo::config::LocalTun {
        ifname: "itun1".to_string(),
        addrs: vec![
            "10.99.1.1".to_string(),
            "10.99.1.2".to_string(),
            "fd99::1".to_string(),
            "fd99::2".to_string(),
        ],
        mtu: 1500,
    };

    let (_reader, _writer) = h3llo::tun::from_config(&local_tun)
        .await
        .map_err(|e| format!("multi_address: from_config failed: {e}"))?;

    let output = Command::new("ip")
        .args(["addr", "show", "itun1"])
        .output()
        .map_err(|e| format!("multi_address: ip addr failed: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("  ip addr show itun1:\n{stdout}");

    for expected in &["10.99.1.1", "10.99.1.2", "fd99::1", "fd99::2"] {
        if !stdout.contains(expected) {
            return Err(format!("multi_address: missing address {expected}"));
        }
    }

    eprintln!("  check_multi_address: PASS");
    Ok(())
}

/// Verifies MTU is configured correctly on the TUN device.
async fn check_mtu_configuration() -> Result<(), String> {
    let local_tun = h3llo::config::LocalTun {
        ifname: "itun2".to_string(),
        addrs: vec!["10.99.2.1".to_string()],
        mtu: 1280,
    };

    let (_reader, _writer) = h3llo::tun::from_config(&local_tun)
        .await
        .map_err(|e| format!("mtu_configuration: from_config failed: {e}"))?;

    let output = Command::new("ip")
        .args(["link", "show", "itun2"])
        .output()
        .map_err(|e| format!("mtu_configuration: ip link failed: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("mtu 1280") {
        return Err(format!(
            "mtu_configuration: expected 'mtu 1280' in: {stdout}"
        ));
    }

    eprintln!("  check_mtu_configuration: PASS");
    Ok(())
}
