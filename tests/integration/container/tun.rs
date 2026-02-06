//! Standalone TUN integration test binary for Docker container execution.
//!
//! Exercises `h3llo::tun::make_tun()` with real TUN devices requiring
//! CAP_NET_ADMIN. Designed to run inside a privileged Docker container
//! via the native orchestrator (`tests/integration/native/tun.rs`).
//!
//! Exit code 0 = all checks passed, 1 = failure.

use ipnet::IpNet;
use std::process::{Command, Stdio};
use tokio::process::Command as AsyncCommand;

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
    check_send_recv().await?;
    Ok(())
}

/// Verifies TUN device creation via `make_tun()` and interface visibility.
async fn check_device_creation() -> Result<(), String> {
    let local_tun = h3llo::config::LocalTun {
        ifname: "itun0".to_string(),
        addrs: vec!["10.99.0.1".parse().unwrap()],
        mtu: 1400,
    };

    let (_reader, _writer) = h3llo::tun::make_tun(&local_tun)
        .await
        .map_err(|e| format!("device_creation: make_tun failed: {e}"))?;

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

/// Checks whether IPv6 is supported by looking for /proc/sys/net/ipv6.
fn has_ipv6_support() -> bool {
    std::path::Path::new("/proc/sys/net/ipv6").exists()
}

/// Verifies multiple IPv4 (and IPv6 if available) addresses are assigned correctly.
async fn check_multi_address() -> Result<(), String> {
    let ipv6_available = has_ipv6_support();
    if !ipv6_available {
        eprintln!("  note: IPv6 not available, testing IPv4 only");
    }

    let mut addrs: Vec<IpNet> = vec![
        "10.99.1.1/32".parse().unwrap(),
        "10.99.1.2/32".parse().unwrap(),
    ];
    if ipv6_available {
        addrs.push("fd99::1/128".parse().unwrap());
        addrs.push("fd99::2/128".parse().unwrap());
    }

    let local_tun = h3llo::config::LocalTun {
        ifname: "itun1".to_string(),
        addrs: addrs.clone(),
        mtu: 1500,
    };

    let (_reader, _writer) = h3llo::tun::make_tun(&local_tun)
        .await
        .map_err(|e| format!("multi_address: make_tun failed: {e}"))?;

    let output = Command::new("ip")
        .args(["addr", "show", "itun1"])
        .output()
        .map_err(|e| format!("multi_address: ip addr failed: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("  ip addr show itun1:\n{stdout}");

    for expected in &addrs {
        // Match full CIDR notation (e.g., "10.99.1.1/32") to avoid false positives
        // from substring matches (e.g., "10.99.1.1" matching "10.99.1.10").
        let addr_str = expected.to_string();
        if !stdout.contains(&addr_str) {
            return Err(format!("multi_address: missing address {addr_str}"));
        }
    }

    eprintln!("  check_multi_address: PASS");
    Ok(())
}

/// Verifies actual data transmission through a TUN device using ICMP echo (ping).
///
/// Creates a TUN device via `make_tun()`, disables rp_filter, adds a route for
/// a remote IP through the TUN, spawns a userspace ICMP echo responder, and runs
/// `ping` to verify round-trip data flow through `TunRx::recv()` and `TunTx::send()`.
async fn check_send_recv() -> Result<(), String> {
    use h3llo::tun::{TunRx, TunTx};

    let local_tun = h3llo::config::LocalTun {
        ifname: "itun3".to_string(),
        addrs: vec!["10.99.3.1".parse().unwrap()],
        mtu: 1400,
    };

    let (mut reader, mut writer) = h3llo::tun::make_tun(&local_tun)
        .await
        .map_err(|e| format!("send_recv: make_tun failed: {e}"))?;

    // Disable rp_filter to allow ICMP replies from non-local source.
    // Write directly to /proc/sys since sysctl binary may not be available.
    for path in [
        "/proc/sys/net/ipv4/conf/all/rp_filter",
        "/proc/sys/net/ipv4/conf/itun3/rp_filter",
    ] {
        std::fs::write(path, "0")
            .map_err(|e| format!("send_recv: failed to set rp_filter ({path}): {e}"))?;
    }

    // Add route so 10.99.3.2 traffic goes through TUN
    let route = Command::new("ip")
        .args(["route", "add", "10.99.3.2/32", "dev", "itun3"])
        .output()
        .map_err(|e| format!("send_recv: ip route add failed: {e}"))?;
    if !route.status.success() {
        return Err(format!(
            "send_recv: ip route add failed: {}",
            String::from_utf8_lossy(&route.stderr)
        ));
    }

    // Spawn ICMP echo responder
    let responder = tokio::spawn(async move {
        let mtu = reader.mtu();
        let mut buf = vec![0u8; mtu];
        loop {
            let len = match reader.recv(&mut buf).await {
                Ok(n) if n >= 28 => n,
                Ok(_) => continue,
                Err(_) => break,
            };

            let packet = &mut buf[..len];
            // IPv4 only
            if packet[0] >> 4 != 4 {
                continue;
            }
            let ihl = ((packet[0] & 0x0F) as usize) * 4;
            if ihl < 20 || len < ihl + 8 {
                continue;
            }
            // Protocol must be ICMP
            if packet[9] != 1 {
                continue;
            }
            // Type must be Echo Request
            if packet[ihl] != 8 {
                continue;
            }

            // Swap src/dst IPs
            let mut src = [0u8; 4];
            let mut dst = [0u8; 4];
            src.copy_from_slice(&packet[12..16]);
            dst.copy_from_slice(&packet[16..20]);
            packet[12..16].copy_from_slice(&dst);
            packet[16..20].copy_from_slice(&src);

            // Set type to Echo Reply
            packet[ihl] = 0;

            // Recompute ICMP checksum
            packet[ihl + 2] = 0;
            packet[ihl + 3] = 0;
            let cksum = internet_checksum(&packet[ihl..len]);
            packet[ihl + 2] = (cksum >> 8) as u8;
            packet[ihl + 3] = (cksum & 0xFF) as u8;

            // Recompute IP header checksum
            packet[10] = 0;
            packet[11] = 0;
            let ip_cksum = internet_checksum(&packet[..ihl]);
            packet[10] = (ip_cksum >> 8) as u8;
            packet[11] = (ip_cksum & 0xFF) as u8;

            let _ = writer.send(&packet[..len]).await;
        }
    });

    // Give the responder time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Use tokio::process::Command (async) to avoid blocking the single-threaded
    // runtime, which would starve the spawned ICMP responder task.
    let ping = AsyncCommand::new("ping")
        .args(["-c", "3", "-W", "2", "10.99.3.2"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("send_recv: ping failed to execute: {e}"))?;

    responder.abort();

    if !ping.status.success() {
        let stdout = String::from_utf8_lossy(&ping.stdout);
        let stderr = String::from_utf8_lossy(&ping.stderr);
        return Err(format!(
            "send_recv: ping 10.99.3.2 failed:\n{stdout}{stderr}"
        ));
    }

    eprintln!("  check_send_recv: PASS");
    Ok(())
}

/// RFC 1071 internet checksum (ones-complement 16-bit sum).
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = data.chunks(2).fold(0u32, |acc, chunk| {
        acc + u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32
    });
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Verifies MTU is configured correctly on the TUN device.
async fn check_mtu_configuration() -> Result<(), String> {
    let local_tun = h3llo::config::LocalTun {
        ifname: "itun2".to_string(),
        addrs: vec!["10.99.2.1".parse().unwrap()],
        mtu: 1280,
    };

    let (_reader, _writer) = h3llo::tun::make_tun(&local_tun)
        .await
        .map_err(|e| format!("mtu_configuration: make_tun failed: {e}"))?;

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
