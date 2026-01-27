//! Standalone route integration test binary for Docker container execution.
//!
//! Exercises real route operations using `RouteManagerHandle` (real netlink API).
//! Creates dummy network interfaces and verifies route sync against the kernel
//! route table using the same handle.
//!
//! Exit code 0 = all checks passed, 1 = failure.

use h3llo::bind::lookup_ifindex;
use h3llo::route::{ipnet_from_route, sync_tun_routes, Route, RouteHandle, RouteManagerHandle};
use ipnet::IpNet;
use std::process::Command;

fn main() {
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
    eprintln!("OK: all route checks passed");
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
    check_basic().await?;
    check_default_split().await?;
    Ok(())
}

/// Verifies basic route sync: adds routes, confirms via kernel listing, then cleans up.
async fn check_basic() -> Result<(), String> {
    setup_dummy("dummy0")?;

    let allowed: Vec<IpNet> = vec![
        "10.99.0.0/24".parse().unwrap(),
        "10.99.1.0/24".parse().unwrap(),
    ];
    let tun_addrs: Vec<IpNet> = vec![];
    let mut handle =
        RouteManagerHandle::new().map_err(|e| format!("basic: RouteManagerHandle::new: {e}"))?;

    sync_tun_routes("dummy0", &tun_addrs, &allowed, &mut handle)
        .await
        .map_err(|e| format!("basic: sync_tun_routes: {e}"))?;

    // Self-verify: list routes and check expected prefixes are present on dummy0
    let installed = routes_on_interface(&mut handle, "dummy0").await?;
    for prefix in &allowed {
        if !installed.contains(prefix) {
            return Err(format!(
                "basic: expected {prefix} in kernel routes, got: {installed:?}"
            ));
        }
    }
    eprintln!("  check_basic: verified {allowed:?} installed on dummy0");

    // Verify cleanup: sync with empty allowed, confirm routes removed
    sync_tun_routes("dummy0", &tun_addrs, &[], &mut handle)
        .await
        .map_err(|e| format!("basic cleanup: sync_tun_routes: {e}"))?;

    let remaining = routes_on_interface(&mut handle, "dummy0").await?;
    for prefix in &allowed {
        if remaining.contains(prefix) {
            return Err(format!(
                "basic: {prefix} still present after cleanup: {remaining:?}"
            ));
        }
    }
    eprintln!("  check_basic: verified routes removed after cleanup");
    eprintln!("  check_basic: PASS");
    Ok(())
}

/// Verifies default route splitting: 0.0.0.0/0 becomes two /1 routes.
async fn check_default_split() -> Result<(), String> {
    setup_dummy("dummy1")?;

    let allowed: Vec<IpNet> = vec!["0.0.0.0/0".parse().unwrap()];
    let tun_addrs: Vec<IpNet> = vec![];
    let mut handle = RouteManagerHandle::new()
        .map_err(|e| format!("default_split: RouteManagerHandle::new: {e}"))?;

    sync_tun_routes("dummy1", &tun_addrs, &allowed, &mut handle)
        .await
        .map_err(|e| format!("default_split: sync_tun_routes: {e}"))?;

    // Self-verify: both /1 halves should be installed (default route is split)
    let installed = routes_on_interface(&mut handle, "dummy1").await?;
    let lower_half: IpNet = "0.0.0.0/1".parse().unwrap();
    let upper_half: IpNet = "128.0.0.0/1".parse().unwrap();
    if !installed.contains(&lower_half) || !installed.contains(&upper_half) {
        return Err(format!(
            "default_split: expected both /1 halves, got: {installed:?}"
        ));
    }
    eprintln!("  check_default_split: verified 0.0.0.0/1 and 128.0.0.0/1 installed on dummy1");
    eprintln!("  check_default_split: PASS");
    Ok(())
}

/// Lists route prefixes currently installed on the named interface.
async fn routes_on_interface(
    handle: &mut RouteManagerHandle,
    ifname: &str,
) -> Result<Vec<IpNet>, String> {
    let ifindex = lookup_ifindex(ifname).ok_or_else(|| format!("interface {ifname} not found"))?;
    let all_routes: Vec<Route> = handle
        .list()
        .await
        .map_err(|e| format!("routes_on_interface: list failed: {e}"))?;
    let prefixes: Vec<IpNet> = all_routes
        .iter()
        .filter(|r| r.if_index() == Some(ifindex))
        .filter_map(|r| ipnet_from_route(r))
        .collect();
    Ok(prefixes)
}

/// Creates a dummy network interface and brings it up.
fn setup_dummy(name: &str) -> Result<(), String> {
    let add = Command::new("ip")
        .args(["link", "add", name, "type", "dummy"])
        .status()
        .map_err(|e| format!("setup_dummy({name}): ip link add: {e}"))?;
    if !add.success() {
        return Err(format!(
            "setup_dummy({name}): failed to create dummy interface"
        ));
    }
    let up = Command::new("ip")
        .args(["link", "set", name, "up"])
        .status()
        .map_err(|e| format!("setup_dummy({name}): ip link set up: {e}"))?;
    if !up.success() {
        return Err(format!("setup_dummy({name}): failed to bring up interface"));
    }
    Ok(())
}
