//! DNS resolver integration tests using testcontainers-rs.
//!
//! Validates real DNS resolution against a CoreDNS container with
//! deterministic zone data. No TUN or BareUDP required.
//!
//! Each test creates its own temporary directory and CoreDNS container,
//! making parallel execution safe (`cargo test` default behavior).
//!
//! Run with: `cargo test --test integration --features test-utils -- --ignored --nocapture`

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const RESOLVER_TIMEOUT: Duration = Duration::from_secs(5);
const COLLECT_TIMEOUT: Duration = Duration::from_secs(10);

use h3llo::actor::ActorExitResult;
use h3llo::dns::{DnsCommand, DnsResolver};
use h3llo::events::{DnsEventDetail, DnsIpResolved, Event};
use h3llo::test_utils::FakeRouteProbe;
use testcontainers::core::{ContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::mpsc;

/// CoreDNS Corefile using the `file` plugin for deterministic zone resolution.
const COREFILE: &str = r#"test.h3llo:53 {
    file /etc/coredns/test.h3llo.zone
    errors
}
"#;

/// RFC-style zone file with SOA, NS, A, and AAAA records.
const ZONE_FILE: &str = r#"$ORIGIN test.h3llo.
@       3600 IN SOA  ns1.test.h3llo. admin.test.h3llo. (
                     2024010101 ; serial
                     3600       ; refresh
                     900        ; retry
                     86400      ; expire
                     300 )      ; minimum
        3600 IN NS   ns1.test.h3llo.
ns1     3600 IN A    127.0.0.1
single  3600 IN A    10.0.0.1
multi   3600 IN A    10.0.0.2
multi   3600 IN A    10.0.0.3
multi   3600 IN AAAA 2001:db8::2
ipv6only 3600 IN AAAA 2001:db8::1
"#;

/// Spawns a CoreDNS container with zone file and returns the mapped host port.
///
/// The returned `TempDir` must outlive the container to keep bind mounts valid.
async fn start_coredns() -> (ContainerAsync<GenericImage>, tempfile::TempDir, u16) {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    std::fs::write(dir.path().join("Corefile"), COREFILE).unwrap();
    std::fs::write(dir.path().join("test.h3llo.zone"), ZONE_FILE).unwrap();

    let container = GenericImage::new("coredns/coredns", "1.12.0")
        .with_wait_for(WaitFor::message_on_stdout("CoreDNS-"))
        .with_exposed_port(ContainerPort::Udp(53))
        .with_cmd(["-conf", "/etc/coredns/Corefile"])
        .with_mount(Mount::bind_mount(
            dir.path().join("Corefile").to_str().unwrap(),
            "/etc/coredns/Corefile",
        ))
        .with_mount(Mount::bind_mount(
            dir.path().join("test.h3llo.zone").to_str().unwrap(),
            "/etc/coredns/test.h3llo.zone",
        ))
        .start()
        .await
        .expect("failed to start CoreDNS container");

    let port = container
        .get_host_port_ipv4(ContainerPort::Udp(53))
        .await
        .unwrap();
    (container, dir, port)
}

/// Spawns a DnsResolver targeting the given server address.
///
/// Uses zero refresh interval so tests don't get automatic re-queries.
async fn spawn_resolver(
    server: SocketAddr,
    timeout: Duration,
) -> (
    mpsc::UnboundedSender<DnsCommand>,
    mpsc::UnboundedReceiver<Event>,
    tokio::task::JoinHandle<ActorExitResult>,
) {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    // refresh_interval = ZERO disables automatic refresh
    let resolver = DnsResolver::new(server, None, None, timeout, Duration::ZERO);
    let (cmd_tx, handle) = resolver
        .spawn(FakeRouteProbe::noop(), event_tx)
        .await
        .expect("resolver spawn failed");
    (cmd_tx, event_rx, handle)
}

/// Collects IpResolved events until timeout or expected count reached.
async fn collect_ip_resolved(
    rx: &mut mpsc::UnboundedReceiver<Event>,
    timeout: Duration,
    expected_count: usize,
) -> Vec<DnsIpResolved> {
    let mut resolved = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    while resolved.len() < expected_count {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(Event::Dns(ev))) => {
                if let DnsEventDetail::IpResolved(ip) = ev.detail {
                    resolved.push(ip);
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => break,
        }
    }
    resolved
}

/// Helper to create a HashSet from a slice of strings.
fn hosts(names: &[&str]) -> HashSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
#[ignore] // Requires Docker
async fn dns_resolve_single_a_record() {
    let (_container, _dir, port) = start_coredns().await;
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (cmd_tx, mut event_rx, handle) = spawn_resolver(server, RESOLVER_TIMEOUT).await;

    cmd_tx
        .send(DnsCommand::SetHostnames {
            hosts: hosts(&["single.test.h3llo"]),
        })
        .unwrap();

    // single.test.h3llo has one A record (10.0.0.1), no AAAA
    // Expect at least 1 IpResolved event
    let resolved = collect_ip_resolved(&mut event_rx, COLLECT_TIMEOUT, 1).await;

    assert!(
        !resolved.is_empty(),
        "expected at least one IpResolved event"
    );

    let has_expected_ip = resolved
        .iter()
        .any(|r| r.host == "single.test.h3llo" && r.address.to_string() == "10.0.0.1");
    assert!(
        has_expected_ip,
        "expected 10.0.0.1 for single.test.h3llo: {:?}",
        resolved
    );

    handle.abort();
}

#[tokio::test]
#[ignore]
async fn dns_resolve_multiple_records() {
    let (_container, _dir, port) = start_coredns().await;
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (cmd_tx, mut event_rx, handle) = spawn_resolver(server, RESOLVER_TIMEOUT).await;

    cmd_tx
        .send(DnsCommand::SetHostnames {
            hosts: hosts(&["multi.test.h3llo"]),
        })
        .unwrap();

    // multi.test.h3llo has: 10.0.0.2, 10.0.0.3 (A), and 2001:db8::2 (AAAA)
    // Expect 3 IpResolved events
    let resolved = collect_ip_resolved(&mut event_rx, COLLECT_TIMEOUT, 3).await;

    let addrs: Vec<IpAddr> = resolved.iter().map(|r| r.address).collect();

    assert!(
        addrs.contains(&"10.0.0.2".parse().unwrap()),
        "missing 10.0.0.2: {addrs:?}"
    );
    assert!(
        addrs.contains(&"10.0.0.3".parse().unwrap()),
        "missing 10.0.0.3: {addrs:?}"
    );
    assert!(
        addrs.contains(&"2001:db8::2".parse().unwrap()),
        "missing 2001:db8::2: {addrs:?}"
    );

    handle.abort();
}

#[tokio::test]
#[ignore]
async fn dns_resolve_aaaa_only() {
    let (_container, _dir, port) = start_coredns().await;
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (cmd_tx, mut event_rx, handle) = spawn_resolver(server, RESOLVER_TIMEOUT).await;

    cmd_tx
        .send(DnsCommand::SetHostnames {
            hosts: hosts(&["ipv6only.test.h3llo"]),
        })
        .unwrap();

    // ipv6only.test.h3llo has only AAAA record: 2001:db8::1
    let resolved = collect_ip_resolved(&mut event_rx, COLLECT_TIMEOUT, 1).await;

    let has_expected_ip = resolved
        .iter()
        .any(|r| r.host == "ipv6only.test.h3llo" && r.address.to_string() == "2001:db8::1");
    assert!(
        has_expected_ip,
        "expected 2001:db8::1 for ipv6only.test.h3llo: {:?}",
        resolved
    );

    handle.abort();
}

#[tokio::test]
#[ignore]
async fn dns_resolve_nxdomain_emits_no_events() {
    let (_container, _dir, port) = start_coredns().await;
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (cmd_tx, mut event_rx, handle) = spawn_resolver(server, RESOLVER_TIMEOUT).await;

    cmd_tx
        .send(DnsCommand::SetHostnames {
            hosts: hosts(&["nonexistent.test.h3llo"]),
        })
        .unwrap();

    // NXDOMAIN should not emit IpResolved events (warning is logged at origin)
    let resolved = collect_ip_resolved(&mut event_rx, Duration::from_secs(3), 1).await;

    assert!(
        resolved.is_empty(),
        "expected no IpResolved events for NXDOMAIN, got: {:?}",
        resolved
    );

    handle.abort();
}

#[tokio::test]
#[ignore]
async fn dns_resolve_multiple_hostnames() {
    let (_container, _dir, port) = start_coredns().await;
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (cmd_tx, mut event_rx, handle) = spawn_resolver(server, RESOLVER_TIMEOUT).await;

    // Register multiple hostnames at once
    cmd_tx
        .send(DnsCommand::SetHostnames {
            hosts: hosts(&["single.test.h3llo", "ipv6only.test.h3llo"]),
        })
        .unwrap();

    // Expect: single (1 A) + ipv6only (1 AAAA) = 2 IPs
    let resolved = collect_ip_resolved(&mut event_rx, COLLECT_TIMEOUT, 2).await;

    let single_resolved = resolved
        .iter()
        .any(|r| r.host == "single.test.h3llo" && r.address.to_string() == "10.0.0.1");
    let ipv6only_resolved = resolved
        .iter()
        .any(|r| r.host == "ipv6only.test.h3llo" && r.address.to_string() == "2001:db8::1");

    assert!(single_resolved, "missing single.test.h3llo: {:?}", resolved);
    assert!(
        ipv6only_resolved,
        "missing ipv6only.test.h3llo: {:?}",
        resolved
    );

    handle.abort();
}
