//! DNS resolver integration tests using testcontainers-rs.
//!
//! Validates real DNS resolution against a CoreDNS container with
//! deterministic zone data. No TUN or BareUDP required.
//!
//! Each test creates its own temporary directory and CoreDNS container,
//! making parallel execution safe (`cargo test` default behavior).
//!
//! Run with: `cargo test --test integration -- --ignored --nocapture`

use std::net::SocketAddr;
use std::time::Duration;

const RESOLVER_TIMEOUT: Duration = Duration::from_secs(5);
const COLLECT_TIMEOUT: Duration = Duration::from_secs(10);

use h3llo::bind::{RouteProbe, RouteProbeError};
use h3llo::dns::{DnsCommand, DnsResolver};
use h3llo::events::{DnsAnswer, DnsAnswerWarning, DnsEventDetail, DnsRecordType, Event};
use testcontainers::core::{ContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::mpsc;

/// NoopProbe returns empty interfaces -- DNS tests don't need interface binding.
#[derive(Clone)]
struct NoopProbe;

impl RouteProbe for NoopProbe {
    async fn probe_interfaces(
        &self,
        _target: &str,
        _tun_if: Option<&str>,
    ) -> Result<Vec<String>, RouteProbeError> {
        Ok(Vec::new())
    }
}

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
async fn spawn_resolver(
    server: SocketAddr,
    timeout: Duration,
) -> (
    mpsc::Sender<DnsCommand>,
    mpsc::Receiver<Event>,
    tokio::task::JoinHandle<()>,
) {
    let (cmd_tx, cmd_rx) = mpsc::channel(4);
    let (event_tx, event_rx) = mpsc::channel(16);
    let resolver = DnsResolver::new(server, None, None, timeout);
    let handle = resolver
        .spawn(NoopProbe, cmd_rx, event_tx)
        .await
        .expect("resolver spawn failed");
    (cmd_tx, event_rx, handle)
}

/// Collects DNS answer events until we have one for each expected record type, skipping non-answer events.
async fn collect_answers(
    rx: &mut mpsc::Receiver<Event>,
    timeout: Duration,
) -> Vec<(DnsRecordType, DnsAnswer)> {
    let mut answers = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    // DnsResolver issues both A and AAAA queries per Resolve command.
    while answers.len() < 2 {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(Event::Dns(ev))) => match ev.detail {
                DnsEventDetail::Answer(answer) => {
                    answers.push((answer.record_type, answer));
                }
                _ => continue,
            },
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => break,
        }
    }
    answers
}

/// Extracts the next DNS event detail from the receiver, skipping bind warnings.
async fn next_dns_detail(rx: &mut mpsc::Receiver<Event>, timeout: Duration) -> DnsEventDetail {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(Event::Dns(ev))) => match &ev.detail {
                DnsEventDetail::BindWarning(_) => continue,
                _ => return ev.detail,
            },
            Ok(Some(_)) => continue,
            Ok(None) => panic!("channel closed unexpectedly"),
            Err(_) => panic!("timed out waiting for DNS event"),
        }
    }
}

#[tokio::test]
#[ignore] // Requires Docker
async fn dns_resolve_single_a_record() {
    let (_container, _dir, port) = start_coredns().await;
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (cmd_tx, mut event_rx, handle) = spawn_resolver(server, RESOLVER_TIMEOUT).await;

    cmd_tx
        .send(DnsCommand::Resolve {
            host: "single.test.h3llo".to_string(),
        })
        .await
        .unwrap();

    let answers = collect_answers(&mut event_rx, COLLECT_TIMEOUT).await;

    // Find the A record answer
    let a_answer = answers
        .iter()
        .find(|(rt, _)| *rt == DnsRecordType::A)
        .map(|(_, a)| a)
        .expect("expected A record answer");

    assert_eq!(a_answer.host, "single.test.h3llo");
    assert!(
        a_answer
            .records
            .iter()
            .any(|r| r.address.to_string() == "10.0.0.1"),
        "expected 10.0.0.1 in A records: {:?}",
        a_answer.records
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
        .send(DnsCommand::Resolve {
            host: "multi.test.h3llo".to_string(),
        })
        .await
        .unwrap();

    let answers = collect_answers(&mut event_rx, COLLECT_TIMEOUT).await;

    // Check A records contain 10.0.0.2 and 10.0.0.3
    let a_answer = answers
        .iter()
        .find(|(rt, _)| *rt == DnsRecordType::A)
        .map(|(_, a)| a)
        .expect("expected A record answer");

    let a_addrs: Vec<String> = a_answer
        .records
        .iter()
        .map(|r| r.address.to_string())
        .collect();
    assert!(
        a_addrs.contains(&"10.0.0.2".to_string()),
        "missing 10.0.0.2: {a_addrs:?}"
    );
    assert!(
        a_addrs.contains(&"10.0.0.3".to_string()),
        "missing 10.0.0.3: {a_addrs:?}"
    );

    // Check AAAA records contain 2001:db8::2
    let aaaa_answer = answers
        .iter()
        .find(|(rt, _)| *rt == DnsRecordType::Aaaa)
        .map(|(_, a)| a)
        .expect("expected AAAA record answer");

    assert!(
        aaaa_answer
            .records
            .iter()
            .any(|r| r.address.to_string() == "2001:db8::2"),
        "expected 2001:db8::2 in AAAA records: {:?}",
        aaaa_answer.records
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
        .send(DnsCommand::Resolve {
            host: "ipv6only.test.h3llo".to_string(),
        })
        .await
        .unwrap();

    let answers = collect_answers(&mut event_rx, COLLECT_TIMEOUT).await;

    // AAAA answer should contain 2001:db8::1
    let aaaa_answer = answers
        .iter()
        .find(|(rt, _)| *rt == DnsRecordType::Aaaa)
        .map(|(_, a)| a)
        .expect("expected AAAA record answer");

    assert!(
        aaaa_answer
            .records
            .iter()
            .any(|r| r.address.to_string() == "2001:db8::1"),
        "expected 2001:db8::1 in AAAA records: {:?}",
        aaaa_answer.records
    );

    // A answer should have no records (no A record for ipv6only)
    let a_answer = answers
        .iter()
        .find(|(rt, _)| *rt == DnsRecordType::A)
        .map(|(_, a)| a);

    if let Some(a) = a_answer {
        assert!(
            a.records.is_empty(),
            "expected no A records for ipv6only: {:?}",
            a.records
        );
    }

    handle.abort();
}

#[tokio::test]
#[ignore]
async fn dns_resolve_nxdomain() {
    let (_container, _dir, port) = start_coredns().await;
    let server: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let (cmd_tx, mut event_rx, handle) = spawn_resolver(server, RESOLVER_TIMEOUT).await;

    cmd_tx
        .send(DnsCommand::Resolve {
            host: "nonexistent.test.h3llo".to_string(),
        })
        .await
        .unwrap();

    let answers = collect_answers(&mut event_rx, COLLECT_TIMEOUT).await;

    // At least one answer should have NxDomain warning
    let has_nxdomain = answers
        .iter()
        .any(|(_, answer)| answer.warnings.contains(&DnsAnswerWarning::NxDomain));
    assert!(
        has_nxdomain,
        "expected NxDomain warning in answers: {:?}",
        answers
    );

    handle.abort();
}

#[tokio::test]
#[ignore]
async fn dns_resolve_timeout() {
    // RFC 5737 TEST-NET-1: guaranteed unroutable in well-configured networks,
    // causing the resolver to timeout rather than receive a response.
    let server: SocketAddr = "192.0.2.1:53".parse().unwrap();
    let (cmd_tx, mut event_rx, handle) = spawn_resolver(server, Duration::from_secs(2)).await;

    cmd_tx
        .send(DnsCommand::Resolve {
            host: "anything.example.com".to_string(),
        })
        .await
        .unwrap();

    // Should receive a Timeout event
    let detail = next_dns_detail(&mut event_rx, COLLECT_TIMEOUT).await;
    match detail {
        DnsEventDetail::Timeout(timeout) => {
            assert_eq!(timeout.host, "anything.example.com");
        }
        other => panic!("expected Timeout, got: {:?}", other),
    }

    handle.abort();
}
