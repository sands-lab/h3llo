//! Minimal reproduction for tokio-quiche Router task leak on client handshake
//! failure.
//!
//! # Bug
//!
//! When `connect_with_config` times out (peer unreachable), the fire-and-forget
//! Router task is never cleaned up. Each failed attempt permanently leaks:
//!
//! - 1 tokio task (stuck in `Poll::Pending` forever)
//! - 1 UDP socket file descriptor
//! - 1 PooledBuf (64 KB from the generic buffer pool)
//!
//! # Mechanism
//!
//! Router shutdown requires two steps (router/mod.rs):
//! 1. `accept_sink.is_closed()` → drop own `shutdown_tx`
//! 2. `shutdown_rx.poll_recv(cx).is_ready()` → exit
//!
//! For failed handshakes, **no IoWorker is ever spawned**, so no `shutdown_tx`
//! clone exists. After the caller drops the accept stream, `is_closed()` becomes
//! true — but nothing wakes the Router to re-check it. The Router sits in
//! `Poll::Pending` forever, holding its socket and buffer.
//!
//! # Expected output (with bug)
//!
//! ```text
//! [ 1/10] ... | FDs: +1 | UDP: +1
//! [ 2/10] ... | FDs: +2 | UDP: +2
//! ...
//! [10/10] ... | FDs: +10 | UDP: +10
//! BUG CONFIRMED: 10 FDs leaked after 10 failed handshakes.
//! ```
//!
//! # Expected output (after fix)
//!
//! ```text
//! Final: ... FDs (+0), ... UDP sockets (+0)
//! No leak detected.
//! ```
//!
//! # Usage
//!
//! ```bash
//! cargo run --example router_leak
//! ```

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_quiche::quic::connect_with_config;
use tokio_quiche::quic::HandshakeInfo;
use tokio_quiche::quic::QuicheConnection;
use tokio_quiche::settings::QuicSettings;
use tokio_quiche::socket::Socket;
use tokio_quiche::ApplicationOverQuic;
use tokio_quiche::ConnectionParams;
use tokio_quiche::QuicResult;

/// Minimal [`ApplicationOverQuic`] that does nothing.
///
/// It will never be driven because the handshake always fails in this test.
struct NoopApp {
    buf: Vec<u8>,
}

impl NoopApp {
    fn new() -> Self {
        Self {
            buf: vec![0u8; 65536],
        }
    }
}

impl ApplicationOverQuic for NoopApp {
    fn on_conn_established(
        &mut self, _qconn: &mut QuicheConnection,
        _info: &HandshakeInfo,
    ) -> QuicResult<()> {
        unreachable!("handshake never succeeds in this test");
    }

    fn should_act(&self) -> bool {
        false
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    fn wait_for_data(
        &mut self, _qconn: &mut QuicheConnection,
    ) -> impl Future<Output = QuicResult<()>> + Send {
        // Never resolves — doesn't matter since the handshake fails first.
        std::future::pending()
    }

    fn process_reads(
        &mut self, _qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        Ok(())
    }

    fn process_writes(
        &mut self, _qconn: &mut QuicheConnection,
    ) -> QuicResult<()> {
        Ok(())
    }
}

/// Count open file descriptors for the current process.
fn count_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

/// Count open UDP sockets for the current process (IPv4 + IPv6).
fn count_udp_sockets() -> usize {
    let mut count = 0;
    for path in ["/proc/self/net/udp", "/proc/self/net/udp6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            // First line is the header row.
            count += content.lines().count().saturating_sub(1);
        }
    }
    count
}

/// Create a connected UDP socket to `target` and wrap it for tokio-quiche.
fn make_socket(
    target: SocketAddr,
) -> Socket<Arc<UdpSocket>, Arc<UdpSocket>> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .expect("socket creation");
    sock.set_nonblocking(true).expect("set nonblocking");
    sock.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())
        .expect("bind");
    sock.connect(&target.into()).expect("connect");

    let std_udp: std::net::UdpSocket = sock.into();
    let tokio_udp = UdpSocket::from_std(std_udp).expect("tokio UdpSocket");
    tokio_udp.try_into().expect("quiche Socket")
}

/// Read RSS (Resident Set Size) in bytes from /proc/self/statm.
fn rss_bytes() -> usize {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<usize>().ok())
        .unwrap_or(0)
        * page_size
}

#[tokio::main]
async fn main() {
    // RFC 5737 TEST-NET-1 — guaranteed non-routable, will always time out.
    let target: SocketAddr = "192.0.2.1:443".parse().unwrap();

    let iterations = 10;
    let baseline_fds = count_fds();
    let baseline_udp = count_udp_sockets();

    let baseline_rss = rss_bytes();

    println!("tokio-quiche Router leak reproduction");
    println!("=====================================");
    println!("Target:            {target} (unreachable)");
    println!("Handshake timeout: 500ms");
    println!("Iterations:        {iterations}");
    println!(
        "Baseline: {baseline_fds} FDs, {baseline_udp} UDP sockets, {:.1} MiB RSS",
        baseline_rss as f64 / 1048576.0
    );
    println!();

    // Launch all connections concurrently to finish fast.
    let mut handles = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        handles.push(tokio::spawn(async move {
            let mut settings = QuicSettings::default();
            settings.handshake_timeout = Some(Duration::from_millis(500));
            settings.verify_peer = false;
            let params = ConnectionParams::new_client(
                settings, None, Default::default(),
            );

            let socket = make_socket(target);
            connect_with_config(
                socket,
                Some("test.example.com"),
                &params,
                NoopApp::new(),
            )
            .await
        }));
    }

    // Collect results, printing after each completes.
    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.await.expect("task panicked");
        let fds = count_fds();
        let udp = count_udp_sockets();

        let rss = rss_bytes();
        println!(
            "[{:2}/{iterations}] error: {:<45} | FDs: +{} | UDP: +{} | RSS: {:.1} MiB",
            i + 1,
            result.err().map_or("(none)".into(), |e| e.to_string()),
            fds.saturating_sub(baseline_fds),
            udp.saturating_sub(baseline_udp),
            rss as f64 / 1048576.0,
        );
    }

    // Give the tokio runtime a chance to run any pending cleanup.
    println!();
    println!("Waiting 3s for async cleanup...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    let final_fds = count_fds();
    let final_udp = count_udp_sockets();
    let leaked_fds = final_fds.saturating_sub(baseline_fds);
    let leaked_udp = final_udp.saturating_sub(baseline_udp);

    let final_rss = rss_bytes();

    println!();
    println!(
        "Final: {final_fds} FDs (+{leaked_fds}), \
         {final_udp} UDP sockets (+{leaked_udp}), \
         {:.1} MiB RSS",
        final_rss as f64 / 1048576.0,
    );
    println!();

    if leaked_fds > 2 {
        println!(
            "BUG CONFIRMED: {leaked_fds} FDs leaked \
             after {iterations} failed handshakes."
        );
        println!(
            "Expected: ~0 (all resources should be cleaned up after timeout)"
        );
        println!(
            "Each leaked FD = 1 Router task stuck in Poll::Pending forever"
        );
    } else {
        println!("No leak detected. Bug may have been fixed.");
    }
}
