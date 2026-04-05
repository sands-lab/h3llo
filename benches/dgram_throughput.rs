//! Benchmark for QUIC DATAGRAM send path: `dgram_send` → `conn.send()`.
//!
//! Measures the throughput of the QUIC DATAGRAM encryption pipeline
//! without network I/O. Uses a loopback quiche client-server pair
//! with in-memory packet exchange.
//!
//! Run with: `cargo bench --bench dgram_throughput`

use std::net::SocketAddr;
use std::time::{Duration, Instant};

const MAX_UDP_PAYLOAD: usize = 1350;
const DGRAM_QUEUE_SIZE: usize = 4096;

// Payload sizes to benchmark (typical IP packet sizes).
const PAYLOAD_SIZES: &[usize] = &[64, 512, 1291];

// ---------------------------------------------------------------------------
// quiche config helpers
// ---------------------------------------------------------------------------

fn make_test_certs() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::io::Write;

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".into()]).expect("cert gen");

    let mut cert_file = tempfile::NamedTempFile::new().unwrap();
    cert_file.write_all(cert.pem().as_bytes()).unwrap();

    let mut key_file = tempfile::NamedTempFile::new().unwrap();
    key_file
        .write_all(signing_key.serialize_pem().as_bytes())
        .unwrap();

    (cert_file, key_file)
}

fn base_config(cc: &str) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD);
    config.set_max_send_udp_payload_size(MAX_UDP_PAYLOAD);
    config.set_initial_max_data(100_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.enable_dgram(true, DGRAM_QUEUE_SIZE, DGRAM_QUEUE_SIZE);
    config.set_max_idle_timeout(60_000);
    config.set_cc_algorithm_name(cc).unwrap();
    config.enable_pacing(false);
    config
}

// ---------------------------------------------------------------------------
// In-memory handshake
// ---------------------------------------------------------------------------

struct LoopbackPair {
    client: quiche::Connection,
    server: quiche::Connection,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    buf: Vec<u8>,
}

impl LoopbackPair {
    fn new(cc: &str) -> Self {
        let (cert_file, key_file) = make_test_certs();

        let mut client_config = base_config(cc);
        client_config.verify_peer(false);

        let mut server_config = base_config(cc);
        server_config
            .load_cert_chain_from_pem_file(cert_file.path().to_str().unwrap())
            .unwrap();
        server_config
            .load_priv_key_from_pem_file(key_file.path().to_str().unwrap())
            .unwrap();

        let client_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

        let scid = quiche::ConnectionId::from_ref(&[0xba; quiche::MAX_CONN_ID_LEN]);
        let dcid = quiche::ConnectionId::from_ref(&[0xbb; quiche::MAX_CONN_ID_LEN]);

        let client = quiche::connect(
            Some("localhost"),
            &scid,
            client_addr,
            server_addr,
            &mut client_config,
        )
        .unwrap();

        let server =
            quiche::accept(&dcid, None, server_addr, client_addr, &mut server_config).unwrap();

        // Temp files must outlive config usage but can be dropped after connect/accept.
        drop(cert_file);
        drop(key_file);

        let mut pair = Self {
            client,
            server,
            client_addr,
            server_addr,
            buf: vec![0u8; 65535],
        };
        pair.handshake();
        pair
    }

    /// Drives QUIC handshake to completion by exchanging packets in memory.
    fn handshake(&mut self) {
        loop {
            // client → server
            self.pump_one_direction(true);
            // server → client
            self.pump_one_direction(false);

            if self.client.is_established() && self.server.is_established() {
                break;
            }
        }
    }

    /// Pumps all pending packets from sender to receiver.
    fn pump_one_direction(&mut self, client_to_server: bool) {
        let (sender, receiver, from, to) = if client_to_server {
            (
                &mut self.client,
                &mut self.server,
                self.client_addr,
                self.server_addr,
            )
        } else {
            (
                &mut self.server,
                &mut self.client,
                self.server_addr,
                self.client_addr,
            )
        };

        loop {
            let (len, _info) = match sender.send(&mut self.buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => panic!("send error: {e}"),
            };

            let info = quiche::RecvInfo { from, to };
            match receiver.recv(&mut self.buf[..len], info) {
                Ok(_) | Err(quiche::Error::Done) => {}
                Err(e) => panic!("recv error: {e}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmark core
// ---------------------------------------------------------------------------

/// Benchmarks dgram_send → conn.send() throughput for a given payload size.
///
/// Measures how many bytes per second can be pushed through the QUIC
/// DATAGRAM encryption pipeline without network I/O.
fn bench_dgram_send(pair: &mut LoopbackPair, payload_size: usize, duration: Duration) -> Stats {
    let payload = vec![0xABu8; payload_size];
    let mut total_pkts: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut send_buf = vec![0u8; 65535];
    let start = Instant::now();

    while start.elapsed() < duration {
        // Fill the dgram queue.
        let mut queued = 0u64;
        loop {
            match pair.client.dgram_send(&payload) {
                Ok(()) => queued += 1,
                Err(quiche::Error::Done) => break,
                Err(e) => panic!("dgram_send: {e}"),
            }
        }

        // Flush via conn.send() — this is where AES-GCM encryption happens.
        // Output is discarded; we only measure encryption throughput.
        loop {
            match pair.client.send(&mut send_buf) {
                Ok(_) => {}
                Err(quiche::Error::Done) => break,
                Err(e) => panic!("send: {e}"),
            }
        }

        total_pkts += queued;
        total_bytes += queued * payload_size as u64;
    }

    let elapsed = start.elapsed();
    Stats {
        elapsed,
        total_pkts,
        total_bytes,
        payload_size,
    }
}

struct Stats {
    elapsed: Duration,
    total_pkts: u64,
    total_bytes: u64,
    payload_size: usize,
}

impl Stats {
    fn pps(&self) -> f64 {
        self.total_pkts as f64 / self.elapsed.as_secs_f64()
    }

    fn gbps(&self) -> f64 {
        (self.total_bytes as f64 * 8.0) / self.elapsed.as_secs_f64() / 1e9
    }

    fn print(&self, label: &str) {
        println!(
            "{label} payload={:>4}B: {:.0} pps, {:.3} Gbps, {} pkts in {:.2}s",
            self.payload_size,
            self.pps(),
            self.gbps(),
            self.total_pkts,
            self.elapsed.as_secs_f64(),
        );
    }
}

fn main() {
    let mut pair = LoopbackPair::new("none");

    let bench_duration = Duration::from_secs(5);
    for &size in PAYLOAD_SIZES {
        let stats = bench_dgram_send(&mut pair, size, bench_duration);
        stats.print("none");
    }
}
