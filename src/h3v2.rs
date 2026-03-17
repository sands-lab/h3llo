//! Raw-quiche HTTP/3 CONNECT-IP transport with separated UDP I/O.
//!
//! Replaces tokio-quiche's internal QUIC driver with a hand-rolled quiche
//! event loop. A single **H3 client** actor owns the `quiche::Connection`
//! and `quiche::h3::Connection`, handles QUIC timers, encrypts/decrypts
//! packets, and bridges DATAGRAM frames between the TUN data plane and
//! reusable BareUDP actors.
//!
//! # Current Scope
//!
//! Client (dial) path only. Server-side listener support requires a
//! CID-based packet router and is deferred to a follow-up PR.

use crate::actor::{ActorError, ActorExitResult};
use crate::auth::generate_bearer_auth;
use crate::bare::{bare_rx_from_socket, bare_tx_from_socket, spawn_udp_rx, spawn_udp_tx};
use crate::bind::{make_unbound_udp_socket, RouteProbe};
use crate::config::{PeerH3, Tuning};
use crate::events::Event;
use crate::h3::{CONNECT_IP_OVERHEAD, CONTEXT_ID_IP};
use crate::metrics::{Counters, Direction, DropReason, Source};
use crate::tun::alloc_packet_buf;
use octets::{varint_len, varint_parse_len, OctetsMut};
use quiche::h3::NameValue;
use rand::Rng;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_quiche::buf_factory::{BufFactory, PooledBuf};
use tracing::{debug, info, warn};

/// Duration used as "infinite" timeout when quiche returns None.
const MAX_TIMEOUT: Duration = Duration::from_secs(86400);

// ========== Connection Handle ==========

/// Established H3 client CONNECT-IP connection.
///
/// Returned by [`dial_h3_client`]. The `tx` sender feeds IP packets into the
/// H3 client actor for encryption and transmission. Join handles are for
/// orchestrator supervision.
pub struct H3ClientConn {
    /// Authenticated peer identifier.
    pub peer_id: String,
    /// Remote socket address.
    pub remote_addr: SocketAddr,
    /// Channel for sending IP packets (TUN → encrypt → UDP).
    pub tx: mpsc::Sender<Vec<PooledBuf>>,
    /// H3 client actor join handle.
    pub engine_handle: JoinHandle<ActorExitResult>,
    /// BareUDP Rx actor join handle.
    pub udp_rx_handle: JoinHandle<ActorExitResult>,
    /// BareUDP Tx actor join handle.
    pub udp_tx_handle: JoinHandle<ActorExitResult>,
}

impl std::fmt::Debug for H3ClientConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3ClientConn")
            .field("peer_id", &self.peer_id)
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}

// ========== Dial Error ==========

/// Dial error for H3 client connection establishment.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// Socket setup failed.
    #[error("socket: {0}")]
    Socket(String),
    /// QUIC/TLS handshake or H3 negotiation failed.
    #[error("handshake: {0}")]
    Handshake(String),
    /// CONNECT-IP rejected by peer.
    #[error("rejected: status {0}")]
    Rejected(String),
    /// Handshake timed out.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
}

// ========== Configuration Helper ==========

/// Creates a quiche QUIC configuration from h3llo tuning parameters.
fn make_quiche_config(tuning: &Tuning, tun_mtu: u16) -> Result<quiche::Config, DialError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| DialError::Handshake(format!("quiche config: {e}")))?;
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| DialError::Handshake(format!("ALPN: {e}")))?;

    let payload_size = tun_mtu as usize + CONNECT_IP_OVERHEAD;
    config.set_max_recv_udp_payload_size(payload_size);
    config.set_max_send_udp_payload_size(payload_size);
    // 10 MB connection-level flow control window (sufficient for tunneled traffic bursts).
    config.set_initial_max_data(10_000_000);
    // 1 MB per-stream window for the CONNECT-IP control stream.
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    // Allow up to 100 concurrent bidirectional/unidirectional streams.
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    // Enable QUIC DATAGRAM with a queue of 1024 send and 1024 recv slots.
    config.enable_dgram(true, 1024, 1024);
    config.set_max_idle_timeout(tuning.h3_max_idle_timeout.as_millis() as u64);
    config
        .set_cc_algorithm_name(&tuning.h3_cc_algorithm)
        .map_err(|e| {
            DialError::Handshake(format!("cc algorithm '{}': {e}", tuning.h3_cc_algorithm))
        })?;
    config.enable_pacing(tuning.h3_enable_pacing);

    if tuning.h3_insecure_skip_verify {
        config.verify_peer(false);
    }
    // TODO: Load system CA certs when verify_peer is true.

    Ok(config)
}

// ========== Public Dial Function ==========

/// Establishes an outbound H3 client CONNECT-IP connection.
///
/// Creates a UDP socket, spawns BareUDP Rx/Tx actors on cloned socket
/// handles, spawns the H3 client actor, and waits for the QUIC+H3
/// handshake to complete.
///
/// # Arguments
///
/// * `peer_h3` - Peer HTTP/3 configuration including endpoint, token, and TLS options.
/// * `remote_addr` - Resolved remote server socket address.
/// * `peer_id` - Authenticated peer identifier for logging and metrics.
/// * `tun_if` - Optional TUN interface to exclude from routing.
/// * `tun_mtu` - TUN MTU in bytes, used for QUIC payload sizing.
/// * `probe` - Route probe for interface selection.
/// * `tuning` - Tuning parameters (timeouts, buffers, congestion control).
/// * `ingress_tx` - Channel to forward decrypted IP packets toward the TUN.
/// * `events_tx` - Channel for emitting metrics events.
///
/// # Errors
///
/// Returns `DialError` on socket, handshake, or timeout failure.
#[allow(clippy::too_many_arguments)]
pub async fn dial_h3_client<P: RouteProbe>(
    peer_h3: &PeerH3,
    remote_addr: SocketAddr,
    peer_id: &str,
    tun_if: Option<&str>,
    tun_mtu: u16,
    probe: &P,
    tuning: &Tuning,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
) -> Result<H3ClientConn, DialError> {
    let endpoint = peer_h3
        .endpoint
        .as_ref()
        .ok_or_else(|| DialError::Socket("peer_h3.endpoint is None".into()))?;
    let server_name = peer_h3.sni.as_deref().unwrap_or(&endpoint.host);
    let authority = if endpoint.port == 443 {
        endpoint.host.clone()
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };

    // Create unconnected UDP socket (BareUDP needs sendmsg with explicit dest).
    let socket = make_unbound_udp_socket(
        remote_addr,
        tun_if,
        peer_h3.bindif.as_deref(),
        probe,
        tuning.socket_buffer_bytes(),
    )
    .await
    .map_err(|e| DialError::Socket(e.to_string()))?;

    let local_addr = socket
        .local_addr()
        .map_err(|e| DialError::Socket(format!("local_addr: {e}")))?;

    // Clone socket fd for separate RX and TX actors.
    let std_socket = socket
        .into_std()
        .map_err(|e| DialError::Socket(format!("into_std: {e}")))?;
    let rx_std = std_socket
        .try_clone()
        .map_err(|e| DialError::Socket(format!("try_clone: {e}")))?;
    let rx_socket =
        UdpSocket::from_std(rx_std).map_err(|e| DialError::Socket(format!("from_std rx: {e}")))?;
    let tx_socket = UdpSocket::from_std(std_socket)
        .map_err(|e| DialError::Socket(format!("from_std tx: {e}")))?;

    let mtu = tun_mtu as usize + CONNECT_IP_OVERHEAD;
    let bare_rx = bare_rx_from_socket(rx_socket, mtu)
        .map_err(|e| DialError::Socket(format!("bare_rx: {e}")))?;
    let bare_tx = bare_tx_from_socket(tx_socket, remote_addr, tuning.udp_enable_offload)
        .map_err(|e| DialError::Socket(format!("bare_tx: {e}")))?;

    // Spawn BareUDP actors.
    let (udp_recv_tx, udp_recv_rx) = mpsc::channel::<Vec<PooledBuf>>(tuning.packet_queue_depth);
    let accepted = HashSet::from([remote_addr.ip()]);
    let (_udp_rx_cmd, udp_rx_handle) = spawn_udp_rx(
        bare_rx,
        accepted,
        udp_recv_tx,
        events_tx.clone(),
        tuning.metrics_push_interval,
    );
    let (udp_send_tx, udp_tx_handle) =
        spawn_udp_tx(bare_tx, peer_id.to_string(), events_tx.clone(), tuning);

    // Create quiche config and connection.
    let mut config = make_quiche_config(tuning, tun_mtu)?;
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let conn = quiche::connect(
        Some(server_name),
        &scid,
        local_addr,
        remote_addr,
        &mut config,
    )
    .map_err(|e| DialError::Handshake(format!("quiche connect: {e}")))?;

    // Build CONNECT-IP headers.
    let auth_header = generate_bearer_auth(&peer_h3.token);
    let connect_headers = vec![
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"connect-ip"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", endpoint.path.as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(b"authorization", auth_header.as_bytes()),
    ];

    // Spawn H3 client actor.
    let (established_tx, established_rx) = oneshot::channel();
    let (egress_tx, engine_handle) = spawn_h3_client(
        conn,
        local_addr,
        remote_addr,
        peer_id.to_string(),
        udp_recv_rx,
        udp_send_tx,
        ingress_tx,
        events_tx,
        tuning,
        ClientHandshake {
            established_tx,
            connect_headers,
        },
    );

    // Wait for handshake.
    match time::timeout(tuning.h3_handshake_timeout, established_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(reason))) => return Err(DialError::Handshake(reason)),
        Ok(Err(_)) => {
            return Err(DialError::Handshake(
                "engine exited during handshake".into(),
            ))
        }
        Err(_) => return Err(DialError::Timeout(tuning.h3_handshake_timeout)),
    }

    info!(%peer_id, %remote_addr, "h3 client connection established");
    Ok(H3ClientConn {
        peer_id: peer_id.to_string(),
        remote_addr,
        tx: egress_tx,
        engine_handle,
        udp_rx_handle,
        udp_tx_handle,
    })
}

// ========== H3 Client Actor ==========

/// CONNECT-IP handshake state consumed by the H3 client actor.
struct ClientHandshake {
    established_tx: oneshot::Sender<Result<(), String>>,
    connect_headers: Vec<quiche::h3::Header>,
}

// ========== H3 Client State Machine ==========

/// Protocol phase of the H3 client connection state machine.
///
/// Encodes the three sequential phases of CONNECT-IP establishment,
/// each carrying only the data relevant to that phase. Transitions
/// happen in the `udp_recv_rx.recv()` arm of the single event loop.
///
/// Packet counters live outside the enum in `spawn_h3_client` locals, since
/// they are session-level accumulators rather than per-phase state.
enum H3Phase {
    /// QUIC/TLS handshake in progress; H3 layer not yet created.
    QuicHandshake {
        /// Handshake notification and CONNECT headers, consumed on transition.
        hs: ClientHandshake,
    },
    /// QUIC established; negotiating H3 SETTINGS and awaiting CONNECT-IP 200.
    H3Handshake {
        /// H3 connection for polling events.
        ///
        /// Boxed to keep enum variant sizes balanced (`quiche::h3::Connection` is ~544 B).
        h3_conn: Box<quiche::h3::Connection>,
        /// QUIC Stream ID varint prefix for DATAGRAM framing.
        qsi_bytes: Vec<u8>,
        /// Handshake completion notifier, consumed on 200 OK or error.
        established_tx: oneshot::Sender<Result<(), String>>,
    },
    /// CONNECT-IP established; steady-state datagram forwarding.
    Established {
        /// H3 connection for polling events and sending datagrams.
        ///
        /// Boxed to keep enum variant sizes balanced (`quiche::h3::Connection` is ~544 B).
        h3_conn: Box<quiche::h3::Connection>,
        /// QUIC Stream ID varint prefix for DATAGRAM framing.
        qsi_bytes: Vec<u8>,
    },
}

impl H3Phase {
    /// Returns `true` when the connection is in steady-state datagram forwarding.
    fn is_established(&self) -> bool {
        matches!(self, H3Phase::Established { .. })
    }

    /// Notifies the handshake waiter of an error, consuming the phase.
    ///
    /// No-op in `Established` phase (already notified on 200 OK).
    fn notify_handshake_error(self, reason: &str) {
        match self {
            H3Phase::QuicHandshake { hs } => {
                let _ = hs.established_tx.send(Err(reason.into()));
            }
            H3Phase::H3Handshake { established_tx, .. } => {
                let _ = established_tx.send(Err(reason.into()));
            }
            H3Phase::Established { .. } => {}
        }
    }
}

/// Encodes a Quarter Stream ID as a QUIC varint byte sequence.
fn encode_qsi(qsi: u64) -> Vec<u8> {
    let len = varint_len(qsi);
    let mut buf = [0u8; 8];
    OctetsMut::with_slice(&mut buf)
        .put_varint(qsi)
        .expect("qsi fits varint");
    buf[..len].to_vec()
}

/// Advances the H3 client phase after feeding UDP packets to quiche.
///
/// Handles state transitions: `QuicHandshake` → `H3Handshake` → `Established`.
/// Called from the `udp_recv_rx.recv()` arm of the unified event loop.
///
/// # Returns
///
/// - `Ok(Some(phase))` — continue with the returned phase.
/// - `Ok(None)` — graceful shutdown (TUN ingress channel closed).
/// - `Err(e)` — fatal error; actor should exit.
async fn advance_phase(
    phase: H3Phase,
    conn: &mut quiche::Connection,
    dgram_buf: &mut [u8],
    ingress_tx: &mpsc::Sender<Vec<PooledBuf>>,
    rx_counters: &mut Counters,
    peer_id: &str,
) -> Result<Option<H3Phase>, ActorError> {
    let err = |reason: String| ActorError::H3Client {
        peer_id: peer_id.to_string(),
        reason,
    };

    match phase {
        H3Phase::QuicHandshake { hs } => {
            if !conn.is_established() {
                return Ok(Some(H3Phase::QuicHandshake { hs }));
            }
            debug!(%peer_id, "QUIC handshake complete, starting H3 negotiation");

            // Destructure for independent ownership. If H3 setup fails,
            // established_tx drops → RecvError in dial_h3_client.
            let ClientHandshake {
                established_tx,
                connect_headers,
            } = hs;

            let h3_config =
                quiche::h3::Config::new().map_err(|e| err(format!("h3 config: {e}")))?;
            let mut h3_conn = quiche::h3::Connection::with_transport(conn, &h3_config)
                .map_err(|e| err(format!("h3 connection: {e}")))?;
            let stream_id = h3_conn
                .send_request(conn, &connect_headers, false)
                .map_err(|e| err(format!("send CONNECT: {e}")))?;

            // QSI = stream_id / 4 per draft-ietf-masque-connect-ip.
            let qsi_bytes = encode_qsi(stream_id / 4);

            Ok(Some(H3Phase::H3Handshake {
                h3_conn: Box::new(h3_conn),
                qsi_bytes,
                established_tx,
            }))
        }

        H3Phase::H3Handshake {
            mut h3_conn,
            qsi_bytes,
            established_tx,
        } => {
            // Poll H3 events for CONNECT-IP 200 OK response.
            loop {
                match h3_conn.poll(conn) {
                    Ok((_sid, quiche::h3::Event::Headers { list, .. })) => {
                        let status = list
                            .iter()
                            .find(|h| h.name() == b":status")
                            .map(|h| h.value().to_vec());
                        match status.as_deref() {
                            Some(b"200") => {
                                info!(%peer_id, "CONNECT-IP accepted");
                                let _ = established_tx.send(Ok(()));
                                return Ok(Some(H3Phase::Established { h3_conn, qsi_bytes }));
                            }
                            Some(s) => {
                                let code = String::from_utf8_lossy(s).to_string();
                                let _ = established_tx.send(Err(format!("rejected: {code}")));
                                return Err(err(format!("CONNECT-IP rejected: {code}")));
                            }
                            None => {
                                let _ = established_tx.send(Err("missing :status".into()));
                                return Err(err("missing :status".into()));
                            }
                        }
                    }
                    Ok((_sid, quiche::h3::Event::GoAway)) => {
                        let _ = established_tx.send(Err("GoAway".into()));
                        return Err(err("GoAway during handshake".into()));
                    }
                    Ok((_sid, ev)) => {
                        debug!(%peer_id, event = ?ev, "ignoring H3 event during handshake");
                        continue;
                    }
                    Err(quiche::h3::Error::Done) => {
                        return Ok(Some(H3Phase::H3Handshake {
                            h3_conn,
                            qsi_bytes,
                            established_tx,
                        }));
                    }
                    Err(e) => {
                        let msg = format!("H3 poll: {e}");
                        let _ = established_tx.send(Err(msg.clone()));
                        return Err(err(msg));
                    }
                }
            }
        }

        H3Phase::Established {
            mut h3_conn,
            qsi_bytes,
        } => {
            process_h3_events(&mut h3_conn, conn, peer_id);
            let ingress_open = drain_datagrams(conn, dgram_buf, ingress_tx, rx_counters).await;
            if !ingress_open {
                return Ok(None); // Signal graceful shutdown.
            }
            Ok(Some(H3Phase::Established { h3_conn, qsi_bytes }))
        }
    }
}

/// Spawns the H3 client actor with a single-loop state machine.
///
/// Returns `(egress_tx, JoinHandle)` where `egress_tx` accepts IP packets
/// from the TUN for encryption and transmission. The actor drives QUIC
/// handshake, H3 CONNECT-IP negotiation, and steady-state datagram
/// forwarding in one unified `tokio::select!` loop.
#[allow(clippy::too_many_arguments)]
fn spawn_h3_client(
    mut conn: quiche::Connection,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    peer_id: String,
    mut udp_recv_rx: mpsc::Receiver<Vec<PooledBuf>>,
    udp_send_tx: mpsc::Sender<Vec<PooledBuf>>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    tuning: &Tuning,
    hs: ClientHandshake,
) -> (mpsc::Sender<Vec<PooledBuf>>, JoinHandle<ActorExitResult>) {
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<PooledBuf>>(tuning.packet_queue_depth);
    let metrics_interval = tuning.metrics_push_interval;
    let keepalive_interval = tuning.h3_keepalive_interval;

    let handle = tokio::spawn(async move {
        let mut send_buf = vec![0u8; 65535];
        let mut recv_buf = vec![0u8; 65535];
        let mut dgram_buf = vec![0u8; 65535];
        let recv_info = quiche::RecvInfo {
            from: remote_addr,
            to: local_addr,
        };

        // Session-level counters, live for the duration of the Established phase.
        let mut rx_counters = Counters::new(Source::Http3, Direction::Rx);
        let mut tx_counters = Counters::new(Source::Http3, Direction::Tx);

        // Send initial QUIC ClientHello.
        flush_quic_send(&mut conn, &mut send_buf, &udp_send_tx).await;

        let mut phase = H3Phase::QuicHandshake { hs };
        let mut ticker = time::interval(metrics_interval);
        let mut keepalive = time::interval(keepalive_interval);
        keepalive.tick().await; // consume the immediate first tick

        let timer = time::sleep(conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        loop {
            let was_established = phase.is_established();
            tokio::select! {
                maybe_batch = udp_recv_rx.recv() => {
                    let Some(packets) = maybe_batch else {
                        phase.notify_handshake_error("UDP Rx closed");
                        return Ok(());
                    };
                    feed_packets(&mut conn, &packets, &mut recv_buf, recv_info);
                    let Some(new_phase) = advance_phase(
                        phase, &mut conn, &mut dgram_buf, &ingress_tx, &mut rx_counters, &peer_id,
                    ).await? else {
                        // Graceful shutdown (TUN ingress channel closed).
                        conn.close(true, 0, b"shutdown").ok();
                        flush_quic_send(&mut conn, &mut send_buf, &udp_send_tx).await;
                        return Ok(());
                    };
                    phase = new_phase;
                }
                maybe_batch = egress_rx.recv(), if was_established => {
                    let Some(packets) = maybe_batch else {
                        conn.close(true, 0, b"shutdown").ok();
                        flush_quic_send(&mut conn, &mut send_buf, &udp_send_tx).await;
                        return Ok(());
                    };
                    // SAFETY: `if was_established` guard guarantees `phase` is `Established`.
                    let H3Phase::Established { ref qsi_bytes, .. } = phase else {
                        unreachable!("egress arm fires only when was_established == true");
                    };
                    send_datagrams(&mut conn, packets, qsi_bytes, &mut tx_counters);
                }
                _ = &mut timer => {
                    conn.on_timeout();
                }
                _ = keepalive.tick(), if was_established => {
                    conn.send_ack_eliciting().ok();
                }
                _ = ticker.tick(), if was_established => {
                    let rx = rx_counters.snapshot(Some(&peer_id), Some(remote_addr));
                    let tx = tx_counters.snapshot(Some(&peer_id), Some(remote_addr));
                    let _ = events_tx.send(Event::Metrics(rx));
                    let _ = events_tx.send(Event::Metrics(tx));
                }
            }

            // Reset intervals on first transition to Established to avoid burst ticks.
            if !was_established && phase.is_established() {
                keepalive.reset();
                ticker.reset();
            }

            // Common post-arm: flush QUIC output and reset timer.
            flush_quic_send(&mut conn, &mut send_buf, &udp_send_tx).await;
            reset_timer(timer.as_mut(), &conn);

            if conn.is_closed() {
                phase.notify_handshake_error("QUIC connection closed");
                return Err(ActorError::H3Client {
                    peer_id,
                    reason: "QUIC connection closed".into(),
                });
            }
        }
    });

    (egress_tx, handle)
}

/// Resets the pinned timer to the next quiche timeout deadline.
///
/// Uses `MAX_TIMEOUT` as sentinel when quiche returns `None` (no pending timers).
fn reset_timer(timer: std::pin::Pin<&mut time::Sleep>, conn: &quiche::Connection) {
    let deadline = match conn.timeout() {
        Some(d) => time::Instant::now() + d,
        None => time::Instant::now() + MAX_TIMEOUT,
    };
    timer.reset(deadline);
}

// ========== Helper Functions ==========

/// Feeds encrypted UDP packets into quiche, using a shared recv_buf.
fn feed_packets(
    conn: &mut quiche::Connection,
    batch: &[PooledBuf],
    recv_buf: &mut [u8],
    info: quiche::RecvInfo,
) {
    for pkt in batch {
        debug_assert!(
            pkt.len() <= recv_buf.len(),
            "packet ({} B) exceeds recv_buf ({} B)",
            pkt.len(),
            recv_buf.len()
        );
        let len = pkt.len().min(recv_buf.len());
        recv_buf[..len].copy_from_slice(&pkt[..len]);
        match conn.recv(&mut recv_buf[..len], info) {
            Ok(_) | Err(quiche::Error::Done) => {}
            Err(e) => debug!(error = ?e, "quiche recv (non-fatal)"),
        }
    }
}

/// Flushes pending QUIC output packets to BareUDP TX.
///
/// Uses `try_send` to avoid blocking the QUIC event loop on backpressure.
async fn flush_quic_send(
    conn: &mut quiche::Connection,
    send_buf: &mut [u8],
    udp_send_tx: &mpsc::Sender<Vec<PooledBuf>>,
) {
    let mut batch: Vec<PooledBuf> = Vec::new();
    loop {
        match conn.send(send_buf) {
            Ok((len, _send_info)) => {
                batch.push(BufFactory::buf_from_slice(&send_buf[..len]));
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                warn!(error = ?e, "quiche send error");
                break;
            }
        }
    }
    if !batch.is_empty() && udp_send_tx.try_send(batch).is_err() {
        debug!("BareUDP TX channel full or closed; dropping QUIC output batch");
    }
}

/// Drains QUIC DATAGRAMs, strips QSI varint + Context ID, sends IP packets to TUN.
///
/// Returns `false` if the ingress channel has closed (TUN side gone), so the
/// caller can exit gracefully — consistent with the bare.rs actor pattern.
async fn drain_datagrams(
    conn: &mut quiche::Connection,
    dgram_buf: &mut [u8],
    ingress_tx: &mpsc::Sender<Vec<PooledBuf>>,
    counters: &mut Counters,
) -> bool {
    let mut batch: Vec<PooledBuf> = Vec::new();
    let mut ok_pkts: u64 = 0;
    let mut ok_bytes: u64 = 0;

    loop {
        match conn.dgram_recv(dgram_buf) {
            Ok(len) => {
                let data = &dgram_buf[..len];
                let Some(&first) = data.first() else {
                    counters.record_drop(DropReason::InvalidFraming, 1, len as u64);
                    continue;
                };
                let qsi_len = varint_parse_len(first);
                if data.len() < qsi_len {
                    counters.record_drop(DropReason::InvalidFraming, 1, len as u64);
                    continue;
                }
                let rest = &data[qsi_len..];
                if rest.is_empty() || rest[0] != CONTEXT_ID_IP {
                    counters.record_drop(DropReason::InvalidFraming, 1, len as u64);
                    continue;
                }
                let ip_pkt = &rest[1..];
                if ip_pkt.is_empty() {
                    counters.record_drop(DropReason::InvalidFraming, 1, len as u64);
                    continue;
                }
                batch.push(alloc_packet_buf(ip_pkt));
                ok_pkts += 1;
                ok_bytes += ip_pkt.len() as u64;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                debug!(error = ?e, "dgram_recv error");
                break;
            }
        }
    }
    if batch.is_empty() {
        return true;
    }
    counters
        .send_and_record(ingress_tx, batch, ok_pkts, ok_bytes)
        .await
}

/// Prepends QSI varint + Context ID to IP packets and queues them as QUIC DATAGRAMs.
fn send_datagrams(
    conn: &mut quiche::Connection,
    packets: Vec<PooledBuf>,
    qsi_bytes: &[u8],
    counters: &mut Counters,
) {
    let mut ok_pkts: u64 = 0;
    let mut ok_bytes: u64 = 0;
    for mut pkt in packets {
        let pkt_len = pkt.len() as u64;
        if !pkt.add_prefix(&[CONTEXT_ID_IP]) {
            counters.record_drop(DropReason::NoHeadroom, 1, pkt_len);
            continue;
        }
        if !pkt.add_prefix(qsi_bytes) {
            counters.record_drop(DropReason::NoHeadroom, 1, pkt_len);
            continue;
        }
        match conn.dgram_send(&pkt) {
            Ok(()) => {
                ok_pkts += 1;
                ok_bytes += pkt_len;
            }
            Err(e) => {
                debug!(error = ?e, "dgram_send failed");
                counters.record_drop(DropReason::SendError, 1, pkt_len);
            }
        }
    }
    if ok_pkts > 0 {
        counters.record_success(ok_pkts, ok_bytes);
    }
}

/// Drains H3 stream events (GoAway, Reset, etc.) during steady-state operation.
fn process_h3_events(
    h3_conn: &mut quiche::h3::Connection,
    conn: &mut quiche::Connection,
    peer_id: &str,
) {
    loop {
        match h3_conn.poll(conn) {
            Ok((_sid, quiche::h3::Event::GoAway)) => {
                info!(%peer_id, "received GoAway");
            }
            Ok((_sid, ev)) => {
                debug!(%peer_id, event = ?ev, "ignoring H3 event");
            }
            Err(quiche::h3::Error::Done) => break,
            Err(e) => {
                debug!(%peer_id, error = ?e, "H3 poll error");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octets::Octets;

    #[test]
    fn datagram_framing_encode_decode() {
        let ip_payload = b"test ip packet";
        // Encode qsi=0 (stream_id=0/4): single byte 0x00.
        let qsi_len = varint_len(0);
        let mut qsi_buf = [0u8; 8];
        OctetsMut::with_slice(&mut qsi_buf).put_varint(0).unwrap();
        let qsi_bytes = &qsi_buf[..qsi_len];

        let mut buf = alloc_packet_buf(ip_payload);
        assert!(buf.add_prefix(&[CONTEXT_ID_IP]));
        assert!(buf.add_prefix(qsi_bytes));

        let data = &buf[..];
        let parsed_qsi_len = varint_parse_len(data[0]);
        let qsi = Octets::with_slice(data).get_varint().unwrap();
        assert_eq!(qsi, 0);
        assert_eq!(data[parsed_qsi_len], CONTEXT_ID_IP);
        assert_eq!(&data[parsed_qsi_len + 1..], ip_payload);
    }

    #[test]
    fn make_quiche_config_valid() {
        let tuning = Tuning::default();
        assert!(make_quiche_config(&tuning, 1350).is_ok());
    }

    #[test]
    fn make_quiche_config_rejects_bad_cc() {
        let tuning = Tuning {
            h3_cc_algorithm: "invalid_algo".to_string(),
            ..Tuning::default()
        };
        assert!(make_quiche_config(&tuning, 1350).is_err());
    }

    #[test]
    fn dial_error_display() {
        let err = DialError::Timeout(Duration::from_secs(5));
        assert!(err.to_string().contains("5s"));
        let err = DialError::Socket("bind failed".into());
        assert!(err.to_string().contains("socket"));
        let err = DialError::Handshake("TLS error".into());
        assert!(err.to_string().contains("handshake"));
        let err = DialError::Rejected("403".into());
        assert!(err.to_string().contains("rejected"));
    }

    #[test]
    fn constants_match_protocol() {
        assert_eq!(CONTEXT_ID_IP, 0x00);
        assert_eq!(CONNECT_IP_OVERHEAD, 59);
    }

    #[tokio::test]
    async fn h32connection_debug_omits_handles() {
        use tokio::sync::mpsc;
        let (tx, _rx) = mpsc::channel::<Vec<PooledBuf>>(1);
        let conn = H3ClientConn {
            peer_id: "peer-1".into(),
            remote_addr: "1.2.3.4:443".parse().unwrap(),
            tx,
            engine_handle: tokio::spawn(async { Ok(()) }),
            udp_rx_handle: tokio::spawn(async { Ok(()) }),
            udp_tx_handle: tokio::spawn(async { Ok(()) }),
        };
        let dbg = format!("{conn:?}");
        assert!(dbg.contains("peer-1"));
        assert!(dbg.contains("1.2.3.4:443"));
        // Join handles are excluded by finish_non_exhaustive
        assert!(!dbg.contains("engine_handle"));
    }

    #[test]
    fn encode_qsi_roundtrip() {
        assert_eq!(encode_qsi(0), vec![0x00]);
        assert_eq!(encode_qsi(1), vec![0x01]);
        assert_eq!(encode_qsi(63).len(), 1);
        let encoded = encode_qsi(64);
        assert_eq!(encoded.len(), 2);
        let parsed = Octets::with_slice(&encoded).get_varint().unwrap();
        assert_eq!(parsed, 64);
    }

    #[test]
    fn advance_phase_noop_before_quic_established() {
        // Verify advance_phase returns QuicHandshake unchanged when QUIC is not established.
        let mut config = make_quiche_config(&Tuning::default(), 1350).unwrap();
        let scid = quiche::ConnectionId::from_ref(&[0u8; 16]);
        let local: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        let mut conn =
            quiche::connect(Some("localhost"), &scid, local, remote, &mut config).unwrap();
        let (established_tx, _established_rx) = oneshot::channel();
        let hs = ClientHandshake {
            established_tx,
            connect_headers: vec![],
        };
        let phase = H3Phase::QuicHandshake { hs };
        let (ingress_tx, _ingress_rx) = mpsc::channel(1);
        let mut dgram_buf = vec![0u8; 65535];
        let mut rx_counters = Counters::new(Source::Http3, Direction::Rx);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(advance_phase(
            phase,
            &mut conn,
            &mut dgram_buf,
            &ingress_tx,
            &mut rx_counters,
            "test-peer",
        ));
        let new_phase = result.unwrap().expect("should return Some");
        assert!(matches!(new_phase, H3Phase::QuicHandshake { .. }));
        assert!(!new_phase.is_established());
    }

    #[test]
    fn h3_phase_is_established_false_for_handshake() {
        let (tx, _rx) = oneshot::channel();
        let phase = H3Phase::QuicHandshake {
            hs: ClientHandshake {
                established_tx: tx,
                connect_headers: vec![],
            },
        };
        assert!(!phase.is_established());
    }
}
