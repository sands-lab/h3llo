//! Raw-quiche HTTP/3 CONNECT-IP transport with separated UDP I/O.
//!
//! Replaces tokio-quiche's internal QUIC driver with a hand-rolled quiche
//! event loop. A single **QuicEngine** actor owns the `quiche::Connection`
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
use crate::metrics::{Counters, Direction, DropReason, Source};
use crate::tun::alloc_packet_buf;
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

/// Context ID for IP payloads per RFC 9484 (always 0).
const CONTEXT_ID_IP: u8 = 0x00;

/// Conservative CONNECT-IP encapsulation overhead in bytes.
const CONNECT_IP_OVERHEAD: usize = 59;

/// Maximum datagrams drained per recv cycle.
const DGRAM_DRAIN_LIMIT: usize = 128;

/// Duration used as "infinite" timeout when quiche returns None.
const MAX_TIMEOUT: Duration = Duration::from_secs(86400);

// ========== QUIC Varint Codec (RFC 9000 §16) ==========

/// Encodes a u64 as a QUIC variable-length integer.
fn encode_varint(val: u64) -> Vec<u8> {
    if val < 64 {
        vec![val as u8]
    } else if val < 16384 {
        vec![0x40 | ((val >> 8) as u8), (val & 0xff) as u8]
    } else if val < 1_073_741_824 {
        let b = (val as u32).to_be_bytes();
        vec![0x80 | b[0], b[1], b[2], b[3]]
    } else {
        let b = val.to_be_bytes();
        vec![0xc0 | b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]
    }
}

/// Decodes a QUIC variable-length integer. Returns `(value, bytes_consumed)`.
fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let len = 1usize << (buf[0] >> 6);
    if buf.len() < len {
        return None;
    }
    let val = match len {
        1 => (buf[0] & 0x3f) as u64,
        2 => u16::from_be_bytes([buf[0] & 0x3f, buf[1]]) as u64,
        4 => u32::from_be_bytes([buf[0] & 0x3f, buf[1], buf[2], buf[3]]) as u64,
        8 => u64::from_be_bytes([
            buf[0] & 0x3f,
            buf[1],
            buf[2],
            buf[3],
            buf[4],
            buf[5],
            buf[6],
            buf[7],
        ]),
        _ => return None,
    };
    Some((val, len))
}

// ========== Connection Handle ==========

/// Established h3-2 CONNECT-IP connection.
///
/// Returned by [`dial_h3_2`]. The `tx` sender feeds IP packets into the
/// QuicEngine for encryption and transmission. Join handles are for
/// orchestrator supervision.
pub struct H32Connection {
    /// Authenticated peer identifier.
    pub peer_id: String,
    /// Remote socket address.
    pub remote_addr: SocketAddr,
    /// Channel for sending IP packets (TUN → encrypt → UDP).
    pub tx: mpsc::Sender<Vec<PooledBuf>>,
    /// QuicEngine actor join handle.
    pub engine_handle: JoinHandle<ActorExitResult>,
    /// BareUDP Rx actor join handle.
    pub udp_rx_handle: JoinHandle<ActorExitResult>,
    /// BareUDP Tx actor join handle.
    pub udp_tx_handle: JoinHandle<ActorExitResult>,
}

impl std::fmt::Debug for H32Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H32Connection")
            .field("peer_id", &self.peer_id)
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}

// ========== Dial Error ==========

/// Dial error for h3-2 connection establishment.
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
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.enable_dgram(true, 1024, 1024);
    config.set_max_idle_timeout(tuning.h3_max_idle_timeout.as_millis() as u64);
    config
        .set_cc_algorithm_name(&tuning.h3_cc_algorithm)
        .map_err(|e| {
            DialError::Handshake(format!("cc algorithm '{}': {e}", tuning.h3_cc_algorithm))
        })?;

    if tuning.h3_insecure_skip_verify {
        config.verify_peer(false);
    }
    // TODO: Load system CA certs when verify_peer is true.

    Ok(config)
}

// ========== Public Dial Function ==========

/// Establishes an outbound h3-2 CONNECT-IP connection.
///
/// Creates a UDP socket, spawns BareUDP Rx/Tx actors on cloned socket
/// handles, spawns the QuicEngine actor, and waits for the QUIC+H3
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
pub async fn dial_h3_2<P: RouteProbe>(
    peer_h3: &PeerH3,
    remote_addr: SocketAddr,
    peer_id: &str,
    tun_if: Option<&str>,
    tun_mtu: u16,
    probe: &P,
    tuning: &Tuning,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
) -> Result<H32Connection, DialError> {
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
    let (engine_rx_tx, engine_rx_rx) = mpsc::channel::<Vec<PooledBuf>>(tuning.packet_queue_depth);
    let accepted = HashSet::from([remote_addr.ip()]);
    let (_udp_rx_cmd, udp_rx_handle) = spawn_udp_rx(
        bare_rx,
        accepted,
        engine_rx_tx,
        events_tx.clone(),
        tuning.metrics_push_interval,
    );
    let (udp_tx_sender, udp_tx_handle) =
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

    // Spawn QuicEngine actor.
    let (established_tx, established_rx) = oneshot::channel();
    let (egress_tx, engine_handle) = spawn_quic_engine(
        conn,
        local_addr,
        remote_addr,
        peer_id.to_string(),
        engine_rx_rx,
        udp_tx_sender,
        ingress_tx,
        events_tx,
        tuning,
        Some(ClientHandshake {
            established_tx,
            connect_headers,
        }),
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

    info!(%peer_id, %remote_addr, "h3-2 connection established");
    Ok(H32Connection {
        peer_id: peer_id.to_string(),
        remote_addr,
        tx: egress_tx,
        engine_handle,
        udp_rx_handle,
        udp_tx_handle,
    })
}

// ========== QuicEngine Actor ==========

/// State passed to QuicEngine for client-side handshake.
struct ClientHandshake {
    established_tx: oneshot::Sender<Result<(), String>>,
    connect_headers: Vec<quiche::h3::Header>,
}

/// Spawns the QuicEngine actor.
///
/// Returns `(egress_tx, JoinHandle)` where `egress_tx` accepts IP packets
/// from the TUN for encryption and transmission.
#[allow(clippy::too_many_arguments)]
fn spawn_quic_engine(
    mut conn: quiche::Connection,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    peer_id: String,
    mut udp_rx: mpsc::Receiver<Vec<PooledBuf>>,
    udp_tx: mpsc::Sender<Vec<PooledBuf>>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    tuning: &Tuning,
    handshake: Option<ClientHandshake>,
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

        // Phase 1+2: Handshake
        flush_quic_send(&mut conn, &mut send_buf, &udp_tx).await;

        let (mut h3_conn, qsi_bytes) = match handshake {
            Some(hs) => {
                match drive_client_handshake(
                    &mut conn,
                    &mut send_buf,
                    &mut recv_buf,
                    &mut udp_rx,
                    &udp_tx,
                    recv_info,
                    &peer_id,
                    hs,
                )
                .await
                {
                    Ok(result) => result,
                    Err(e) => {
                        return Err(ActorError::QuicEngine {
                            peer_id,
                            reason: format!("handshake: {e}"),
                        })
                    }
                }
            }
            None => {
                return Err(ActorError::QuicEngine {
                    peer_id,
                    reason: "server mode not yet implemented".into(),
                })
            }
        };

        // Phase 3: Steady-state with pinned timer (Bold's pattern avoids per-iteration timer alloc)
        let mut rx_counters = Counters::new(Source::Http3, Direction::Rx);
        let mut tx_counters = Counters::new(Source::Http3, Direction::Tx);
        let mut ticker = time::interval(metrics_interval);
        let mut keepalive = time::interval(keepalive_interval);
        keepalive.tick().await; // consume the immediate first tick

        let timer = time::sleep(conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                maybe_batch = udp_rx.recv() => {
                    let Some(packets) = maybe_batch else { return Ok(()); };
                    feed_packets(&mut conn, &packets, &mut recv_buf, recv_info);
                    process_h3_events(&mut h3_conn, &mut conn, &peer_id);
                    drain_datagrams(
                        &mut conn,
                        &mut dgram_buf,
                        &ingress_tx,
                        &mut rx_counters,
                    ).await;
                    flush_quic_send(&mut conn, &mut send_buf, &udp_tx).await;
                    reset_timer(timer.as_mut(), &conn);
                }
                maybe_batch = egress_rx.recv() => {
                    let Some(packets) = maybe_batch else {
                        conn.close(true, 0, b"shutdown").ok();
                        flush_quic_send(&mut conn, &mut send_buf, &udp_tx).await;
                        return Ok(());
                    };
                    send_datagrams(&mut conn, packets, &qsi_bytes, &mut tx_counters);
                    flush_quic_send(&mut conn, &mut send_buf, &udp_tx).await;
                    reset_timer(timer.as_mut(), &conn);
                }
                _ = &mut timer => {
                    conn.on_timeout();
                    flush_quic_send(&mut conn, &mut send_buf, &udp_tx).await;
                    if conn.is_closed() {
                        return Err(ActorError::QuicEngine {
                            peer_id,
                            reason: "connection timed out".into(),
                        });
                    }
                    reset_timer(timer.as_mut(), &conn);
                }
                _ = keepalive.tick() => {
                    conn.send_ack_eliciting().ok();
                    flush_quic_send(&mut conn, &mut send_buf, &udp_tx).await;
                    reset_timer(timer.as_mut(), &conn);
                }
                _ = ticker.tick() => {
                    let rx = rx_counters.snapshot(Some(&peer_id), Some(remote_addr));
                    let tx = tx_counters.snapshot(Some(&peer_id), Some(remote_addr));
                    let _ = events_tx.send(Event::Metrics(rx));
                    let _ = events_tx.send(Event::Metrics(tx));
                }
            }

            if conn.is_closed() {
                return Err(ActorError::QuicEngine {
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

// ========== Handshake ==========

/// Drives client-side QUIC + H3 handshake. Returns `(h3_conn, qsi_bytes)`.
///
/// `qsi_bytes` is the QUIC stream ID (QSI) encoded as a QUIC varint,
/// used as the DATAGRAM frame prefix per draft-ietf-masque-connect-ip.
#[allow(clippy::too_many_arguments)]
async fn drive_client_handshake(
    conn: &mut quiche::Connection,
    send_buf: &mut [u8],
    recv_buf: &mut [u8],
    udp_rx: &mut mpsc::Receiver<Vec<PooledBuf>>,
    udp_tx: &mpsc::Sender<Vec<PooledBuf>>,
    recv_info: quiche::RecvInfo,
    peer_id: &str,
    hs: ClientHandshake,
) -> Result<(quiche::h3::Connection, Vec<u8>), String> {
    // Phase 1: QUIC handshake
    let timer = time::sleep(conn.timeout().unwrap_or(MAX_TIMEOUT));
    tokio::pin!(timer);

    loop {
        tokio::select! {
            batch = udp_rx.recv() => {
                let Some(pkts) = batch else {
                    return Err("UDP Rx closed during handshake".into());
                };
                feed_packets(conn, &pkts, recv_buf, recv_info);
            }
            _ = &mut timer => {
                conn.on_timeout();
            }
        }
        flush_quic_send(conn, send_buf, udp_tx).await;
        if conn.is_established() {
            break;
        }
        if conn.is_closed() {
            return Err("connection closed during QUIC handshake".into());
        }
        reset_timer(timer.as_mut(), conn);
    }

    debug!(%peer_id, "QUIC handshake complete, starting H3 negotiation");

    // Phase 2: H3 CONNECT-IP
    let h3_config = quiche::h3::Config::new().map_err(|e| format!("h3 config: {e}"))?;
    let mut h3_conn = quiche::h3::Connection::with_transport(conn, &h3_config)
        .map_err(|e| format!("h3 connection: {e}"))?;
    let stream_id = h3_conn
        .send_request(conn, &hs.connect_headers, false)
        .map_err(|e| format!("send CONNECT: {e}"))?;
    flush_quic_send(conn, send_buf, udp_tx).await;
    reset_timer(timer.as_mut(), conn);

    // QSI = stream_id / 4 per draft-ietf-masque-connect-ip
    let qsi = stream_id / 4;
    let qsi_bytes = encode_varint(qsi);

    loop {
        tokio::select! {
            batch = udp_rx.recv() => {
                let Some(pkts) = batch else {
                    let _ = hs.established_tx.send(Err("UDP Rx closed".into()));
                    return Err("UDP Rx closed during H3 handshake".into());
                };
                feed_packets(conn, &pkts, recv_buf, recv_info);
            }
            _ = &mut timer => {
                conn.on_timeout();
            }
        }
        flush_quic_send(conn, send_buf, udp_tx).await;
        reset_timer(timer.as_mut(), conn);

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
                            let _ = hs.established_tx.send(Ok(()));
                            return Ok((h3_conn, qsi_bytes));
                        }
                        Some(s) => {
                            let code = String::from_utf8_lossy(s).to_string();
                            let _ = hs.established_tx.send(Err(format!("rejected: {code}")));
                            return Err(format!("CONNECT-IP rejected: {code}"));
                        }
                        None => {
                            let _ = hs.established_tx.send(Err("missing :status".into()));
                            return Err("missing :status".into());
                        }
                    }
                }
                Ok((_sid, quiche::h3::Event::GoAway)) => {
                    let _ = hs.established_tx.send(Err("GoAway".into()));
                    return Err("GoAway during handshake".into());
                }
                Ok(_) => continue,
                Err(quiche::h3::Error::Done) => break,
                Err(e) => {
                    let msg = format!("H3 poll: {e}");
                    let _ = hs.established_tx.send(Err(msg.clone()));
                    return Err(msg);
                }
            }
        }
        if conn.is_closed() {
            let _ = hs.established_tx.send(Err("closed during H3".into()));
            return Err("closed during H3 handshake".into());
        }
    }
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
    udp_tx: &mpsc::Sender<Vec<PooledBuf>>,
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
    if !batch.is_empty() {
        let _ = udp_tx.try_send(batch);
    }
}

/// Drains QUIC DATAGRAMs, strips QSI varint + Context ID, sends IP packets to TUN.
async fn drain_datagrams(
    conn: &mut quiche::Connection,
    dgram_buf: &mut [u8],
    ingress_tx: &mpsc::Sender<Vec<PooledBuf>>,
    counters: &mut Counters,
) {
    let mut batch: Vec<PooledBuf> = Vec::new();
    let mut ok_pkts: u64 = 0;
    let mut ok_bytes: u64 = 0;

    for _ in 0..DGRAM_DRAIN_LIMIT {
        match conn.dgram_recv(dgram_buf) {
            Ok(len) => {
                let data = &dgram_buf[..len];
                let Some((_qsi, qsi_len)) = decode_varint(data) else {
                    counters.record_drop(DropReason::InvalidFraming, 1, len as u64);
                    continue;
                };
                let rest = &data[qsi_len..];
                if rest.is_empty() || rest[0] != CONTEXT_ID_IP {
                    counters.record_drop(DropReason::InvalidFraming, 1, len as u64);
                    continue;
                }
                let ip_pkt = &rest[1..];
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
    if !batch.is_empty() {
        counters
            .send_and_record(ingress_tx, batch, ok_pkts, ok_bytes)
            .await;
    }
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

    #[test]
    fn varint_roundtrip() {
        for val in [0, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824] {
            let enc = encode_varint(val);
            let (dec, len) = decode_varint(&enc).unwrap();
            assert_eq!(dec, val);
            assert_eq!(len, enc.len());
        }
    }

    #[test]
    fn decode_varint_empty_and_truncated() {
        assert!(decode_varint(&[]).is_none());
        assert!(decode_varint(&[0x40]).is_none()); // 2-byte prefix, only 1 byte provided
    }

    #[test]
    fn datagram_framing_encode_decode() {
        let ip_payload = b"test ip packet";
        let qsi_bytes = encode_varint(0); // stream_id=0, qsi=0
        let mut buf = alloc_packet_buf(ip_payload);
        assert!(buf.add_prefix(&[CONTEXT_ID_IP]));
        assert!(buf.add_prefix(&qsi_bytes));

        let data = &buf[..];
        let (qsi, qsi_len) = decode_varint(data).unwrap();
        assert_eq!(qsi, 0);
        assert_eq!(data[qsi_len], CONTEXT_ID_IP);
        assert_eq!(&data[qsi_len + 1..], ip_payload);
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
        let conn = H32Connection {
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
}
