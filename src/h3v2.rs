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
use crate::tun::alloc_uninit_packet_buf;
use octets::{varint_len, varint_parse_len, Octets, OctetsMut};
use quiche::h3::NameValue;
use rand::Rng;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_quiche::buf_factory::PooledBuf;
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
fn make_quiche_config(
    tuning: &Tuning,
    max_udp_payload: usize,
) -> Result<quiche::Config, DialError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| DialError::Handshake(format!("quiche config: {e}")))?;
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| DialError::Handshake(format!("ALPN: {e}")))?;

    config.set_max_recv_udp_payload_size(max_udp_payload);
    config.set_max_send_udp_payload_size(max_udp_payload);
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

// ========== H3 Client Engine ==========

/// H3 control/session state bound to the CONNECT-IP request.
struct H3Session {
    /// H3 connection for polling events and sending datagrams.
    ///
    /// Boxed because `quiche::h3::Connection` is ~544 B.
    h3_conn: Box<quiche::h3::Connection>,
    /// Stream ID of the CONNECT-IP request.
    connect_stream_id: u64,
    /// Quarter Stream ID for DATAGRAM framing validation.
    expected_qsi: u64,
    /// Pre-encoded QSI varint bytes for DATAGRAM framing prefix.
    qsi_bytes: Vec<u8>,
    /// Whether the CONNECT-IP request has been accepted (200 OK received).
    connect_accepted: bool,
}

/// Single actor state for both startup and established phases.
///
/// Owns the QUIC connection and all I/O channels. The `establish` method
/// drives handshake, then `run` handles steady-state datagram forwarding.
struct H3ClientEngine {
    conn: quiche::Connection,
    session: Option<H3Session>,

    authority: String,
    connect_path: String,
    auth_header: String,

    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    peer_id: String,
    max_udp_payload: usize,

    udp_recv_rx: mpsc::Receiver<Vec<PooledBuf>>,
    udp_send_tx: mpsc::Sender<Vec<PooledBuf>>,

    egress_rx: mpsc::Receiver<Vec<PooledBuf>>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,

    metrics_interval: Duration,
    keepalive_interval: Duration,
}

/// Result of polling H3 events for the CONNECT-IP control stream.
enum ConnectPoll {
    /// No actionable events yet.
    Pending,
    /// CONNECT-IP 200 OK received (or was already received).
    Accepted,
    /// CONNECT-IP rejected with the given status code.
    Rejected { status: String },
    /// CONNECT-IP stream closed or errored.
    Closed { reason: String },
}

impl H3Session {
    /// Returns `true` when the CONNECT-IP session is fully ready for datagram forwarding.
    fn connect_ready(&self, conn: &quiche::Connection) -> bool {
        self.connect_accepted
            && self.h3_conn.dgram_enabled_by_peer(conn)
            && self.h3_conn.extended_connect_enabled_by_peer()
    }

    /// Polls H3 events for the CONNECT-IP control stream.
    fn poll_connect_response(
        &mut self,
        conn: &mut quiche::Connection,
        peer_id: &str,
    ) -> Result<ConnectPoll, DialError> {
        loop {
            match self.h3_conn.poll(conn) {
                Ok((sid, quiche::h3::Event::Headers { list, .. })) => {
                    if sid != self.connect_stream_id {
                        debug!(%peer_id, sid, "ignoring headers on non-CONNECT stream");
                        continue;
                    }

                    let status = list
                        .iter()
                        .find(|h| h.name() == b":status")
                        .map(|h| String::from_utf8_lossy(h.value()).to_string());

                    match status.as_deref() {
                        Some("200") => {
                            self.connect_accepted = true;
                        }
                        Some(code) => {
                            return Ok(ConnectPoll::Rejected {
                                status: code.to_string(),
                            });
                        }
                        None => {
                            return Ok(ConnectPoll::Closed {
                                reason: "missing :status on CONNECT-IP response".into(),
                            });
                        }
                    }
                }

                Ok((sid, quiche::h3::Event::Finished)) => {
                    if sid == self.connect_stream_id {
                        return Ok(ConnectPoll::Closed {
                            reason: "CONNECT-IP stream finished".into(),
                        });
                    }
                }

                Ok((sid, quiche::h3::Event::Reset(code))) => {
                    if sid == self.connect_stream_id {
                        return Ok(ConnectPoll::Closed {
                            reason: format!("CONNECT-IP stream reset: {code}"),
                        });
                    }
                }

                Ok((_sid, quiche::h3::Event::GoAway)) => {
                    info!(%peer_id, "received H3 GOAWAY");
                }

                Ok((_sid, quiche::h3::Event::PriorityUpdate)) => {}

                Ok((_sid, ev)) => {
                    debug!(%peer_id, event = ?ev, "ignoring unrelated H3 event");
                }

                Err(quiche::h3::Error::Done) => {
                    return Ok(if self.connect_accepted {
                        ConnectPoll::Accepted
                    } else {
                        ConnectPoll::Pending
                    });
                }

                Err(e) => {
                    return Err(DialError::Handshake(format!("H3 poll: {e}")));
                }
            }
        }
    }
}

/// Batch of IP packets waiting for `ingress_tx` capacity, with deferred metrics.
struct PendingIngress {
    batch: Vec<PooledBuf>,
    pkts: u64,
    bytes: u64,
    /// When the batch first became pending (for congestion duration tracking).
    since: Instant,
}

impl H3ClientEngine {
    fn recv_info(&self) -> quiche::RecvInfo {
        quiche::RecvInfo {
            from: self.remote_addr,
            to: self.local_addr,
        }
    }

    /// Best-effort flush of QUIC output to the UDP send channel.
    ///
    /// Used during handshake and close, where pending-send tracking is unnecessary.
    /// Drops on channel backpressure — acceptable because quiche retransmits during
    /// handshake and CONNECTION_CLOSE is best-effort.
    fn flush_send(&mut self) {
        let batch = collect_udp_send(&mut self.conn, self.max_udp_payload);
        if !batch.is_empty() {
            let _ = self.udp_send_tx.try_send(batch);
        }
    }

    /// Startup phase: wait for QUIC establishment + H3 CONNECT-IP acceptance.
    async fn establish(mut self) -> Result<Self, DialError> {
        let recv_info = self.recv_info();

        // Send initial QUIC packets (e.g. ClientHello).
        self.flush_send();

        let timer = time::sleep(self.conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                maybe_batch = self.udp_recv_rx.recv() => {
                    let Some(packets) = maybe_batch else {
                        return Err(DialError::Handshake("UDP Rx closed during startup".into()));
                    };

                    handle_udp_recv(&mut self.conn, packets, recv_info);

                    if self.session.is_none() && self.conn.is_established() {
                        debug!(%self.peer_id, "QUIC established; starting H3 CONNECT-IP");
                        self.start_h3_connect()?;
                    }

                    if let Some(session) = &mut self.session {
                        match session.poll_connect_response(&mut self.conn, &self.peer_id)? {
                            ConnectPoll::Pending | ConnectPoll::Accepted => {}
                            ConnectPoll::Rejected { status } => {
                                return Err(DialError::Rejected(status));
                            }
                            ConnectPoll::Closed { reason } => {
                                return Err(DialError::Handshake(reason));
                            }
                        }

                        if session.connect_ready(&self.conn) {
                            return Ok(self);
                        }
                    }
                }

                _ = &mut timer => {
                    self.conn.on_timeout();
                }
            }

            self.flush_send();
            reset_timer(timer.as_mut(), &self.conn);

            if self.conn.is_closed() {
                return Err(DialError::Handshake(
                    "QUIC connection closed during startup".into(),
                ));
            }
        }
    }

    /// Creates H3 connection, sends CONNECT-IP request, and stores session state.
    fn start_h3_connect(&mut self) -> Result<(), DialError> {
        let h3_config = quiche::h3::Config::new()
            .map_err(|e| DialError::Handshake(format!("h3 config: {e}")))?;

        let mut h3_conn = quiche::h3::Connection::with_transport(&mut self.conn, &h3_config)
            .map_err(|e| DialError::Handshake(format!("h3 connection: {e}")))?;

        let connect_headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", self.authority.as_bytes()),
            quiche::h3::Header::new(b":path", self.connect_path.as_bytes()),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            quiche::h3::Header::new(b"authorization", self.auth_header.as_bytes()),
        ];

        let connect_stream_id = h3_conn
            .send_request(&mut self.conn, &connect_headers, false)
            .map_err(|e| DialError::Handshake(format!("send CONNECT: {e}")))?;

        let expected_qsi = connect_stream_id / 4;
        let qsi_bytes = encode_qsi(expected_qsi);

        self.session = Some(H3Session {
            h3_conn: Box::new(h3_conn),
            connect_stream_id,
            expected_qsi,
            qsi_bytes,
            connect_accepted: false,
        });

        Ok(())
    }

    /// Established phase: steady-state datagram forwarding.
    ///
    /// Uses three pending slots for zero-drop backpressure:
    /// - `pending_ingress`: IP packets from dgram_recv waiting for `ingress_tx` capacity.
    /// - `pending_egress`: IP packets from TUN waiting for `conn.dgram_send()` capacity.
    /// - `pending_send`: encrypted QUIC packets waiting for `udp_send_tx` capacity.
    async fn run(mut self) -> ActorExitResult {
        let recv_info = self.recv_info();
        let mut session = self
            .session
            .take()
            .expect("session present after establish");

        // Destructure into locals to avoid &mut self vs &self.field borrow
        // conflicts inside tokio::select! (reserve() holds &Sender across arms).
        let mut conn = self.conn;
        let mut udp_recv_rx = self.udp_recv_rx;
        let udp_send_tx = self.udp_send_tx;
        let mut egress_rx = self.egress_rx;
        let ingress_tx = self.ingress_tx;
        let events_tx = self.events_tx;
        let peer_id = self.peer_id;
        let remote_addr = self.remote_addr;
        let max_udp_payload = self.max_udp_payload;

        let mut rx_counters = Counters::new(Source::Http3, Direction::Rx);
        let mut tx_counters = Counters::new(Source::Http3, Direction::Tx);

        let mut pending_ingress: Option<PendingIngress> = None;
        let mut pending_egress: Option<Vec<PooledBuf>> = None;
        let mut pending_send: Option<Vec<PooledBuf>> = None;

        let mut ticker = time::interval(self.metrics_interval);
        let mut keepalive = time::interval(self.keepalive_interval);
        keepalive.tick().await;

        let timer = time::sleep(conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        /// Inline close helper: sends QUIC close frame and best-effort flushes.
        macro_rules! close_flush {
            ($reason:expr) => {{
                conn.close(true, 0, $reason).ok();
                let batch = collect_udp_send(&mut conn, max_udp_payload);
                if !batch.is_empty() {
                    let _ = udp_send_tx.try_send(batch);
                }
            }};
        }

        loop {
            tokio::select! {
                // UDP → quiche → dgram_recv → ingress_tx.
                // Blocked only when ingress is pending (no room for more datagrams).
                // NOT blocked by pending_send — ACKs arriving here may resolve
                // pending_egress, and pending_send drains quickly via reserve().
                maybe_batch = udp_recv_rx.recv(),
                    if pending_ingress.is_none() =>
                {
                    let Some(packets) = maybe_batch else {
                        close_flush!(b"udp rx closed");
                        return Ok(());
                    };

                    handle_udp_recv(&mut conn, packets, recv_info);

                    match session.poll_connect_response(&mut conn, &peer_id) {
                        Ok(ConnectPoll::Pending | ConnectPoll::Accepted) => {}
                        Ok(ConnectPoll::Rejected { status }) => {
                            let reason =
                                format!("CONNECT-IP rejected after establish: {status}");
                            close_flush!(b"connect-ip rejected");
                            return Err(ActorError::H3Client { peer_id, reason });
                        }
                        Ok(ConnectPoll::Closed { reason }) => {
                            close_flush!(b"connect-ip control closed");
                            return Err(ActorError::H3Client { peer_id, reason });
                        }
                        Err(e) => {
                            close_flush!(b"h3 poll error");
                            return Err(ActorError::H3Client {
                                peer_id,
                                reason: e.to_string(),
                            });
                        }
                    }

                    if let Some((batch, pkts, bytes)) = collect_router_ingress(
                        &mut conn,
                        max_udp_payload,
                        &mut rx_counters,
                        session.expected_qsi,
                    ) {
                        match ingress_tx.try_send(batch) {
                            Ok(()) => {
                                rx_counters.record_success(pkts, bytes);
                            }
                            Err(mpsc::error::TrySendError::Full(batch)) => {
                                pending_ingress = Some(PendingIngress {
                                    batch, pkts, bytes,
                                    since: Instant::now(),
                                });
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                close_flush!(b"shutdown");
                                return Ok(());
                            }
                        }
                    }
                }

                // Drain pending ingress when ingress_tx has capacity.
                permit_res = ingress_tx.reserve(),
                    if pending_ingress.is_some() =>
                {
                    match permit_res {
                        Ok(permit) => {
                            let pi = pending_ingress.take().unwrap();
                            rx_counters.record_queue_full(pi.since.elapsed());
                            rx_counters.record_success(pi.pkts, pi.bytes);
                            permit.send(pi.batch);
                        }
                        Err(_closed) => {
                            close_flush!(b"shutdown");
                            return Ok(());
                        }
                    }
                }

                // TUN → dgram_send. Blocked when egress is pending (dgram queue full).
                maybe_batch = egress_rx.recv(),
                    if pending_egress.is_none() =>
                {
                    let Some(packets) = maybe_batch else {
                        close_flush!(b"shutdown");
                        return Ok(());
                    };

                    pending_egress = handle_router_egress(
                        &mut conn,
                        packets,
                        &session.qsi_bytes,
                        &mut tx_counters,
                    );
                }

                // Drain pending send when udp_send_tx has capacity.
                permit_res = udp_send_tx.reserve(),
                    if pending_send.is_some() =>
                {
                    match permit_res {
                        Ok(permit) => {
                            permit.send(pending_send.take().unwrap());
                        }
                        Err(_closed) => {
                            close_flush!(b"udp tx closed");
                            return Ok(());
                        }
                    }
                }

                _ = &mut timer => {
                    conn.on_timeout();
                }

                _ = keepalive.tick() => {
                    conn.send_ack_eliciting().ok();
                }

                _ = ticker.tick() => {
                    let rx = rx_counters.snapshot(Some(&peer_id), Some(remote_addr));
                    let tx = tx_counters.snapshot(Some(&peer_id), Some(remote_addr));
                    let _ = events_tx.send(Event::Metrics(rx));
                    let _ = events_tx.send(Event::Metrics(tx));
                }
            }

            flush_and_retry_router_egress(
                &mut conn,
                max_udp_payload,
                &udp_send_tx,
                &mut pending_egress,
                &mut pending_send,
                &session.qsi_bytes,
                &mut tx_counters,
            );
            reset_timer(timer.as_mut(), &conn);

            if conn.is_closed() {
                return Err(ActorError::H3Client {
                    peer_id,
                    reason: "QUIC connection closed".into(),
                });
            }
        }
    }
}

// ========== Public Dial Function ==========

/// Establishes an outbound H3 client CONNECT-IP connection.
///
/// Creates a UDP socket, spawns BareUDP Rx/Tx actors on cloned socket
/// handles, builds the H3 client engine, and drives QUIC+H3 handshake
/// on the crypto runtime before entering steady-state forwarding.
///
/// # Arguments
///
/// * `crypto_rt` - Runtime handle for spawning the H3 client engine.
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
    crypto_rt: &RuntimeHandle,
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

    let connect_path = endpoint.path.clone();
    let auth_header = generate_bearer_auth(&peer_h3.token);

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

    let max_udp_payload = tun_mtu as usize + CONNECT_IP_OVERHEAD;
    let bare_rx = bare_rx_from_socket(rx_socket, max_udp_payload)
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
    let mut config = make_quiche_config(tuning, max_udp_payload)?;
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

    let (egress_tx, egress_rx) = mpsc::channel::<Vec<PooledBuf>>(tuning.packet_queue_depth);

    let engine = H3ClientEngine {
        conn,
        session: None,

        authority,
        connect_path,
        auth_header,

        local_addr,
        remote_addr,
        peer_id: peer_id.to_string(),
        max_udp_payload,

        udp_recv_rx,
        udp_send_tx: udp_send_tx.clone(),

        egress_rx,
        ingress_tx,
        events_tx: events_tx.clone(),

        metrics_interval: tuning.metrics_push_interval,
        keepalive_interval: tuning.h3_keepalive_interval,
    };

    let startup_handle = crypto_rt.spawn(engine.establish());

    let result = match time::timeout(tuning.h3_handshake_timeout, startup_handle).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_err)) => Err(DialError::Handshake(format!(
            "startup task join error: {join_err}"
        ))),
        Err(_) => Err(DialError::Timeout(tuning.h3_handshake_timeout)),
    };

    let engine = match result {
        Ok(engine) => engine,
        Err(err) => {
            udp_rx_handle.abort();
            udp_tx_handle.abort();
            return Err(err);
        }
    };

    let engine_handle = crypto_rt.spawn(engine.run());

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

// ========== QSI Helpers ==========

/// Encodes a Quarter Stream ID as a QUIC varint byte sequence.
fn encode_qsi(qsi: u64) -> Vec<u8> {
    let len = varint_len(qsi);
    let mut buf = [0u8; 8];
    OctetsMut::with_slice(&mut buf)
        .put_varint(qsi)
        .expect("qsi fits varint");
    buf[..len].to_vec()
}

/// Decodes a Quarter Stream ID varint from the start of a buffer.
///
/// Returns `(qsi_value, qsi_byte_length)` on success.
fn decode_qsi(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let qsi_len = varint_parse_len(first);
    if buf.len() < qsi_len {
        return None;
    }

    let mut octets = Octets::with_slice(buf);
    let qsi = octets.get_varint().ok()?;
    Some((qsi, qsi_len))
}

// ========== Helper Functions ==========

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

/// Decrypts a batch of received UDP packets by feeding them into quiche.
///
/// Takes ownership of the batch to pass each buffer mutably to `conn.recv()`,
/// avoiding an intermediate copy through a shared receive buffer.
fn handle_udp_recv(conn: &mut quiche::Connection, batch: Vec<PooledBuf>, info: quiche::RecvInfo) {
    for mut pkt in batch {
        match conn.recv(&mut pkt, info) {
            Ok(_) | Err(quiche::Error::Done) => {}
            Err(e) => debug!(error = ?e, "quiche recv (non-fatal)"),
        }
    }
}

/// Collects pending QUIC output packets into a batch.
///
/// Pure function with no channel dependency — the caller is responsible for
/// sending the batch via `try_send` + `pending_send` pattern.
fn collect_udp_send(conn: &mut quiche::Connection, max_udp_payload: usize) -> Vec<PooledBuf> {
    let mut batch: Vec<PooledBuf> = Vec::new();
    loop {
        let mut buf = alloc_uninit_packet_buf(max_udp_payload);
        match conn.send(&mut buf) {
            Ok((len, _send_info)) => {
                buf.truncate(len);
                batch.push(buf);
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                warn!(error = ?e, "quiche send error");
                break;
            }
        }
    }
    batch
}

/// Validates and strips QSI + Context ID framing from a DATAGRAM buffer.
///
/// Returns the prefix length to strip on success, or `None` for any framing error.
fn validate_datagram_framing(buf: &[u8], expected_qsi: u64) -> Option<usize> {
    let (qsi, qsi_len) = decode_qsi(buf)?;
    if qsi != expected_qsi {
        return None;
    }
    let prefix_len = qsi_len + 1;
    if buf.len() < prefix_len || buf[qsi_len] != CONTEXT_ID_IP {
        return None;
    }
    // Must have IP payload after the prefix.
    if buf.len() == prefix_len {
        return None;
    }
    Some(prefix_len)
}

/// Collects inbound QUIC DATAGRAMs with QSI validation and strips framing.
///
/// Returns `(batch, pkts, bytes)` if any valid datagrams were collected, or
/// `None` if the dgram queue was empty. The caller is responsible for sending
/// the batch to `ingress_tx` (via `try_send` / pending pattern).
fn collect_router_ingress(
    conn: &mut quiche::Connection,
    max_udp_payload: usize,
    counters: &mut Counters,
    expected_qsi: u64,
) -> Option<(Vec<PooledBuf>, u64, u64)> {
    let mut batch: Vec<PooledBuf> = Vec::new();
    let mut ok_pkts: u64 = 0;
    let mut ok_bytes: u64 = 0;

    loop {
        let mut buf = alloc_uninit_packet_buf(max_udp_payload);
        match conn.dgram_recv(&mut buf) {
            Ok(len) => {
                buf.truncate(len);

                let Some(prefix_len) = validate_datagram_framing(&buf, expected_qsi) else {
                    counters.record_drop(DropReason::InvalidFraming, 1, len as u64);
                    continue;
                };

                buf.pop_front(prefix_len);
                ok_pkts += 1;
                ok_bytes += buf.len() as u64;
                batch.push(buf);
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                debug!(error = ?e, "dgram_recv error");
                break;
            }
        }
    }

    if batch.is_empty() {
        return None;
    }

    Some((batch, ok_pkts, ok_bytes))
}

/// Encodes egress IP packets as QUIC DATAGRAMs with QSI varint + Context ID prefix.
///
/// Returns unsent packets (with framing stripped) when the dgram queue is full,
/// so the caller can store them as `pending_egress` for retry after `flush_send`.
fn handle_router_egress(
    conn: &mut quiche::Connection,
    packets: Vec<PooledBuf>,
    qsi_bytes: &[u8],
    counters: &mut Counters,
) -> Option<Vec<PooledBuf>> {
    let prefix_len = qsi_bytes.len() + 1;
    let mut ok_pkts: u64 = 0;
    let mut ok_bytes: u64 = 0;
    let mut iter = packets.into_iter();

    while let Some(mut pkt) = iter.next() {
        let pkt_len = pkt.len() as u64;
        if !pkt.add_prefix(&[CONTEXT_ID_IP]) || !pkt.add_prefix(qsi_bytes) {
            counters.record_drop(DropReason::NoHeadroom, 1, pkt_len);
            continue;
        }
        match conn.dgram_send(&pkt) {
            Ok(()) => {
                ok_pkts += 1;
                ok_bytes += pkt_len;
            }
            Err(quiche::Error::Done) => {
                // Queue full: undo framing and collect remaining for retry.
                debug!(
                    "dgram_send queue full; {} pkts pending",
                    1 + iter.size_hint().0
                );
                pkt.pop_front(prefix_len);
                let mut remaining = vec![pkt];
                remaining.extend(iter);
                if ok_pkts > 0 {
                    counters.record_success(ok_pkts, ok_bytes);
                }
                return Some(remaining);
            }
            Err(e) => {
                // Non-queue-full error (e.g. BufferTooShort, InvalidState):
                // drop to prevent infinite retry.
                debug!(error = ?e, "dgram_send failed; dropping packet");
                counters.record_drop(DropReason::SendError, 1, pkt_len);
            }
        }
    }

    if ok_pkts > 0 {
        counters.record_success(ok_pkts, ok_bytes);
    }
    None
}

/// Tries to send a QUIC output batch to `udp_send_tx`.
///
/// Returns `Some(batch)` when the channel is full so the caller can store it
/// as `pending_send` for retry via `reserve()`.
fn try_send_udp(
    udp_send_tx: &mpsc::Sender<Vec<PooledBuf>>,
    batch: Vec<PooledBuf>,
) -> Option<Vec<PooledBuf>> {
    match udp_send_tx.try_send(batch) {
        Ok(()) => None,
        Err(mpsc::error::TrySendError::Full(batch)) => Some(batch),
        Err(mpsc::error::TrySendError::Closed(_)) => None,
    }
}

/// Retries pending egress datagrams and flushes QUIC output, with two-phase retry.
///
/// Phase 1: retry `pending_egress` (previous collect/send may have freed dgram space).
/// Phase 2: collect + try-send QUIC output.
/// Phase 3: retry `pending_egress` again (phase 2 may have freed more space).
/// Phase 4: final collect + try-send for any new QUIC output from phase 3.
fn flush_and_retry_router_egress(
    conn: &mut quiche::Connection,
    max_udp_payload: usize,
    udp_send_tx: &mpsc::Sender<Vec<PooledBuf>>,
    pending_egress: &mut Option<Vec<PooledBuf>>,
    pending_send: &mut Option<Vec<PooledBuf>>,
    qsi_bytes: &[u8],
    tx_counters: &mut Counters,
) {
    // Phase 1: retry pending egress before drain.
    if let Some(remaining) = pending_egress.take() {
        *pending_egress = handle_router_egress(conn, remaining, qsi_bytes, tx_counters);
    }

    // Phase 2: collect QUIC output → try_send to udp_send_tx.
    if pending_send.is_none() {
        let batch = collect_udp_send(conn, max_udp_payload);
        if !batch.is_empty() {
            *pending_send = try_send_udp(udp_send_tx, batch);
        }
    }

    // Phase 3: drain may have freed dgram queue space → retry again.
    if let Some(remaining) = pending_egress.take() {
        *pending_egress = handle_router_egress(conn, remaining, qsi_bytes, tx_counters);
    }

    // Phase 4: flush any new QUIC output from retried datagrams.
    if pending_send.is_none() {
        let batch = collect_udp_send(conn, max_udp_payload);
        if !batch.is_empty() {
            *pending_send = try_send_udp(udp_send_tx, batch);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::alloc_packet_buf;

    #[test]
    fn datagram_framing_encode_decode() {
        let ip_payload = b"test ip packet";
        let qsi_bytes = encode_qsi(0);

        let mut buf = alloc_packet_buf(ip_payload);
        assert!(buf.add_prefix(&[CONTEXT_ID_IP]));
        assert!(buf.add_prefix(&qsi_bytes));

        let data = &buf[..];
        let (qsi, qsi_len) = decode_qsi(data).expect("valid QSI");
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
    fn decode_qsi_roundtrip() {
        // Single-byte varints.
        assert_eq!(decode_qsi(&[0x00]), Some((0, 1)));
        assert_eq!(decode_qsi(&[0x01]), Some((1, 1)));
        assert_eq!(decode_qsi(&[0x3f]), Some((63, 1)));

        // Two-byte varint via QSI roundtrip.
        let encoded = encode_qsi(64);
        assert_eq!(decode_qsi(&encoded), Some((64, 2)));

        // Empty buffer.
        assert_eq!(decode_qsi(&[]), None);

        // Truncated 2-byte varint (first byte indicates 2-byte encoding).
        assert_eq!(decode_qsi(&[0x40]), None);
    }
}
