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
    /// BareUDP Rx actor command sender (kept alive to prevent actor shutdown).
    pub udp_rx_cmd: mpsc::UnboundedSender<crate::bare::BareUdpRxCommand>,
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
    /// CONNECT-IP DATAGRAM framing codec for this request stream.
    datagram_codec: ConnectIpDatagramCodec,
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

    io: EngineIo,
    meta: EngineMeta,
    run_state: RunState,

    metrics_interval: Duration,
    keepalive_interval: Duration,
}

/// Channels owned by the H3 client actor.
struct EngineIo {
    udp_recv_rx: mpsc::Receiver<Vec<PooledBuf>>,
    udp_send_tx: mpsc::Sender<Vec<PooledBuf>>,
    egress_rx: mpsc::Receiver<Vec<PooledBuf>>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
}

/// Connection metadata shared across startup and established phases.
struct EngineMeta {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    peer_id: String,
    max_udp_payload: usize,
}

impl EngineMeta {
    fn recv_info(&self) -> quiche::RecvInfo {
        quiche::RecvInfo {
            from: self.remote_addr,
            to: self.local_addr,
        }
    }

    fn actor_error(&self, reason: impl Into<String>) -> ActorError {
        ActorError::H3Client {
            peer_id: self.peer_id.clone(),
            reason: reason.into(),
        }
    }
}

/// Result of advancing CONNECT-IP control-plane state.
enum ConnectProgress {
    /// CONNECT-IP is not ready for datagram forwarding yet.
    Pending,
    /// CONNECT-IP is fully established and ready for datagrams.
    Ready,
}

/// Error raised while advancing CONNECT-IP control-plane state.
enum ConnectFailure {
    /// CONNECT-IP rejected with the given status code.
    Rejected(String),
    /// CONNECT-IP stream closed unexpectedly.
    Closed(String),
    /// H3 control-plane polling itself failed.
    Poll(String),
}

impl ConnectFailure {
    fn close_reason(&self) -> &'static [u8] {
        match self {
            Self::Rejected(_) => b"connect-ip rejected",
            Self::Closed(_) => b"connect-ip control closed",
            Self::Poll(_) => b"h3 poll error",
        }
    }

    fn into_dial_error(self) -> DialError {
        match self {
            Self::Rejected(status) => DialError::Rejected(status),
            Self::Closed(reason) | Self::Poll(reason) => DialError::Handshake(reason),
        }
    }

    fn into_actor_reason(self) -> String {
        match self {
            Self::Rejected(status) => format!("CONNECT-IP rejected after establish: {status}"),
            Self::Closed(reason) | Self::Poll(reason) => reason,
        }
    }
}

/// CONNECT-IP DATAGRAM framing codec bound to one CONNECT request stream.
struct ConnectIpDatagramCodec {
    expected_qsi: u64,
    qsi_bytes: Vec<u8>,
}

impl ConnectIpDatagramCodec {
    fn new(connect_stream_id: u64) -> Self {
        let expected_qsi = connect_stream_id / 4;
        let qsi_bytes = encode_qsi(expected_qsi);
        Self {
            expected_qsi,
            qsi_bytes,
        }
    }

    fn prefix_len(&self) -> usize {
        self.qsi_bytes.len() + 1
    }

    fn prepend(&self, packet: &mut PooledBuf) -> bool {
        packet.add_prefix(&[CONTEXT_ID_IP]) && packet.add_prefix(&self.qsi_bytes)
    }

    fn strip(&self, packet: &mut PooledBuf) -> bool {
        let Some((qsi, qsi_len)) = decode_qsi(packet) else {
            return false;
        };
        if qsi != self.expected_qsi {
            return false;
        }

        let prefix_len = qsi_len + 1;
        if packet.len() < prefix_len || packet[qsi_len] != CONTEXT_ID_IP {
            return false;
        }
        if packet.len() == prefix_len {
            return false;
        }

        debug_assert_eq!(prefix_len, self.prefix_len());
        packet.pop_front(prefix_len);
        true
    }

    fn undo_prefix(&self, packet: &mut PooledBuf) {
        packet.pop_front(self.prefix_len());
    }
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
    ) -> Result<ConnectProgress, ConnectFailure> {
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
                            return Err(ConnectFailure::Rejected(code.to_string()));
                        }
                        None => {
                            return Err(ConnectFailure::Closed(
                                "missing :status on CONNECT-IP response".into(),
                            ));
                        }
                    }
                }

                Ok((sid, quiche::h3::Event::Finished)) => {
                    if sid == self.connect_stream_id {
                        return Err(ConnectFailure::Closed("CONNECT-IP stream finished".into()));
                    }
                }

                Ok((sid, quiche::h3::Event::Reset(code))) => {
                    if sid == self.connect_stream_id {
                        return Err(ConnectFailure::Closed(format!(
                            "CONNECT-IP stream reset: {code}"
                        )));
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
                    return Ok(if self.connect_ready(conn) {
                        ConnectProgress::Ready
                    } else {
                        ConnectProgress::Pending
                    });
                }

                Err(e) => {
                    return Err(ConnectFailure::Poll(format!("H3 poll: {e}")));
                }
            }
        }
    }
}

/// Packet batch waiting for downstream capacity, with congestion timing.
struct PendingBatch {
    batch: Vec<PooledBuf>,
    /// When the batch first became pending (for congestion duration tracking).
    since: Instant,
}

impl PendingBatch {
    fn new(batch: Vec<PooledBuf>) -> Self {
        Self {
            batch,
            since: Instant::now(),
        }
    }

    fn enqueue(
        tx: &mpsc::Sender<Vec<PooledBuf>>,
        batch: Vec<PooledBuf>,
    ) -> Result<Option<Self>, ()> {
        if batch.is_empty() {
            return Ok(None);
        }

        match tx.try_send(batch) {
            Ok(()) => Ok(None),
            Err(mpsc::error::TrySendError::Full(batch)) => Ok(Some(Self::new(batch))),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(()),
        }
    }

    fn resume<F>(
        slot: &mut Option<Self>,
        permit_res: Result<mpsc::Permit<'_, Vec<PooledBuf>>, mpsc::error::SendError<()>>,
        on_waited: F,
    ) -> Result<(), ()>
    where
        F: FnOnce(Duration),
    {
        match permit_res {
            Ok(permit) => {
                let pending = slot.take().expect("pending batch present");
                on_waited(pending.since.elapsed());
                permit.send(pending.batch);
                Ok(())
            }
            Err(_closed) => Err(()),
        }
    }
}

/// Exit reason for the established-phase event loop.
///
/// Carried out of the loop via `break` so that QUIC close + UDP flush
/// happen exactly once, after the loop.
enum LoopExit {
    Ok(&'static [u8]),
    Err {
        close_reason: &'static [u8],
        reason: String,
    },
}

/// Established-phase mutable state that does not own transport resources.
struct RunState {
    rx_counters: Counters,
    tx_counters: Counters,
    pending_ingress: Option<PendingBatch>,
    pending_egress: Option<PendingBatch>,
    pending_send: Option<PendingBatch>,
}

impl RunState {
    fn new() -> Self {
        Self {
            rx_counters: Counters::new(Source::Http3, Direction::Rx),
            tx_counters: Counters::new(Source::Http3, Direction::Tx),
            pending_ingress: None,
            pending_egress: None,
            pending_send: None,
        }
    }

    fn flush_and_retry(
        &mut self,
        conn: &mut quiche::Connection,
        session: &H3Session,
        meta: &EngineMeta,
        udp_send_tx: &mpsc::Sender<Vec<PooledBuf>>,
    ) -> Result<(), ()> {
        if self.pending_send.is_none() {
            self.pending_send = flush_udp_send(conn, meta.max_udp_payload, udp_send_tx)?;
        }

        if let Some(pending) = self.pending_egress.take() {
            self.tx_counters.record_queue_full(pending.since.elapsed());
            if let Some(remaining) = handle_router_egress(
                conn,
                pending.batch,
                &session.datagram_codec,
                &mut self.tx_counters,
            ) {
                self.pending_egress = Some(PendingBatch::new(remaining));
            }
        }

        if self.pending_send.is_none() {
            self.pending_send = flush_udp_send(conn, meta.max_udp_payload, udp_send_tx)?;
        }

        Ok(())
    }

    fn emit_metrics(&self, meta: &EngineMeta, events_tx: &mpsc::UnboundedSender<Event>) {
        let rx = self
            .rx_counters
            .snapshot(Some(&meta.peer_id), Some(meta.remote_addr));
        let tx = self
            .tx_counters
            .snapshot(Some(&meta.peer_id), Some(meta.remote_addr));
        let _ = events_tx.send(Event::Metrics(rx));
        let _ = events_tx.send(Event::Metrics(tx));
    }
}

impl LoopExit {
    fn close_reason(&self) -> &'static [u8] {
        match self {
            Self::Ok(r) => r,
            Self::Err { close_reason, .. } => close_reason,
        }
    }

    fn into_result(self, meta: &EngineMeta) -> ActorExitResult {
        match self {
            Self::Ok(_) => Ok(()),
            Self::Err { reason, .. } => Err(meta.actor_error(reason)),
        }
    }
}

impl H3ClientEngine {
    /// Best-effort flush of QUIC output to the UDP send channel.
    ///
    /// Used during handshake and close, where pending-send tracking is unnecessary.
    /// Drops on channel backpressure — acceptable because quiche retransmits during
    /// handshake and CONNECTION_CLOSE is best-effort.
    fn flush_send(&mut self) {
        // Best-effort: ignore both Full and Closed during handshake/shutdown.
        let _ = flush_udp_send(
            &mut self.conn,
            self.meta.max_udp_payload,
            &self.io.udp_send_tx,
        );
    }

    /// Startup phase: wait for QUIC establishment + H3 CONNECT-IP acceptance.
    async fn establish(
        mut self,
        authority: String,
        connect_path: String,
        auth_header: String,
    ) -> Result<Self, DialError> {
        let recv_info = self.meta.recv_info();

        // Send initial QUIC packets (e.g. ClientHello).
        self.flush_send();

        let timer = time::sleep(self.conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                maybe_batch = self.io.udp_recv_rx.recv() => {
                    let Some(packets) = maybe_batch else {
                        return Err(DialError::Handshake("UDP Rx closed during startup".into()));
                    };

                    handle_udp_recv(&mut self.conn, packets, recv_info);

                    if self.session.is_none() && self.conn.is_established() {
                        debug!(%self.meta.peer_id, "QUIC established; starting H3 CONNECT-IP");
                        // Two-phase H3 startup: send SETTINGS in a separate
                        // QUIC packet before the CONNECT-IP request so the
                        // server's H3 driver processes SETTINGS first, avoiding
                        // a ControllerWentAway race in tokio-quiche.
                        Self::start_h3_session(&mut self.conn, &mut self.session)?;
                        self.flush_send();
                        Self::send_connect_request(
                            &mut self.conn,
                            self.session.as_mut().unwrap(),
                            &authority, &connect_path, &auth_header,
                        )?;
                    }

                    if let Some(session) = &mut self.session {
                        match session.poll_connect_response(&mut self.conn, &self.meta.peer_id) {
                            Ok(ConnectProgress::Pending) => {}
                            Ok(ConnectProgress::Ready) => return Ok(self),
                            Err(err) => return Err(err.into_dial_error()),
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

    /// Creates the H3 connection, queuing SETTINGS on the control stream.
    ///
    /// The caller should flush after this and before [`send_connect_request`]
    /// so that the server processes SETTINGS before the CONNECT-IP request.
    fn start_h3_session(
        conn: &mut quiche::Connection,
        session: &mut Option<H3Session>,
    ) -> Result<(), DialError> {
        let h3_config = quiche::h3::Config::new()
            .map_err(|e| DialError::Handshake(format!("h3 config: {e}")))?;

        let h3_conn = quiche::h3::Connection::with_transport(conn, &h3_config)
            .map_err(|e| DialError::Handshake(format!("h3 connection: {e}")))?;

        *session = Some(H3Session {
            h3_conn: Box::new(h3_conn),
            // Placeholder values updated by send_connect_request.
            connect_stream_id: 0,
            datagram_codec: ConnectIpDatagramCodec::new(0),
            connect_accepted: false,
        });

        Ok(())
    }

    /// Sends the CONNECT-IP request on the session's H3 connection.
    fn send_connect_request(
        conn: &mut quiche::Connection,
        session: &mut H3Session,
        authority: &str,
        connect_path: &str,
        auth_header: &str,
    ) -> Result<(), DialError> {
        let connect_headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", authority.as_bytes()),
            quiche::h3::Header::new(b":path", connect_path.as_bytes()),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            quiche::h3::Header::new(b"authorization", auth_header.as_bytes()),
        ];

        let connect_stream_id = session
            .h3_conn
            .send_request(conn, &connect_headers, false)
            .map_err(|e| DialError::Handshake(format!("send CONNECT: {e}")))?;

        session.connect_stream_id = connect_stream_id;
        session.datagram_codec = ConnectIpDatagramCodec::new(connect_stream_id);

        Ok(())
    }

    /// Established phase: steady-state datagram forwarding.
    ///
    /// Uses three pending slots for zero-drop backpressure:
    /// - `pending_ingress`: IP packets from dgram_recv waiting for `ingress_tx` capacity.
    /// - `pending_egress`: IP packets from TUN waiting for `conn.dgram_send()` capacity.
    /// - `pending_send`: encrypted QUIC packets waiting for `udp_send_tx` capacity.
    async fn run(self) -> ActorExitResult {
        let recv_info = self.meta.recv_info();

        let H3ClientEngine {
            mut conn,
            session,
            io:
                EngineIo {
                    mut udp_recv_rx,
                    udp_send_tx,
                    mut egress_rx,
                    ingress_tx,
                    events_tx,
                },
            meta,
            mut run_state,
            metrics_interval,
            keepalive_interval,
        } = self;
        let mut session = session.expect("session present after establish");

        let mut ticker = time::interval(metrics_interval);
        let mut keepalive = time::interval(keepalive_interval);
        keepalive.tick().await;

        let timer = time::sleep(conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        let exit: LoopExit = loop {
            let ingress_pending = run_state.pending_ingress.is_some();
            let egress_pending = run_state.pending_egress.is_some();
            let send_pending = run_state.pending_send.is_some();

            tokio::select! {
                // UDP → quiche → dgram_recv → ingress_tx.
                // Blocked only when ingress is pending (no room for more datagrams).
                // NOT blocked by pending_send — ACKs arriving here may resolve
                // pending_egress, and pending_send drains quickly via reserve().
                maybe_batch = udp_recv_rx.recv(),
                    if !ingress_pending =>
                {
                    let Some(packets) = maybe_batch else {
                        break LoopExit::Ok(b"udp rx closed");
                    };

                    handle_udp_recv(&mut conn, packets, recv_info);

                    match session.poll_connect_response(&mut conn, &meta.peer_id) {
                        Ok(ConnectProgress::Pending | ConnectProgress::Ready) => {}
                        Err(err) => break LoopExit::Err {
                            close_reason: err.close_reason(),
                            reason: err.into_actor_reason(),
                        },
                    }

                    run_state.pending_ingress = match PendingBatch::enqueue(
                        &ingress_tx,
                        collect_router_ingress(
                            &mut conn,
                            meta.max_udp_payload,
                            &mut run_state.rx_counters,
                            &session.datagram_codec,
                        ),
                    ) {
                        Ok(pending) => pending,
                        Err(()) => break LoopExit::Ok(b"shutdown"),
                    };
                }

                // Drain pending ingress when ingress_tx has capacity.
                permit_res = ingress_tx.reserve(),
                    if ingress_pending =>
                {
                    if PendingBatch::resume(
                        &mut run_state.pending_ingress, permit_res,
                        |waited| run_state.rx_counters.record_queue_full(waited),
                    ).is_err() {
                        break LoopExit::Ok(b"shutdown");
                    }
                }

                // TUN → dgram_send. Blocked when egress is pending (dgram queue full).
                maybe_batch = egress_rx.recv(),
                    if !egress_pending =>
                {
                    let Some(packets) = maybe_batch else {
                        break LoopExit::Ok(b"shutdown");
                    };

                    if let Some(remaining) = handle_router_egress(
                        &mut conn,
                        packets,
                        &session.datagram_codec,
                        &mut run_state.tx_counters,
                    ) {
                        run_state.pending_egress = Some(PendingBatch::new(remaining));
                    }
                }

                // Drain pending send when udp_send_tx has capacity.
                permit_res = udp_send_tx.reserve(),
                    if send_pending =>
                {
                    if PendingBatch::resume(
                        &mut run_state.pending_send, permit_res,
                        |waited| run_state.tx_counters.record_queue_full(waited),
                    ).is_err() {
                        break LoopExit::Ok(b"udp tx closed");
                    }
                }

                _ = &mut timer => {
                    conn.on_timeout();
                }

                _ = keepalive.tick() => {
                    conn.send_ack_eliciting().ok();
                }

                _ = ticker.tick() => {
                    run_state.emit_metrics(&meta, &events_tx);
                }
            }

            if run_state
                .flush_and_retry(&mut conn, &session, &meta, &udp_send_tx)
                .is_err()
            {
                break LoopExit::Err {
                    close_reason: b"udp tx closed",
                    reason: "BareUDP TX channel closed".into(),
                };
            }
            reset_timer(timer.as_mut(), &conn);

            if conn.is_closed() {
                break LoopExit::Err {
                    close_reason: b"conn closed",
                    reason: "QUIC connection closed".into(),
                };
            }
        };

        // Single cleanup point: close QUIC and flush remaining packets.
        conn.close(true, 0, exit.close_reason()).ok();
        let _ = flush_udp_send(&mut conn, meta.max_udp_payload, &udp_send_tx);
        exit.into_result(&meta)
    }
}

// ========== Public Dial Function ==========

/// Establishes an outbound H3 client CONNECT-IP connection.
///
/// Creates a UDP socket, spawns BareUDP Rx/Tx actors (on the caller's
/// runtime via `tokio::spawn`), builds the H3 client engine, and drives
/// QUIC+H3 handshake on `crypto_rt` before entering steady-state forwarding.
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
/// * `crypto_rt` - Runtime handle for the H3 engine (handshake + forwarding).
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
    crypto_rt: &RuntimeHandle,
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
    let (udp_rx_cmd, udp_rx_handle) = spawn_udp_rx(
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

        io: EngineIo {
            udp_recv_rx,
            udp_send_tx: udp_send_tx.clone(),
            egress_rx,
            ingress_tx,
            events_tx: events_tx.clone(),
        },
        meta: EngineMeta {
            local_addr,
            remote_addr,
            peer_id: peer_id.to_string(),
            max_udp_payload,
        },
        run_state: RunState::new(),

        metrics_interval: tuning.metrics_push_interval,
        keepalive_interval: tuning.h3_keepalive_interval,
    };

    let startup_handle = crypto_rt.spawn(engine.establish(authority, connect_path, auth_header));
    tokio::pin!(startup_handle);

    let result = match time::timeout(tuning.h3_handshake_timeout, &mut startup_handle).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_err)) => Err(DialError::Handshake(format!(
            "startup task join error: {join_err}"
        ))),
        Err(_) => {
            // Abort the detached establish task — dropping JoinHandle only
            // detaches in Tokio, it does not cancel the spawned task.
            startup_handle.abort();
            Err(DialError::Timeout(tuning.h3_handshake_timeout))
        }
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
        udp_rx_cmd,
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
    timer.reset(time::Instant::now() + conn.timeout().unwrap_or(MAX_TIMEOUT));
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
    let mut batch = Vec::new();
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

/// Collects inbound QUIC DATAGRAMs with QSI validation and strips framing.
///
/// Records Rx success counters at decode time (Rx = decoded from QUIC, not
/// downstream delivery). Returns the batch for the caller to send via
/// `try_send` / pending pattern.
fn collect_router_ingress(
    conn: &mut quiche::Connection,
    max_udp_payload: usize,
    counters: &mut Counters,
    codec: &ConnectIpDatagramCodec,
) -> Vec<PooledBuf> {
    let mut batch = Vec::new();
    let mut ok_pkts: u64 = 0;
    let mut ok_bytes: u64 = 0;

    loop {
        let mut buf = alloc_uninit_packet_buf(max_udp_payload);
        match conn.dgram_recv(&mut buf) {
            Ok(len) => {
                buf.truncate(len);

                if !codec.strip(&mut buf) {
                    counters.record_drop(DropReason::InvalidFraming, 1, len as u64);
                    continue;
                }
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

    if ok_pkts > 0 {
        counters.record_success(ok_pkts, ok_bytes);
    }
    batch
}

/// Encodes egress IP packets as QUIC DATAGRAMs with QSI varint + Context ID prefix.
///
/// Returns unsent packets (with framing stripped) when the dgram queue is full,
/// so the caller can store them as `pending_egress` for retry after `flush_send`.
fn handle_router_egress(
    conn: &mut quiche::Connection,
    packets: Vec<PooledBuf>,
    codec: &ConnectIpDatagramCodec,
    counters: &mut Counters,
) -> Option<Vec<PooledBuf>> {
    let mut ok_pkts: u64 = 0;
    let mut ok_bytes: u64 = 0;
    let mut iter = packets.into_iter();

    while let Some(mut pkt) = iter.next() {
        let pkt_len = pkt.len() as u64;
        if !codec.prepend(&mut pkt) {
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
                codec.undo_prefix(&mut pkt);
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

/// Collects QUIC output and tries to send it to `udp_send_tx`.
///
/// Returns `Ok(Some(batch))` when the channel is full (store as `pending_send`),
/// `Ok(None)` on success or empty, `Err(())` when the channel is closed.
fn flush_udp_send(
    conn: &mut quiche::Connection,
    max_udp_payload: usize,
    udp_send_tx: &mpsc::Sender<Vec<PooledBuf>>,
) -> Result<Option<PendingBatch>, ()> {
    PendingBatch::enqueue(udp_send_tx, collect_udp_send(conn, max_udp_payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::ActorKind;
    use crate::bind::test_support::FakeRouteProbe;
    use crate::config::default_mtu;
    use crate::events::{ConnectionDirection, Event};
    use crate::h3::test_support::{insecure_tuning, test_peer_h3, TestCertBundle};
    use crate::h3::{make_h3_listener, spawn_h3_listener, spawn_h3_rx, spawn_h3_tx};
    use crate::tun::alloc_packet_buf;
    use std::collections::HashMap;
    use tokio_quiche::buf_factory::BufFactory;

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
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let conn = H3ClientConn {
            peer_id: "peer-1".into(),
            remote_addr: "1.2.3.4:443".parse().unwrap(),
            tx,
            engine_handle: tokio::spawn(async { Ok(()) }),
            udp_rx_cmd: cmd_tx,
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

    // ========== Test Helpers ==========

    fn test_meta() -> EngineMeta {
        EngineMeta {
            local_addr: "127.0.0.1:5000".parse().unwrap(),
            remote_addr: "10.0.0.1:443".parse().unwrap(),
            peer_id: "peer-x".into(),
            max_udp_payload: 1400,
        }
    }

    // ========== ConnectFailure Tests ==========

    #[test]
    fn connect_failure_close_reason() {
        assert_eq!(
            ConnectFailure::Rejected("403".into()).close_reason(),
            b"connect-ip rejected"
        );
        assert_eq!(
            ConnectFailure::Closed("stream fin".into()).close_reason(),
            b"connect-ip control closed"
        );
        assert_eq!(
            ConnectFailure::Poll("h3 error".into()).close_reason(),
            b"h3 poll error"
        );
    }

    #[test]
    fn connect_failure_into_dial_error() {
        let err = ConnectFailure::Rejected("403".into()).into_dial_error();
        assert!(matches!(err, DialError::Rejected(s) if s == "403"));

        let err = ConnectFailure::Closed("stream closed".into()).into_dial_error();
        assert!(matches!(err, DialError::Handshake(s) if s == "stream closed"));

        let err = ConnectFailure::Poll("poll failed".into()).into_dial_error();
        assert!(matches!(err, DialError::Handshake(s) if s == "poll failed"));
    }

    #[test]
    fn connect_failure_into_actor_reason() {
        let reason = ConnectFailure::Rejected("403".into()).into_actor_reason();
        assert!(reason.contains("CONNECT-IP rejected"));
        assert!(reason.contains("403"));

        let reason = ConnectFailure::Closed("fin".into()).into_actor_reason();
        assert_eq!(reason, "fin");

        let reason = ConnectFailure::Poll("poll err".into()).into_actor_reason();
        assert_eq!(reason, "poll err");
    }

    // ========== LoopExit Tests ==========

    #[test]
    fn loop_exit_close_reason() {
        let ok = LoopExit::Ok(b"shutdown");
        assert_eq!(ok.close_reason(), b"shutdown");

        let err = LoopExit::Err {
            close_reason: b"conn closed",
            reason: "QUIC closed".into(),
        };
        assert_eq!(err.close_reason(), b"conn closed");
    }

    #[test]
    fn loop_exit_into_result_ok() {
        let exit = LoopExit::Ok(b"graceful");
        assert!(exit.into_result(&test_meta()).is_ok());
    }

    #[test]
    fn loop_exit_into_result_err() {
        let exit = LoopExit::Err {
            close_reason: b"conn closed",
            reason: "QUIC connection closed".into(),
        };
        let result = exit.into_result(&test_meta());
        let err = result.unwrap_err();
        assert!(matches!(&err, ActorError::H3Client { peer_id, reason }
            if peer_id == "peer-x" && reason == "QUIC connection closed"
        ));
        assert_eq!(err.kind(), ActorKind::Restartable);
    }

    // ========== PendingBatch Tests ==========

    #[test]
    fn pending_batch_enqueue_empty_returns_none() {
        let (tx, _rx) = mpsc::channel::<Vec<PooledBuf>>(1);
        let result = PendingBatch::enqueue(&tx, vec![]);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn pending_batch_enqueue_success() {
        let (tx, mut rx) = mpsc::channel::<Vec<PooledBuf>>(1);
        let batch = vec![alloc_packet_buf(b"pkt1")];
        let result = PendingBatch::enqueue(&tx, batch);
        assert!(matches!(result, Ok(None)));
        // Verify the batch was actually sent.
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn pending_batch_enqueue_full_returns_pending() {
        let (tx, _rx) = mpsc::channel::<Vec<PooledBuf>>(1);
        // Fill the channel directly, not via the function under test.
        let _ = tx.try_send(vec![alloc_packet_buf(b"fill")]);
        let batch = vec![alloc_packet_buf(b"overflow")];
        let result = PendingBatch::enqueue(&tx, batch);
        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn pending_batch_enqueue_closed_returns_err() {
        let (tx, rx) = mpsc::channel::<Vec<PooledBuf>>(1);
        drop(rx);
        let batch = vec![alloc_packet_buf(b"orphan")];
        let result = PendingBatch::enqueue(&tx, batch);
        assert!(matches!(result, Err(())));
    }

    // ========== EngineMeta Tests ==========

    #[test]
    fn engine_meta_recv_info() {
        let meta = test_meta();
        let info = meta.recv_info();
        assert_eq!(info.from, meta.remote_addr);
        assert_eq!(info.to, meta.local_addr);
    }

    #[test]
    fn engine_meta_actor_error() {
        let meta = test_meta();
        let err = meta.actor_error("connection reset");
        assert!(matches!(&err, ActorError::H3Client { peer_id, reason }
            if peer_id == "peer-x" && reason == "connection reset"
        ));
        assert_eq!(err.kind(), ActorKind::Restartable);
    }

    // ========== ConnectIpDatagramCodec Tests ==========

    #[test]
    fn codec_new_qsi_and_prefix_len() {
        for (stream_id, expect_qsi, expect_prefix) in
            [(0, 0, 2), (4, 1, 2), (256, 64, 3), (1024, 256, 3)]
        {
            let codec = ConnectIpDatagramCodec::new(stream_id);
            assert_eq!(codec.expected_qsi, expect_qsi, "sid={stream_id}");
            assert_eq!(codec.qsi_bytes, encode_qsi(expect_qsi), "sid={stream_id}");
            assert_eq!(codec.prefix_len(), expect_prefix, "sid={stream_id}");
        }
    }

    #[test]
    fn codec_prepend_adds_qsi_then_context_id() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = alloc_packet_buf(b"payload");
        assert!(codec.prepend(&mut buf));
        assert_eq!(buf[0], 0x00); // QSI
        assert_eq!(buf[1], CONTEXT_ID_IP); // Context ID
        assert_eq!(&buf[2..], b"payload");
    }

    #[test]
    fn codec_strip_happy_path() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut framed = vec![0x00, CONTEXT_ID_IP];
        framed.extend_from_slice(b"ip packet");
        let mut buf = BufFactory::dgram_from_vec(framed);
        assert!(codec.strip(&mut buf));
        assert_eq!(&buf[..], b"ip packet");
    }

    #[test]
    fn codec_strip_rejects_wrong_qsi() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![0x01, CONTEXT_ID_IP, 0xFF]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_wrong_context_id() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![0x00, 0x01, 0xFF]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_empty_payload() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![0x00, CONTEXT_ID_IP]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_too_short() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![0x00]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_empty_buffer() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_roundtrip_prepend_strip() {
        for stream_id in [0u64, 4, 252, 256, 1024] {
            let codec = ConnectIpDatagramCodec::new(stream_id);
            let payload = b"roundtrip test payload";
            let mut buf = alloc_packet_buf(payload);
            assert!(
                codec.prepend(&mut buf),
                "prepend failed for sid={stream_id}"
            );
            let framed_data = buf[..].to_vec();
            let mut recv_buf = BufFactory::dgram_from_vec(framed_data);
            assert!(
                codec.strip(&mut recv_buf),
                "strip failed for sid={stream_id}"
            );
            assert_eq!(&recv_buf[..], payload);
        }
    }

    #[test]
    fn codec_undo_prefix_restores_payload() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = alloc_packet_buf(b"undo test");
        assert!(codec.prepend(&mut buf));
        codec.undo_prefix(&mut buf);
        assert_eq!(&buf[..], b"undo test");
    }

    // ========== RunState Tests ==========

    #[test]
    fn run_state_new_has_no_pending() {
        let state = RunState::new();
        assert!(state.pending_ingress.is_none());
        assert!(state.pending_egress.is_none());
        assert!(state.pending_send.is_none());
    }

    // ========== Integration Test Helpers ==========

    use crate::h3::test_support::await_server_connection;

    /// Test server wrapping h3.rs listener with cert and handle lifecycle management.
    struct TestServer {
        cmd_tx: mpsc::UnboundedSender<crate::h3::H3ListenerCommand>,
        events_rx: mpsc::UnboundedReceiver<Event>,
        bound_addr: SocketAddr,
        _certs: TestCertBundle,
        _handle: JoinHandle<crate::actor::ActorExitResult>,
    }

    impl TestServer {
        async fn start(peer_tokens: HashMap<String, String>) -> Self {
            let certs = TestCertBundle::generate();
            let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

            let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
                .expect("make_h3_listener");

            let (events_tx, events_rx) = mpsc::unbounded_channel();
            let (cmd_tx, handle, bound_addr) = spawn_h3_listener(
                listener,
                peer_tokens,
                default_mtu(),
                events_tx,
                &Tuning::default(),
            );

            // Give listener time to start accepting.
            tokio::time::sleep(Duration::from_millis(50)).await;

            Self {
                cmd_tx,
                events_rx,
                bound_addr,
                _certs: certs,
                _handle: handle,
            }
        }
    }

    /// Dials the h3v2 client against a test server, returning the connection,
    /// the ingress receiver (server-to-client datagram path), and the events
    /// receiver (must be kept alive to prevent actor shutdown).
    async fn dial_test_client(
        bound_addr: SocketAddr,
        token: &str,
        peer_id: &str,
    ) -> (
        H3ClientConn,
        mpsc::Receiver<Vec<PooledBuf>>,
        mpsc::UnboundedReceiver<Event>,
    ) {
        let peer_h3 = test_peer_h3(bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let tuning = insecure_tuning();

        let (ingress_tx, ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        let conn = dial_h3_client(
            &peer_h3,
            bound_addr,
            peer_id,
            None,
            default_mtu(),
            &probe,
            &tuning,
            &tokio::runtime::Handle::current(),
            ingress_tx,
            events_tx,
        )
        .await
        .expect("dial_h3_client failed");

        (conn, ingress_rx, events_rx)
    }

    // ========== h3v2 Client-Server Integration Tests ==========

    #[tokio::test]
    async fn h3v2_handshake_success() {
        let peer_id = "h3v2-test-client";
        let token = "h3v2-test-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;

        let (conn, _ingress_rx, _cli_events_rx) =
            dial_test_client(server.bound_addr, token, peer_id).await;

        assert_eq!(conn.peer_id, peer_id);
        assert_eq!(conn.remote_addr, server.bound_addr);

        // Server should emit H3Connected with correct peer_id.
        let server_event = await_server_connection(&mut server.events_rx).await;
        assert_eq!(server_event.connection.peer_id, peer_id);
        assert_eq!(server_event.direction, ConnectionDirection::Inbound);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_handshake_rejected_wrong_token() {
        let peer_id = "h3v2-reject-peer";
        let correct_token = "correct-token-12";
        let wrong_token = "wrong-token-12ch";
        let peer_tokens = HashMap::from([(peer_id.to_string(), correct_token.to_string())]);

        let server = TestServer::start(peer_tokens).await;

        let peer_h3 = test_peer_h3(server.bound_addr, wrong_token);
        let probe = FakeRouteProbe::noop();
        let tuning = insecure_tuning();

        let (ingress_tx, _ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let result = dial_h3_client(
            &peer_h3,
            server.bound_addr,
            peer_id,
            None,
            default_mtu(),
            &probe,
            &tuning,
            &tokio::runtime::Handle::current(),
            ingress_tx,
            events_tx,
        )
        .await;

        assert!(
            matches!(result, Err(DialError::Rejected(_))),
            "expected Rejected, got {:?}",
            result,
        );

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_datagram_client_to_server() {
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let peer_id = "h3v2-c2s-client";
        let token = "h3v2-c2s-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;
        let (conn, _ingress_rx, _cli_events_rx) =
            dial_test_client(server.bound_addr, token, peer_id).await;

        // Obtain server-side connection and set up RX actor.
        let server_event = await_server_connection(&mut server.events_rx).await;
        let (server_rx, _server_tx) = server_event.connection.into_actors();
        let (server_router_tx, mut server_router_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (srv_events_tx, _srv_events_rx) = mpsc::unbounded_channel();
        let _server_rx_handle = spawn_h3_rx(
            server_rx,
            server_router_tx,
            srv_events_tx,
            Duration::from_secs(60),
        );

        // Send test packet via h3v2 client.
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        let pkt = alloc_packet_buf(&test_packet);
        conn.tx.send(vec![pkt]).await.expect("send failed");

        // Verify server received the packet.
        let batch = tokio::time::timeout(Duration::from_secs(5), server_router_rx.recv())
            .await
            .expect("timeout waiting for datagram")
            .expect("channel closed");

        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &test_packet[..]);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_datagram_server_to_client() {
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let peer_id = "h3v2-s2c-client";
        let token = "h3v2-s2c-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;
        let (_conn, mut ingress_rx, _cli_events_rx) =
            dial_test_client(server.bound_addr, token, peer_id).await;

        // Obtain server-side connection and set up TX actor.
        let server_event = await_server_connection(&mut server.events_rx).await;
        let (_server_rx, server_tx) = server_event.connection.into_actors();
        let (srv_events_tx, _srv_events_rx) = mpsc::unbounded_channel();
        let (server_send_tx, _server_tx_handle) = spawn_h3_tx(
            server_tx,
            srv_events_tx,
            Duration::from_secs(60),
            256,
            Duration::from_secs(20),
        );

        // Send test packet from server.
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2));
        let pkt = alloc_packet_buf(&test_packet);
        server_send_tx.send(vec![pkt]).await.expect("send failed");

        // Verify client received the packet via ingress_rx.
        let batch = tokio::time::timeout(Duration::from_secs(5), ingress_rx.recv())
            .await
            .expect("timeout waiting for datagram")
            .expect("channel closed");

        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &test_packet[..]);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_datagram_bidirectional() {
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let peer_id = "h3v2-bidir-client";
        let token = "h3v2-bidir-tok-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;
        let (conn, mut ingress_rx, _cli_events_rx) =
            dial_test_client(server.bound_addr, token, peer_id).await;

        // Set up server RX and TX actors.
        let server_event = await_server_connection(&mut server.events_rx).await;
        let (server_rx, server_tx) = server_event.connection.into_actors();
        let (srv_events_tx, _srv_events_rx) = mpsc::unbounded_channel();

        let (c2s_router_tx, mut c2s_router_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let _server_rx_handle = spawn_h3_rx(
            server_rx,
            c2s_router_tx,
            srv_events_tx.clone(),
            Duration::from_secs(60),
        );

        let (server_send_tx, _server_tx_handle) = spawn_h3_tx(
            server_tx,
            srv_events_tx,
            Duration::from_secs(60),
            256,
            Duration::from_secs(20),
        );

        // Client -> Server
        let packet_c2s = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        conn.tx
            .send(vec![alloc_packet_buf(&packet_c2s)])
            .await
            .expect("c2s send failed");
        let batch_c2s = tokio::time::timeout(Duration::from_secs(5), c2s_router_rx.recv())
            .await
            .expect("timeout c2s")
            .expect("channel closed");
        assert_eq!(&batch_c2s[0][..], &packet_c2s[..]);

        // Server -> Client
        let packet_s2c = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2));
        server_send_tx
            .send(vec![alloc_packet_buf(&packet_s2c)])
            .await
            .expect("s2c send failed");
        let batch_s2c = tokio::time::timeout(Duration::from_secs(5), ingress_rx.recv())
            .await
            .expect("timeout s2c")
            .expect("channel closed");
        assert_eq!(&batch_s2c[0][..], &packet_s2c[..]);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_connection_shutdown() {
        let peer_id = "h3v2-shutdown-peer";
        let token = "h3v2-shutdown-tk12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;
        let (conn, _ingress_rx, _cli_events_rx) =
            dial_test_client(server.bound_addr, token, peer_id).await;

        // Verify server accepted the connection.
        let _server_event = await_server_connection(&mut server.events_rx).await;

        // Drop the egress sender to trigger client shutdown.
        // Keep udp_rx_cmd alive so the BareUDP RX actor doesn't exit
        // before the engine processes the egress channel closure.
        let H3ClientConn {
            engine_handle,
            udp_rx_cmd: _udp_rx_cmd,
            udp_rx_handle,
            udp_tx_handle,
            tx,
            ..
        } = conn;
        drop(tx);

        // Engine handle should terminate cleanly within a reasonable timeout.
        let engine_result = tokio::time::timeout(Duration::from_secs(5), engine_handle)
            .await
            .expect("engine_handle did not terminate in time")
            .expect("engine task panicked");
        assert!(
            engine_result.is_ok(),
            "engine exited with error: {:?}",
            engine_result
        );

        // UDP actors may be aborted by the engine or complete on their own.
        // Best-effort check: they should not hang indefinitely.
        let _ = tokio::time::timeout(Duration::from_secs(2), udp_rx_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), udp_tx_handle).await;

        drop(server.cmd_tx);
    }
}
