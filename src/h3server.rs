//! H3 CONNECT-IP server: CID-based multiplexed listener with per-connection engines.
//!
//! Uses a single UDP socket with CID routing to multiplex all inbound QUIC
//! connections. See [`make_h3v2_listener`] + [`spawn_h3v2_listener`] for the
//! public entry points.

use crate::actor::{ActorError, ActorExitResult};
use crate::auth::validate_connect_auth;
use crate::bare::{bare_rx_from_socket, spawn_server_udp_rx};
use crate::bind::make_server_udp_socket;
use crate::config::Tuning;
use crate::events::Event;
use crate::h3::CONNECT_IP_OVERHEAD;
use crate::h3v2::{
    apply_transport_config, collect_router_ingress, handle_udp_recv, H3Session, MAX_TIMEOUT,
};
use crate::metrics::{Counters, Direction, Source};
use quiche::h3::NameValue;
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_quiche::buf_factory::PooledBuf;
use tracing::{debug, info, warn};

// ========== Server Error ==========

/// Error type for H3 server listener setup and per-connection acceptance.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Socket or listener setup failed.
    #[error("socket: {0}")]
    Socket(String),
    /// TLS or QUIC configuration failed.
    #[error("config: {0}")]
    Config(String),
    /// Connection acceptance or CONNECT-IP handshake failed.
    #[error("accept: {0}")]
    Accept(String),
}

// ========== Server Connection Handle ==========

/// Established H3 server CONNECT-IP connection (one per client).
///
/// Returned to the orchestrator (via events channel) when a client completes
/// the QUIC + CONNECT-IP handshake. Connection lifetime is managed by the
/// multiplexed listener, not by per-connection actor handles.
pub struct H3ServerConn {
    /// Authenticated peer identifier (from Bearer token validation).
    pub peer_id: String,
    /// Remote client socket address.
    pub remote_addr: SocketAddr,
}

impl std::fmt::Debug for H3ServerConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3ServerConn")
            .field("peer_id", &self.peer_id)
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}

// ========== Server Validation Helpers ==========

/// Validates CONNECT-IP headers on a raw quiche H3 request (server-side).
///
/// Checks `:method=CONNECT`, `:protocol=connect-ip`, `capsule-protocol=?1`
/// per RFC 9484. Pseudo-headers use exact `==` (always lowercased by HTTP/3
/// framing per RFC 9114 §4.2); regular headers use case-insensitive matching.
fn validate_server_connect_headers(headers: &[quiche::h3::Header]) -> Result<(), String> {
    let method = headers
        .iter()
        .find(|h| h.name() == b":method")
        .map(|h| h.value());
    if method != Some(b"CONNECT") {
        return Err("invalid :method, expected CONNECT".into());
    }
    let protocol = headers
        .iter()
        .find(|h| h.name() == b":protocol")
        .map(|h| h.value());
    if protocol != Some(b"connect-ip") {
        return Err("invalid :protocol, expected connect-ip".into());
    }
    let capsule = headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case(b"capsule-protocol"))
        .map(|h| h.value());
    if capsule != Some(b"?1") {
        return Err("invalid capsule-protocol, expected ?1".into());
    }
    Ok(())
}

/// Validates Bearer token auth on a raw quiche H3 request (server-side).
///
/// Returns the authenticated peer ID on success.
fn validate_server_auth(
    headers: &[quiche::h3::Header],
    tokens: &HashMap<String, String>,
) -> Result<String, String> {
    let auth_value = headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case(b"authorization"))
        .map(|h| String::from_utf8_lossy(h.value()).to_string());
    let peer_iter = tokens.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    validate_connect_auth(auth_value.as_deref(), peer_iter).map_err(|reason| reason.to_string())
}

// ========== Server-Side H3Session Extension ==========

/// Result of advancing the server-side CONNECT-IP handshake.
enum ServerConnectProgress {
    /// Server is still waiting for more H3 state.
    Pending,
    /// CONNECT-IP is fully established and authenticated.
    Ready(String),
}

impl H3Session {
    /// Polls server-side H3 events until the inbound CONNECT-IP request advances.
    fn poll_connect_request(
        &mut self,
        conn: &mut quiche::Connection,
        pending_peer_id: &mut Option<String>,
        peer_tokens: &HashMap<String, String>,
    ) -> Result<ServerConnectProgress, ServerError> {
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    if pending_peer_id.is_some() || self.connect_accepted {
                        return Err(ServerError::Accept("duplicate CONNECT-IP request".into()));
                    }

                    validate_server_connect_headers(&list).map_err(ServerError::Accept)?;
                    let peer_id = validate_server_auth(&list, peer_tokens)
                        .map_err(|e| ServerError::Accept(format!("auth: {e}")))?;

                    let response = [
                        quiche::h3::Header::new(b":status", b"200"),
                        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
                    ];
                    self.h3_conn
                        .send_response(conn, stream_id, &response, false)
                        .map_err(|e| ServerError::Accept(format!("send 200: {e}")))?;

                    self.bind_connect_stream(stream_id);
                    self.mark_connect_accepted();

                    if self.connect_ready(conn) {
                        return Ok(ServerConnectProgress::Ready(peer_id));
                    }

                    *pending_peer_id = Some(peer_id);
                }

                Ok((sid, quiche::h3::Event::Finished)) if sid == self.connect_stream_id => {
                    return Err(ServerError::Accept("CONNECT-IP stream finished".into()));
                }

                Ok((sid, quiche::h3::Event::Reset(code))) if sid == self.connect_stream_id => {
                    return Err(ServerError::Accept(format!(
                        "CONNECT-IP stream reset: {code}"
                    )));
                }

                Ok((_sid, quiche::h3::Event::GoAway)) => {
                    return Err(ServerError::Accept("GOAWAY during handshake".into()));
                }

                Ok((_sid, _)) => {}

                Err(quiche::h3::Error::Done) => {
                    if self.connect_ready(conn) {
                        if let Some(peer_id) = pending_peer_id.take() {
                            return Ok(ServerConnectProgress::Ready(peer_id));
                        }
                    }
                    return Ok(ServerConnectProgress::Pending);
                }

                Err(e) => {
                    return Err(ServerError::Accept(format!("h3 poll: {e}")));
                }
            }
        }
    }
}

// ========== Configuration Helpers ==========

/// Creates a quiche QUIC server configuration with TLS credentials.
fn make_server_quiche_config(
    tuning: &Tuning,
    max_udp_payload: usize,
    cert_path: &Path,
    key_path: &Path,
) -> Result<quiche::Config, ServerError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| ServerError::Config(format!("quiche config: {e}")))?;
    config
        .load_cert_chain_from_pem_file(
            cert_path
                .to_str()
                .ok_or_else(|| ServerError::Config("invalid cert path encoding".into()))?,
        )
        .map_err(|e| ServerError::Config(format!("cert: {e}")))?;
    config
        .load_priv_key_from_pem_file(
            key_path
                .to_str()
                .ok_or_else(|| ServerError::Config("invalid key path encoding".into()))?,
        )
        .map_err(|e| ServerError::Config(format!("key: {e}")))?;
    apply_transport_config(&mut config, tuning, max_udp_payload)
        .map_err(|e| ServerError::Config(format!("transport config: {e}")))?;
    Ok(config)
}

// ========== H3v2 Server Listener ==========

/// H3v2 listener state, created by [`make_h3v2_listener`], spawned by
/// [`spawn_h3v2_listener`]. Follows the Actor Initialization Pattern.
pub struct H3v2Listener {
    socket: std::net::UdpSocket,
    bound_addr: SocketAddr,
    config: quiche::Config,
    max_udp_payload: usize,
}

/// Commands accepted by the H3v2 listener actor.
#[derive(Debug, Clone)]
pub enum H3v2ListenerCommand {
    /// Replace the peer token map used for CONNECT-IP authentication.
    UpdatePeerTokens(HashMap<String, String>),
}

/// Creates H3v2 listener state from configuration.
///
/// Performs all fallible I/O: socket binding, TLS credential loading,
/// QUIC config construction. Does NOT spawn any tasks.
pub fn make_h3v2_listener(
    listen_addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    tun_mtu: u16,
    tuning: &Tuning,
) -> Result<H3v2Listener, ServerError> {
    let socket = make_server_udp_socket(listen_addr, tuning.socket_buffer_bytes())
        .map_err(|e| ServerError::Socket(e.to_string()))?;
    let bound_addr = socket
        .local_addr()
        .map_err(|e| ServerError::Socket(format!("local_addr: {e}")))?;
    let max_udp_payload = tun_mtu as usize + CONNECT_IP_OVERHEAD;
    let config = make_server_quiche_config(tuning, max_udp_payload, cert_path, key_path)?;
    let std_socket = socket
        .into_std()
        .map_err(|e| ServerError::Socket(format!("into_std: {e}")))?;

    info!(%listen_addr, %bound_addr, "h3v2 listener created");
    Ok(H3v2Listener {
        socket: std_socket,
        bound_addr,
        config,
        max_udp_payload,
    })
}

// ========== Per-Connection State ==========

/// Per-connection state in the multiplexed server listener.
struct ServerConn {
    conn: quiche::Connection,
    session: Option<H3Session>,
    remote_addr: SocketAddr,
    peer_id: String,
    phase: ServerConnPhase,
    rx_counters: Counters,
    tx_counters: Counters,
    /// Registered CIDs for cleanup on connection removal.
    cids: Vec<Vec<u8>>,
}

/// Server-side connection phase in the multiplexed listener.
enum ServerConnPhase {
    Handshaking {
        started_at: Instant,
        pending_peer_id: Option<String>,
    },
    Established,
}

impl ServerConn {
    fn new(conn: quiche::Connection, remote_addr: SocketAddr, cids: Vec<Vec<u8>>) -> Self {
        Self {
            conn,
            session: None,
            remote_addr,
            peer_id: remote_addr.to_string(),
            phase: ServerConnPhase::Handshaking {
                started_at: Instant::now(),
                pending_peer_id: None,
            },
            rx_counters: Counters::new(Source::Http3, Direction::Rx),
            tx_counters: Counters::new(Source::Http3, Direction::Tx),
            cids,
        }
    }

    fn recv_info(&self, bound_addr: SocketAddr) -> quiche::RecvInfo {
        quiche::RecvInfo {
            from: self.remote_addr,
            to: bound_addr,
        }
    }

    fn is_established(&self) -> bool {
        matches!(self.phase, ServerConnPhase::Established)
    }

    fn handshake_timed_out(&self, timeout: Duration) -> bool {
        match &self.phase {
            ServerConnPhase::Handshaking { started_at, .. } => started_at.elapsed() > timeout,
            ServerConnPhase::Established => false,
        }
    }

    fn ensure_session(&mut self) -> Result<(), ServerError> {
        if self.session.is_some() || !self.conn.is_established() {
            return Ok(());
        }

        debug!(remote = %self.remote_addr, "QUIC established; awaiting CONNECT-IP request");
        self.session =
            Some(H3Session::with_transport(&mut self.conn).map_err(ServerError::Accept)?);
        Ok(())
    }

    fn advance_handshake(
        &mut self,
        peer_tokens: &HashMap<String, String>,
    ) -> Result<Option<String>, ServerError> {
        self.ensure_session()?;

        let progress = {
            let Some(session) = self.session.as_mut() else {
                return Ok(None);
            };
            let pending_peer_id = match &mut self.phase {
                ServerConnPhase::Handshaking {
                    pending_peer_id, ..
                } => pending_peer_id,
                ServerConnPhase::Established => return Ok(None),
            };

            session.poll_connect_request(&mut self.conn, pending_peer_id, peer_tokens)?
        };

        match progress {
            ServerConnectProgress::Pending => Ok(None),
            ServerConnectProgress::Ready(peer_id) => {
                self.peer_id = peer_id.clone();
                self.phase = ServerConnPhase::Established;
                Ok(Some(peer_id))
            }
        }
    }

    fn drain_control(&mut self) -> bool {
        let Some(session) = self.session.as_mut() else {
            return false;
        };

        loop {
            match session.h3_conn.poll(&mut self.conn) {
                Ok((sid, quiche::h3::Event::Finished)) if sid == session.connect_stream_id => {
                    return false;
                }
                Ok((sid, quiche::h3::Event::Reset(_))) if sid == session.connect_stream_id => {
                    return false;
                }
                Ok((_sid, quiche::h3::Event::GoAway)) => return false,
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => return true,
                Err(_) => return false,
            }
        }
    }

    fn forward_ingress(
        &mut self,
        max_udp_payload: usize,
        ingress_tx: &mpsc::Sender<Vec<PooledBuf>>,
    ) {
        let Some(session) = self.session.as_ref() else {
            return;
        };

        let dgrams = collect_router_ingress(
            &mut self.conn,
            max_udp_payload,
            &mut self.rx_counters,
            &session.datagram_codec,
        );
        if !dgrams.is_empty() {
            let _ = ingress_tx.try_send(dgrams);
        }
    }

    fn close(&mut self, reason: &'static [u8]) {
        self.conn.close(true, 0, reason).ok();
    }

    fn flush_send(&mut self, socket: &UdpSocket, send_buf: &mut [u8]) {
        flush_server_send(&mut self.conn, socket, self.remote_addr, send_buf);
    }

    fn emit_metrics(&self, events_tx: &mpsc::UnboundedSender<Event>) {
        let rx = self
            .rx_counters
            .snapshot(Some(&self.peer_id), Some(self.remote_addr));
        let tx = self
            .tx_counters
            .snapshot(Some(&self.peer_id), Some(self.remote_addr));
        let _ = events_tx.send(Event::Metrics(rx));
        let _ = events_tx.send(Event::Metrics(tx));
    }
}

// ========== Packet Routing ==========

/// Parsed routing metadata from the first QUIC packet in a batch.
struct ServerPacketHeader {
    dcid: Vec<u8>,
    hdr_ty: quiche::Type,
    hdr_version: u32,
    client_scid: Vec<u8>,
}

impl ServerPacketHeader {
    fn parse(batch: &mut [PooledBuf]) -> Option<Self> {
        let hdr = quiche::Header::from_slice(batch.first_mut()?, quiche::MAX_CONN_ID_LEN).ok()?;
        Some(Self {
            dcid: hdr.dcid.as_ref().to_vec(),
            hdr_ty: hdr.ty,
            hdr_version: hdr.version,
            client_scid: hdr.scid.as_ref().to_vec(),
        })
    }
}

/// Flushes QUIC output packets inline via `send_to`.
fn flush_server_send(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    dest: SocketAddr,
    send_buf: &mut [u8],
) {
    loop {
        match conn.send(send_buf) {
            Ok((len, _send_info)) => {
                let _ = socket.try_send_to(&send_buf[..len], dest);
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                warn!(error = ?e, "quiche send error");
                break;
            }
        }
    }
}

// ========== Server Runtime ==========

/// Server runtime that multiplexes all inbound H3v2 connections on one socket.
struct ServerRuntime {
    bound_addr: SocketAddr,
    config: quiche::Config,
    max_udp_payload: usize,
    handshake_timeout: Duration,
    send_socket: UdpSocket,
    send_buf: Vec<u8>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    cid_table: HashMap<Vec<u8>, usize>,
    connections: HashMap<usize, ServerConn>,
    next_conn_id: usize,
}

impl ServerRuntime {
    fn new(
        bound_addr: SocketAddr,
        config: quiche::Config,
        max_udp_payload: usize,
        handshake_timeout: Duration,
        send_socket: UdpSocket,
        ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
        events_tx: mpsc::UnboundedSender<Event>,
    ) -> Self {
        Self {
            bound_addr,
            config,
            max_udp_payload,
            handshake_timeout,
            send_socket,
            send_buf: vec![0u8; max_udp_payload],
            ingress_tx,
            events_tx,
            cid_table: HashMap::new(),
            connections: HashMap::new(),
            next_conn_id: 0,
        }
    }

    async fn run(
        mut self,
        mut udp_recv_rx: mpsc::Receiver<(SocketAddr, Vec<PooledBuf>)>,
        mut cmd_rx: mpsc::UnboundedReceiver<H3v2ListenerCommand>,
        mut peer_tokens: HashMap<String, String>,
        metrics_interval: Duration,
        keepalive_interval: Duration,
    ) -> ActorExitResult {
        let mut ticker = time::interval(metrics_interval);
        let mut keepalive = time::interval(keepalive_interval);
        keepalive.tick().await;

        let timer = time::sleep(MAX_TIMEOUT);
        tokio::pin!(timer);

        info!(bound_addr = %self.bound_addr, "h3v2 listener started");

        loop {
            tokio::select! {
                maybe_pkt = udp_recv_rx.recv() => {
                    let Some((remote, batch)) = maybe_pkt else {
                        return Err(ActorError::BareRxRecv {
                            addr: self.bound_addr.to_string(),
                            source: std::io::Error::other("recv actor closed"),
                        });
                    };

                    self.handle_udp_batch(remote, batch, &peer_tokens);
                }

                _ = &mut timer => {
                    self.on_timeout();
                }

                _ = keepalive.tick() => {
                    self.on_keepalive();
                }

                _ = ticker.tick() => {
                    self.on_metrics_tick();
                }

                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(H3v2ListenerCommand::UpdatePeerTokens(update)) => {
                            peer_tokens = update;
                            debug!("h3v2 listener: updated peer tokens");
                        }
                        None => return Ok(()),
                    }
                }
            }

            self.reset_timer(timer.as_mut());
        }
    }

    fn handle_udp_batch(
        &mut self,
        remote: SocketAddr,
        mut batch: Vec<PooledBuf>,
        peer_tokens: &HashMap<String, String>,
    ) {
        let Some(header) = ServerPacketHeader::parse(&mut batch) else {
            return;
        };

        if let Some(&conn_id) = self.cid_table.get(&header.dcid) {
            self.handle_existing_connection(conn_id, batch, peer_tokens);
            return;
        }

        self.accept_new_connection(remote, batch, header);
    }

    fn handle_existing_connection(
        &mut self,
        conn_id: usize,
        batch: Vec<PooledBuf>,
        peer_tokens: &HashMap<String, String>,
    ) {
        let bound_addr = self.bound_addr;
        let max_udp_payload = self.max_udp_payload;
        let ingress_tx = &self.ingress_tx;
        let send_socket = &self.send_socket;
        let send_buf = &mut self.send_buf;

        let Some(sc) = self.connections.get_mut(&conn_id) else {
            return;
        };

        let recv_info = sc.recv_info(bound_addr);
        handle_udp_recv(&mut sc.conn, batch, recv_info);

        if sc.is_established() {
            if !sc.drain_control() {
                sc.close(b"h3 control closed");
            } else {
                sc.forward_ingress(max_udp_payload, ingress_tx);
            }
        } else {
            match sc.advance_handshake(peer_tokens) {
                Ok(Some(ref peer_id)) => {
                    info!(%peer_id, remote = %sc.remote_addr, "server: CONNECT-IP established");
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(remote = %sc.remote_addr, error = %e, "server handshake failed");
                    sc.close(b"handshake failed");
                }
            }
        }

        sc.flush_send(send_socket, send_buf);
    }

    fn accept_new_connection(
        &mut self,
        remote: SocketAddr,
        batch: Vec<PooledBuf>,
        header: ServerPacketHeader,
    ) {
        if header.hdr_ty != quiche::Type::Initial {
            return;
        }

        if !quiche::version_is_supported(header.hdr_version) {
            if let Ok(len) = quiche::negotiate_version(
                &quiche::ConnectionId::from_ref(&header.client_scid),
                &quiche::ConnectionId::from_ref(&header.dcid),
                &mut self.send_buf,
            ) {
                let _ = self.send_socket.try_send_to(&self.send_buf[..len], remote);
            }
            return;
        }

        let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
        rand::rng().fill_bytes(&mut scid_bytes);
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        // TODO: Stateless retry for public-facing deployments.
        let mut conn = match quiche::accept(&scid, None, self.bound_addr, remote, &mut self.config)
        {
            Ok(c) => c,
            Err(e) => {
                warn!(%remote, error = ?e, "quiche accept failed");
                return;
            }
        };

        handle_udp_recv(
            &mut conn,
            batch,
            quiche::RecvInfo {
                from: remote,
                to: self.bound_addr,
            },
        );

        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;

        // TODO: Track NEW_CONNECTION_ID / RETIRE_CONNECTION_ID for CID rotation.
        // Acceptable for stable-NAT VPN use.
        let cids = vec![header.dcid, scid_bytes.to_vec()];
        for cid in &cids {
            self.cid_table.insert(cid.clone(), conn_id);
        }

        let mut sc = ServerConn::new(conn, remote, cids);
        sc.flush_send(&self.send_socket, &mut self.send_buf);
        self.connections.insert(conn_id, sc);
    }

    fn on_timeout(&mut self) {
        let send_socket = &self.send_socket;
        let send_buf = &mut self.send_buf;

        for sc in self.connections.values_mut() {
            sc.conn.on_timeout();
            sc.flush_send(send_socket, send_buf);
        }
    }

    fn on_keepalive(&mut self) {
        let send_socket = &self.send_socket;
        let send_buf = &mut self.send_buf;

        for sc in self.connections.values_mut() {
            if !sc.is_established() {
                continue;
            }

            sc.conn.send_ack_eliciting().ok();
            sc.flush_send(send_socket, send_buf);
        }
    }

    fn on_metrics_tick(&mut self) {
        let remove: Vec<usize> = self
            .connections
            .iter()
            .filter(|(_, sc)| sc.conn.is_closed() || sc.handshake_timed_out(self.handshake_timeout))
            .map(|(&id, _)| id)
            .collect();

        for id in remove {
            self.remove_connection(id);
        }

        for sc in self.connections.values() {
            sc.emit_metrics(&self.events_tx);
        }
    }

    fn remove_connection(&mut self, conn_id: usize) {
        if let Some(sc) = self.connections.get_mut(&conn_id) {
            if !sc.conn.is_closed() {
                sc.close(b"handshake timeout");
                sc.flush_send(&self.send_socket, &mut self.send_buf);
            }
        }

        if let Some(sc) = self.connections.remove(&conn_id) {
            for cid in &sc.cids {
                self.cid_table.remove(cid);
            }
        }
    }

    fn next_timeout(&self) -> Duration {
        self.connections
            .values()
            .filter_map(|sc| sc.conn.timeout())
            .min()
            .unwrap_or(MAX_TIMEOUT)
    }

    fn reset_timer(&self, timer: std::pin::Pin<&mut time::Sleep>) {
        timer.reset(time::Instant::now() + self.next_timeout());
    }
}

fn spawn_listener_start_error(
    crypto_rt: &RuntimeHandle,
    bound_addr: SocketAddr,
    source: std::io::Error,
) -> JoinHandle<ActorExitResult> {
    crypto_rt.spawn(async move {
        Err(ActorError::BareRxRecv {
            addr: bound_addr.to_string(),
            source,
        })
    })
}

/// Spawns the H3v2 listener with separated I/O and crypto:
///
/// - **Recv actor** (I/O thread via `tokio::spawn`): quinn-udp GRO-aware recv,
///   sends `(SocketAddr, Vec<PooledBuf>)` batches via channel.
/// - **Multiplexed engine** (`crypto_rt`): CID routing, QUIC crypto, H3 handshake,
///   datagram forwarding, inline `send_to`.
///
/// Returns command sender, engine join handle, and bound address.
#[allow(clippy::too_many_arguments)]
pub fn spawn_h3v2_listener(
    listener: H3v2Listener,
    peer_tokens: HashMap<String, String>,
    tuning: &Tuning,
    crypto_rt: &RuntimeHandle,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
) -> (
    mpsc::UnboundedSender<H3v2ListenerCommand>,
    JoinHandle<ActorExitResult>,
    SocketAddr,
) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let bound_addr = listener.bound_addr;

    let H3v2Listener {
        socket: std_socket,
        config,
        max_udp_payload,
        ..
    } = listener;

    let tuning = tuning.clone();
    let handshake_timeout = tuning.h3_handshake_timeout;

    // Clone socket: recv_std → recv actor (I/O thread), std_socket → engine (crypto_rt).
    let recv_std = match std_socket.try_clone() {
        Ok(s) => s,
        Err(e) => {
            let handle = spawn_listener_start_error(crypto_rt, bound_addr, e);
            return (cmd_tx, handle, bound_addr);
        }
    };

    // Recv actor on I/O thread — reuses BareUDP recv with source addr tagging.
    let (udp_recv_tx, udp_recv_rx) =
        mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(tuning.packet_queue_depth);
    let recv_socket = match UdpSocket::from_std(recv_std) {
        Ok(s) => s,
        Err(e) => {
            let handle = spawn_listener_start_error(crypto_rt, bound_addr, e);
            return (cmd_tx, handle, bound_addr);
        }
    };
    let bare_rx = match bare_rx_from_socket(recv_socket, max_udp_payload) {
        Ok(rx) => rx,
        Err(e) => {
            let handle = spawn_listener_start_error(
                crypto_rt,
                bound_addr,
                std::io::Error::other(e.to_string()),
            );
            return (cmd_tx, handle, bound_addr);
        }
    };
    let _recv_handle = spawn_server_udp_rx(bare_rx, udp_recv_tx);

    // Multiplexed engine on crypto_rt.
    let handle = crypto_rt.spawn(async move {
        let send_socket = UdpSocket::from_std(std_socket).map_err(|e| ActorError::BareRxRecv {
            addr: bound_addr.to_string(),
            source: e,
        })?;
        let runtime = ServerRuntime::new(
            bound_addr,
            config,
            max_udp_payload,
            handshake_timeout,
            send_socket,
            ingress_tx,
            events_tx,
        );

        runtime
            .run(
                udp_recv_rx,
                cmd_rx,
                peer_tokens,
                tuning.metrics_push_interval,
                tuning.h3_keepalive_interval,
            )
            .await
    });

    (cmd_tx, handle, bound_addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== ServerError Tests ==========

    #[test]
    fn server_error_display() {
        let err = ServerError::Socket("bind failed".into());
        assert!(err.to_string().contains("socket"));
        let err = ServerError::Config("cert not found".into());
        assert!(err.to_string().contains("config"));
        let err = ServerError::Accept("auth failed".into());
        assert!(err.to_string().contains("accept"));
    }

    // ========== H3ServerConn Tests ==========

    #[test]
    fn h3_server_conn_debug_format() {
        let conn = H3ServerConn {
            peer_id: "client-1".into(),
            remote_addr: "10.0.0.2:54321".parse().unwrap(),
        };
        let dbg = format!("{conn:?}");
        assert!(dbg.contains("client-1"));
        assert!(dbg.contains("10.0.0.2:54321"));
    }

    // ========== Validation Helper Tests ==========

    #[test]
    fn validate_server_connect_headers_accepts_valid() {
        let headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            quiche::h3::Header::new(b"authorization", b"Bearer test-token"),
        ];
        assert!(validate_server_connect_headers(&headers).is_ok());
    }

    #[test]
    fn validate_server_connect_headers_rejects_bad_method() {
        let headers = vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        assert!(validate_server_connect_headers(&headers).is_err());
    }

    #[test]
    fn validate_server_connect_headers_rejects_bad_protocol() {
        let headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"websocket"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        assert!(validate_server_connect_headers(&headers).is_err());
    }

    #[test]
    fn validate_server_auth_accepts_valid_token() {
        let headers = vec![quiche::h3::Header::new(
            b"authorization",
            b"Bearer my-secret-token",
        )];
        let mut tokens = HashMap::new();
        tokens.insert("peer-1".to_string(), "my-secret-token".to_string());
        let result = validate_server_auth(&headers, &tokens);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "peer-1");
    }

    #[test]
    fn validate_server_auth_rejects_wrong_token() {
        let headers = vec![quiche::h3::Header::new(
            b"authorization",
            b"Bearer wrong-token",
        )];
        let mut tokens = HashMap::new();
        tokens.insert("peer-1".to_string(), "correct-token".to_string());
        assert!(validate_server_auth(&headers, &tokens).is_err());
    }

    // ========== make_h3v2_listener Tests ==========

    #[tokio::test]
    async fn make_h3v2_listener_rejects_missing_cert() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tuning = Tuning::default();
        let result = make_h3v2_listener(
            addr,
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
            1400,
            &tuning,
        );
        assert!(result.is_err());
    }
}
