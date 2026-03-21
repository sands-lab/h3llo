//! H3 CONNECT-IP server: CID-based dispatcher with per-connection H3Engine.
//!
//! Architecture:
//! - **UDP RX actor** (I/O thread): GRO-aware recv, emits `(SocketAddr, Vec<PooledBuf>)`.
//! - **Server UDP TX actor** (I/O thread): shared send actor for all connections.
//! - **H3Dispatcher** (`crypto_rt`): CID routing, connection acceptance, actor lifecycle.
//! - **H3Engine** (`crypto_rt`): per-connection unified QUIC/H3 engine with ingress + egress.
//!
//! See [`make_h3v2_listener`] + [`spawn_h3v2_listener`] for the public entry points.

use crate::actor::{ActorError, ActorExitResult};
use crate::auth::validate_connect_auth;
use crate::bind::make_server_udp_socket;
use crate::config::Tuning;
use crate::events::Event;
use crate::h3::CONNECT_IP_OVERHEAD;
use crate::h3engine::{
    apply_transport_config, handle_udp_recv, reset_timer, EngineIo, EngineMeta, EngineRole,
    H3Engine, RunState,
};
use crate::h3session::{ConnectFailure, ConnectProgress, H3Session, HeaderAction, MAX_TIMEOUT};
use crate::udp;
use quiche::h3::NameValue;
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
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

// ========== Server-Specific H3Engine Methods ==========

impl H3Engine {
    /// Server-side QUIC + CONNECT-IP handshake.
    ///
    /// Waits for QUIC establishment, validates the inbound CONNECT-IP request
    /// (headers + auth), sends 200 OK, and updates `meta.peer_id` with the
    /// authenticated identity. Returns the ready engine or a `ServerError`.
    async fn accept(
        mut self,
        peer_tokens: &HashMap<String, String>,
        timeout: Duration,
    ) -> Result<Self, ServerError> {
        let recv_info = self.meta.recv_info();

        let deadline = time::sleep(timeout);
        tokio::pin!(deadline);
        let timer = time::sleep(self.conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        let mut server_handler = |h3: &mut quiche::h3::Connection,
                                  conn: &mut quiche::Connection,
                                  stream_id: u64,
                                  headers: &[quiche::h3::Header]| {
            validate_server_connect_headers(headers).map_err(ConnectFailure::Closed)?;
            let pid = validate_server_auth(headers, peer_tokens)
                .map_err(|e| ConnectFailure::Closed(format!("auth: {e}")))?;

            let response = [
                quiche::h3::Header::new(b":status", b"200"),
                quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            ];
            h3.send_response(conn, stream_id, &response, false)
                .map_err(|e| ConnectFailure::Closed(format!("send 200: {e}")))?;

            Ok(HeaderAction::Accept {
                stream_id,
                peer_id: Some(pid),
            })
        };

        loop {
            tokio::select! {
                maybe_batch = self.io.udp_recv_rx.recv() => {
                    let Some((_remote, batch)) = maybe_batch else {
                        return Err(ServerError::Accept(
                            "udp rx closed during handshake".into(),
                        ));
                    };

                    handle_udp_recv(&mut self.conn, batch, recv_info);

                    // Lazily create H3 session once QUIC is established.
                    if self.session.is_none() && self.conn.is_established() {
                        debug!(
                            remote = %self.meta.remote_addr,
                            "QUIC established; awaiting CONNECT-IP request"
                        );
                        self.session = Some(
                            H3Session::with_transport(&mut self.conn)
                                .map_err(ServerError::Accept)?,
                        );
                    }

                    if let Some(session) = self.session.as_mut() {
                        match session
                            .poll_h3_events(
                                &mut self.conn,
                                &self.meta.peer_id,
                                &mut server_handler,
                            )
                            .map_err(|e| ServerError::Accept(e.into_actor_reason()))?
                        {
                            ConnectProgress::Ready => {
                                let peer_id = session
                                    .accepted_peer_id
                                    .take()
                                    .expect("peer_id set by server handler");
                                self.flush_send();
                                self.meta.peer_id = peer_id;
                                return Ok(self);
                            }
                            ConnectProgress::Pending => {}
                        }
                    }
                }

                _ = &mut timer => {
                    self.conn.on_timeout();
                }

                _ = &mut deadline => {
                    self.conn.close(true, 0, b"handshake timeout").ok();
                    self.flush_send();
                    return Err(ServerError::Accept("handshake timeout".into()));
                }
            }

            self.flush_send();
            reset_timer(timer.as_mut(), &self.conn);

            if self.conn.is_closed() {
                return Err(ServerError::Accept(
                    "QUIC connection closed during handshake".into(),
                ));
            }
        }
    }
}

// ========== Server Dispatcher ==========

/// Handle for a spawned per-connection actor.
struct ConnActorHandle {
    /// Forward tagged QUIC packets from the dispatcher to this actor.
    packet_tx: mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    /// Registered CIDs for cleanup on actor completion.
    cids: Vec<Vec<u8>>,
    /// Actor task handle for lifecycle tracking.
    handle: JoinHandle<ActorExitResult>,
}

/// Shared channel senders cloned into each per-connection [`H3Engine`].
#[derive(Clone)]
struct DispatchIo {
    /// Tagged UDP send channel shared by all connections.
    udp_send_tx: mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    /// Router ingress channel for decoded IP packets.
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    /// System event channel (metrics, connection events).
    events_tx: mpsc::UnboundedSender<Event>,
}

/// Per-connection parameters extracted from [`Tuning`].
struct ConnParams {
    handshake_timeout: Duration,
    packet_queue_depth: usize,
    metrics_interval: Duration,
    keepalive_interval: Duration,
}

/// CID-routing dispatcher that accepts new connections and forwards packets
/// to per-connection [`H3Engine`] tasks.
struct H3Dispatcher {
    bound_addr: SocketAddr,
    config: quiche::Config,
    max_udp_payload: usize,
    io: DispatchIo,
    conn_params: ConnParams,
    cid_table: HashMap<Vec<u8>, usize>,
    actors: HashMap<usize, ConnActorHandle>,
    next_conn_id: usize,
    /// Reusable buffer for version negotiation packets only.
    neg_buf: Vec<u8>,
}

impl H3Dispatcher {
    async fn run(
        mut self,
        mut udp_recv_rx: mpsc::Receiver<(SocketAddr, Vec<PooledBuf>)>,
        mut cmd_rx: mpsc::UnboundedReceiver<H3v2ListenerCommand>,
        mut peer_tokens: HashMap<String, String>,
    ) -> ActorExitResult {
        let mut cleanup_ticker = time::interval(Duration::from_secs(1));

        info!(bound_addr = %self.bound_addr, "h3v2 dispatcher started");

        loop {
            tokio::select! {
                maybe_pkt = udp_recv_rx.recv() => {
                    let Some((remote, batch)) = maybe_pkt else {
                        return Err(ActorError::UdpRxRecv {
                            addr: self.bound_addr.to_string(),
                            source: std::io::Error::other("recv actor closed"),
                        });
                    };

                    self.handle_udp_batch(remote, batch, &peer_tokens);
                }

                _ = cleanup_ticker.tick() => {
                    self.cleanup_finished_actors();
                }

                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(H3v2ListenerCommand::UpdatePeerTokens(update)) => {
                            peer_tokens = update;
                            debug!("dispatcher: updated peer tokens");
                        }
                        None => return Ok(()),
                    }
                }
            }
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
            // Forward to existing per-connection actor.
            if let Some(actor) = self.actors.get(&conn_id) {
                if actor.packet_tx.try_send((remote, batch)).is_err() {
                    debug!(
                        conn_id,
                        "actor packet channel full or closed; dropping batch"
                    );
                }
            }
            return;
        }

        self.accept_and_spawn(remote, batch, header, peer_tokens);
    }

    fn accept_and_spawn(
        &mut self,
        remote: SocketAddr,
        batch: Vec<PooledBuf>,
        header: ServerPacketHeader,
        peer_tokens: &HashMap<String, String>,
    ) {
        if header.hdr_ty != quiche::Type::Initial {
            return;
        }

        if !quiche::version_is_supported(header.hdr_version) {
            if let Ok(len) = quiche::negotiate_version(
                &quiche::ConnectionId::from_ref(&header.client_scid),
                &quiche::ConnectionId::from_ref(&header.dcid),
                &mut self.neg_buf,
            ) {
                let mut pkt = crate::tun::alloc_uninit_packet_buf(len);
                pkt[..len].copy_from_slice(&self.neg_buf[..len]);
                pkt.truncate(len);
                let _ = self.io.udp_send_tx.try_send((remote, vec![pkt]));
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

        // Register CIDs before spawning actor so subsequent packets route correctly.
        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;

        // TODO: Track NEW_CONNECTION_ID / RETIRE_CONNECTION_ID for CID rotation.
        let cids = vec![header.dcid, scid_bytes.to_vec()];
        for cid in &cids {
            self.cid_table.insert(cid.clone(), conn_id);
        }

        // Create per-connection channels.
        let depth = self.conn_params.packet_queue_depth;
        let (packet_tx, packet_rx) = mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(depth);
        let (egress_tx, egress_rx) = mpsc::channel::<Vec<PooledBuf>>(depth);
        let channels = self.io.clone();
        let peer_tokens = peer_tokens.clone();
        let handshake_timeout = self.conn_params.handshake_timeout;

        let mut engine = H3Engine {
            conn,
            session: None,
            io: EngineIo {
                udp_recv_rx: packet_rx,
                udp_send_tx: channels.udp_send_tx,
                egress_rx,
                ingress_tx: channels.ingress_tx,
                events_tx: channels.events_tx,
            },
            meta: EngineMeta {
                local_addr: self.bound_addr,
                remote_addr: remote,
                peer_id: remote.to_string(), // placeholder until auth
                max_udp_payload: self.max_udp_payload,
            },
            run_state: RunState::new(),
            metrics_interval: self.conn_params.metrics_interval,
            keepalive_interval: self.conn_params.keepalive_interval,
            role: EngineRole::Server,
        };

        // Send initial handshake output (ServerHello) synchronously before
        // spawning the task, preserving current timing behavior.
        engine.flush_send();

        // Spawn per-connection actor.
        let handle = tokio::spawn(async move {
            let engine = match engine.accept(&peer_tokens, handshake_timeout).await {
                Ok(engine) => engine,
                Err(e) => {
                    warn!(%remote, error = %e, "server handshake failed");
                    return Ok(());
                }
            };

            info!(
                peer_id = %engine.meta.peer_id,
                %remote,
                "server: CONNECT-IP established"
            );

            // TODO: Emit H3ServerConn { peer_id, remote_addr, tx: egress_tx }
            // to the orchestrator for routing integration.
            let _ = &egress_tx; // suppress unused warning for now

            engine.run().await
        });

        self.actors.insert(
            conn_id,
            ConnActorHandle {
                packet_tx,
                cids,
                handle,
            },
        );
    }

    fn cleanup_finished_actors(&mut self) {
        let finished: Vec<usize> = self
            .actors
            .iter()
            .filter(|(_, a)| a.handle.is_finished())
            .map(|(&id, _)| id)
            .collect();

        for conn_id in finished {
            if let Some(actor) = self.actors.remove(&conn_id) {
                for cid in &actor.cids {
                    self.cid_table.remove(cid);
                }
            }
        }
    }
}

// ========== Spawn ==========

fn spawn_listener_start_error(
    crypto_rt: &RuntimeHandle,
    bound_addr: SocketAddr,
    source: std::io::Error,
) -> JoinHandle<ActorExitResult> {
    crypto_rt.spawn(async move {
        Err(ActorError::UdpRxRecv {
            addr: bound_addr.to_string(),
            source,
        })
    })
}

/// Spawns the H3v2 listener with separated I/O and crypto:
///
/// - **Recv actor** (I/O thread): quinn-udp GRO-aware recv.
/// - **TX actor** (I/O thread): shared send actor for all connections.
/// - **Dispatcher** (`crypto_rt`): CID routing, connection acceptance.
/// - **Per-connection actors** (`crypto_rt`): QUIC crypto, H3 session,
///   datagram forwarding with backpressure.
///
/// Returns command sender, dispatcher join handle, and bound address.
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

    // Convert std socket to tokio and create shared UDP actors.
    let socket = match UdpSocket::from_std(std_socket) {
        Ok(s) => s,
        Err(e) => {
            let handle = spawn_listener_start_error(crypto_rt, bound_addr, e);
            return (cmd_tx, handle, bound_addr);
        }
    };
    let (udp_rx, udp_tx) = match udp::make_udp(socket, max_udp_payload, tuning.udp_enable_offload) {
        Ok(pair) => pair,
        Err(e) => {
            let handle = spawn_listener_start_error(
                crypto_rt,
                bound_addr,
                std::io::Error::other(e.to_string()),
            );
            return (cmd_tx, handle, bound_addr);
        }
    };

    // RX actor on I/O thread.
    let (udp_recv_tx, udp_recv_rx) =
        mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(tuning.packet_queue_depth);
    let _recv_handle = udp::spawn_udp_rx(udp_rx, udp_recv_tx);

    // TX actor on I/O thread (GSO-aware, replaces per-packet try_send_to).
    let (udp_send_tx, _tx_handle) = udp::spawn_udp_tx(udp_tx, tuning.packet_queue_depth);

    // Dispatcher on crypto_rt.
    let handle = crypto_rt.spawn(async move {
        let dispatcher = H3Dispatcher {
            bound_addr,
            config,
            max_udp_payload,
            io: DispatchIo {
                udp_send_tx,
                ingress_tx,
                events_tx,
            },
            conn_params: ConnParams {
                handshake_timeout: tuning.h3_handshake_timeout,
                packet_queue_depth: tuning.packet_queue_depth,
                metrics_interval: tuning.metrics_push_interval,
                keepalive_interval: tuning.h3_keepalive_interval,
            },
            cid_table: HashMap::new(),
            actors: HashMap::new(),
            next_conn_id: 0,
            neg_buf: vec![0u8; max_udp_payload],
        };

        dispatcher.run(udp_recv_rx, cmd_rx, peer_tokens).await
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
