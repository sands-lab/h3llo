//! H3 CONNECT-IP server: CID-based dispatcher with per-connection H3Engine.
//!
//! Architecture:
//! - **UDP RX actor** (I/O thread): GRO-aware recv, emits `(SocketAddr, Vec<PooledBuf>)`.
//! - **Server UDP TX actor** (I/O thread): shared send actor for all connections.
//! - **H3Dispatcher** (`crypto_rt`): CID routing, connection acceptance, actor lifecycle.
//! - **H3Engine** (`crypto_rt`): per-connection unified QUIC/H3 engine with ingress + egress.
//!
//! See [`make_h3_dispatcher`] + [`spawn_h3_dispatcher`] for the public entry points.

use crate::actor::{ActorError, ActorExitResult};
use crate::auth::validate_connect_auth;
use crate::bind::make_server_udp_socket;
use crate::config::Tuning;
use crate::events::{ConnOrigin, Event, H3v2ConnectedEvent};
use crate::h3engine::{
    apply_transport_config, handle_udp_recv, reset_timer, EngineIo, EngineMeta, H3Engine, RunState,
};
use crate::h3session::CONNECT_IP_OVERHEAD;
use crate::h3session::{ConnectFailure, ConnectProgress, H3Session, HeaderAction, MAX_TIMEOUT};
use crate::helpers::alloc_uninit_packet_buf;
use crate::udp;
use quiche::h3::NameValue;
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_quiche::buf_factory::PooledBuf;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

// ========== Server Error ==========

/// Error type for H3 server listener setup and per-connection acceptance.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ServerError {
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

// ========== H3 Dispatcher ==========

/// Commands accepted by the H3 dispatcher actor.
#[derive(Debug)]
pub enum DispatcherCommand {
    /// Replace the peer token map used for CONNECT-IP authentication.
    UpdatePeerTokens(HashMap<String, String>),
}

/// Creates [`H3Dispatcher`] state ready for spawning.
///
/// Performs all fallible setup: socket binding, TLS credential loading,
/// QUIC config construction, and UDP socket initialization. Does NOT spawn
/// any tasks — use [`spawn_h3_dispatcher`] for that.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_h3_dispatcher(
    listen_addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    tun_mtu: u16,
    tuning: &Tuning,
    udp_rt: &RuntimeHandle,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
) -> Result<(H3Dispatcher, SocketAddr), ServerError> {
    let std_socket = make_server_udp_socket(listen_addr, tuning.socket_buffer_bytes())
        .map_err(|e| ServerError::Socket(e.to_string()))?;
    let bound_addr = std_socket
        .local_addr()
        .map_err(|e| ServerError::Socket(format!("local_addr: {e}")))?;
    let max_udp_payload = tun_mtu as usize + CONNECT_IP_OVERHEAD;
    let config = make_server_quiche_config(tuning, max_udp_payload, cert_path, key_path)?;

    let (udp_rx, udp_tx) = {
        let _guard = udp_rt.enter();
        udp::make_udp(std_socket, max_udp_payload, tuning.udp_enable_offload)
            .map_err(|e| ServerError::Socket(format!("make_udp: {e}")))?
    };

    let dispatcher = H3Dispatcher {
        bound_addr,
        config,
        max_udp_payload,
        udp_rx,
        udp_tx,
        ingress_tx,
        events_tx,
        tuning: tuning.clone(),
    };

    info!(%listen_addr, %bound_addr, "h3 dispatcher created");
    Ok((dispatcher, bound_addr))
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
        let deadline = time::sleep(timeout);
        tokio::pin!(deadline);
        let timer = time::sleep(self.conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        let remote_addr = self.meta.remote_addr;
        let mut server_handler = |h3: &mut quiche::h3::Connection,
                                  conn: &mut quiche::Connection,
                                  stream_id: u64,
                                  headers: &[quiche::h3::Header]| {
            if let Err(reason) = validate_server_connect_headers(headers) {
                debug!(stream_id, reason, "rejecting non-CONNECT-IP stream");
                let _ = h3.send_response(
                    conn,
                    stream_id,
                    &[quiche::h3::Header::new(b":status", b"400")],
                    true,
                );
                return Ok(HeaderAction::Ignore);
            }
            let pid = match validate_server_auth(headers, peer_tokens) {
                Ok(id) => id,
                Err(e) => {
                    warn!(stream_id, %remote_addr, error = %e, "rejecting unauthenticated stream");
                    let _ = h3.send_response(
                        conn,
                        stream_id,
                        &[quiche::h3::Header::new(b":status", b"401")],
                        true,
                    );
                    return Ok(HeaderAction::Ignore);
                }
            };

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
                    let Some((remote, batch)) = maybe_batch else {
                        return Err(ServerError::Accept(
                            "udp rx closed during handshake".into(),
                        ));
                    };

                    handle_udp_recv(&mut self.conn, batch, self.meta.recv_info(remote), None);

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
                        match session.poll_h3_events(
                            &mut self.conn,
                            &self.meta.peer_id,
                            &mut server_handler,
                        ) {
                            Ok(ConnectProgress::Ready) => {
                                let peer_id = session
                                    .accepted_peer_id
                                    .take()
                                    .expect("peer_id set by server handler");
                                self.flush_send();
                                self.meta.peer_id = peer_id;
                                return Ok(self);
                            }
                            Ok(ConnectProgress::Pending) => {}
                            Err(e) => {
                                self.flush_send();
                                return Err(ServerError::Accept(e.into_actor_reason()));
                            }
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

/// H3 dispatcher state created by [`make_h3_dispatcher`].
///
/// Contains all resources needed to run the dispatcher. Spawned infallibly
/// via [`spawn_h3_dispatcher`], which creates UDP I/O actors and the
/// dispatcher task.
pub struct H3Dispatcher {
    bound_addr: SocketAddr,
    config: quiche::Config,
    max_udp_payload: usize,
    udp_rx: udp::UdpRx,
    udp_tx: udp::UdpTx,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    tuning: Tuning,
}

/// Runtime state for the CID-routing dispatcher loop.
///
/// Built by [`spawn_h3_dispatcher`] from an [`H3Dispatcher`] after UDP actors
/// are spawned. Routes packets to per-connection actors by CID.
struct DispatcherRuntime {
    bound_addr: SocketAddr,
    config: quiche::Config,
    max_udp_payload: usize,
    io: DispatchIo,
    tuning: Tuning,
    /// Maps each registered CID directly to the per-connection packet sender.
    cid_table: HashMap<Vec<u8>, mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>>,
}

impl DispatcherRuntime {
    async fn run(
        mut self,
        mut udp_recv_rx: mpsc::Receiver<(SocketAddr, Vec<PooledBuf>)>,
        mut cmd_rx: mpsc::UnboundedReceiver<DispatcherCommand>,
        mut peer_tokens: HashMap<String, String>,
    ) -> ActorExitResult {
        let mut cleanup_ticker = time::interval(Duration::from_secs(1));

        info!(bound_addr = %self.bound_addr, "h3 dispatcher started");

        loop {
            tokio::select! {
                maybe_pkt = udp_recv_rx.recv() => {
                    let Some((remote, batch)) = maybe_pkt else {
                        return Err(ActorError::UdpRxRecv {
                            addr: self.bound_addr.to_string(),
                            source: std::io::Error::other("recv actor closed"),
                        });
                    };

                    self.handle_udp_batch(remote, batch, &peer_tokens).await;
                }

                _ = cleanup_ticker.tick() => {
                    self.cid_table.retain(|_, tx| !tx.is_closed());
                }

                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(DispatcherCommand::UpdatePeerTokens(update)) => {
                            peer_tokens = update;
                            info!("dispatcher: updated peer tokens");
                        }
                        None => return Ok(()),
                    }
                }
            }
        }
    }

    async fn handle_udp_batch(
        &mut self,
        remote: SocketAddr,
        mut batch: Vec<PooledBuf>,
        peer_tokens: &HashMap<String, String>,
    ) {
        let Some(header) = ServerPacketHeader::parse(&mut batch) else {
            debug!(%remote, "dispatcher: failed to parse packet header, dropping batch");
            return;
        };

        if let Some(tx) = self.cid_table.get(&header.dcid) {
            if tx.send((remote, batch)).await.is_err() {
                debug!(%remote, "dispatcher: connection channel closed, dropping packet");
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
            debug!(%remote, ty = ?header.hdr_ty, "dispatcher: dropping non-Initial packet for unknown CID");
            return;
        }

        if !quiche::version_is_supported(header.hdr_version) {
            let mut pkt = alloc_uninit_packet_buf(self.max_udp_payload);
            if let Ok(len) = quiche::negotiate_version(
                &quiche::ConnectionId::from_ref(&header.client_scid),
                &quiche::ConnectionId::from_ref(&header.dcid),
                &mut pkt,
            ) {
                pkt.truncate(len);
                if self.io.udp_send_tx.try_send((remote, vec![pkt])).is_err() {
                    debug!(%remote, "dispatcher: failed to send version negotiation");
                }
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
            None,
        );

        // Create per-connection channels.
        let depth = self.tuning.packet_queue_depth;
        let (packet_tx, packet_rx) = mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(depth);

        // Register CIDs before spawning actor so subsequent packets route correctly.
        // TODO: Track NEW_CONNECTION_ID / RETIRE_CONNECTION_ID for CID rotation.
        for cid in [header.dcid, scid_bytes.to_vec()] {
            self.cid_table.insert(cid, packet_tx.clone());
        }
        let (egress_tx, egress_rx) = mpsc::channel::<Vec<PooledBuf>>(depth);
        let channels = self.io.clone();
        let peer_tokens = peer_tokens.clone();
        let handshake_timeout = self.tuning.h3_handshake_timeout;

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
            metrics_interval: self.tuning.metrics_push_interval,
            keepalive_interval: self.tuning.h3_keepalive_interval,
            origin: ConnOrigin::Server,
            udp_cancel: None,
        };

        // Send initial handshake output (ServerHello) synchronously before
        // spawning the task, preserving current timing behavior.
        engine.flush_send();

        // Spawn per-connection actor (detached — cleanup via sender liveness).
        tokio::spawn(async move {
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

            if engine
                .io
                .events_tx
                .send(Event::H3v2Connected(H3v2ConnectedEvent {
                    peer_id: engine.meta.peer_id.clone(),
                    remote_addr: remote,
                    tx: egress_tx,
                    origin: ConnOrigin::Server,
                    handles: Vec::new(),
                }))
                .is_err()
            {
                warn!(peer_id = %engine.meta.peer_id, %remote, "events channel closed; aborting connection");
                return Ok(());
            }

            engine.run().await
        });
    }
}

// ========== Spawn ==========

/// Spawns the H3 dispatcher: UDP I/O actors on `udp_rt`, dispatcher on `crypto_rt`.
///
/// Consumes the [`H3Dispatcher`] state from [`make_h3_dispatcher`], spawns
/// UDP RX/TX actors, then spawns the CID-routing dispatcher loop.
///
/// Returns command sender, dispatcher join handle, and bound address.
pub fn spawn_h3_dispatcher(
    dispatcher: H3Dispatcher,
    peer_tokens: HashMap<String, String>,
    udp_rt: &RuntimeHandle,
    crypto_rt: &RuntimeHandle,
) -> (
    mpsc::UnboundedSender<DispatcherCommand>,
    JoinHandle<ActorExitResult>,
    SocketAddr,
) {
    let H3Dispatcher {
        bound_addr,
        config,
        max_udp_payload,
        udp_rx,
        udp_tx,
        ingress_tx,
        events_tx,
        tuning,
    } = dispatcher;

    // Spawn UDP actors on udp_rt.
    // TODO: Return UDP actor JoinHandles for orchestrator supervision.
    // Currently dropped — if a UDP actor exits unexpectedly the dispatcher
    // keeps running without visibility, silently breaking the listener.
    let (udp_recv_rx, udp_send_tx) = {
        let _guard = udp_rt.enter();
        let (udp_recv_tx, udp_recv_rx) =
            mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(tuning.packet_queue_depth);
        let cancel = CancellationToken::new();
        let _recv_handle = udp::spawn_udp_rx(udp_rx, udp_recv_tx, cancel);
        let (udp_send_tx, _tx_handle) = udp::spawn_udp_tx(udp_tx, tuning.packet_queue_depth);
        (udp_recv_rx, udp_send_tx)
    };

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    let handle = crypto_rt.spawn(async move {
        let runtime = DispatcherRuntime {
            bound_addr,
            config,
            max_udp_payload,
            io: DispatchIo {
                udp_send_tx,
                ingress_tx,
                events_tx,
            },
            tuning,
            cid_table: HashMap::new(),
        };
        runtime.run(udp_recv_rx, cmd_rx, peer_tokens).await
    });

    (cmd_tx, handle, bound_addr)
}

/// Shared test utilities for H3v2 listener integration tests across modules.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::events::{Event, H3v2ConnectedEvent};

    /// Waits for an `H3v2ConnectedEvent` on the events channel, with timeout.
    ///
    /// Skips non-H3v2Connected events (e.g. metrics). Panics on timeout or if
    /// the channel closes before an H3v2Connected event arrives.
    pub async fn await_h3v2_connection(
        events_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    ) -> H3v2ConnectedEvent {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::H3v2Connected(connected) = event {
                    return connected;
                }
            }
            panic!("events channel closed without H3v2Connected");
        })
        .await
        .expect("timeout waiting for H3v2Connected event")
    }
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

    // ========== make_h3_dispatcher Tests ==========

    #[tokio::test]
    async fn make_h3_dispatcher_rejects_missing_cert() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tuning = Tuning::default();
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let (ingress_tx, _ingress_rx) = mpsc::channel(1);
        let rt = tokio::runtime::Handle::current();
        let result = make_h3_dispatcher(
            addr,
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
            1400,
            &tuning,
            &rt,
            ingress_tx,
            events_tx,
        );
        assert!(result.is_err());
    }

    // ========== Integration Test Imports ==========

    use crate::bind::test_support::FakeRouteProbe;
    use crate::config::default_mtu;
    use crate::events::DialContext;
    use crate::h3::{dial_h3, spawn_h3_rx, spawn_h3_tx, DialError as OldDialError, H3Connection};
    use crate::h3dialer::{dial_h3_client, DialError};
    use crate::h3session::test_support::{insecure_tuning, test_peer_h3, TestCertBundle};
    use crate::helpers::alloc_packet_buf;
    use crate::helpers::test_packets::make_ipv4_packet;
    use std::net::Ipv4Addr;
    use test_support::await_h3v2_connection;
    use tokio_quiche::buf_factory::PooledBuf;

    // ========== Test Harness ==========

    /// Test server wrapping H3 dispatcher with cert and handle lifecycle management.
    struct TestH3Server {
        cmd_tx: mpsc::UnboundedSender<DispatcherCommand>,
        events_rx: mpsc::UnboundedReceiver<Event>,
        ingress_rx: mpsc::Receiver<Vec<PooledBuf>>,
        bound_addr: SocketAddr,
        _certs: TestCertBundle,
        _handle: JoinHandle<ActorExitResult>,
    }

    impl TestH3Server {
        async fn start(peer_tokens: HashMap<String, String>) -> Self {
            let certs = TestCertBundle::generate();
            let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let tuning = Tuning::default();
            let (ingress_tx, ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
            let (events_tx, events_rx) = mpsc::unbounded_channel();
            let rt = tokio::runtime::Handle::current();

            let (dispatcher, bound_addr) = make_h3_dispatcher(
                listen_addr,
                certs.cert_path(),
                certs.key_path(),
                default_mtu(),
                &tuning,
                &rt,
                ingress_tx,
                events_tx,
            )
            .expect("make_h3_dispatcher");

            let (cmd_tx, handle, _) = spawn_h3_dispatcher(dispatcher, peer_tokens, &rt, &rt);

            // Give dispatcher time to start accepting.
            tokio::time::sleep(Duration::from_millis(50)).await;

            Self {
                cmd_tx,
                events_rx,
                ingress_rx,
                bound_addr,
                _certs: certs,
                _handle: handle,
            }
        }
    }

    // ========== Integration Test Helpers ==========

    /// Dials the h3v2 server with the OLD client (h3.rs tokio-quiche).
    async fn dial_old_client(bound_addr: SocketAddr, token: &str, peer_id: &str) -> H3Connection {
        let peer_h3 = test_peer_h3(bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let tuning = insecure_tuning();

        dial_h3(
            &peer_h3,
            bound_addr,
            peer_id,
            None,
            default_mtu(),
            &probe,
            &tuning,
        )
        .await
        .expect("dial_h3 failed")
    }

    /// Dials the h3v2 server with the NEW client (h3dialer.rs raw quiche).
    async fn dial_new_client(
        bound_addr: SocketAddr,
        token: &str,
        peer_id: &str,
    ) -> (H3v2ConnectedEvent, mpsc::Receiver<Vec<PooledBuf>>) {
        let peer_h3 = test_peer_h3(bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let tuning = insecure_tuning();

        let (ingress_tx, ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let ctx = DialContext::test(peer_id, tuning, events_tx);

        let event = dial_h3_client(&peer_h3, bound_addr, &ctx, &probe, ingress_tx)
            .await
            .expect("dial_h3_client failed");

        (event, ingress_rx)
    }

    // ========== Old Client (h3.rs) → H3v2 Listener Tests ==========

    #[tokio::test]
    async fn h3v2_listener_handshake_old_client() {
        let peer_id = "old-cli-hs-peer";
        let token = "old-cli-hs-tk-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let server = TestH3Server::start(peer_tokens).await;
        let conn = dial_old_client(server.bound_addr, token, peer_id).await;

        assert_eq!(conn.peer_id, peer_id);
        assert_eq!(conn.remote_addr, server.bound_addr);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_listener_auth_reject_old_client() {
        let peer_id = "old-cli-rj-peer";
        let correct_token = "correct-token-12";
        let wrong_token = "wrong-token-12ch";
        let peer_tokens = HashMap::from([(peer_id.to_string(), correct_token.to_string())]);

        let server = TestH3Server::start(peer_tokens).await;

        let peer_h3 = test_peer_h3(server.bound_addr, wrong_token);
        let probe = FakeRouteProbe::noop();
        let tuning = insecure_tuning();

        let result = dial_h3(
            &peer_h3,
            server.bound_addr,
            peer_id,
            None,
            default_mtu(),
            &probe,
            &tuning,
        )
        .await;

        assert!(
            matches!(result, Err(OldDialError::Auth(_))),
            "expected Auth error, got {:?}",
            result,
        );

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_listener_datagram_c2s_old_client() {
        let peer_id = "old-cli-c2s-peer";
        let token = "old-cli-c2s-tk12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestH3Server::start(peer_tokens).await;
        let conn = dial_old_client(server.bound_addr, token, peer_id).await;

        // Set up old client TX actor.
        let (_client_rx, client_tx) = conn.into_actors();
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let (client_send_tx, _tx_handle) = spawn_h3_tx(
            client_tx,
            events_tx,
            Duration::from_secs(60),
            256,
            Duration::from_secs(20),
        );

        // Send test packet.
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        let pkt = alloc_packet_buf(&test_packet);
        client_send_tx.send(vec![pkt]).await.expect("send failed");

        // Verify server received the packet via ingress_rx.
        let batch = tokio::time::timeout(Duration::from_secs(5), server.ingress_rx.recv())
            .await
            .expect("timeout waiting for datagram")
            .expect("channel closed");

        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &test_packet[..]);

        drop(server.cmd_tx);
    }

    // ========== New Client (h3dialer.rs) → H3v2 Listener Tests ==========

    #[tokio::test]
    async fn h3v2_listener_handshake_new_client() {
        let peer_id = "new-cli-hs-peer";
        let token = "new-cli-hs-tk-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let server = TestH3Server::start(peer_tokens).await;
        let (event, _ingress_rx) = dial_new_client(server.bound_addr, token, peer_id).await;

        assert_eq!(event.peer_id, peer_id);
        assert_eq!(event.remote_addr, server.bound_addr);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_listener_auth_reject_new_client() {
        let peer_id = "new-cli-rj-peer";
        let correct_token = "correct-token-12";
        let wrong_token = "wrong-token-12ch";
        let peer_tokens = HashMap::from([(peer_id.to_string(), correct_token.to_string())]);

        let server = TestH3Server::start(peer_tokens).await;

        let peer_h3 = test_peer_h3(server.bound_addr, wrong_token);
        let probe = FakeRouteProbe::noop();
        let tuning = insecure_tuning();

        let (ingress_tx, _ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let ctx = DialContext::test(peer_id, tuning, events_tx);

        let result = dial_h3_client(&peer_h3, server.bound_addr, &ctx, &probe, ingress_tx).await;

        assert!(
            matches!(result, Err(DialError::Rejected(_))),
            "expected Rejected, got {result:?}",
        );

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_listener_datagram_c2s_new_client() {
        let peer_id = "new-cli-c2s-peer";
        let token = "new-cli-c2s-tk12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestH3Server::start(peer_tokens).await;
        let (event, _ingress_rx) = dial_new_client(server.bound_addr, token, peer_id).await;

        // Send test packet via new client.
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        let pkt = alloc_packet_buf(&test_packet);
        event.tx.send(vec![pkt]).await.expect("send failed");

        // Verify server received the packet.
        let batch = tokio::time::timeout(Duration::from_secs(5), server.ingress_rx.recv())
            .await
            .expect("timeout waiting for datagram")
            .expect("channel closed");

        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &test_packet[..]);

        drop(server.cmd_tx);
    }

    // ========== Server→Client Tests ==========

    #[tokio::test]
    async fn h3v2_listener_datagram_s2c_old_client() {
        let peer_id = "old-cli-s2c-peer";
        let token = "old-cli-s2c-tk12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestH3Server::start(peer_tokens).await;
        let conn = dial_old_client(server.bound_addr, token, peer_id).await;
        let event = await_h3v2_connection(&mut server.events_rx).await;

        // Set up old client RX actor.
        let (client_rx, _client_tx) = conn.into_actors();
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let (client_ingress_tx, mut client_ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let _rx_handle = spawn_h3_rx(
            client_rx,
            client_ingress_tx,
            events_tx,
            Duration::from_secs(60),
        );

        // Send test packet from server.
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2));
        let pkt = alloc_packet_buf(&test_packet);
        event.tx.send(vec![pkt]).await.expect("send failed");

        // Verify client received the packet.
        let batch = tokio::time::timeout(Duration::from_secs(5), client_ingress_rx.recv())
            .await
            .expect("timeout waiting for datagram")
            .expect("channel closed");

        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &test_packet[..]);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_listener_datagram_s2c_new_client() {
        let peer_id = "new-cli-s2c-peer";
        let token = "new-cli-s2c-tk12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestH3Server::start(peer_tokens).await;
        let (_cli_event, mut ingress_rx) = dial_new_client(server.bound_addr, token, peer_id).await;
        let event = await_h3v2_connection(&mut server.events_rx).await;

        // Verify event fields carry correct connection metadata.
        assert_eq!(event.peer_id, peer_id);
        assert_eq!(event.origin, ConnOrigin::Server);

        // Send test packet from server.
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2));
        let pkt = alloc_packet_buf(&test_packet);
        event.tx.send(vec![pkt]).await.expect("send failed");

        // Verify client received the packet via ingress_rx.
        let batch = tokio::time::timeout(Duration::from_secs(5), ingress_rx.recv())
            .await
            .expect("timeout waiting for datagram")
            .expect("channel closed");

        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &test_packet[..]);

        drop(server.cmd_tx);
    }

    // ========== Bidirectional Tests ==========

    #[tokio::test]
    async fn h3v2_listener_bidirectional_old_client() {
        let peer_id = "old-cli-bi-peer";
        let token = "old-cli-bi-tk-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestH3Server::start(peer_tokens).await;
        let conn = dial_old_client(server.bound_addr, token, peer_id).await;
        let event = await_h3v2_connection(&mut server.events_rx).await;

        let (client_rx, client_tx) = conn.into_actors();
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let (client_send_tx, _tx_handle) = spawn_h3_tx(
            client_tx,
            events_tx.clone(),
            Duration::from_secs(60),
            256,
            Duration::from_secs(20),
        );
        let (client_ingress_tx, mut client_ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let _rx_handle = spawn_h3_rx(
            client_rx,
            client_ingress_tx,
            events_tx,
            Duration::from_secs(60),
        );

        // Client → Server
        let packet_c2s = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        client_send_tx
            .send(vec![alloc_packet_buf(&packet_c2s)])
            .await
            .expect("c2s failed");
        let batch = tokio::time::timeout(Duration::from_secs(5), server.ingress_rx.recv())
            .await
            .expect("timeout c2s")
            .expect("closed");
        assert_eq!(&batch[0][..], &packet_c2s[..]);

        // Server → Client
        let packet_s2c = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2));
        event
            .tx
            .send(vec![alloc_packet_buf(&packet_s2c)])
            .await
            .expect("s2c failed");
        let batch = tokio::time::timeout(Duration::from_secs(5), client_ingress_rx.recv())
            .await
            .expect("timeout s2c")
            .expect("closed");
        assert_eq!(&batch[0][..], &packet_s2c[..]);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_listener_bidirectional_new_client() {
        let peer_id = "new-cli-bi-peer";
        let token = "new-cli-bi-tk-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestH3Server::start(peer_tokens).await;
        let (cli_event, mut ingress_rx) = dial_new_client(server.bound_addr, token, peer_id).await;
        let event = await_h3v2_connection(&mut server.events_rx).await;

        // Client → Server
        let packet_c2s = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        cli_event
            .tx
            .send(vec![alloc_packet_buf(&packet_c2s)])
            .await
            .expect("c2s failed");
        let batch = tokio::time::timeout(Duration::from_secs(5), server.ingress_rx.recv())
            .await
            .expect("timeout c2s")
            .expect("closed");
        assert_eq!(&batch[0][..], &packet_c2s[..]);

        // Server → Client
        let packet_s2c = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2));
        event
            .tx
            .send(vec![alloc_packet_buf(&packet_s2c)])
            .await
            .expect("s2c failed");
        let batch = tokio::time::timeout(Duration::from_secs(5), ingress_rx.recv())
            .await
            .expect("timeout s2c")
            .expect("closed");
        assert_eq!(&batch[0][..], &packet_s2c[..]);

        drop(server.cmd_tx);
    }

    // ========== Lifecycle Tests ==========

    #[tokio::test]
    async fn h3v2_listener_shutdown() {
        let peer_id = "sd-listener-peer";
        let token = "sd-listener-tk12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let server = TestH3Server::start(peer_tokens).await;

        // Verify a client can connect.
        let (event, _ingress_rx) = dial_new_client(server.bound_addr, token, peer_id).await;
        assert_eq!(event.peer_id, peer_id);

        // Drop command sender to trigger listener shutdown.
        let handle = server._handle;
        drop(server.cmd_tx);

        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("listener did not terminate in time")
            .expect("listener task panicked");
        assert!(
            result.is_ok(),
            "listener should shut down gracefully: {:?}",
            result,
        );
    }

    #[tokio::test]
    async fn h3v2_listener_client_shutdown() {
        let peer_id = "sd-client-peer-1";
        let token = "sd-client-tk-1-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestH3Server::start(peer_tokens).await;
        let (cli_event, _ingress_rx) = dial_new_client(server.bound_addr, token, peer_id).await;

        let _event = await_h3v2_connection(&mut server.events_rx).await;

        // Drop the egress sender to trigger client shutdown.
        let H3v2ConnectedEvent { tx, handles, .. } = cli_event;
        drop(tx);
        let mut handles = handles.into_iter();
        let engine_handle = handles.next().unwrap();
        let udp_rx_handle = handles.next().unwrap();
        let udp_tx_handle = handles.next().unwrap();

        // Engine handle should terminate cleanly within a reasonable timeout.
        let engine_result = tokio::time::timeout(Duration::from_secs(5), engine_handle)
            .await
            .expect("engine_handle did not terminate in time")
            .expect("engine task panicked");
        assert!(
            engine_result.is_ok(),
            "engine exited with error: {:?}",
            engine_result,
        );

        // UDP actors may be aborted by the engine or complete on their own.
        let _ = tokio::time::timeout(Duration::from_secs(2), udp_rx_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), udp_tx_handle).await;

        drop(server.cmd_tx);
    }
}
