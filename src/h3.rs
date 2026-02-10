//! HTTP/3 CONNECT-IP transport: connection setup, auth, and datagram send/receive.
//!
//! Implements RFC 9484 CONNECT-IP over HTTP/3 using QUIC DATAGRAM frames.
//! Context ID is always 0 (no dynamic context allocation).
//!
//! # Architecture
//!
//! Follows the same actor pattern as BareUDP:
//! - `spawn_h3_rx`: Receives DATAGRAM frames and forwards to TUN-Tx
//! - `spawn_h3_tx`: Receives packets from TUN-Rx and sends as DATAGRAMs
//! - `dial_h3`: Establishes outbound CONNECT-IP connections (socket + handshake)
//! - `spawn_h3_listener`: Accepts inbound CONNECT-IP connections

use crate::actor::{ActorError, ActorExitResult};
use crate::auth::{generate_bearer_auth, validate_connect_auth};
use crate::bind::{make_client_udp_socket, RouteProbe};
use crate::config::{PeerH3, Tuning};
use crate::events::{
    ConnectionDirection, Direction, Event, H3ConnectedEvent, TransportEvent, TransportKind,
};
use crate::metrics::TransportCounters;
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
#[cfg(test)]
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::buf_factory::PooledBuf;
use tokio_quiche::http3::driver::{
    ClientH3Driver, ClientH3Event, H3Event, InboundFrame, InboundFrameStream, NewClientRequest,
    OutboundFrame, OutboundFrameSender, ServerH3Driver, ServerH3Event,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::listen;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::QuicCommand;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::settings::{
    CertificateKind, ConnectionParams, Hooks, QuicSettings, TlsCertificatePaths,
};
use tracing::{debug, error, warn};

/// Context ID for IP payloads per RFC 9484 (always 0 for CONNECT-IP).
const CONTEXT_ID_IP: u8 = 0x00;

/// Conservative CONNECT-IP encapsulation overhead in bytes per
/// [RFC 9484 Section 7.2](https://datatracker.ietf.org/doc/html/rfc9484#section-7.2).
///
/// 51B base (QUIC v1 worst-case) + 8B optional DATAGRAM Length = 59B.
/// See `docs/protocol.md` § MTU Guidance for the full byte-by-byte breakdown.
/// QUIC `max_send/recv_udp_payload_size` = `TUN_MTU + CONNECT_IP_OVERHEAD`.
const CONNECT_IP_OVERHEAD: usize = 59;

// ========== Auth Helpers ==========

/// Extracts and validates the Authorization header from HTTP/3 headers.
///
/// Returns the authenticated peer ID on success, or an error reason on failure.
fn extract_and_validate_auth(
    headers: &[Header],
    tokens: &HashMap<String, String>,
) -> Result<String, &'static str> {
    let auth_header = headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case(b"authorization"))
        .map(|h| String::from_utf8_lossy(h.value()).to_string());

    let peer_iter = tokens.iter().map(|(k, v)| (k.as_str(), v.as_str()));
    validate_connect_auth(auth_header.as_deref(), peer_iter)
}

/// Validates that headers contain `capsule-protocol: ?1` per RFC 9484.
fn has_capsule_protocol(headers: &[Header]) -> bool {
    headers
        .iter()
        .any(|h| h.name().eq_ignore_ascii_case(b"capsule-protocol") && h.value() == b"?1")
}

/// Sends HTTP/3 response headers via the OutboundFrameSender.
///
/// Per RFC 9297 Section 2.1, the `capsule-protocol` header MUST only be included
/// on 2xx (Successful) responses. Error responses (400, 401, etc.) MUST NOT
/// include this header to avoid protocol fingerprinting.
async fn send_response_headers(
    sender: &mut OutboundFrameSender,
    status: &[u8],
) -> Result<(), &'static str> {
    let headers = if status.len() == 3 && status[0] == b'2' {
        vec![
            Header::new(b":status", status),
            Header::new(b"capsule-protocol", b"?1"),
        ]
    } else {
        vec![Header::new(b":status", status)]
    };
    sender
        .send(OutboundFrame::Headers(headers, None))
        .await
        .map_err(|_| "failed to send response headers")
}

/// Validates CONNECT-IP protocol headers per RFC 9484.
///
/// Checks that the request uses Extended CONNECT with:
/// - `:method` == `CONNECT`
/// - `:protocol` == `connect-ip`
/// - `capsule-protocol` == `?1`
///
/// # Returns
///
/// `Ok(())` if all required headers are present and valid, or an error reason.
fn validate_connect_ip_headers(headers: &[Header]) -> Result<(), &'static str> {
    let method = headers
        .iter()
        .find(|h| h.name() == b":method")
        .map(|h| h.value());
    if method != Some(b"CONNECT") {
        return Err("invalid :method, expected CONNECT");
    }

    let protocol = headers
        .iter()
        .find(|h| h.name() == b":protocol")
        .map(|h| h.value());
    if protocol != Some(b"connect-ip") {
        return Err("invalid :protocol, expected connect-ip");
    }

    let capsule = headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case(b"capsule-protocol"))
        .map(|h| h.value());
    if capsule != Some(b"?1") {
        return Err("invalid capsule-protocol, expected ?1");
    }

    Ok(())
}

/// Handles a single inbound H3 CONNECT-IP connection handshake.
///
/// Waits for exactly one Headers event and one NewFlow event (in either order),
/// then sends 200 OK and emits the established connection. Rejects duplicate
/// Headers or NewFlow events by closing the connection immediately. Times out
/// after `h3_handshake_timeout` to prevent resource exhaustion from stalled clients.
async fn handle_h3_connection(
    mut controller: tokio_quiche::http3::driver::ServerH3Controller,
    remote_addr: SocketAddr,
    tokens: HashMap<String, String>,
    events_tx: mpsc::UnboundedSender<Event>,
    h3_handshake_timeout: Duration,
) {
    let handshake = async {
        // Extract cmd_sender before the handshake loop consumes event_receiver_mut().
        let quic_cmd_tx = controller.cmd_sender();

        // State for auth/flow handshake. Each handshake expects exactly one
        // Headers event and one NewFlow event. Duplicates are detected via
        // Option presence and cause immediate connection rejection.
        let mut pending_auth: Option<String> = None;
        let mut pending_flow: Option<(OutboundFrameSender, InboundFrameStream, u64)> = None;
        let mut pending_sender: Option<OutboundFrameSender> = None;

        while let Some(event) = controller.event_receiver_mut().recv().await {
            match event {
                ServerH3Event::Headers {
                    incoming_headers, ..
                } => {
                    // Reject duplicate Headers event - use Option presence check
                    if pending_auth.is_some() || pending_sender.is_some() {
                        warn!(%remote_addr, "duplicate Headers event, rejecting connection");
                        return;
                    }

                    // Validate CONNECT-IP protocol headers per RFC 9484
                    if let Err(reason) = validate_connect_ip_headers(&incoming_headers.headers) {
                        warn!(%remote_addr, %reason, "CONNECT-IP protocol validation failed");
                        let mut sender = incoming_headers.send;
                        let _ = send_response_headers(&mut sender, b"400").await;
                        return;
                    }

                    match extract_and_validate_auth(&incoming_headers.headers, &tokens) {
                        Ok(peer_id) => {
                            pending_auth = Some(peer_id);
                            pending_sender = Some(incoming_headers.send);
                        }
                        Err(reason) => {
                            warn!(%remote_addr, %reason, "CONNECT-IP auth rejected");
                            let mut sender = incoming_headers.send;
                            let _ = send_response_headers(&mut sender, b"401").await;
                            return;
                        }
                    }
                }
                ServerH3Event::Core(H3Event::NewFlow {
                    flow_id,
                    send,
                    recv,
                }) => {
                    // Reject duplicate NewFlow event - use Option presence check
                    if pending_flow.is_some() {
                        warn!(%remote_addr, "duplicate NewFlow event, rejecting connection");
                        return;
                    }

                    pending_flow = Some((send, recv, flow_id));
                }
                ServerH3Event::Core(H3Event::ConnectionShutdown(_)) => return,
                ServerH3Event::Core(H3Event::ConnectionError(e)) => {
                    warn!(%remote_addr, error = ?e, "H3 connection error");
                    return;
                }
                other => {
                    debug!(
                        %remote_addr,
                        event = ?other,
                        "ignoring unhandled H3 server event during handshake"
                    );
                    continue;
                }
            }

            // Check if all pieces ready to establish connection.
            // Must check references first, because take() in pattern matching
            // would consume values even if the whole pattern doesn't match.
            if matches!(
                (&pending_auth, &pending_flow, &pending_sender),
                (Some(_), Some(_), Some(_))
            ) {
                let (Some(peer_id), Some((dgram_tx, dgram_rx, flow_id)), Some(mut sender)) = (
                    pending_auth.take(),
                    pending_flow.take(),
                    pending_sender.take(),
                ) else {
                    error!(%remote_addr, "internal error: handshake state inconsistent");
                    return;
                };
                if send_response_headers(&mut sender, b"200").await.is_err() {
                    warn!(%remote_addr, "failed to send 200 response");
                    return;
                }
                debug!(%peer_id, %remote_addr, "H3 connection established");

                let cmd_tx = quic_cmd_tx.clone();
                let keepalive_tx: KeepaliveSender = Box::new(move || {
                    cmd_tx
                        .send(QuicCommand::Custom(Box::new(|conn| {
                            conn.send_ack_eliciting().ok();
                        })))
                        .is_ok()
                });

                let conn = H3Connection {
                    peer_id,
                    remote_addr,
                    datagram_tx: dgram_tx,
                    datagram_rx: dgram_rx,
                    flow_id,
                    keepalive_tx,
                };
                let event = Event::Transport(TransportEvent::H3Connected(H3ConnectedEvent {
                    connection: conn,
                    direction: ConnectionDirection::Inbound,
                }));
                if events_tx.send(event).is_err() {
                    debug!(%remote_addr, "events channel closed");
                }
                return;
            }
        }

        // Event stream closed before handshake completed
        if pending_auth.is_some() || pending_flow.is_some() {
            debug!(%remote_addr, "H3 handshake incomplete: connection closed");
        }
    };

    if time::timeout(h3_handshake_timeout, handshake)
        .await
        .is_err()
    {
        warn!(%remote_addr, "H3 handshake timeout");
    }
}

// ========== Error Types ==========

/// Dial error for H3 connection establishment.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// Socket setup failed.
    #[error("socket failed: {0}")]
    Socket(String),
    /// TLS setup failed.
    #[error("tls failed: {0}")]
    Tls(String),
    /// QUIC handshake failed.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// CONNECT-IP request rejected.
    #[error("connect-ip rejected: status {0}")]
    Rejected(u16),
    /// Authentication failed.
    #[error("auth failed: {0}")]
    Auth(String),
    /// Handshake timed out.
    #[error("dial timed out after {0:?}")]
    Timeout(Duration),
}

/// Listener error for H3 server setup.
#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    /// Socket binding failed.
    #[error("bind failed: {0}")]
    Bind(String),
    /// TLS setup failed.
    #[error("tls failed: {0}")]
    Tls(String),
}

// ========== Connection Handle ==========

/// Callback that sends a QUIC PING frame. Returns `false` when the channel is closed.
pub type KeepaliveSender = Box<dyn Fn() -> bool + Send + Sync>;

/// Established HTTP/3 CONNECT-IP connection with datagram channels.
///
/// Holds the peer identifier, remote address, and tokio-quiche datagram
/// channels for bidirectional IP packet exchange.
pub struct H3Connection {
    /// Authenticated peer identifier.
    pub peer_id: String,
    /// Remote socket address.
    pub remote_addr: SocketAddr,
    /// Sender for outbound DATAGRAM frames (from tokio-quiche).
    pub datagram_tx: OutboundFrameSender,
    /// Receiver for inbound DATAGRAM frames (from tokio-quiche).
    pub datagram_rx: InboundFrameStream,
    /// DATAGRAM flow ID for this connection.
    pub flow_id: u64,
    /// Sends keepalive PING; returns `false` when the cmd channel is closed.
    pub keepalive_tx: KeepaliveSender,
}

impl std::fmt::Debug for H3Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Connection")
            .field("peer_id", &self.peer_id)
            .field("remote_addr", &self.remote_addr)
            .field("flow_id", &self.flow_id)
            .finish_non_exhaustive()
    }
}

impl H3Connection {
    /// Splits the connection into separate RX and TX actor states.
    ///
    /// Consumes the connection, returning state structs suitable for
    /// `spawn_h3_rx` and `spawn_h3_tx`.
    pub fn into_actors(self) -> (H3Rx, H3Tx) {
        let rx = H3Rx {
            peer_id: self.peer_id.clone(),
            datagram_rx: self.datagram_rx,
        };
        let tx = H3Tx {
            peer_id: self.peer_id,
            datagram_tx: self.datagram_tx,
            flow_id: self.flow_id,
            keepalive_tx: self.keepalive_tx,
        };
        (rx, tx)
    }
}

// ========== Dial Function ==========

/// Establishes an outbound HTTP/3 CONNECT-IP connection to a peer.
///
/// Performs socket creation, route probing, QUIC handshake, and CONNECT-IP
/// protocol negotiation in a single async call. Extracts host/path from
/// `peer_h3.endpoint` internally.
///
/// # Arguments
///
/// * `peer_h3` - Peer HTTP/3 configuration (endpoint, token, ca, insecure, bindif).
/// * `remote_addr` - Resolved target socket address (from DNS resolution).
/// * `peer_id` - Remote peer ID.
/// * `tun_if` - Optional TUN interface name to exclude from route probing.
/// * `tun_mtu` - TUN interface MTU for deriving QUIC payload size.
/// * `probe` - Route probe implementation for interface selection.
///
/// # Errors
///
/// Returns `DialError` if connection establishment fails:
/// - `DialError::Socket` if endpoint is `None` or socket setup fails
/// - `DialError::Handshake` if QUIC/H3 handshake fails
/// - `DialError::Auth` if authentication is rejected
/// - `DialError::Timeout` if handshake times out
pub async fn dial_h3<P: RouteProbe>(
    peer_h3: &PeerH3,
    remote_addr: SocketAddr,
    peer_id: &str,
    tun_if: Option<&str>,
    tun_mtu: u16,
    probe: &P,
    tuning: &Tuning,
) -> Result<H3Connection, DialError> {
    // Extract endpoint fields - return error if None (listen-only peer)
    let endpoint = peer_h3
        .endpoint
        .as_ref()
        .ok_or_else(|| DialError::Socket("peer_h3.endpoint is None".to_string()))?;
    let server_name = peer_h3.sni.as_deref().unwrap_or(&endpoint.host);
    // Per HTTP semantics (RFC 9110 §7.2), :authority must include host:port
    // when the port is not the default for the scheme (443 for https).
    let authority = if endpoint.port == 443 {
        endpoint.host.clone()
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let path = &endpoint.path;

    debug!(%remote_addr, %server_name, %authority, %peer_id, "dialing H3 endpoint");

    // Create UDP socket with route probing
    let socket = make_client_udp_socket(remote_addr, tun_if, peer_h3.bindif.as_deref(), probe)
        .await
        .map_err(|e| DialError::Socket(e.to_string()))?;

    // TODO: Implement custom CA certificate support for server verification.
    // Currently using system roots via tokio-quiche defaults.
    if peer_h3.ca.is_some() {
        warn!("ca_cert_path is configured but not yet implemented; using system roots");
    }

    // Configure QUIC settings
    let quic_udp_payload_size = tun_mtu as usize + CONNECT_IP_OVERHEAD;
    let mut quic_settings = QuicSettings::default();
    quic_settings.max_idle_timeout = Some(tuning.h3_max_idle_timeout);
    // Only disable verification when explicitly requested (testing only)
    if !peer_h3.insecure {
        quic_settings.verify_peer = true;
    }

    quic_settings.max_send_udp_payload_size = quic_udp_payload_size;
    quic_settings.max_recv_udp_payload_size = quic_udp_payload_size;

    let params = ConnectionParams::new_client(quic_settings, None, Hooks::default());

    // Create H3 driver and controller
    let (h3_driver, mut controller) = ClientH3Driver::new(Http3Settings::default());

    // Extract cmd_sender before the handshake loop consumes the controller's
    // event receiver (cmd_sender() borrows &self, handshake takes &mut self).
    let quic_cmd_tx = controller.cmd_sender();

    // Establish QUIC connection with H3 driver
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut socket: tokio_quiche::socket::Socket<_, _> = socket
        .try_into()
        .map_err(|e: std::io::Error| DialError::Socket(e.to_string()))?;
    // Enable GSO/GRO on Linux for better UDP throughput.
    #[cfg(target_os = "linux")]
    socket.apply_max_capabilities();

    let _quic_conn =
        tokio_quiche::quic::connect_with_config(socket, Some(server_name), &params, h3_driver)
            .await
            .map_err(|e| DialError::Handshake(format!("QUIC connect failed: {}", e)))?;

    // Build auth header
    let auth_header = generate_bearer_auth(&peer_h3.token);

    // Build Extended CONNECT request headers per RFC 9484 / protocol.md
    let headers = vec![
        Header::new(b":method", b"CONNECT"),
        Header::new(b":protocol", b"connect-ip"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", authority.as_bytes()),
        Header::new(b":path", path.as_bytes()),
        Header::new(b"capsule-protocol", b"?1"),
        Header::new(b"authorization", auth_header.as_bytes()),
    ];

    // Send CONNECT request
    controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 0,
            headers,
            body_writer: None,
        })
        .map_err(|e| DialError::Handshake(format!("send CONNECT failed: {:?}", e)))?;

    // Wait for response headers and NewFlow event with timeout
    let handshake_result = time::timeout(tuning.h3_handshake_timeout, async {
        let mut datagram_tx: Option<OutboundFrameSender> = None;
        let mut datagram_rx: Option<InboundFrameStream> = None;
        let mut flow_id: Option<u64> = None;
        let mut status_validated = false;

        while let Some(event) = controller.event_receiver_mut().recv().await {
            match event {
                ClientH3Event::Core(H3Event::IncomingHeaders(incoming)) => {
                    // Check status code
                    let status = incoming
                        .headers
                        .iter()
                        .find(|h| h.name() == b":status")
                        .map(|h| h.value());
                    match status {
                        Some(s) if s.len() == 3 && s[0] == b'2' => {
                            // Validate capsule-protocol header per RFC 9484
                            if !has_capsule_protocol(&incoming.headers) {
                                warn!(%remote_addr, "server response missing capsule-protocol: ?1");
                                return Err(DialError::Handshake(
                                    "server response missing capsule-protocol: ?1".to_string(),
                                ));
                            }

                            debug!(%remote_addr, "CONNECT-IP accepted");
                            status_validated = true;
                            // If NewFlow already arrived, we can exit
                            if datagram_tx.is_some() {
                                break;
                            }
                        }
                        Some(b"401") => {
                            return Err(DialError::Auth("unauthorized".to_string()));
                        }
                        Some(code) => {
                            let code_str = String::from_utf8_lossy(code);
                            let code_num: u16 = code_str.parse().unwrap_or(0);
                            return Err(DialError::Rejected(code_num));
                        }
                        None => {
                            return Err(DialError::Handshake("missing status".to_string()));
                        }
                    }
                }
                ClientH3Event::Core(H3Event::NewFlow {
                    flow_id: fid,
                    send,
                    recv,
                }) => {
                    datagram_tx = Some(send);
                    datagram_rx = Some(recv);
                    flow_id = Some(fid);
                    // Only break if status was already validated
                    if status_validated {
                        break;
                    }
                }
                ClientH3Event::Core(H3Event::ConnectionError(e)) => {
                    return Err(DialError::Handshake(format!("H3 error: {:?}", e)));
                }
                ClientH3Event::Core(H3Event::ConnectionShutdown(_)) => {
                    return Err(DialError::Handshake("connection shutdown".to_string()));
                }
                other => {
                    debug!(
                        %remote_addr,
                        event = ?other,
                        "ignoring unhandled H3 client event during handshake"
                    );
                    continue;
                }
            }
        }

        let datagram_tx = datagram_tx
            .ok_or_else(|| DialError::Handshake("no datagram_tx from NewFlow".to_string()))?;
        let datagram_rx = datagram_rx
            .ok_or_else(|| DialError::Handshake("no datagram_rx from NewFlow".to_string()))?;
        let flow_id =
            flow_id.ok_or_else(|| DialError::Handshake("no flow_id from NewFlow".to_string()))?;

        Ok((datagram_tx, datagram_rx, flow_id))
    })
    .await
    .map_err(|_| DialError::Timeout(tuning.h3_handshake_timeout))??;

    let (datagram_tx, datagram_rx, flow_id) = handshake_result;

    let keepalive_tx: KeepaliveSender = Box::new(move || {
        quic_cmd_tx
            .send(QuicCommand::Custom(Box::new(|conn| {
                conn.send_ack_eliciting().ok();
            })))
            .is_ok()
    });

    Ok(H3Connection {
        peer_id: peer_id.to_string(),
        remote_addr,
        datagram_tx,
        datagram_rx,
        flow_id,
        keepalive_tx,
    })
}

// ========== Receive Loop ==========

/// H3 receive actor state.
///
/// Holds the datagram receiver and peer metadata for the receive loop.
#[derive(Debug)]
pub struct H3Rx {
    /// Peer identifier for logging and metrics.
    pub peer_id: String,
    /// Inbound datagram receiver (from tokio-quiche).
    pub datagram_rx: InboundFrameStream,
}

/// Spawns the HTTP/3 receive loop for a single connection.
///
/// Receives datagrams from the inbound channel and forwards IP packets
/// (after stripping Context ID 0) to the TUN-Tx queue.
///
/// # Arguments
///
/// * `rx` - H3 receive state (peer_id and datagram_rx).
/// * `packet_tx` - Bounded channel to push received packets into (data plane).
/// * `events_tx` - Unbounded channel for emitting receive metrics.
/// * `interval` - Metrics emission interval.
pub fn spawn_h3_rx(
    rx: H3Rx,
    packet_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> JoinHandle<ActorExitResult> {
    let H3Rx {
        peer_id,
        mut datagram_rx,
    } = rx;
    let peer = peer_id.clone();

    tokio::spawn(async move {
        let mut counters = TransportCounters::new(TransportKind::Http3, Direction::Rx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                frame = datagram_rx.recv() => {
                    let Some(inbound_frame) = frame else {
                        debug!(peer = %peer, "datagram stream closed");
                        return Ok(());
                    };

                    match inbound_frame {
                        InboundFrame::Datagram(pooled_dgram) => {
                            let mut dgram = pooled_dgram;
                            if dgram.is_empty() || dgram[0] != CONTEXT_ID_IP {
                                counters.record_drop(
                                    crate::events::DropReason::InvalidFraming,
                                    dgram.len(),
                                );
                                continue;
                            }
                            dgram.pop_front(1);
                            let len = dgram.len();
                            // H3 delivers one datagram at a time; wrap in single-element batch
                            if packet_tx.send(vec![dgram]).await.is_err() {
                                counters.record_drop(
                                    crate::events::DropReason::ChannelClosed,
                                    len,
                                );
                                return Ok(());
                            }
                            counters.record_success(len);
                        }
                        InboundFrame::Body(pooled_buf, _fin) => {
                            // Body frames are unexpected for CONNECT-IP per RFC 9484;
                            // IP payloads should arrive as DATAGRAM frames. Drop immediately.
                            warn!(
                                peer = %peer,
                                len = pooled_buf.len(),
                                "received unexpected Body frame on CONNECT-IP stream"
                            );
                            counters.record_drop(
                                crate::events::DropReason::InvalidFraming,
                                pooled_buf.len(),
                            );
                        }
                    }
                }
                _ = ticker.tick() => {
                    let metrics = counters.snapshot(Some(&peer), None);
                    if events_tx.send(Event::Transport(TransportEvent::Metrics(metrics))).is_err() {
                        return Ok(());
                    }
                }
            }
        }
    })
}

// ========== Transmit Loop ==========

/// H3 transmit actor state.
///
/// Holds the datagram sender, flow ID, and keepalive callback for the transmit loop.
pub struct H3Tx {
    /// Peer identifier for logging and metrics.
    pub peer_id: String,
    /// Outbound datagram sender (to tokio-quiche).
    pub datagram_tx: OutboundFrameSender,
    /// DATAGRAM flow ID for this connection.
    pub flow_id: u64,
    /// Sends keepalive PING; returns `false` when the cmd channel is closed.
    pub keepalive_tx: KeepaliveSender,
}

impl std::fmt::Debug for H3Tx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Tx")
            .field("peer_id", &self.peer_id)
            .field("flow_id", &self.flow_id)
            .finish_non_exhaustive()
    }
}

/// Spawns the HTTP/3 send loop for a single connection.
///
/// Receives packets from TUN-Rx and sends as datagrams with Context ID 0
/// through the outbound datagram sender.
///
/// Creates a bounded packet channel internally (actor owns the receiver).
/// Returns the packet sender and join handle.
///
/// # Arguments
///
/// * `tx` - H3 transmit state (peer_id, datagram_tx, flow_id).
/// * `events_tx` - Unbounded channel for emitting transmit metrics.
/// * `interval` - Metrics emission interval.
pub fn spawn_h3_tx(
    tx: H3Tx,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
    packet_queue_depth: usize,
    keepalive_interval: Duration,
) -> (mpsc::Sender<Vec<PooledBuf>>, JoinHandle<ActorExitResult>) {
    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<PooledBuf>>(packet_queue_depth);

    let H3Tx {
        peer_id,
        mut datagram_tx,
        flow_id,
        keepalive_tx,
    } = tx;
    let peer = peer_id.clone();

    let handle = tokio::spawn(async move {
        let mut counters = TransportCounters::new(TransportKind::Http3, Direction::Tx);
        let mut ticker = time::interval(interval);
        let mut keepalive_ticker = time::interval(keepalive_interval);
        keepalive_ticker.tick().await; // Skip first immediate tick

        loop {
            tokio::select! {
                maybe_batch = packet_rx.recv() => {
                    let packets = match maybe_batch {
                        Some(batch) => batch,
                        None => return Ok(()), // Channel closed, exit gracefully
                    };

                    for mut packet in packets {
                        let len = packet.len();
                        // Zero-copy: prepend Context ID using reserved headroom.
                        if !packet.add_prefix(&[CONTEXT_ID_IP]) {
                            counters.record_drop(crate::events::DropReason::NoHeadroom, len);
                            continue;
                        }
                        let frame = OutboundFrame::Datagram(packet, flow_id);

                        if datagram_tx.send(frame).await.is_err() {
                            counters.record_drop(crate::events::DropReason::SendError, len);
                            return Err(ActorError::H3TxSend {
                                peer_id: peer.clone(),
                                reason: "datagram channel closed".to_string(),
                            });
                        }
                        counters.record_success(len);
                    }
                }
                _ = ticker.tick() => {
                    let metrics = counters.snapshot(Some(&peer), None);
                    if events_tx.send(Event::Transport(TransportEvent::Metrics(metrics))).is_err() {
                        return Ok(());
                    }
                }
                _ = keepalive_ticker.tick() => {
                    if !(keepalive_tx)() {
                        debug!(peer = %peer, "keepalive: cmd channel closed");
                        return Ok(());
                    }
                }
            }
        }
    });

    (packet_tx, handle)
}

// ========== Listener ==========

/// State for the HTTP/3 listener actor.
///
/// Created via `make_h3_listener`, spawned via `spawn_h3_listener`.
/// Follows the Actor Initialization Pattern documented in `docs/internals.md`.
pub struct H3Listener {
    /// Bound UDP socket for QUIC.
    socket: std::net::UdpSocket,
    /// Actual bound address (may differ from requested if port was 0).
    bound_addr: SocketAddr,
    /// Path to TLS certificate (owned).
    cert_path: String,
    /// Path to TLS private key (owned).
    key_path: String,
}

/// Commands accepted by the H3 listener actor.
///
/// Note: No Shutdown command - shutdown via channel close (consistent with other actors).
#[derive(Debug, Clone)]
pub enum H3ListenerCommand {
    /// Update peer tokens for authentication.
    UpdatePeerTokens(HashMap<String, String>),
}

/// Creates H3 listener state from configuration.
///
/// Performs all fallible I/O: socket binding, path validation.
/// Does NOT spawn any tasks.
///
/// # Arguments
///
/// * `listen_addr` - Address to listen on.
/// * `cert_path` - Path to TLS certificate.
/// * `key_path` - Path to TLS private key.
///
/// # Errors
///
/// Returns `ListenerError` if socket binding fails or paths are invalid.
pub fn make_h3_listener(
    listen_addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
) -> Result<H3Listener, ListenerError> {
    // Bind socket
    let socket =
        std::net::UdpSocket::bind(listen_addr).map_err(|e| ListenerError::Bind(e.to_string()))?;

    let bound_addr = socket
        .local_addr()
        .map_err(|e| ListenerError::Bind(format!("failed to get local addr: {}", e)))?;

    // Validate and convert paths to owned strings
    let cert_str = cert_path
        .to_str()
        .ok_or_else(|| ListenerError::Tls("invalid cert path encoding".to_string()))?
        .to_string();
    let key_str = key_path
        .to_str()
        .ok_or_else(|| ListenerError::Tls("invalid key path encoding".to_string()))?
        .to_string();

    debug!(%listen_addr, %bound_addr, "H3 listener state created");

    Ok(H3Listener {
        socket,
        bound_addr,
        cert_path: cert_str,
        key_path: key_str,
    })
}

/// Spawns the H3 listener actor from prepared state.
///
/// Creates command channel internally (actor owns receiver).
/// Returns command sender, join handle, and bound address.
///
/// # Arguments
///
/// * `listener` - H3 listener state from `make_h3_listener`.
/// * `peer_tokens` - Map of peer ID to expected token for authentication.
/// * `tun_mtu` - TUN interface MTU for deriving QUIC payload size.
/// * `events_tx` - Unbounded channel for emitting events to orchestrator.
pub fn spawn_h3_listener(
    listener: H3Listener,
    mut peer_tokens: HashMap<String, String>,
    tun_mtu: u16,
    events_tx: mpsc::UnboundedSender<Event>,
    tuning: &Tuning,
) -> (
    mpsc::UnboundedSender<H3ListenerCommand>,
    JoinHandle<ActorExitResult>,
    SocketAddr,
) {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<H3ListenerCommand>();

    let H3Listener {
        socket,
        bound_addr,
        cert_path,
        key_path,
    } = listener;

    debug!(%bound_addr, "spawning H3 listener actor");

    // Configure TLS with certificate paths
    let tls_config = TlsCertificatePaths {
        cert: &cert_path,
        private_key: &key_path,
        kind: CertificateKind::X509,
    };

    let quic_udp_payload_size = tun_mtu as usize + CONNECT_IP_OVERHEAD;
    let mut quic_settings = QuicSettings::default();
    quic_settings.max_idle_timeout = Some(tuning.h3_max_idle_timeout);
    quic_settings.max_send_udp_payload_size = quic_udp_payload_size;
    quic_settings.max_recv_udp_payload_size = quic_udp_payload_size;

    let conn_params = ConnectionParams::new_server(quic_settings, tls_config, Default::default());

    // Create tokio-quiche listener (infallible after socket is bound)
    let mut listeners = listen(
        vec![socket],
        conn_params,
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )
    .expect("listen on already-bound socket should not fail");

    let mut accept_stream = listeners.remove(0);
    let h3_handshake_timeout = tuning.h3_handshake_timeout;

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(H3ListenerCommand::UpdatePeerTokens(update)) => {
                            peer_tokens = update;
                            debug!("updated peer tokens");
                        }
                        None => {
                            return Ok(());
                        }
                    }
                }
                conn_result = accept_stream.next() => {
                    match conn_result {
                        Some(Ok(initial_conn)) => {
                            let (driver, controller) =
                                ServerH3Driver::new(Http3Settings::default());
                            let quic_conn = initial_conn.start(driver);
                            let remote_addr = quic_conn.peer_addr();
                            drop(quic_conn);

                            tokio::spawn(handle_h3_connection(
                                controller,
                                remote_addr,
                                peer_tokens.clone(),
                                events_tx.clone(),
                                h3_handshake_timeout,
                            ));
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "accept error");
                        }
                        None => {
                            return Ok(());
                        }
                    }
                }
            }
        }
    });

    (cmd_tx, handle, bound_addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::test_support::FakeRouteProbe;

    // ========== Auth Helper Tests ==========

    #[test]
    fn extract_and_validate_auth_accepts_valid() {
        let auth_header = crate::auth::generate_bearer_auth("token-for-peer1");
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b"authorization", auth_header.as_bytes()),
        ];
        let tokens: HashMap<String, String> =
            [("peer1".to_string(), "token-for-peer1".to_string())]
                .into_iter()
                .collect();

        let result = extract_and_validate_auth(&headers, &tokens);
        assert_eq!(result, Ok("peer1".to_string()));
    }

    #[test]
    fn extract_and_validate_auth_rejects_missing() {
        let headers = vec![Header::new(b":method", b"CONNECT")];
        let tokens: HashMap<String, String> =
            [("peer1".to_string(), "token-for-peer1".to_string())]
                .into_iter()
                .collect();

        let result = extract_and_validate_auth(&headers, &tokens);
        assert!(result.is_err());
    }

    #[test]
    fn extract_and_validate_auth_rejects_wrong_token() {
        let auth_header = crate::auth::generate_bearer_auth("wrong-token");
        let headers = vec![Header::new(b"authorization", auth_header.as_bytes())];
        let tokens: HashMap<String, String> = [("peer1".to_string(), "correct-token".to_string())]
            .into_iter()
            .collect();

        let result = extract_and_validate_auth(&headers, &tokens);
        assert!(result.is_err());
    }

    // ========== PooledBuf Datagram Encoding Tests ==========

    #[test]
    fn pooled_buf_headroom_encode_prepends_context_id() {
        use crate::tun::alloc_packet_buf;

        let payload = b"test payload";
        let mut buf = alloc_packet_buf(payload);
        assert_eq!(&buf[..], payload);

        // Encode: prepend Context ID using headroom
        assert!(buf.add_prefix(&[CONTEXT_ID_IP]));
        assert_eq!(buf[0], 0x00);
        assert_eq!(&buf[1..], payload);
    }

    #[test]
    fn pooled_buf_decode_strips_context_id() {
        let data = [0x00, 1, 2, 3, 4];
        let mut dgram = BufFactory::dgram_from_vec(data.to_vec());
        assert!(!dgram.is_empty() && dgram[0] == CONTEXT_ID_IP);
        dgram.pop_front(1);
        assert_eq!(&dgram[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn pooled_buf_decode_rejects_empty() {
        let dgram = BufFactory::dgram_from_vec(vec![]);
        assert!(dgram.is_empty());
    }

    #[test]
    fn pooled_buf_decode_rejects_wrong_context_id() {
        let dgram = BufFactory::dgram_from_vec(vec![0x01, 1, 2, 3]);
        assert!(dgram[0] != CONTEXT_ID_IP);
    }

    #[test]
    fn pooled_buf_roundtrip_encode_decode() {
        use crate::tun::alloc_packet_buf;

        let original = b"ip packet data";
        let mut buf = alloc_packet_buf(original);

        // Encode: prepend Context ID
        assert!(buf.add_prefix(&[CONTEXT_ID_IP]));

        // Decode: strip Context ID
        assert_eq!(buf[0], CONTEXT_ID_IP);
        buf.pop_front(1);
        assert_eq!(&buf[..], original);
    }

    // ========== CONNECT-IP Header Validation Tests ==========

    #[test]
    fn validate_connect_ip_headers_accepts_valid() {
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"connect-ip"),
            Header::new(b"capsule-protocol", b"?1"),
        ];
        assert!(validate_connect_ip_headers(&headers).is_ok());
    }

    #[test]
    fn validate_connect_ip_headers_rejects_wrong_method() {
        let headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":protocol", b"connect-ip"),
            Header::new(b"capsule-protocol", b"?1"),
        ];
        assert_eq!(
            validate_connect_ip_headers(&headers),
            Err("invalid :method, expected CONNECT")
        );
    }

    #[test]
    fn validate_connect_ip_headers_rejects_missing_protocol() {
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b"capsule-protocol", b"?1"),
        ];
        assert_eq!(
            validate_connect_ip_headers(&headers),
            Err("invalid :protocol, expected connect-ip")
        );
    }

    #[test]
    fn validate_connect_ip_headers_rejects_wrong_capsule() {
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"connect-ip"),
            Header::new(b"capsule-protocol", b"?0"),
        ];
        assert_eq!(
            validate_connect_ip_headers(&headers),
            Err("invalid capsule-protocol, expected ?1")
        );
    }

    #[test]
    fn validate_connect_ip_headers_case_insensitive_capsule() {
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"connect-ip"),
            Header::new(b"Capsule-Protocol", b"?1"),
        ];
        assert!(validate_connect_ip_headers(&headers).is_ok());
    }

    // ========== DialError Display Tests ==========

    #[test]
    fn dial_error_displays_correctly() {
        let err = DialError::Handshake("timeout".to_string());
        assert!(err.to_string().contains("handshake"));
        assert!(err.to_string().contains("timeout"));

        let err = DialError::Rejected(401);
        assert!(err.to_string().contains("401"));

        let err = DialError::Socket("address in use".to_string());
        assert!(err.to_string().contains("socket"));
        assert!(err.to_string().contains("address in use"));

        let err = DialError::Timeout(Duration::from_secs(30));
        assert!(err.to_string().contains("timed out"));
        assert!(err.to_string().contains("30"));
    }

    // ========== ListenerError Display Tests ==========

    #[test]
    fn listener_error_displays_correctly() {
        let err = ListenerError::Bind("address in use".to_string());
        assert!(err.to_string().contains("bind"));
        assert!(err.to_string().contains("address in use"));

        let err = ListenerError::Tls("cert expired".to_string());
        assert!(err.to_string().contains("tls"));
        assert!(err.to_string().contains("cert expired"));
    }

    // ========== Test Utilities ==========

    /// Test certificate bundle with temporary files.
    struct TestCertBundle {
        cert_file: tempfile::NamedTempFile,
        key_file: tempfile::NamedTempFile,
    }

    impl TestCertBundle {
        /// Generates a self-signed certificate for localhost using rcgen.
        fn generate() -> Self {
            use rcgen::{generate_simple_self_signed, CertifiedKey};
            use std::io::Write;

            let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
            let CertifiedKey { cert, key_pair } =
                generate_simple_self_signed(subject_alt_names).expect("cert generation");

            let mut cert_file = tempfile::NamedTempFile::new().expect("create cert temp file");
            cert_file
                .write_all(cert.pem().as_bytes())
                .expect("write cert");

            let mut key_file = tempfile::NamedTempFile::new().expect("create key temp file");
            key_file
                .write_all(key_pair.serialize_pem().as_bytes())
                .expect("write key");

            Self {
                cert_file,
                key_file,
            }
        }

        fn cert_path(&self) -> &std::path::Path {
            self.cert_file.path()
        }

        fn key_path(&self) -> &std::path::Path {
            self.key_file.path()
        }
    }

    // ========== Capsule-Protocol Helper Tests ==========

    #[test]
    fn has_capsule_protocol_accepts_valid_header() {
        let headers = vec![
            Header::new(b":status", b"200"),
            Header::new(b"capsule-protocol", b"?1"),
        ];
        assert!(has_capsule_protocol(&headers));
    }

    #[test]
    fn has_capsule_protocol_rejects_missing_header() {
        let headers = vec![Header::new(b":status", b"200")];
        assert!(!has_capsule_protocol(&headers));
    }

    #[test]
    fn has_capsule_protocol_rejects_wrong_value() {
        let headers = vec![
            Header::new(b":status", b"200"),
            Header::new(b"capsule-protocol", b"?0"),
        ];
        assert!(!has_capsule_protocol(&headers));
    }

    #[test]
    fn has_capsule_protocol_case_insensitive() {
        let headers = vec![
            Header::new(b":status", b"200"),
            Header::new(b"Capsule-Protocol", b"?1"),
        ];
        assert!(has_capsule_protocol(&headers));
    }

    // ========== dial_h3 Error Tests ==========

    #[tokio::test]
    async fn dial_h3_rejects_missing_endpoint() {
        use crate::config::PeerH3;

        let peer_h3 = PeerH3 {
            endpoint: None,
            token: "test-token-12ch".to_string(),
            ca: None,
            insecure: true,
            bindif: None,
            sni: None,
        };
        let probe = FakeRouteProbe::noop();

        let result = dial_h3(
            &peer_h3,
            "127.0.0.1:443".parse().unwrap(),
            "peer_id",
            None,
            crate::config::default_mtu(),
            &probe,
            &Tuning::default(),
        )
        .await;

        assert!(matches!(result, Err(DialError::Socket(_))));
    }

    // ========== make_h3_listener Tests ==========

    #[test]
    fn make_h3_listener_binds_socket() {
        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let result = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path());

        assert!(result.is_ok());
        let listener = result.unwrap();
        assert_ne!(listener.bound_addr.port(), 0, "should bind to actual port");
    }

    #[tokio::test]
    async fn spawn_h3_listener_from_state_graceful_shutdown() {
        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path())
            .expect("make_h3_listener");

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let (cmd_tx, handle, bound_addr) = spawn_h3_listener(
            listener,
            HashMap::new(),
            crate::config::default_mtu(),
            events_tx,
            &Tuning::default(),
        );

        // Verify bound address is valid
        assert_ne!(bound_addr.port(), 0);

        // Drop command sender to trigger shutdown
        drop(cmd_tx);

        let result = tokio::time::timeout(Duration::from_millis(500), handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "listener should shutdown gracefully"
        );
    }

    // ========== Listener Lifecycle Tests ==========

    #[tokio::test]
    async fn listener_spawns_and_accepts_commands() {
        let certs = TestCertBundle::generate();

        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer_tokens = HashMap::from([("test-peer".to_string(), "test-token-12ch".to_string())]);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path())
            .expect("make_h3_listener");
        let (cmd_tx, handle, _bound_addr) = spawn_h3_listener(
            listener,
            peer_tokens,
            crate::config::default_mtu(),
            events_tx,
            &Tuning::default(),
        );

        // Verify command channel is functional
        assert!(cmd_tx
            .send(H3ListenerCommand::UpdatePeerTokens(HashMap::new()))
            .is_ok());

        // Clean shutdown
        drop(cmd_tx);
        let result = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "listener should shut down cleanly"
        );
    }

    // ========== Test Helper: build PeerH3 for dial tests ==========

    /// Creates a test `PeerH3` for integration tests with insecure TLS.
    fn test_peer_h3(bound_addr: SocketAddr, token: &str) -> crate::config::PeerH3 {
        use crate::config::{H3Endpoint, PeerH3};
        PeerH3 {
            endpoint: Some(H3Endpoint {
                host: "localhost".to_string(),
                port: bound_addr.port(),
                path: "/.well-known/masque/udp/*/*/".to_string(),
            }),
            token: token.to_string(),
            ca: None,
            insecure: true,
            bindif: None,
            sni: None,
        }
    }

    // ========== Client-Server Integration Tests ==========
    //
    // These tests perform real QUIC/H3 handshakes over loopback. They use
    // self-signed certificates with `insecure=true` for testing.

    #[tokio::test]
    async fn handshake_success() {
        use crate::events::{ConnectionDirection, Event, TransportEvent};

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "test-client";
        let token = "test-token-12chars";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path())
            .expect("make_h3_listener");
        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listener,
            peer_tokens,
            crate::config::default_mtu(),
            events_tx,
            &Tuning::default(),
        );

        // Give listener time to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        let peer_h3 = test_peer_h3(bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let client_result = dial_h3(
            &peer_h3,
            bound_addr,
            peer_id,
            None,
            crate::config::default_mtu(),
            &probe,
            &Tuning::default(),
        )
        .await;

        assert!(
            client_result.is_ok(),
            "dial_h3 failed: {:?}",
            client_result.err()
        );
        let client_conn = client_result.unwrap();
        assert_eq!(client_conn.peer_id, peer_id);

        // Server should emit an H3Connected event
        let server_event = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Transport(TransportEvent::H3Connected(connected)) = event {
                    return Some(connected);
                }
            }
            None
        })
        .await
        .expect("timeout waiting for server connection")
        .expect("no H3Connected event received");
        assert_eq!(server_event.connection.peer_id, peer_id);
        assert_eq!(server_event.direction, ConnectionDirection::Inbound);

        // Clean shutdown
        drop(cmd_tx);
    }

    #[tokio::test]
    async fn handshake_success_with_sni_override() {
        use crate::events::{ConnectionDirection, Event, TransportEvent};

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "sni-client";
        let token = "sni-test-token-12ch";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path())
            .expect("make_h3_listener");
        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listener,
            peer_tokens,
            crate::config::default_mtu(),
            events_tx,
            &Tuning::default(),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Create PeerH3 with sni override matching the cert SAN ("localhost")
        let mut peer_h3 = test_peer_h3(bound_addr, token);
        peer_h3.sni = Some("localhost".to_string());

        let probe = FakeRouteProbe::noop();
        let client_result = dial_h3(
            &peer_h3,
            bound_addr,
            peer_id,
            None,
            crate::config::default_mtu(),
            &probe,
            &Tuning::default(),
        )
        .await;

        assert!(
            client_result.is_ok(),
            "dial_h3 with SNI override failed: {:?}",
            client_result.err()
        );
        let client_conn = client_result.unwrap();
        assert_eq!(client_conn.peer_id, peer_id);

        // Server should emit an H3Connected event
        let server_event = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Transport(TransportEvent::H3Connected(connected)) = event {
                    return Some(connected);
                }
            }
            None
        })
        .await
        .expect("timeout waiting for server connection")
        .expect("no H3Connected event received");
        assert_eq!(server_event.connection.peer_id, peer_id);
        assert_eq!(server_event.direction, ConnectionDirection::Inbound);

        drop(cmd_tx);
    }

    // ========== H3Connection::into_actors Tests ==========

    #[tokio::test]
    async fn h3_connection_into_actors_preserves_peer_id() {
        use crate::events::{Event, TransportEvent};

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "split-test-peer";
        let token = "split-test-token12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path())
            .expect("make listener");
        let (cmd_tx, _handle, bound_addr) = spawn_h3_listener(
            listener,
            peer_tokens,
            crate::config::default_mtu(),
            events_tx,
            &Tuning::default(),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        let peer_h3 = test_peer_h3(bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let _client_conn = dial_h3(
            &peer_h3,
            bound_addr,
            peer_id,
            None,
            crate::config::default_mtu(),
            &probe,
            &Tuning::default(),
        )
        .await
        .expect("dial");

        let server_event = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Transport(TransportEvent::H3Connected(connected)) = event {
                    return Some(connected);
                }
            }
            None
        })
        .await
        .expect("timeout")
        .expect("no conn");

        let (rx, tx) = server_event.connection.into_actors();
        assert_eq!(rx.peer_id, peer_id);
        assert_eq!(tx.peer_id, peer_id);

        drop(cmd_tx);
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_secret() {
        use crate::events::{Event, TransportEvent};

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_tokens =
            HashMap::from([("test-client".to_string(), "correct-token-12".to_string())]);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path())
            .expect("make_h3_listener");
        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listener,
            peer_tokens,
            crate::config::default_mtu(),
            events_tx,
            &Tuning::default(),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        // PeerH3 with intentionally wrong token
        let peer_h3 = test_peer_h3(bound_addr, "wrong-token-12ch");
        let probe = FakeRouteProbe::noop();
        let result = dial_h3(
            &peer_h3,
            bound_addr,
            "test-client",
            None,
            crate::config::default_mtu(),
            &probe,
            &Tuning::default(),
        )
        .await;

        match result {
            Err(DialError::Auth(_)) | Err(DialError::Rejected(401)) => {}
            Err(other) => panic!("expected Auth error, got {:?}", other),
            Ok(_) => panic!("expected dial to fail with wrong secret"),
        }

        // Server should NOT have emitted an H3Connected event
        let server_recv = tokio::time::timeout(Duration::from_millis(500), async {
            while let Some(event) = events_rx.recv().await {
                if matches!(event, Event::Transport(TransportEvent::H3Connected(_))) {
                    return Some(());
                }
            }
            None
        })
        .await;
        assert!(
            server_recv.is_err() || server_recv.unwrap().is_none(),
            "server should not accept connection with wrong secret"
        );

        drop(cmd_tx);
    }

    #[tokio::test]
    async fn handshake_rejects_unknown_peer() {
        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Server only knows "known-peer"
        let peer_tokens =
            HashMap::from([("known-peer".to_string(), "token-12chars-x".to_string())]);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path())
            .expect("make_h3_listener");
        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listener,
            peer_tokens,
            crate::config::default_mtu(),
            events_tx,
            &Tuning::default(),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        let peer_h3 = test_peer_h3(bound_addr, "any-token-12chr");
        let probe = FakeRouteProbe::noop();
        let result = dial_h3(
            &peer_h3,
            bound_addr,
            "unknown-peer",
            None,
            crate::config::default_mtu(),
            &probe,
            &Tuning::default(),
        )
        .await;

        assert!(matches!(
            result,
            Err(DialError::Auth(_) | DialError::Rejected(401))
        ));

        drop(cmd_tx);
    }

    #[tokio::test]
    async fn datagram_roundtrip() {
        use crate::events::{Event, TransportEvent};
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "datagram-client";
        let token = "datagram-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (listener_events_tx, mut listener_events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path())
            .expect("make_h3_listener");
        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listener,
            peer_tokens,
            crate::config::default_mtu(),
            listener_events_tx,
            &Tuning::default(),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        let peer_h3 = test_peer_h3(bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let client_conn = dial_h3(
            &peer_h3,
            bound_addr,
            peer_id,
            None,
            crate::config::default_mtu(),
            &probe,
            &Tuning::default(),
        )
        .await
        .expect("dial failed");

        let server_event = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = listener_events_rx.recv().await {
                if let Event::Transport(TransportEvent::H3Connected(connected)) = event {
                    return Some(connected);
                }
            }
            None
        })
        .await
        .expect("timeout")
        .expect("no connection");

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let metrics_interval = Duration::from_secs(60);

        // Split client connection into RX/TX actors
        let (_client_rx, client_tx) = client_conn.into_actors();

        // Client TX actor
        let (client_packet_tx, _client_tx_handle) = spawn_h3_tx(
            client_tx,
            events_tx.clone(),
            metrics_interval,
            256,
            Duration::from_secs(20),
        );

        // Split server connection for RX
        let (server_rx, _server_tx) = server_event.connection.into_actors();

        // Server RX actor
        let (server_packet_tx, mut server_packet_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let _server_rx_handle =
            spawn_h3_rx(server_rx, server_packet_tx, events_tx, metrics_interval);

        // Send test packet (allocate with headroom for H3 TX encoding)
        use crate::tun::alloc_packet_buf;
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        let pkt = alloc_packet_buf(&test_packet);
        client_packet_tx.send(vec![pkt]).await.expect("send failed");

        // Verify receipt
        let batch = tokio::time::timeout(Duration::from_secs(5), server_packet_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &test_packet[..]);

        drop(cmd_tx);
    }

    #[tokio::test]
    async fn datagram_bidirectional() {
        use crate::events::{Event, TransportEvent};
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "bidir-client";
        let token = "bidir-token-12ch";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (listener_events_tx, mut listener_events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path())
            .expect("make_h3_listener");
        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listener,
            peer_tokens,
            crate::config::default_mtu(),
            listener_events_tx,
            &Tuning::default(),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        let peer_h3 = test_peer_h3(bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let client_conn = dial_h3(
            &peer_h3,
            bound_addr,
            peer_id,
            None,
            crate::config::default_mtu(),
            &probe,
            &Tuning::default(),
        )
        .await
        .expect("dial failed");

        let server_event = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = listener_events_rx.recv().await {
                if let Event::Transport(TransportEvent::H3Connected(connected)) = event {
                    return Some(connected);
                }
            }
            None
        })
        .await
        .expect("timeout")
        .expect("no connection");

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let metrics_interval = Duration::from_secs(60);

        // Split client connection
        let (client_rx, client_tx) = client_conn.into_actors();

        use crate::tun::alloc_packet_buf;

        // Client TX -> Server RX
        let (client_send_tx, _) = spawn_h3_tx(
            client_tx,
            events_tx.clone(),
            metrics_interval,
            256,
            Duration::from_secs(20),
        );

        let (server_to_client_tx, mut client_packet_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let _client_rx_handle = spawn_h3_rx(
            client_rx,
            server_to_client_tx,
            events_tx.clone(),
            metrics_interval,
        );

        // Split server connection
        let (server_rx, server_tx) = server_event.connection.into_actors();

        // Server TX -> Client RX
        let (server_send_tx, _) = spawn_h3_tx(
            server_tx,
            events_tx.clone(),
            metrics_interval,
            256,
            Duration::from_secs(20),
        );

        let (client_to_server_tx, mut server_packet_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let _server_rx_handle =
            spawn_h3_rx(server_rx, client_to_server_tx, events_tx, metrics_interval);

        // Test client -> server
        let packet_c2s = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        client_send_tx
            .send(vec![alloc_packet_buf(&packet_c2s)])
            .await
            .unwrap();

        let batch_c2s = tokio::time::timeout(Duration::from_secs(5), server_packet_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(batch_c2s.len(), 1);
        assert_eq!(&batch_c2s[0][..], &packet_c2s[..]);

        // Test server -> client
        let packet_s2c = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2));
        server_send_tx
            .send(vec![alloc_packet_buf(&packet_s2c)])
            .await
            .unwrap();

        let batch_s2c = tokio::time::timeout(Duration::from_secs(5), client_packet_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(batch_s2c.len(), 1);
        assert_eq!(&batch_s2c[0][..], &packet_s2c[..]);

        drop(cmd_tx);
    }

    #[tokio::test]
    async fn connection_graceful_shutdown() {
        use crate::events::{Event, TransportEvent};

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "shutdown-client";
        let token = "shutdown-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path())
            .expect("make_h3_listener");
        let (cmd_tx, listener_handle, bound_addr) = spawn_h3_listener(
            listener,
            peer_tokens,
            crate::config::default_mtu(),
            events_tx,
            &Tuning::default(),
        );

        tokio::time::sleep(Duration::from_millis(50)).await;

        let peer_h3 = test_peer_h3(bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let _client_conn = dial_h3(
            &peer_h3,
            bound_addr,
            peer_id,
            None,
            crate::config::default_mtu(),
            &probe,
            &Tuning::default(),
        )
        .await
        .expect("dial failed");

        let _server_event = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Transport(TransportEvent::H3Connected(connected)) = event {
                    return Some(connected);
                }
            }
            None
        })
        .await
        .expect("timeout")
        .expect("no connection");

        // Graceful shutdown: drop command channel with active connection
        drop(cmd_tx);

        // Listener should exit cleanly
        let result = tokio::time::timeout(Duration::from_secs(2), listener_handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "listener should shutdown gracefully"
        );
    }

    #[test]
    fn default_mtu_fits_ipv6_ethernet() {
        // Verify: default TUN MTU + CONNECT-IP overhead + IPv6/UDP headers <= 1500
        let default_mtu: usize = crate::config::default_mtu() as usize;
        let total = default_mtu + CONNECT_IP_OVERHEAD + 48;
        assert!(
            total <= 1500,
            "default MTU {total} exceeds 1500-byte Ethernet frame"
        );
    }
}
