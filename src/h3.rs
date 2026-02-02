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
//! - `dial_h3`: Establishes outbound CONNECT-IP connections
//! - `spawn_h3_listener`: Accepts inbound CONNECT-IP connections

use crate::actor::{ActorError, ActorExitResult};
use crate::auth::{generate_basic_auth, validate_connect_auth};
use crate::bind::{make_client_udp_socket, RouteProbe};
use crate::events::{Direction, Event, TransportEvent, TransportKind};
use crate::metrics::TransportCounters;
use crate::PACKET_QUEUE_DEPTH;
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_quiche::buf_factory::BufFactory;
use tokio_quiche::http3::driver::{
    ClientH3Driver, ClientH3Event, H3Event, InboundFrame, InboundFrameStream, NewClientRequest,
    OutboundFrame, OutboundFrameSender, ServerH3Driver, ServerH3Event,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::SimpleConnectionIdGenerator;
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::settings::{
    CertificateKind, ConnectionParams, Hooks, QuicSettings, TlsCertificatePaths,
};
use tokio_quiche::{listen, QuicConnection};
use tracing::{debug, error, warn};

/// Context ID for IP payloads per RFC 9484 (always 0 for CONNECT-IP).
const CONTEXT_ID_IP: u8 = 0x00;

// ========== Auth Helpers ==========

/// Extracts and validates the Authorization header from HTTP/3 headers.
///
/// Returns the authenticated peer ID on success, or an error reason on failure.
fn extract_and_validate_auth(
    headers: &[Header],
    secrets: &HashMap<String, String>,
) -> Result<String, &'static str> {
    let auth_header = headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case(b"authorization"))
        .map(|h| String::from_utf8_lossy(h.value()).to_string());

    let peer_iter = secrets.iter().map(|(k, v)| (k.as_str(), v.as_str()));
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

/// Handshake timeout for H3 CONNECT-IP connections.
const H3_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

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
/// after [`H3_HANDSHAKE_TIMEOUT`] to prevent resource exhaustion from stalled clients.
async fn handle_h3_connection(
    mut controller: tokio_quiche::http3::driver::ServerH3Controller,
    quic_conn: QuicConnection,
    remote_addr: SocketAddr,
    secrets: HashMap<String, String>,
    conn_tx: mpsc::UnboundedSender<H3Connection>,
) {
    let handshake = async {
        // State for auth/flow handshake. Each handshake expects exactly one
        // Headers event and one NewFlow event. Duplicates are detected via
        // Option presence and cause immediate connection rejection.
        let mut pending_auth: Option<String> = None;
        let mut pending_flow: Option<(OutboundFrameSender, InboundFrameStream, u64)> = None;
        let mut pending_sender: Option<OutboundFrameSender> = None;
        let mut quic_conn = Some(quic_conn);

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

                    match extract_and_validate_auth(&incoming_headers.headers, &secrets) {
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
                (&pending_auth, &pending_flow, &pending_sender, &quic_conn),
                (Some(_), Some(_), Some(_), Some(_))
            ) {
                let (
                    Some(peer_id),
                    Some((dgram_tx, dgram_rx, flow_id)),
                    Some(mut sender),
                    Some(quic),
                ) = (
                    pending_auth.take(),
                    pending_flow.take(),
                    pending_sender.take(),
                    quic_conn.take(),
                )
                else {
                    error!(%remote_addr, "internal error: handshake state inconsistent");
                    return;
                };
                if send_response_headers(&mut sender, b"200").await.is_err() {
                    warn!(%remote_addr, "failed to send 200 response");
                    return;
                }
                debug!(%peer_id, %remote_addr, "H3 connection established");
                let conn = H3Connection {
                    peer_id,
                    remote_addr,
                    datagram_tx: dgram_tx,
                    datagram_rx: dgram_rx,
                    flow_id,
                    quic_conn: quic,
                };
                if conn_tx.send(conn).is_err() {
                    debug!(%remote_addr, "connection channel closed");
                }
                return;
            }
        }

        // Event stream closed before handshake completed
        if pending_auth.is_some() || pending_flow.is_some() {
            debug!(%remote_addr, "H3 handshake incomplete: connection closed");
        }
    };

    if time::timeout(H3_HANDSHAKE_TIMEOUT, handshake)
        .await
        .is_err()
    {
        warn!(%remote_addr, "H3 handshake timeout");
    }
}

// ========== Datagram Encoding ==========

/// Prepends Context ID (0x00) to a payload for CONNECT-IP datagram encoding.
#[inline]
pub fn encode_datagram(payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(CONTEXT_ID_IP);
    buf.extend_from_slice(payload);
    buf
}

/// Strips Context ID from a received datagram, returning the payload.
///
/// Returns `None` if the datagram is empty or has an unexpected Context ID.
#[inline]
pub fn decode_datagram(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() || data[0] != CONTEXT_ID_IP {
        return None;
    }
    Some(&data[1..])
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
    /// QUIC connection metadata (holds peer_addr, local_addr, etc.).
    #[allow(dead_code)] // May be used for connection management
    pub quic_conn: QuicConnection,
}

// ========== Dial Function ==========

/// Establishes an HTTP/3 CONNECT-IP connection to a peer.
///
/// # Arguments
///
/// * `remote_addr` - Resolved target socket address.
/// * `server_name` - Server hostname for TLS SNI.
/// * `path` - CONNECT-IP request path.
/// * `local_id` - Local node ID (Basic Auth username).
/// * `peer_secret` - Peer's shared secret (Basic Auth password).
/// * `ca_cert_path` - Optional path to CA certificate for server verification.
/// * `bindif` - Optional interface name to bind the socket.
/// * `tun_if` - Optional TUN interface name to exclude from probing.
/// * `probe` - Route probe implementation for interface selection.
/// * `insecure_skip_verify` - Skip TLS certificate verification (for testing only).
///
/// # Errors
///
/// Returns `DialError` if connection establishment fails.
///
/// # Security Warning
///
/// Setting `insecure_skip_verify` to `true` disables TLS certificate verification,
/// making the connection vulnerable to MITM attacks. Only use for testing.
#[allow(clippy::too_many_arguments)]
pub async fn dial_h3<P: RouteProbe>(
    remote_addr: SocketAddr,
    server_name: &str,
    path: &str,
    local_id: &str,
    peer_id: &str,
    peer_secret: &str,
    ca_cert_path: Option<&Path>,
    bindif: Option<&str>,
    tun_if: Option<&str>,
    probe: &P,
    insecure_skip_verify: bool,
) -> Result<H3Connection, DialError> {
    debug!(%remote_addr, %server_name, %local_id, %peer_id, "dialing H3 endpoint");

    // Create connected socket with route probing
    let socket = make_client_udp_socket(remote_addr, tun_if, bindif, probe)
        .await
        .map_err(|e| DialError::Socket(e.to_string()))?;

    // TODO: Implement custom CA certificate support for server verification.
    // Currently using system roots via tokio-quiche defaults.
    if ca_cert_path.is_some() {
        warn!("ca_cert_path is configured but not yet implemented; using system roots");
    }

    // Configure QUIC settings
    let mut quic_settings = QuicSettings::default();
    quic_settings.max_idle_timeout = Some(H3_HANDSHAKE_TIMEOUT);
    // Only disable verification when explicitly requested (testing only)
    if !insecure_skip_verify {
        quic_settings.verify_peer = true;
    }

    let params = ConnectionParams::new_client(quic_settings, None, Hooks::default());

    // Create H3 driver and controller
    let (h3_driver, mut controller) = ClientH3Driver::new(Http3Settings::default());

    // Establish QUIC connection with H3 driver
    let quic_conn = tokio_quiche::quic::connect_with_config(
        socket
            .try_into()
            .map_err(|e: std::io::Error| DialError::Socket(e.to_string()))?,
        Some(server_name),
        &params,
        h3_driver,
    )
    .await
    .map_err(|e| DialError::Handshake(format!("QUIC connect failed: {}", e)))?;

    // Build auth header
    let auth_header = generate_basic_auth(local_id, peer_secret);

    // Build Extended CONNECT request headers per RFC 9484 / protocol.md
    let headers = vec![
        Header::new(b":method", b"CONNECT"),
        Header::new(b":protocol", b"connect-ip"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", server_name.as_bytes()),
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
    let handshake_result = time::timeout(H3_HANDSHAKE_TIMEOUT, async {
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
    .map_err(|_| DialError::Timeout(H3_HANDSHAKE_TIMEOUT))??;

    let (datagram_tx, datagram_rx, flow_id) = handshake_result;

    Ok(H3Connection {
        peer_id: peer_id.to_string(),
        remote_addr,
        datagram_tx,
        datagram_rx,
        flow_id,
        quic_conn,
    })
}

// ========== Receive Loop ==========

/// Spawns the HTTP/3 receive loop for a single connection.
///
/// Receives datagrams from the inbound channel and forwards IP packets
/// (after stripping Context ID 0) to the TUN-Tx queue.
///
/// # Arguments
///
/// * `peer_id` - Peer identifier for logging and metrics.
/// * `datagram_rx` - Inbound datagram receiver (from tokio-quiche).
/// * `packet_tx` - Bounded channel to push received packets into (data plane).
/// * `events_tx` - Unbounded channel for emitting receive metrics.
/// * `interval` - Metrics emission interval.
pub fn spawn_h3_rx(
    peer_id: String,
    mut datagram_rx: InboundFrameStream,
    packet_tx: mpsc::Sender<Vec<u8>>,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> JoinHandle<ActorExitResult> {
    let peer = peer_id.clone();

    tokio::spawn(async move {
        let mut counters = TransportCounters::new(TransportKind::Http3, Direction::Rx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                frame = datagram_rx.recv() => {
                    match frame {
                        Some(inbound_frame) => {
                            match &inbound_frame {
                                InboundFrame::Datagram(pooled_dgram) => {
                                    let data = pooled_dgram.as_ref();
                                    if let Some(payload) = decode_datagram(data) {
                                        let len = payload.len();
                                        if packet_tx.send(payload.to_vec()).await.is_err() {
                                            counters.record_drop(
                                                crate::events::DropReason::ChannelClosed,
                                                len,
                                            );
                                            return Ok(());
                                        }
                                        counters.record_success(len);
                                    } else {
                                        counters.record_drop(
                                            crate::events::DropReason::InvalidFraming,
                                            data.len(),
                                        );
                                    }
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
                        None => {
                            debug!(peer = %peer, "datagram stream closed");
                            return Ok(());
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

/// Spawns the HTTP/3 send loop for a single connection.
///
/// Receives packets from TUN-Rx and sends as datagrams with Context ID 0
/// through the outbound datagram sender.
///
/// # Arguments
///
/// * `peer_id` - Peer identifier for logging and metrics.
/// * `datagram_tx` - Outbound datagram sender (to tokio-quiche).
/// * `flow_id` - DATAGRAM flow ID for this connection.
/// * `events_tx` - Unbounded channel for emitting transmit metrics.
/// * `interval` - Metrics emission interval.
///
/// # Returns
///
/// Returns the packet sender channel and join handle.
pub fn spawn_h3_tx(
    peer_id: String,
    mut datagram_tx: OutboundFrameSender,
    flow_id: u64,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> (mpsc::Sender<Vec<u8>>, JoinHandle<ActorExitResult>) {
    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_DEPTH);
    let peer = peer_id.clone();

    let handle = tokio::spawn(async move {
        let mut counters = TransportCounters::new(TransportKind::Http3, Direction::Tx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                maybe_packet = packet_rx.recv() => {
                    let packet = match maybe_packet {
                        Some(p) => p,
                        None => return Ok(()), // Channel closed, exit gracefully
                    };

                    let len = packet.len();
                    let encoded = encode_datagram(&packet);

                    // Wrap in OutboundFrame::Datagram with flow_id
                    let pooled_dgram = BufFactory::dgram_from_vec(encoded);
                    let frame = OutboundFrame::Datagram(pooled_dgram, flow_id);

                    if datagram_tx.send(frame).await.is_err() {
                        counters.record_drop(crate::events::DropReason::SendError, len);
                        return Err(ActorError::H3TxSend {
                            peer_id: peer.clone(),
                            reason: "datagram channel closed".to_string(),
                        });
                    }
                    counters.record_success(len);
                }
                _ = ticker.tick() => {
                    let metrics = counters.snapshot(Some(&peer), None);
                    if events_tx.send(Event::Transport(TransportEvent::Metrics(metrics))).is_err() {
                        return Ok(());
                    }
                }
            }
        }
    });

    (packet_tx, handle)
}

// ========== Listener ==========

/// Commands accepted by the H3 listener actor.
///
/// Note: No Shutdown command - shutdown via channel close (consistent with other actors).
#[derive(Debug, Clone)]
pub enum H3ListenerCommand {
    /// Update peer secrets for authentication.
    UpdatePeerSecrets(HashMap<String, String>),
}

/// Spawns the H3 listener actor for accepting inbound CONNECT-IP connections.
///
/// Uses direct select loop pattern matching BareUDP: handles commands and
/// accept stream in a single select without intermediate message types.
/// Actor owns peer_secrets directly; updates arrive via UpdatePeerSecrets command.
///
/// # Arguments
///
/// * `listen_addr` - Address to listen on.
/// * `cert_path` - Path to TLS certificate.
/// * `key_path` - Path to TLS private key.
/// * `peer_secrets` - Map of peer ID to expected secret for authentication.
/// * `conn_tx` - Unbounded channel for emitting established connections.
///
/// # Returns
///
/// Returns the actual bound address, the command sender, and join handle.
/// When `listen_addr` uses port 0, the returned address contains the assigned port.
/// Shutdown by dropping cmd_tx (no explicit Shutdown command).
///
/// # Errors
///
/// Returns `ListenerError` if listener setup fails.
pub async fn spawn_h3_listener(
    listen_addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    mut peer_secrets: HashMap<String, String>,
    conn_tx: mpsc::UnboundedSender<H3Connection>,
) -> Result<
    (
        mpsc::UnboundedSender<H3ListenerCommand>,
        JoinHandle<ActorExitResult>,
        SocketAddr,
    ),
    ListenerError,
> {
    // Create command channel (actor owns receiver directly - direct select pattern)
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<H3ListenerCommand>();

    debug!(%listen_addr, "starting H3 listener");

    // Server socket binds directly to listen address (no route probing needed).
    // Use std socket for better compatibility with tokio-quiche.
    let socket =
        std::net::UdpSocket::bind(listen_addr).map_err(|e| ListenerError::Bind(e.to_string()))?;

    // Get actual bound address (may differ from listen_addr if port was 0)
    let bound_addr = socket
        .local_addr()
        .map_err(|e| ListenerError::Bind(format!("failed to get local addr: {}", e)))?;

    // Convert Path to &str for TlsCertificatePaths
    let cert_str = cert_path
        .to_str()
        .ok_or_else(|| ListenerError::Tls("invalid cert path encoding".to_string()))?;
    let key_str = key_path
        .to_str()
        .ok_or_else(|| ListenerError::Tls("invalid key path encoding".to_string()))?;

    // Configure TLS with certificate paths
    let tls_config = TlsCertificatePaths {
        cert: cert_str,
        private_key: key_str,
        kind: CertificateKind::X509,
    };

    // Create connection parameters for server
    let conn_params = ConnectionParams::new_server(
        Default::default(), // QuicSettings with enable_dgram=true by default
        tls_config,
        Default::default(), // Hooks
    );

    // Create tokio-quiche listener
    let mut listeners = listen(
        vec![socket],
        conn_params,
        SimpleConnectionIdGenerator,
        DefaultMetrics,
    )
    .map_err(|e| ListenerError::Bind(format!("listen failed: {}", e)))?;

    let mut accept_stream = listeners.remove(0);

    let handle = tokio::spawn(async move {
        // Actor owns peer_secrets directly (Option 2A: message passing pattern)
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(H3ListenerCommand::UpdatePeerSecrets(update)) => {
                            // Direct assignment - actor owns the state
                            peer_secrets = update;
                            debug!("updated peer secrets");
                        }
                        None => {
                            // Command channel closed - shutdown
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

                            tokio::spawn(handle_h3_connection(
                                controller,
                                quic_conn,
                                remote_addr,
                                peer_secrets.clone(),
                                conn_tx.clone(),
                            ));
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "accept error");
                        }
                        None => {
                            // Accept stream ended
                            return Ok(());
                        }
                    }
                }
            }
        }
    });

    Ok((cmd_tx, handle, bound_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::RouteProbeError;

    // ========== Test Doubles ==========

    /// Test double that returns a fixed probe result.
    /// For H3 loopback tests, use `FakeRouteProbe { result: Ok(vec![]) }`.
    #[derive(Clone)]
    struct FakeRouteProbe {
        result: Result<Vec<String>, RouteProbeError>,
    }

    impl RouteProbe for FakeRouteProbe {
        async fn probe_interfaces(
            &self,
            _target: &str,
            _tun_if: Option<&str>,
        ) -> Result<Vec<String>, RouteProbeError> {
            self.result.clone()
        }
    }

    // ========== Auth Helper Tests ==========

    #[test]
    fn extract_and_validate_auth_accepts_valid() {
        let auth_header = crate::auth::generate_basic_auth("peer1", "secret123");
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b"authorization", auth_header.as_bytes()),
        ];
        let secrets: HashMap<String, String> = [("peer1".to_string(), "secret123".to_string())]
            .into_iter()
            .collect();

        let result = extract_and_validate_auth(&headers, &secrets);
        assert_eq!(result, Ok("peer1".to_string()));
    }

    #[test]
    fn extract_and_validate_auth_rejects_missing() {
        let headers = vec![Header::new(b":method", b"CONNECT")];
        let secrets: HashMap<String, String> = [("peer1".to_string(), "secret123".to_string())]
            .into_iter()
            .collect();

        let result = extract_and_validate_auth(&headers, &secrets);
        assert!(result.is_err());
    }

    #[test]
    fn extract_and_validate_auth_rejects_wrong_secret() {
        let auth_header = crate::auth::generate_basic_auth("peer1", "wrongpass");
        let headers = vec![Header::new(b"authorization", auth_header.as_bytes())];
        let secrets: HashMap<String, String> = [("peer1".to_string(), "secret123".to_string())]
            .into_iter()
            .collect();

        let result = extract_and_validate_auth(&headers, &secrets);
        assert!(result.is_err());
    }

    // ========== Datagram Encoding Tests ==========

    #[test]
    fn encode_prepends_context_id() {
        let payload = b"test payload";
        let encoded = encode_datagram(payload);
        assert_eq!(encoded[0], 0x00);
        assert_eq!(&encoded[1..], payload);
    }

    #[test]
    fn decode_strips_context_id() {
        let data = [0x00, 1, 2, 3, 4];
        let payload = decode_datagram(&data).unwrap();
        assert_eq!(payload, &[1, 2, 3, 4]);
    }

    #[test]
    fn decode_rejects_empty_data() {
        assert!(decode_datagram(&[]).is_none());
    }

    #[test]
    fn decode_rejects_wrong_context_id() {
        let data = [0x01, 1, 2, 3];
        assert!(decode_datagram(&data).is_none());
    }

    #[test]
    fn roundtrip_encode_decode() {
        let original = b"ip packet data";
        let encoded = encode_datagram(original);
        let decoded = decode_datagram(&encoded).unwrap();
        assert_eq!(decoded, original);
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

    // ========== Listener Lifecycle Tests ==========

    #[tokio::test]
    async fn listener_spawns_and_accepts_commands() {
        let certs = TestCertBundle::generate();

        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer_secrets = HashMap::from([("test-peer".to_string(), "test-secret".to_string())]);
        let (conn_tx, _conn_rx) = mpsc::unbounded_channel();

        let (cmd_tx, handle, _bound_addr) = spawn_h3_listener(
            listen_addr,
            certs.cert_path(),
            certs.key_path(),
            peer_secrets,
            conn_tx,
        )
        .await
        .expect("listener spawn");

        // Verify command channel is functional
        assert!(cmd_tx
            .send(H3ListenerCommand::UpdatePeerSecrets(HashMap::new()))
            .is_ok());

        // Clean shutdown
        drop(cmd_tx);
        let result = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "listener should shut down cleanly"
        );
    }

    #[tokio::test]
    async fn listener_rejects_invalid_cert_path() {
        // Use tempdir to generate platform-agnostic missing paths
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let missing_cert = temp_dir.path().join("missing-cert.pem");
        let missing_key = temp_dir.path().join("missing-key.pem");

        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer_secrets = HashMap::new();
        let (conn_tx, _conn_rx) = mpsc::unbounded_channel();

        let result = spawn_h3_listener(
            listen_addr,
            &missing_cert,
            &missing_key,
            peer_secrets,
            conn_tx,
        )
        .await;

        assert!(result.is_err());
    }

    // ========== Client-Server Integration Tests ==========
    //
    // These tests perform real QUIC/H3 handshakes over loopback. They use
    // self-signed certificates with `insecure_skip_verify=true` for testing.

    #[tokio::test]
    async fn handshake_success() {
        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "test-client";
        let secret = "test-secret-123";
        let peer_secrets = HashMap::from([(peer_id.to_string(), secret.to_string())]);

        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();

        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listen_addr,
            certs.cert_path(),
            certs.key_path(),
            peer_secrets,
            conn_tx,
        )
        .await
        .expect("listener spawn");

        // Give listener time to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        let probe = FakeRouteProbe { result: Ok(vec![]) };
        let client_result = dial_h3(
            bound_addr,
            "localhost",
            "/.well-known/masque/udp/*/*/",
            peer_id,
            peer_id,
            secret,
            None,
            None,
            None,
            &probe,
            true, // insecure_skip_verify for testing
        )
        .await;

        assert!(
            client_result.is_ok(),
            "dial_h3 failed: {:?}",
            client_result.err()
        );
        let client_conn = client_result.unwrap();
        assert_eq!(client_conn.peer_id, peer_id);

        // Server should also receive the connection
        let server_conn = tokio::time::timeout(Duration::from_secs(5), conn_rx.recv())
            .await
            .expect("timeout waiting for server connection")
            .expect("server connection channel closed");
        assert_eq!(server_conn.peer_id, peer_id);

        // Clean shutdown
        drop(cmd_tx);
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_secret() {
        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_secrets =
            HashMap::from([("test-client".to_string(), "correct-secret".to_string())]);
        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();

        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listen_addr,
            certs.cert_path(),
            certs.key_path(),
            peer_secrets,
            conn_tx,
        )
        .await
        .expect("listener spawn");

        tokio::time::sleep(Duration::from_millis(50)).await;

        let probe = FakeRouteProbe { result: Ok(vec![]) };
        let result = dial_h3(
            bound_addr,
            "localhost",
            "/.well-known/masque/udp/*/*/",
            "test-client",
            "test-client",
            "wrong-secret",
            None,
            None,
            None,
            &probe,
            true, // insecure_skip_verify for testing
        )
        .await;

        match result {
            Err(DialError::Auth(_)) | Err(DialError::Rejected(401)) => {}
            Err(other) => panic!("expected Auth error, got {:?}", other),
            Ok(_) => panic!("expected dial to fail with wrong secret"),
        }

        // Server should NOT have accepted a connection
        let server_recv = tokio::time::timeout(Duration::from_millis(500), conn_rx.recv()).await;
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
        let peer_secrets = HashMap::from([("known-peer".to_string(), "secret".to_string())]);
        let (conn_tx, _conn_rx) = mpsc::unbounded_channel();

        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listen_addr,
            certs.cert_path(),
            certs.key_path(),
            peer_secrets,
            conn_tx,
        )
        .await
        .expect("listener spawn");

        tokio::time::sleep(Duration::from_millis(50)).await;

        let probe = FakeRouteProbe { result: Ok(vec![]) };
        let result = dial_h3(
            bound_addr,
            "localhost",
            "/.well-known/masque/udp/*/*/",
            "unknown-peer",
            "unknown-peer",
            "any-secret",
            None,
            None,
            None,
            &probe,
            true, // insecure_skip_verify for testing
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
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "datagram-client";
        let secret = "datagram-secret";
        let peer_secrets = HashMap::from([(peer_id.to_string(), secret.to_string())]);

        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();

        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listen_addr,
            certs.cert_path(),
            certs.key_path(),
            peer_secrets,
            conn_tx,
        )
        .await
        .expect("listener spawn");

        tokio::time::sleep(Duration::from_millis(50)).await;

        let probe = FakeRouteProbe { result: Ok(vec![]) };
        let client_conn = dial_h3(
            bound_addr,
            "localhost",
            "/.well-known/masque/udp/*/*/",
            peer_id,
            peer_id,
            secret,
            None,
            None,
            None,
            &probe,
            true, // insecure_skip_verify for testing
        )
        .await
        .expect("dial failed");

        let server_conn = tokio::time::timeout(Duration::from_secs(5), conn_rx.recv())
            .await
            .expect("timeout")
            .expect("no connection");

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let metrics_interval = Duration::from_secs(60);

        // Client TX actor
        let (client_packet_tx, _client_tx_handle) = spawn_h3_tx(
            peer_id.to_string(),
            client_conn.datagram_tx,
            client_conn.flow_id,
            events_tx.clone(),
            metrics_interval,
        );

        // Server RX actor
        let (server_packet_tx, mut server_packet_rx) = mpsc::channel(16);
        let _server_rx_handle = spawn_h3_rx(
            peer_id.to_string(),
            server_conn.datagram_rx,
            server_packet_tx,
            events_tx,
            metrics_interval,
        );

        // Send test packet
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        client_packet_tx
            .send(test_packet.clone())
            .await
            .expect("send failed");

        // Verify receipt
        let received = tokio::time::timeout(Duration::from_secs(5), server_packet_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(received, test_packet);

        drop(cmd_tx);
    }

    #[tokio::test]
    async fn datagram_bidirectional() {
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "bidir-client";
        let secret = "bidir-secret";
        let peer_secrets = HashMap::from([(peer_id.to_string(), secret.to_string())]);

        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();

        let (cmd_tx, _listener_handle, bound_addr) = spawn_h3_listener(
            listen_addr,
            certs.cert_path(),
            certs.key_path(),
            peer_secrets,
            conn_tx,
        )
        .await
        .expect("listener spawn");

        tokio::time::sleep(Duration::from_millis(50)).await;

        let probe = FakeRouteProbe { result: Ok(vec![]) };
        let client_conn = dial_h3(
            bound_addr,
            "localhost",
            "/.well-known/masque/udp/*/*/",
            peer_id,
            peer_id,
            secret,
            None,
            None,
            None,
            &probe,
            true, // insecure_skip_verify for testing
        )
        .await
        .expect("dial failed");

        let server_conn = tokio::time::timeout(Duration::from_secs(5), conn_rx.recv())
            .await
            .expect("timeout")
            .expect("no connection");

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let metrics_interval = Duration::from_secs(60);

        // Client TX -> Server RX
        let (client_send_tx, _) = spawn_h3_tx(
            peer_id.to_string(),
            client_conn.datagram_tx,
            client_conn.flow_id,
            events_tx.clone(),
            metrics_interval,
        );

        let (server_to_client_tx, mut client_packet_rx) = mpsc::channel(16);
        let _client_rx_handle = spawn_h3_rx(
            peer_id.to_string(),
            client_conn.datagram_rx,
            server_to_client_tx,
            events_tx.clone(),
            metrics_interval,
        );

        // Server TX -> Client RX
        let (server_send_tx, _) = spawn_h3_tx(
            "server".to_string(),
            server_conn.datagram_tx,
            server_conn.flow_id,
            events_tx.clone(),
            metrics_interval,
        );

        let (client_to_server_tx, mut server_packet_rx) = mpsc::channel(16);
        let _server_rx_handle = spawn_h3_rx(
            "server".to_string(),
            server_conn.datagram_rx,
            client_to_server_tx,
            events_tx,
            metrics_interval,
        );

        // Test client -> server
        let packet_c2s = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        client_send_tx.send(packet_c2s.clone()).await.unwrap();

        let received_c2s = tokio::time::timeout(Duration::from_secs(5), server_packet_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(received_c2s, packet_c2s);

        // Test server -> client
        let packet_s2c = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2));
        server_send_tx.send(packet_s2c.clone()).await.unwrap();

        let received_s2c = tokio::time::timeout(Duration::from_secs(5), client_packet_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(received_s2c, packet_s2c);

        drop(cmd_tx);
    }

    #[tokio::test]
    async fn connection_graceful_shutdown() {
        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "shutdown-client";
        let secret = "shutdown-secret";
        let peer_secrets = HashMap::from([(peer_id.to_string(), secret.to_string())]);

        let (conn_tx, mut conn_rx) = mpsc::unbounded_channel();

        let (cmd_tx, listener_handle, bound_addr) = spawn_h3_listener(
            listen_addr,
            certs.cert_path(),
            certs.key_path(),
            peer_secrets,
            conn_tx,
        )
        .await
        .expect("listener spawn");

        tokio::time::sleep(Duration::from_millis(50)).await;

        let probe = FakeRouteProbe { result: Ok(vec![]) };
        let _client_conn = dial_h3(
            bound_addr,
            "localhost",
            "/.well-known/masque/udp/*/*/",
            peer_id,
            peer_id,
            secret,
            None,
            None,
            None,
            &probe,
            true, // insecure_skip_verify for testing
        )
        .await
        .expect("dial failed");

        let _server_conn = tokio::time::timeout(Duration::from_secs(5), conn_rx.recv())
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
}
