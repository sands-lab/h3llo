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
use crate::bind::{make_client_udp_socket, make_server_udp_socket, RouteProbe};
use crate::config::{PeerH3, Tuning};
use crate::events::{ConnectionDirection, Event, H3ConnectedEvent};
use crate::helpers::{send_with_backpressure, SendEvent};
use crate::metrics::{Counters, Direction, Source};
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
use tokio_quiche::listen_with_capabilities;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quic::{ConnectionShutdownBehaviour, QuicCommand};
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::settings::{
    CertificateKind, ConnectionParams, Hooks, QuicSettings, TlsCertificatePaths,
};
use tokio_quiche::socket::QuicListener;
use tracing::{debug, error, info, warn};

/// Builds common `QuicSettings` from `Tuning` and TUN MTU.
///
/// Sets DATAGRAM support, idle timeout, UDP payload sizes (MTU + CONNECT-IP overhead),
/// congestion control algorithm, and pacing. Callers may further customize the
/// returned settings (e.g., `verify_peer` for client connections).
fn make_quic_settings(tuning: &Tuning, tun_mtu: u16) -> QuicSettings {
    let quic_udp_payload_size = tun_mtu as usize + CONNECT_IP_OVERHEAD;
    let mut s = QuicSettings::default();
    s.enable_dgram = true;
    s.handshake_timeout = Some(tuning.h3_handshake_timeout);
    s.max_idle_timeout = Some(tuning.h3_max_idle_timeout);
    s.max_send_udp_payload_size = quic_udp_payload_size;
    s.max_recv_udp_payload_size = quic_udp_payload_size;
    s.cc_algorithm = tuning.h3_cc_algorithm.clone();
    s.enable_pacing = tuning.h3_enable_pacing;
    s
}

/// Context ID for IP payloads per RFC 9484 (always 0 for CONNECT-IP).
pub(crate) const CONTEXT_ID_IP: u8 = 0x00;

/// Maximum packets per H3 RX batch before flush.
const H3_RX_BATCH_SIZE: usize = 128;

/// Conservative CONNECT-IP encapsulation overhead in bytes per
/// [RFC 9484 Section 7.2](https://datatracker.ietf.org/doc/html/rfc9484#section-7.2).
///
/// 51B base (QUIC v1 worst-case) + 8B optional DATAGRAM Length = 59B.
/// See `docs/protocol.md` § MTU Guidance for the full byte-by-byte breakdown.
/// QUIC `max_send/recv_udp_payload_size` = `TUN_MTU + CONNECT_IP_OVERHEAD`.
pub(crate) const CONNECT_IP_OVERHEAD: usize = 59;

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

/// Returns `true` if `status` is a 3-digit ASCII HTTP 2xx code.
fn is_success_status(status: &[u8]) -> bool {
    status.len() == 3 && status[0] == b'2'
}

/// Finds a header by case-insensitive name lookup and returns its value.
///
/// Case-insensitive matching is safe for HTTP/3 pseudo-headers (`:method`, `:protocol`)
/// because they are always lowercase per RFC 9114 Section 4.3.
fn find_header_value<'a>(headers: &'a [Header], name: &[u8]) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case(name))
        .map(|h| h.value())
}

/// Type-erased callback for issuing QUIC control commands.
type QuicCommandSender = Box<dyn Fn(QuicCommand) -> bool + Send + Sync>;

/// Creates a QUIC command sender from a typed driver command channel.
fn make_quic_command_sender<C: From<QuicCommand> + Send + 'static>(
    quic_cmd_tx: tokio_quiche::http3::driver::RequestSender<C, QuicCommand>,
) -> QuicCommandSender {
    Box::new(move |cmd| quic_cmd_tx.send(cmd).is_ok())
}

/// Requests a graceful QUIC connection close via the driver command channel.
fn close_quic_connection<C: From<QuicCommand> + Send + 'static>(
    quic_cmd_tx: &tokio_quiche::http3::driver::RequestSender<C, QuicCommand>,
) {
    let _ = quic_cmd_tx.send(QuicCommand::ConnectionClose(ConnectionShutdownBehaviour {
        send_application_close: false,
        error_code: 0,
        reason: Vec::new(),
    }));
}

/// Sends HTTP/3 response headers via the OutboundFrameSender.
///
/// Per RFC 9297 Section 2.1, the `capsule-protocol` header MUST only be included
/// on 2xx (Successful) responses. Error responses (400, 401, etc.) MUST NOT
/// include this header to avoid protocol fingerprinting.
///
/// This only sends response headers and does not close the request stream.
async fn send_response_headers(
    sender: &mut OutboundFrameSender,
    status: &[u8],
) -> Result<(), &'static str> {
    let headers = if is_success_status(status) {
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

/// Sends a non-2xx response and closes the request stream with FIN.
///
/// Uses Trailers to end the stream explicitly without forcing connection close.
async fn send_error_response_and_finish_stream(
    sender: &mut OutboundFrameSender,
    status: &[u8],
) -> Result<(), &'static str> {
    if is_success_status(status) {
        return Err("status must be non-2xx for error response");
    }
    send_response_headers(sender, status).await?;
    sender
        .send(OutboundFrame::Trailers(Vec::new(), None))
        .await
        .map_err(|_| "failed to finish error response stream")
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
    if find_header_value(headers, b":method") != Some(b"CONNECT") {
        return Err("invalid :method, expected CONNECT");
    }
    if find_header_value(headers, b":protocol") != Some(b"connect-ip") {
        return Err("invalid :protocol, expected connect-ip");
    }
    if find_header_value(headers, b"capsule-protocol") != Some(b"?1") {
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
    // Extract cmd_sender before the handshake loop consumes event_receiver_mut().
    let quic_cmd_tx = controller.cmd_sender();

    let handshake = async {
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
                        close_quic_connection(&quic_cmd_tx);
                        return;
                    }

                    // Validate CONNECT-IP protocol headers per RFC 9484
                    if let Err(reason) = validate_connect_ip_headers(&incoming_headers.headers) {
                        warn!(%remote_addr, %reason, "CONNECT-IP protocol validation failed");
                        let mut sender = incoming_headers.send;
                        if let Err(send_err) =
                            send_error_response_and_finish_stream(&mut sender, b"400").await
                        {
                            warn!(
                                %remote_addr,
                                %send_err,
                                "failed to send/finish 400 response stream"
                            );
                            close_quic_connection(&quic_cmd_tx);
                        }
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
                            if let Err(send_err) =
                                send_error_response_and_finish_stream(&mut sender, b"401").await
                            {
                                warn!(
                                    %remote_addr,
                                    %send_err,
                                    "failed to send/finish 401 response stream"
                                );
                                close_quic_connection(&quic_cmd_tx);
                            }
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
                        close_quic_connection(&quic_cmd_tx);
                        return;
                    }

                    pending_flow = Some((send, recv, flow_id));
                }
                ServerH3Event::Core(H3Event::ConnectionShutdown(_)) => return,
                ServerH3Event::Core(H3Event::ConnectionError(e)) => {
                    let peer = pending_auth.as_deref().unwrap_or("unknown");
                    warn!(%remote_addr, peer, error = ?e, "H3 connection error during handshake");
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
                    close_quic_connection(&quic_cmd_tx);
                    return;
                };
                if send_response_headers(&mut sender, b"200").await.is_err() {
                    warn!(%remote_addr, "failed to send 200 response");
                    close_quic_connection(&quic_cmd_tx);
                    return;
                }
                info!(%peer_id, %remote_addr, "H3 inbound connection established");

                let quic_cmd_send = make_quic_command_sender(quic_cmd_tx.clone());

                let conn = H3Connection {
                    peer_id,
                    remote_addr,
                    datagram_tx: dgram_tx,
                    datagram_rx: dgram_rx,
                    flow_id,
                    quic_cmd_send,
                };
                let event = Event::H3Connected(H3ConnectedEvent {
                    connection: conn,
                    direction: ConnectionDirection::Inbound,
                });
                if events_tx.send(event).is_err() {
                    debug!(%remote_addr, "events channel closed");
                    close_quic_connection(&quic_cmd_tx);
                }
                return;
            }
        }

        // Event stream closed before handshake completed
        if pending_auth.is_some() || pending_flow.is_some() {
            warn!(%remote_addr, "H3 handshake incomplete: connection closed before completion");
            close_quic_connection(&quic_cmd_tx);
        }
    };

    if time::timeout(h3_handshake_timeout, handshake)
        .await
        .is_err()
    {
        warn!(%remote_addr, "H3 handshake timeout");
        close_quic_connection(&quic_cmd_tx);
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
    /// QUIC command sender used for keepalive and explicit close.
    pub quic_cmd_send: QuicCommandSender,
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
            remote_addr: self.remote_addr,
            datagram_rx: self.datagram_rx,
        };
        let tx = H3Tx {
            peer_id: self.peer_id,
            remote_addr: self.remote_addr,
            datagram_tx: self.datagram_tx,
            flow_id: self.flow_id,
            quic_cmd_send: self.quic_cmd_send,
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
/// * `peer_h3` - Peer HTTP/3 configuration (endpoint, token, bindif).
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
    let socket = make_client_udp_socket(
        remote_addr,
        tun_if,
        peer_h3.bindif.as_deref(),
        probe,
        tuning.socket_buffer_bytes(),
    )
    .await
    .map_err(|e| DialError::Socket(e.to_string()))?;

    // Configure QUIC settings
    let mut quic_settings = make_quic_settings(tuning, tun_mtu);
    // Only disable verification when explicitly requested (testing only)
    if !tuning.h3_insecure_skip_verify {
        quic_settings.verify_peer = true;
    }

    let params = ConnectionParams::new_client(quic_settings, None, Hooks::default());

    // Create H3 driver and controller
    let h3_settings = Http3Settings {
        enable_extended_connect: true,
        ..Default::default()
    };
    let (h3_driver, mut controller) = ClientH3Driver::new(h3_settings);

    // Extract cmd_sender before the handshake loop consumes the controller's
    // event receiver (cmd_sender() borrows &self, handshake takes &mut self).
    let quic_cmd_tx = controller.cmd_sender();

    // Establish QUIC connection with H3 driver
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut socket: tokio_quiche::socket::Socket<_, _> = socket
        .try_into()
        .map_err(|e: std::io::Error| DialError::Socket(e.to_string()))?;
    // Enable GSO/GRO on Linux for better UDP throughput when configured.
    #[cfg(target_os = "linux")]
    if tuning.udp_enable_offload {
        socket.apply_max_capabilities();
    }

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
    if let Err(e) = controller.request_sender().send(NewClientRequest {
        request_id: 0,
        headers,
        body_writer: None,
    }) {
        close_quic_connection(&quic_cmd_tx);
        return Err(DialError::Handshake(format!(
            "send CONNECT failed: {:?}",
            e
        )));
    }

    // Wait for response headers and NewFlow event with timeout
    let handshake_result = match time::timeout(tuning.h3_handshake_timeout, async {
        // These three fields are kept as separate Options (rather than a single
        // Option<(_, _, _)>) because the NewFlow delivery may not be atomic —
        // per-field errors aid debugging when a partial state is observed.
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
                    let Some(s) = status else {
                        return Err(DialError::Handshake("missing status".to_string()));
                    };
                    if s == b"401" {
                        return Err(DialError::Auth("unauthorized".to_string()));
                    }
                    if !is_success_status(s) {
                        let code_str = String::from_utf8_lossy(s);
                        let code_num: u16 = code_str.parse().unwrap_or(0);
                        return Err(DialError::Rejected(code_num));
                    }

                    // Validate capsule-protocol header per RFC 9484
                    if find_header_value(&incoming.headers, b"capsule-protocol") != Some(b"?1") {
                        warn!(%remote_addr, "server response missing capsule-protocol: ?1");
                        return Err(DialError::Handshake(
                            "server response missing capsule-protocol: ?1".to_string(),
                        ));
                    }

                    info!(%remote_addr, "CONNECT-IP accepted");
                    status_validated = true;
                    // If NewFlow already arrived, we can exit
                    if datagram_tx.is_some() {
                        break;
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

        if !status_validated {
            return Err(DialError::Handshake(
                "missing successful CONNECT-IP response status".to_string(),
            ));
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
    {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => {
            close_quic_connection(&quic_cmd_tx);
            return Err(err);
        }
        Err(_) => {
            close_quic_connection(&quic_cmd_tx);
            return Err(DialError::Timeout(tuning.h3_handshake_timeout));
        }
    };

    let (datagram_tx, datagram_rx, flow_id) = handshake_result;

    let quic_cmd_send = make_quic_command_sender(quic_cmd_tx);

    Ok(H3Connection {
        peer_id: peer_id.to_string(),
        remote_addr,
        datagram_tx,
        datagram_rx,
        flow_id,
        quic_cmd_send,
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
    /// Remote socket address for per-connection metrics disambiguation.
    pub remote_addr: SocketAddr,
    /// Inbound datagram receiver (from tokio-quiche).
    pub datagram_rx: InboundFrameStream,
}

/// Spawns the HTTP/3 receive loop for a single connection.
///
/// Receives datagrams from the inbound channel and forwards IP packets
/// (after stripping Context ID 0) to the router actor. Uses a
/// `recv()` + `try_recv()` drain pattern to batch all immediately-ready
/// frames into a single `Vec<PooledBuf>`, mirroring tokio-quiche's
/// synchronous `gather_data_from_quiche_conn` loop.
///
/// # Arguments
///
/// * `rx` - H3 receive state (peer_id and datagram_rx).
/// * `ingress_tx` - Bounded channel to push received packets to the router actor.
/// * `events_tx` - Unbounded channel for emitting receive metrics.
/// * `interval` - Metrics emission interval.
pub fn spawn_h3_rx(
    rx: H3Rx,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> JoinHandle<ActorExitResult> {
    let H3Rx {
        peer_id,
        remote_addr,
        mut datagram_rx,
    } = rx;
    let peer = peer_id.clone();

    tokio::spawn(async move {
        let mut counters = Counters::new(Source::Http3, Direction::Rx);
        let mut ticker = time::interval(interval);
        loop {
            tokio::select! {
                frame = datagram_rx.recv() => {
                    let Some(first) = frame else {
                        debug!(peer = %peer, "datagram stream closed");
                        return Ok(());
                    };

                    let mut batch: Vec<PooledBuf> = Vec::with_capacity(H3_RX_BATCH_SIZE);
                    let mut ok_pkts: u64 = 0;
                    let mut ok_bytes: u64 = 0;

                    // Process the first frame that woke us.
                    handle_inbound_frame(
                        &peer, first,
                        &mut batch, &mut ok_pkts, &mut ok_bytes,
                        &mut counters,
                    );

                    // Drain all immediately-ready frames without awaiting.
                    while batch.len() < H3_RX_BATCH_SIZE {
                        let Some(f) = datagram_rx.try_recv().ok() else { break };
                        handle_inbound_frame(
                            &peer, f,
                            &mut batch, &mut ok_pkts, &mut ok_bytes,
                            &mut counters,
                        );
                    }

                    if !counters.send_and_record(&ingress_tx, batch, ok_pkts, ok_bytes).await {
                        return Ok(());
                    }
                }
                _ = ticker.tick() => {
                    let metrics = counters.snapshot(Some(&peer), Some(remote_addr));
                    if events_tx.send(Event::Metrics(metrics)).is_err() {
                        return Ok(());
                    }
                }
            }
        }
    })
}

/// Processes a single inbound H3 frame: strips Context ID, pushes valid
/// IP datagrams into the batch, and records metrics for invalid frames.
#[inline]
fn handle_inbound_frame(
    peer: &str,
    inbound_frame: InboundFrame,
    batch: &mut Vec<PooledBuf>,
    ok_pkts: &mut u64,
    ok_bytes: &mut u64,
    counters: &mut Counters,
) {
    match inbound_frame {
        InboundFrame::Datagram(mut dgram) => {
            if dgram.is_empty() || dgram[0] != CONTEXT_ID_IP {
                counters.record_drop(
                    crate::metrics::DropReason::InvalidFraming,
                    1,
                    dgram.len() as u64,
                );
                return;
            }
            dgram.pop_front(1);
            let len = dgram.len() as u64;
            batch.push(dgram);
            *ok_pkts += 1;
            *ok_bytes += len;
        }
        InboundFrame::Body(pooled_buf, _fin) => {
            warn!(
                peer = %peer,
                len = pooled_buf.len(),
                "received unexpected Body frame on CONNECT-IP stream"
            );
            counters.record_drop(
                crate::metrics::DropReason::InvalidFraming,
                1,
                pooled_buf.len() as u64,
            );
        }
    }
}

// ========== Transmit Loop ==========

/// H3 transmit actor state.
///
/// Holds the datagram sender, flow ID, and QUIC command sender for the transmit loop.
pub struct H3Tx {
    /// Peer identifier for logging and metrics.
    pub peer_id: String,
    /// Remote socket address for per-connection metrics disambiguation.
    pub remote_addr: SocketAddr,
    /// Outbound datagram sender (to tokio-quiche).
    pub datagram_tx: OutboundFrameSender,
    /// DATAGRAM flow ID for this connection.
    pub flow_id: u64,
    /// QUIC command sender used for keepalive and explicit close.
    pub quic_cmd_send: QuicCommandSender,
}

impl std::fmt::Debug for H3Tx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Tx")
            .field("peer_id", &self.peer_id)
            .field("remote_addr", &self.remote_addr)
            .field("flow_id", &self.flow_id)
            .finish_non_exhaustive()
    }
}

/// Spawns the HTTP/3 send loop for a single connection.
///
/// Receives packets from TUN-Rx and sends as datagrams with Context ID 0
/// through the outbound datagram sender.
///
/// # Batch Counting
///
/// Uses `try_send` on the underlying `mpsc::Sender` for non-blocking sends.
/// All packets that succeed via `try_send` within a single `Vec<PooledBuf>`
/// form one batch. When the channel is full (`TrySendError::Full`), the
/// current sub-batch is flushed, the blocked packet is sent via
/// `Sender::send().await` (recording queue-full duration), and a new
/// sub-batch begins. This yields accurate `packets / batches` ratios that
/// reflect actual channel saturation rather than always 1:1.
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
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<PooledBuf>>(packet_queue_depth);

    let H3Tx {
        peer_id,
        remote_addr,
        datagram_tx,
        flow_id,
        quic_cmd_send,
    } = tx;
    let peer = peer_id.clone();

    let handle = tokio::spawn(async move {
        let mut counters = Counters::new(Source::Http3, Direction::Tx);
        let mut ticker = time::interval(interval);
        let mut keepalive_ticker = time::interval(keepalive_interval);
        keepalive_ticker.tick().await; // Skip first immediate tick

        // Bypass PollSender's Sink abstraction: use the underlying mpsc::Sender
        // directly for try_send/send, avoiding per-packet poll_ready+flush overhead.
        let inner_tx = datagram_tx
            .get_ref()
            .ok_or_else(|| ActorError::H3TxSend {
                peer_id: peer.clone(),
                reason: "datagram channel closed before TX loop started".to_string(),
            })?
            .clone();
        drop(datagram_tx); // Release PollSender; inner_tx owns the only Sender handle.

        loop {
            tokio::select! {
                maybe_batch = egress_rx.recv() => {
                    let Some(packets) = maybe_batch else {
                        let _ = quic_cmd_send(QuicCommand::ConnectionClose(
                            ConnectionShutdownBehaviour {
                                send_application_close: false,
                                error_code: 0,
                                reason: Vec::new(),
                            },
                        ));
                        return Ok(()); // Channel closed, exit gracefully
                    };

                    // Batch-aware sending: use try_send for non-blocking path,
                    // fall back to inner_tx.send().await on channel-full.
                    // Each channel-full boundary starts a new batch for metrics.
                    let mut seg_pkts: u64 = 0;
                    let mut seg_bytes: u64 = 0;

                    for mut packet in packets {
                        let len = packet.len();
                        // Zero-copy: prepend Context ID using reserved headroom.
                        if !packet.add_prefix(&[CONTEXT_ID_IP]) {
                            counters.record_drop(crate::metrics::DropReason::NoHeadroom, 1, len as u64);
                            continue;
                        }
                        let frame = OutboundFrame::Datagram(packet, flow_id);

                        send_with_backpressure(&inner_tx, frame, |event| match event {
                            SendEvent::Fast => {
                                seg_pkts += 1;
                                seg_bytes += len as u64;
                            }
                            SendEvent::Full => {
                                // Flush current segment as a completed batch.
                                if seg_pkts > 0 {
                                    counters.record_success(seg_pkts, seg_bytes);
                                }
                            }
                            // Keep existing semantics: queue-full wait is only recorded
                            // when the awaited send succeeds.
                            SendEvent::Waited(waited) => {
                                counters.record_queue_full(waited);
                                // The blocking-sent packet starts a new segment.
                                seg_pkts = 1;
                                seg_bytes = len as u64;
                            }
                        })
                        .await
                        .map_err(|_| {
                            counters.record_drop(
                                crate::metrics::DropReason::SendError, 1, len as u64,
                            );
                            ActorError::H3TxSend {
                                peer_id: peer.clone(),
                                reason: "datagram channel closed".to_string(),
                            }
                        })?;
                    }

                    // Record the final segment of this batch.
                    if seg_pkts > 0 {
                        counters.record_success(seg_pkts, seg_bytes);
                    }
                }
                _ = ticker.tick() => {
                    let metrics = counters.snapshot(Some(&peer), Some(remote_addr));
                    if events_tx.send(Event::Metrics(metrics)).is_err() {
                        return Ok(());
                    }
                }
                _ = keepalive_ticker.tick() => {
                    if !quic_cmd_send(QuicCommand::Custom(Box::new(|conn| {
                        conn.send_ack_eliciting().ok();
                    }))) {
                        debug!(peer = %peer, "keepalive: cmd channel closed");
                        return Ok(());
                    }
                }
            }
        }
    });

    (egress_tx, handle)
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
/// Does NOT spawn any tasks. Uses the unified socket path via
/// `make_server_udp_socket` for consistent buffer sizing.
///
/// # Arguments
///
/// * `listen_addr` - Address to listen on.
/// * `cert_path` - Path to TLS certificate.
/// * `key_path` - Path to TLS private key.
/// * `socket_buffer_bytes` - SO_RCVBUF/SO_SNDBUF size in bytes; 0 skips configuration.
///
/// # Errors
///
/// Returns `ListenerError` if socket binding fails or paths are invalid.
pub fn make_h3_listener(
    listen_addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    socket_buffer_bytes: usize,
) -> Result<H3Listener, ListenerError> {
    // Bind socket via unified path (applies SO_RCVBUF/SO_SNDBUF)
    let socket = make_server_udp_socket(listen_addr, socket_buffer_bytes)
        .map_err(|e| ListenerError::Bind(e.to_string()))?
        .into_std()
        .map_err(|e| ListenerError::Bind(format!("tokio-to-std conversion: {e}")))?;

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

    info!(%listen_addr, %bound_addr, "H3 listener created");

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

    info!(%bound_addr, "H3 listener started");

    // Configure TLS with certificate paths
    let tls_config = TlsCertificatePaths {
        cert: &cert_path,
        private_key: &key_path,
        kind: CertificateKind::X509,
    };

    let quic_settings = make_quic_settings(tuning, tun_mtu);

    let conn_params = ConnectionParams::new_server(quic_settings, tls_config, Default::default());

    // Convert to QuicListener and conditionally enable GSO/GRO offload.
    // Using listen_with_capabilities avoids the implicit apply_max_capabilities
    // that listen() performs, giving us control via the udp_enable_offload flag.
    let mut quic_listener: QuicListener = socket
        .try_into()
        .expect("infallible: already-bound socket -> QuicListener");
    #[cfg(target_os = "linux")]
    if tuning.udp_enable_offload {
        quic_listener.apply_max_capabilities();
    }
    let mut listeners = listen_with_capabilities([quic_listener], conn_params, DefaultMetrics)
        .expect("infallible: listen on already-bound socket");

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
                    let Some(result) = conn_result else {
                        return Ok(());
                    };
                    let initial_conn = match result {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(error = %e, "accept error");
                            continue;
                        }
                    };

                    let h3_settings = Http3Settings {
                        enable_extended_connect: true,
                        ..Default::default()
                    };
                    let (driver, controller) =
                        ServerH3Driver::new(h3_settings);
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
            }
        }
    });

    (cmd_tx, handle, bound_addr)
}

// ========== Test Support ==========

/// Shared test utilities for H3 integration tests across modules.
///
/// Available in test builds and with the `test-utils` feature.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) mod test_support {
    use crate::config::{H3Endpoint, PeerH3, Tuning};
    use std::net::SocketAddr;

    /// Test certificate bundle with temporary files.
    ///
    /// Generates a self-signed TLS certificate for `localhost` / `127.0.0.1`
    /// using rcgen. The temporary files are cleaned up on drop.
    pub struct TestCertBundle {
        cert_file: tempfile::NamedTempFile,
        key_file: tempfile::NamedTempFile,
    }

    impl TestCertBundle {
        /// Generates a self-signed certificate for localhost using rcgen.
        pub fn generate() -> Self {
            use rcgen::{generate_simple_self_signed, CertifiedKey};
            use std::io::Write;

            let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(subject_alt_names).expect("cert generation");

            let mut cert_file = tempfile::NamedTempFile::new().expect("create cert temp file");
            cert_file
                .write_all(cert.pem().as_bytes())
                .expect("write cert");

            let mut key_file = tempfile::NamedTempFile::new().expect("create key temp file");
            key_file
                .write_all(signing_key.serialize_pem().as_bytes())
                .expect("write key");

            Self {
                cert_file,
                key_file,
            }
        }

        /// Returns the path to the certificate PEM file.
        pub fn cert_path(&self) -> &std::path::Path {
            self.cert_file.path()
        }

        /// Returns the path to the private key PEM file.
        pub fn key_path(&self) -> &std::path::Path {
            self.key_file.path()
        }
    }

    /// Returns `Tuning` with `h3_insecure_skip_verify: true` for tests using self-signed certs.
    pub fn insecure_tuning() -> Tuning {
        Tuning {
            h3_insecure_skip_verify: true,
            ..Default::default()
        }
    }

    /// Creates a test `PeerH3` config pointing at the given server address.
    pub fn test_peer_h3(bound_addr: SocketAddr, token: &str) -> PeerH3 {
        PeerH3 {
            endpoint: Some(H3Endpoint {
                host: "localhost".to_string(),
                port: bound_addr.port(),
                path: "/.well-known/masque/udp/*/*/".to_string(),
            }),
            token: token.to_string(),
            bindif: None,
            sni: None,
        }
    }

    /// Waits for an `H3ConnectedEvent` on the events channel, with timeout.
    ///
    /// Skips non-H3Connected events (e.g. metrics). Panics on timeout or if
    /// the channel closes before an H3Connected event arrives.
    pub async fn await_server_connection(
        events_rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::events::Event>,
    ) -> crate::events::H3ConnectedEvent {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Some(event) = events_rx.recv().await {
                if let crate::events::Event::H3Connected(connected) = event {
                    return connected;
                }
            }
            panic!("events channel closed without H3Connected");
        })
        .await
        .expect("timeout waiting for H3Connected event")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::test_support::FakeRouteProbe;
    use test_support::{await_server_connection, insecure_tuning, test_peer_h3, TestCertBundle};

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

    #[test]
    fn make_quic_settings_applies_handshake_timeout() {
        let tuning = Tuning {
            h3_handshake_timeout: Duration::from_secs(7),
            ..Tuning::default()
        };

        let settings = make_quic_settings(&tuning, crate::config::default_mtu());

        assert_eq!(settings.handshake_timeout, Some(Duration::from_secs(7)));
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

    // ========== find_header_value Tests ==========

    #[test]
    fn find_header_value_exact_match() {
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b"capsule-protocol", b"?1"),
        ];
        assert_eq!(
            find_header_value(&headers, b":method"),
            Some(b"CONNECT".as_slice())
        );
        assert_eq!(
            find_header_value(&headers, b"capsule-protocol"),
            Some(b"?1".as_slice())
        );
    }

    #[test]
    fn find_header_value_case_insensitive() {
        let headers = vec![Header::new(b"Capsule-Protocol", b"?1")];
        assert_eq!(
            find_header_value(&headers, b"capsule-protocol"),
            Some(b"?1".as_slice())
        );
    }

    #[test]
    fn find_header_value_missing() {
        let headers = vec![Header::new(b":status", b"200")];
        assert_eq!(find_header_value(&headers, b"capsule-protocol"), None);
    }

    // ========== dial_h3 Error Tests ==========

    #[tokio::test]
    async fn dial_h3_rejects_missing_endpoint() {
        use crate::config::PeerH3;

        let peer_h3 = PeerH3 {
            endpoint: None,
            token: "test-token-12ch".to_string(),
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

    #[tokio::test]
    async fn make_h3_listener_binds_socket() {
        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let result = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0);

        assert!(result.is_ok());
        let listener = result.unwrap();
        assert_ne!(listener.bound_addr.port(), 0, "should bind to actual port");
    }

    #[tokio::test]
    async fn spawn_h3_listener_from_state_graceful_shutdown() {
        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
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

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
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

    // ========== Client-Server Integration Tests ==========
    //
    // These tests perform real QUIC/H3 handshakes over loopback. They use
    // self-signed certificates with `insecure=true` for testing.

    #[tokio::test]
    async fn handshake_success() {
        use crate::events::{ConnectionDirection, Event};

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "test-client";
        let token = "test-token-12chars";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
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
            &insecure_tuning(),
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
        let server_event = await_server_connection(&mut events_rx).await;
        assert_eq!(server_event.connection.peer_id, peer_id);
        assert_eq!(server_event.direction, ConnectionDirection::Inbound);

        // Clean shutdown
        drop(cmd_tx);
    }

    #[tokio::test]
    async fn handshake_success_with_sni_override() {
        use crate::events::{ConnectionDirection, Event};

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "sni-client";
        let token = "sni-test-token-12ch";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
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
            &insecure_tuning(),
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
        let server_event = await_server_connection(&mut events_rx).await;
        assert_eq!(server_event.connection.peer_id, peer_id);
        assert_eq!(server_event.direction, ConnectionDirection::Inbound);

        drop(cmd_tx);
    }

    // ========== H3Connection::into_actors Tests ==========

    #[tokio::test]
    async fn h3_connection_into_actors_preserves_peer_id() {
        use crate::events::Event;

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "split-test-peer";
        let token = "split-test-token12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
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
            &insecure_tuning(),
        )
        .await
        .expect("dial");

        let server_event = await_server_connection(&mut events_rx).await;

        let (rx, tx) = server_event.connection.into_actors();
        assert_eq!(rx.peer_id, peer_id);
        assert_eq!(tx.peer_id, peer_id);
        assert_eq!(rx.remote_addr, tx.remote_addr);
        assert!(rx.remote_addr.ip().is_loopback());

        drop(cmd_tx);
    }

    #[tokio::test]
    async fn handshake_rejects_wrong_secret() {
        use crate::events::Event;

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_tokens =
            HashMap::from([("test-client".to_string(), "correct-token-12".to_string())]);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
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
            &insecure_tuning(),
        )
        .await;

        match result {
            Err(DialError::Auth(_) | DialError::Rejected(401)) => {}
            Err(other) => panic!("expected Auth error, got {:?}", other),
            Ok(_) => panic!("expected dial to fail with wrong secret"),
        }

        // Server should NOT have emitted an H3Connected event
        let server_recv = tokio::time::timeout(Duration::from_millis(500), async {
            while let Some(event) = events_rx.recv().await {
                if matches!(event, Event::H3Connected(_)) {
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

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
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
            &insecure_tuning(),
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
        use crate::events::Event;
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "datagram-client";
        let token = "datagram-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (listener_events_tx, mut listener_events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
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
            &insecure_tuning(),
        )
        .await
        .expect("dial failed");

        let server_event = await_server_connection(&mut listener_events_rx).await;

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let metrics_interval = Duration::from_secs(60);

        // Split client connection into RX/TX actors
        let (_client_rx, client_tx) = client_conn.into_actors();

        // Client TX actor
        let (client_egress_tx, _client_tx_handle) = spawn_h3_tx(
            client_tx,
            events_tx.clone(),
            metrics_interval,
            256,
            Duration::from_secs(20),
        );

        // Split server connection for RX
        let (server_rx, _server_tx) = server_event.connection.into_actors();

        // Server RX actor
        let (server_router_tx, mut server_router_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let _server_rx_handle =
            spawn_h3_rx(server_rx, server_router_tx, events_tx, metrics_interval);

        // Send test packet (allocate with headroom for H3 TX encoding)
        use crate::tun::alloc_packet_buf;
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        let pkt = alloc_packet_buf(&test_packet);
        client_egress_tx.send(vec![pkt]).await.expect("send failed");

        // Verify receipt
        let batch = tokio::time::timeout(Duration::from_secs(5), server_router_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &test_packet[..]);

        drop(cmd_tx);
    }

    #[tokio::test]
    async fn datagram_bidirectional() {
        use crate::events::Event;
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "bidir-client";
        let token = "bidir-token-12ch";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (listener_events_tx, mut listener_events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
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
            &insecure_tuning(),
        )
        .await
        .expect("dial failed");

        let server_event = await_server_connection(&mut listener_events_rx).await;

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

        let (s2c_router_tx, mut s2c_router_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let _client_rx_handle = spawn_h3_rx(
            client_rx,
            s2c_router_tx,
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

        let (c2s_router_tx, mut c2s_router_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let _server_rx_handle = spawn_h3_rx(server_rx, c2s_router_tx, events_tx, metrics_interval);

        // Test client -> server
        let packet_c2s = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        client_send_tx
            .send(vec![alloc_packet_buf(&packet_c2s)])
            .await
            .unwrap();

        let batch_c2s = tokio::time::timeout(Duration::from_secs(5), c2s_router_rx.recv())
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

        let batch_s2c = tokio::time::timeout(Duration::from_secs(5), s2c_router_rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(batch_s2c.len(), 1);
        assert_eq!(&batch_s2c[0][..], &packet_s2c[..]);

        drop(cmd_tx);
    }

    #[tokio::test]
    async fn connection_graceful_shutdown() {
        use crate::events::Event;

        let certs = TestCertBundle::generate();
        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let peer_id = "shutdown-client";
        let token = "shutdown-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
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
            &insecure_tuning(),
        )
        .await
        .expect("dial failed");

        let _server_event = await_server_connection(&mut events_rx).await;

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

    // ========== H3 TX Batch Counting Tests ==========

    /// Verifies that H3 TX batch counting uses try_send semantics:
    /// a batch of packets that all succeed via try_send -> 1 batch count.
    #[tokio::test]
    async fn h3_tx_batch_counting_try_send() {
        use crate::events::Event;
        use crate::tun::alloc_packet_buf;
        use tokio_util::sync::PollSender;

        // Large capacity ensures all try_send calls succeed without backpressure.
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<OutboundFrame>(64);
        let datagram_tx: OutboundFrameSender = PollSender::new(outbound_tx);

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let quic_cmd_send: QuicCommandSender = Box::new(|_| true);

        let tx = H3Tx {
            peer_id: "batch-test".to_string(),
            remote_addr: "127.0.0.1:1234".parse().unwrap(),
            datagram_tx,
            flow_id: 0,
            quic_cmd_send,
        };

        let (egress_tx, tx_handle) = spawn_h3_tx(
            tx,
            events_tx,
            Duration::from_millis(50), // short interval for metrics emission
            16,
            Duration::from_secs(60),
        );

        // Drain outbound frames in background.
        let drain = tokio::spawn(async move { while outbound_rx.recv().await.is_some() {} });

        // Send a batch of 5 packets — capacity=64 so all try_send succeed.
        let payload = vec![0u8; 100];
        let batch: Vec<PooledBuf> = (0..5).map(|_| alloc_packet_buf(&payload)).collect();
        egress_tx.send(batch).await.unwrap();

        // Wait for a metrics tick.
        let metrics = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(Event::Metrics(m)) = events_rx.recv().await {
                    if m.stats.succeeded.packets > 0 {
                        return m;
                    }
                }
            }
        })
        .await
        .expect("metrics timeout");

        // All 5 packets sent via try_send in one batch -> batches == 1.
        assert_eq!(metrics.stats.succeeded.packets, 5);
        assert_eq!(metrics.stats.succeeded.batches, 1);
        // No queue-full events.
        assert_eq!(metrics.stats.congestion.queue_full_count, 0);

        drop(egress_tx);
        let _ = tx_handle.await;
        drain.abort();
    }

    /// Verifies that when the outbound channel is full, H3 TX:
    /// 1. Records queue_full congestion events
    /// 2. Splits the batch into multiple segments (batch count > 1)
    #[tokio::test]
    async fn h3_tx_backpressure_splits_batch() {
        use crate::events::Event;
        use crate::tun::alloc_packet_buf;
        use tokio_util::sync::PollSender;

        // Channel capacity = 1 to guarantee backpressure on batch of 3.
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<OutboundFrame>(1);
        let datagram_tx: OutboundFrameSender = PollSender::new(outbound_tx);

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let quic_cmd_send: QuicCommandSender = Box::new(|_| true);

        let tx = H3Tx {
            peer_id: "bp-peer".to_string(),
            remote_addr: "127.0.0.1:5678".parse().unwrap(),
            datagram_tx,
            flow_id: 0,
            quic_cmd_send,
        };

        let (egress_tx, tx_handle) = spawn_h3_tx(
            tx,
            events_tx,
            Duration::from_millis(50),
            16,
            Duration::from_secs(60),
        );

        // Drain slowly to trigger backpressure.
        let drain = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                if outbound_rx.recv().await.is_none() {
                    break;
                }
            }
        });

        // Send batch of 3 packets with capacity=1 -> at least 2 backpressure events.
        let payload = vec![0u8; 100];
        let batch: Vec<PooledBuf> = (0..3).map(|_| alloc_packet_buf(&payload)).collect();
        egress_tx.send(batch).await.unwrap();

        // Wait for metrics.
        let metrics = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(Event::Metrics(m)) = events_rx.recv().await {
                    if m.stats.succeeded.packets >= 3 {
                        return m;
                    }
                }
            }
        })
        .await
        .expect("metrics timeout");

        assert_eq!(metrics.stats.succeeded.packets, 3);
        // With capacity=1 and slow drain, batch count should be > 1.
        assert!(
            metrics.stats.succeeded.batches > 1,
            "expected batch splitting from backpressure, got batches={}",
            metrics.stats.succeeded.batches
        );
        // Queue full events should have been recorded.
        assert!(
            metrics.stats.congestion.queue_full_count > 0,
            "expected queue_full events"
        );
        assert!(metrics.stats.congestion.queue_full_duration > Duration::ZERO);

        drop(egress_tx);
        let _ = tx_handle.await;
        drain.abort();
    }
}
