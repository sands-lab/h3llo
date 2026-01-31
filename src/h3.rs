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

#[allow(unused_imports)] // ActorError will be used when dial/rx loops report errors
use crate::actor::{ActorError, ActorExitResult};
use crate::auth::generate_basic_auth;
use crate::bind::{bind_udp_socket, RouteProbe};
use crate::events::{Direction, Event, TransportEvent, TransportKind};
use crate::metrics::TransportCounters;
use crate::PACKET_QUEUE_DEPTH;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::debug;

/// Context ID for IP payloads per RFC 9484 (always 0 for CONNECT-IP).
const CONTEXT_ID_IP: u8 = 0x00;

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
    /// Sender for outbound DATAGRAM frames.
    ///
    /// TODO: Replace with `OutboundFrameSender` when tokio-quiche integration is complete.
    pub datagram_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Receiver for inbound DATAGRAM frames.
    ///
    /// TODO: Replace with `InboundFrameStream` when tokio-quiche integration is complete.
    pub datagram_rx: mpsc::UnboundedReceiver<Vec<u8>>,
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
///
/// # Errors
///
/// Returns `DialError` if connection establishment fails.
#[allow(clippy::too_many_arguments)]
pub async fn dial_h3<P: RouteProbe>(
    remote_addr: SocketAddr,
    server_name: &str,
    path: &str,
    local_id: &str,
    peer_secret: &str,
    ca_cert_path: Option<&Path>,
    bindif: Option<&str>,
    tun_if: Option<&str>,
    probe: &P,
) -> Result<H3Connection, DialError> {
    debug!(%remote_addr, %server_name, %local_id, "dialing H3 endpoint");

    // Bind socket to interface
    let bind_addr = if remote_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };

    let socket = bind_udp_socket(bind_addr, bindif, remote_addr.ip(), tun_if, probe)
        .await
        .map_err(|e| DialError::Tls(format!("socket bind failed: {}", e)))?;

    socket
        .connect(remote_addr)
        .await
        .map_err(|e| DialError::Handshake(format!("connect failed: {}", e)))?;

    // Load CA certificate if provided (sync read - TLS certs are small)
    let _ca_cert = if let Some(ca_path) = ca_cert_path {
        Some(std::fs::read(ca_path).map_err(|e| DialError::Tls(format!("read CA cert: {}", e)))?)
    } else {
        None
    };

    // Build auth header using auth.rs
    let _auth_header = generate_basic_auth(local_id, peer_secret);

    // Suppress unused variable warnings for future implementation
    let _ = (socket, server_name, path, _ca_cert, _auth_header);

    // TODO: Connect using tokio-quiche
    // 1. Create ClientH3Driver with DATAGRAM support
    // 2. Send Extended CONNECT request with auth header
    // 3. Wait for 200 OK response
    // 4. Extract datagram channels from H3Event::NewFlow

    todo!("Complete dial_h3 with tokio-quiche ClientH3Driver")
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
/// * `datagram_rx` - Inbound datagram receiver (from tokio-quiche or mock).
/// * `packet_tx` - Bounded channel to push received packets into (data plane).
/// * `events_tx` - Unbounded channel for emitting receive metrics.
/// * `interval` - Metrics emission interval.
pub fn spawn_h3_rx(
    peer_id: String,
    mut datagram_rx: mpsc::UnboundedReceiver<Vec<u8>>,
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
                        Some(data) => {
                            if let Some(payload) = decode_datagram(&data) {
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
/// * `datagram_tx` - Outbound datagram sender (to tokio-quiche or mock).
/// * `events_tx` - Unbounded channel for emitting transmit metrics.
/// * `interval` - Metrics emission interval.
///
/// # Returns
///
/// Returns the packet sender channel and join handle.
pub fn spawn_h3_tx(
    peer_id: String,
    datagram_tx: mpsc::UnboundedSender<Vec<u8>>,
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

                    if datagram_tx.send(encoded).is_err() {
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

/// Internal events from the H3 driver forwarded to the listener actor.
#[derive(Debug)]
#[allow(dead_code)] // Variants will be used when tokio-quiche integration is complete
enum H3ListenerEvent {
    /// New connection established with DATAGRAM flow ready.
    NewConnection {
        peer_id: String,
        remote_addr: SocketAddr,
        datagram_tx: mpsc::UnboundedSender<Vec<u8>>,
        datagram_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    },
    /// Connection closed or errored.
    ConnectionClosed {
        peer_id: Option<String>,
        reason: String,
    },
}

/// Internal message type for listener actor (commands + events).
#[allow(dead_code)] // Event variant will be used when tokio-quiche integration is complete
enum H3ListenerMsg {
    Command(H3ListenerCommand),
    Event(H3ListenerEvent),
}

/// Spawns the H3 listener actor for accepting inbound CONNECT-IP connections.
///
/// Uses an event-forwarding coroutine pattern: a separate coroutine calls
/// the tokio-quiche controller's event receiver and forwards events to the
/// listener's internal message channel. This avoids `Arc<Mutex<_>>` while keeping
/// the main select loop responsive to both commands and H3 events.
///
/// # Arguments
///
/// * `listen_addr` - Address to listen on.
/// * `cert_path` - Path to TLS certificate.
/// * `key_path` - Path to TLS private key.
/// * `peer_secrets` - Map of peer ID to expected secret for authentication.
/// * `conn_tx` - Unbounded channel for emitting established connections.
/// * `bindif` - Optional interface name to bind the socket.
/// * `tun_if` - Optional TUN interface name to exclude from probing.
/// * `probe` - Route probe implementation for interface selection.
///
/// # Returns
///
/// Returns the command sender and join handle.
/// Shutdown by dropping cmd_tx (no explicit Shutdown command).
///
/// # Errors
///
/// Returns `ListenerError` if listener setup fails.
#[allow(clippy::too_many_arguments)]
pub async fn spawn_h3_listener<P: RouteProbe + Send + Sync + 'static>(
    listen_addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    #[allow(unused_mut, unused_variables)]
    // Will be used when tokio-quiche integration is complete
    mut peer_secrets: HashMap<String, String>,
    conn_tx: mpsc::UnboundedSender<H3Connection>,
    bindif: Option<&str>,
    tun_if: Option<&str>,
    probe: P,
) -> Result<
    (
        mpsc::UnboundedSender<H3ListenerCommand>,
        JoinHandle<ActorExitResult>,
    ),
    ListenerError,
> {
    // Create internal message channel (commands + events)
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<H3ListenerMsg>();

    // Create external command channel that wraps messages
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<H3ListenerCommand>();
    let msg_tx_cmd = msg_tx.clone();

    // Forward commands to internal channel
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            if msg_tx_cmd.send(H3ListenerMsg::Command(cmd)).is_err() {
                break;
            }
        }
    });

    debug!(%listen_addr, bindif = ?bindif, "starting H3 listener");

    // Bind socket to interface
    let socket = bind_udp_socket(listen_addr, bindif, listen_addr.ip(), tun_if, &probe)
        .await
        .map_err(|e| ListenerError::Bind(e.to_string()))?;

    // Load TLS config (sync read - TLS certs are small)
    let _cert_chain =
        std::fs::read(cert_path).map_err(|e| ListenerError::Tls(format!("read cert: {}", e)))?;
    let _key =
        std::fs::read(key_path).map_err(|e| ListenerError::Tls(format!("read key: {}", e)))?;

    // Suppress unused variable warnings for future implementation
    let _ = (socket, msg_tx, probe, _cert_chain, _key);

    // TODO: Create tokio-quiche listener with TLS config
    // TODO: Spawn event forwarder coroutine for the controller:
    //
    // let msg_tx_events = msg_tx.clone();
    // tokio::spawn(async move {
    //     while let Some(event) = controller.event_receiver_mut().recv().await {
    //         match event {
    //             ServerH3Event::Core(H3Event::NewFlow { send, recv, .. }) => {
    //                 // Validate auth, then forward
    //                 msg_tx_events.send(H3ListenerMsg::Event(
    //                     H3ListenerEvent::NewConnection { ... }
    //                 )).ok();
    //             }
    //             _ => {}
    //         }
    //     }
    // });

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = msg_rx.recv() => {
                    match msg {
                        Some(H3ListenerMsg::Command(H3ListenerCommand::UpdatePeerSecrets(update))) => {
                            // TODO: Use peer_secrets for auth when tokio-quiche integration is complete
                            // peer_secrets = update;
                            let _ = update;
                            debug!("updated peer secrets");
                        }
                        Some(H3ListenerMsg::Event(H3ListenerEvent::NewConnection {
                            peer_id,
                            remote_addr,
                            datagram_tx,
                            datagram_rx,
                        })) => {
                            debug!(peer_id, %remote_addr, "new H3 connection established");
                            let conn = H3Connection {
                                peer_id,
                                remote_addr,
                                datagram_tx,
                                datagram_rx,
                            };
                            if conn_tx.send(conn).is_err() {
                                debug!("connection channel closed, shutting down");
                                return Ok(());
                            }
                        }
                        Some(H3ListenerMsg::Event(H3ListenerEvent::ConnectionClosed {
                            peer_id,
                            reason,
                        })) => {
                            debug!(?peer_id, reason, "H3 connection closed");
                        }
                        None => {
                            // All message senders dropped - shutdown
                            return Ok(());
                        }
                    }
                }
            }
        }
    });

    Ok((cmd_tx, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ========== DialError Display Tests ==========

    #[test]
    fn dial_error_displays_correctly() {
        let err = DialError::Handshake("timeout".to_string());
        assert!(err.to_string().contains("handshake"));
        assert!(err.to_string().contains("timeout"));

        let err = DialError::Rejected(401);
        assert!(err.to_string().contains("401"));
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
}
