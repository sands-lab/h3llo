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
use crate::events::{Direction, Event, TransportEvent, TransportKind};
use crate::metrics::TransportCounters;
use crate::PACKET_QUEUE_DEPTH;
use base64::{engine::general_purpose::STANDARD, Engine};
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

// ========== BasicAuth Helpers ==========

/// Encodes credentials as HTTP Basic Auth header value.
fn basic_auth_header(user: &str, pass: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{}:{}", user, pass)))
}

/// Parses Basic Auth header, returning (username, password) if valid.
#[allow(dead_code)] // Used by spawn_h3_listener when fully implemented
fn parse_basic_auth(header: &str) -> Option<(String, String)> {
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (user, pass) = s.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
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

/// HTTP/3 connection handle wrapping tokio-quiche internals.
#[derive(Debug)]
pub struct H3Conn {
    /// Peer identifier for logging and metrics.
    peer_id: String,
    /// Remote endpoint for debugging.
    #[allow(dead_code)]
    endpoint: String,
    // TODO: Add tokio-quiche connection fields when implementing
}

impl H3Conn {
    /// Returns the peer ID for this connection.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }
}

// ========== Dial Function ==========

/// Establishes an HTTP/3 CONNECT-IP connection to a peer.
///
/// # Arguments
///
/// * `endpoint` - Target endpoint URL (https://host:port/path)
/// * `local_id` - Local node ID (Basic Auth username)
/// * `peer_secret` - Peer's shared secret (Basic Auth password)
/// * `peer_id` - Remote peer identifier
/// * `cert_path` - Path to TLS certificate
/// * `key_path` - Path to TLS private key
///
/// # Errors
///
/// Returns `DialError` if connection establishment fails.
pub async fn dial_h3(
    endpoint: &str,
    local_id: &str,
    peer_secret: &str,
    peer_id: &str,
    _cert_path: &Path,
    _key_path: &Path,
) -> Result<H3Conn, DialError> {
    debug!(endpoint, local_id, peer_id, "dialing H3 endpoint");

    // Build auth header for logging (not for actual use in placeholder)
    let _auth = basic_auth_header(local_id, peer_secret);

    // TODO: Implement with tokio-quiche
    // 1. Parse endpoint URL
    // 2. Load TLS config (cert, key)
    // 3. Create QUIC client connection with DATAGRAM support
    // 4. Send Extended CONNECT request:
    //    :method = CONNECT
    //    :protocol = connect-ip
    //    :scheme = https
    //    :authority = <host:port>
    //    :path = <path>
    //    Authorization = Basic base64(local_id:peer_secret)
    //    Capsule-Protocol: ?1
    //    Datagram-Format: 1
    // 5. Handle 401 challenge if needed
    // 6. Wait for 200 OK

    todo!("Implement dial_h3 with tokio-quiche")
}

// ========== Receive Loop ==========

/// Spawns the HTTP/3 receive loop for a single connection.
///
/// Receives DATAGRAM frames and forwards IP packets (after stripping Context ID)
/// to the TUN-Tx queue.
///
/// # Arguments
///
/// * `conn` - Established H3 connection handle.
/// * `packet_tx` - Bounded channel to push received packets into (data plane).
/// * `events_tx` - Unbounded channel for emitting receive metrics.
/// * `interval` - Metrics emission interval.
pub fn spawn_h3_rx(
    conn: H3Conn,
    _packet_tx: mpsc::Sender<Vec<u8>>,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> JoinHandle<ActorExitResult> {
    let peer_id = conn.peer_id.clone();

    tokio::spawn(async move {
        let counters = TransportCounters::new(TransportKind::Http3, Direction::Rx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                // TODO: Replace with actual tokio-quiche datagram receive
                // result = conn.recv_datagram() => { ... }
                _ = ticker.tick() => {
                    let metrics = counters.snapshot(Some(&peer_id), None);
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
/// Receives packets from TUN-Rx and sends as DATAGRAM frames with Context ID 0.
///
/// # Arguments
///
/// * `conn` - Established H3 connection handle.
/// * `events_tx` - Unbounded channel for emitting transmit metrics.
/// * `interval` - Metrics emission interval.
///
/// # Returns
///
/// Returns the packet sender channel and join handle.
pub fn spawn_h3_tx(
    conn: H3Conn,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> (mpsc::Sender<Vec<u8>>, JoinHandle<ActorExitResult>) {
    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_DEPTH);
    let peer_id = conn.peer_id.clone();

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
                    let _encoded = encode_datagram(&packet);

                    // TODO: Replace with actual tokio-quiche datagram send
                    // match conn.send_datagram(&encoded).await { ... }

                    counters.record_success(len);
                }
                _ = ticker.tick() => {
                    let metrics = counters.snapshot(Some(&peer_id), None);
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
#[derive(Debug, Clone)]
pub enum H3ListenerCommand {
    /// Update peer secrets for authentication.
    UpdatePeerSecrets(HashMap<String, String>),
}

/// Spawns the H3 listener actor for accepting inbound CONNECT-IP connections.
///
/// # Arguments
///
/// * `listen_addr` - Address to listen on.
/// * `cert_path` - Path to TLS certificate.
/// * `key_path` - Path to TLS private key.
/// * `peer_secrets` - Map of peer ID to expected secret for authentication.
/// * `tun_tx` - Packet channel to TUN-Tx for inbound packets.
/// * `events_tx` - Unbounded channel for emitting H3 events.
///
/// # Returns
///
/// Returns the command sender and join handle.
///
/// # Errors
///
/// Returns `ListenerError` if listener setup fails.
pub async fn spawn_h3_listener(
    listen_addr: SocketAddr,
    _cert_path: &Path,
    _key_path: &Path,
    peer_secrets: HashMap<String, String>,
    _tun_tx: mpsc::Sender<Vec<u8>>,
    _events_tx: mpsc::UnboundedSender<Event>,
) -> Result<(mpsc::UnboundedSender<H3ListenerCommand>, JoinHandle<ActorExitResult>), ListenerError> {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    // TODO: secrets will be used for auth when accept loop is fully implemented
    let _ = peer_secrets;

    debug!(%listen_addr, "starting H3 listener");

    // TODO: Implement with tokio-quiche
    // 1. Load TLS config (cert, key)
    // 2. Create QUIC server with DATAGRAM support
    // 3. Accept loop:
    //    a. Accept connection
    //    b. Receive Extended CONNECT request
    //    c. Authenticate via Basic Auth using parse_basic_auth
    //    d. Verify peer_id in secrets map
    //    e. Send 200 OK or 401 Unauthorized
    //    f. Spawn per-connection actors

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(H3ListenerCommand::UpdatePeerSecrets(_update)) => {
                            // TODO: Apply update when accept loop is fully implemented
                            debug!("updated peer secrets");
                        }
                        None => return Ok(()), // Channel closed
                    }
                }
                // TODO: Add accept branch
            }
        }
    });

    Ok((cmd_tx, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== BasicAuth Tests ==========

    #[test]
    fn basic_auth_roundtrip() {
        let header = basic_auth_header("user", "pass");
        let (u, p) = parse_basic_auth(&header).unwrap();
        assert_eq!(u, "user");
        assert_eq!(p, "pass");
    }

    #[test]
    fn parse_handles_password_with_colons() {
        let header = basic_auth_header("admin", "pass:word:extra");
        let (u, p) = parse_basic_auth(&header).unwrap();
        assert_eq!(u, "admin");
        assert_eq!(p, "pass:word:extra");
    }

    #[test]
    fn parse_rejects_non_basic() {
        assert!(parse_basic_auth("Bearer token").is_none());
        assert!(parse_basic_auth("Digest realm=test").is_none());
    }

    #[test]
    fn parse_rejects_invalid_base64() {
        assert!(parse_basic_auth("Basic !!!invalid!!!").is_none());
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
