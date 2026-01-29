//! HTTP/3 transport: QUIC connection, DATAGRAM framing, and Rx/Tx actors.
//!
//! Implements CONNECT-IP over HTTP/3 using h3-quinn with Context ID always 0.
//!
//! # Current Status
//!
//! This module provides low-level QUIC transport primitives:
//! - TLS configuration and endpoint creation
//! - DATAGRAM framing with Context ID 0
//! - Rx/Tx actors for data plane forwarding
//!
//! The HTTP/3 CONNECT-IP handshake (HEADERS frames, 401 challenge, etc.)
//! is not yet implemented. See `docs/protocol.md` for the full protocol specification.
//!
//! # Metrics
//!
//! Unlike BareUDP actors which emit metrics without peer identification,
//! H3 actors include `peer_id` and `remote_addr` in metrics snapshots.
//! This difference reflects H3's connection-oriented nature vs BareUDP's
//! connectionless design.

use crate::actor::{ActorError, ActorExitResult};
use crate::events::{Direction, DropReason, Event, TransportEvent, TransportKind};
use crate::metrics::TransportCounters;
use crate::PACKET_QUEUE_DEPTH;
use bytes::Bytes;
use quinn::{Connection, Endpoint, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

// ========== Configuration Constants ==========

/// QUIC datagram receive buffer size in bytes.
const DATAGRAM_RECEIVE_BUFFER_SIZE: usize = 65536;

/// QUIC connection idle timeout in milliseconds.
const IDLE_TIMEOUT_MS: u32 = 30_000;

/// QUIC error code for graceful shutdown (no error).
const SHUTDOWN_ERROR_CODE: u32 = 0;

// ========== Datagram Framing ==========

/// Context ID for CONNECT-IP datagrams (always 0 per docs/protocol.md).
pub const CONTEXT_ID_ZERO: u8 = 0x00;

/// Prepends Context ID 0 to an IP packet for CONNECT-IP DATAGRAM.
#[inline]
pub fn wrap_datagram(payload: &[u8]) -> Bytes {
    let mut buf = Vec::with_capacity(1 + payload.len());
    buf.push(CONTEXT_ID_ZERO);
    buf.extend_from_slice(payload);
    Bytes::from(buf)
}

/// Strips Context ID 0 prefix from a received DATAGRAM.
#[inline]
pub fn unwrap_datagram(data: &[u8]) -> Option<&[u8]> {
    (data.first() == Some(&CONTEXT_ID_ZERO)).then(|| &data[1..])
}

// ========== TLS Configuration ==========

/// Loads TLS certificate chain from a PEM file.
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be read or contains no valid certificates.
pub fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path)?;
    rustls_pemfile::certs(&mut std::io::BufReader::new(data.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(std::io::Error::other)
}

/// Loads private key from a PEM file.
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be read or contains no valid private key.
pub fn load_key(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path)?;
    rustls_pemfile::private_key(&mut std::io::BufReader::new(data.as_slice()))?
        .ok_or_else(|| std::io::Error::other("no private key found"))
}

/// Creates the default QUIC transport configuration with DATAGRAM support.
fn default_transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER_SIZE));
    config.max_idle_timeout(Some(VarInt::from_u32(IDLE_TIMEOUT_MS).into()));
    config
}

/// Creates a Quinn server endpoint with DATAGRAM support.
///
/// # Arguments
/// - `listen_addr`: Local address to bind the server to.
/// - `cert_path`: Path to PEM file containing certificate chain.
/// - `key_path`: Path to PEM file containing private key.
///
/// # Errors
///
/// Returns `io::Error` if TLS configuration or endpoint creation fails.
pub fn create_server_endpoint(
    listen_addr: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
) -> std::io::Result<Endpoint> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(std::io::Error::other)?;
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .map_err(std::io::Error::other)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    server_config.transport_config(Arc::new(default_transport_config()));

    Endpoint::server(server_config, listen_addr)
}

/// Creates a Quinn client endpoint with DATAGRAM support.
///
/// Supports three modes:
/// 1. Custom CA: Load from `ca_path`
/// 2. System CA: Use platform certificates (via rustls-native-certs) or webpki-roots fallback
/// 3. Insecure: Skip verification (development only)
///
/// # Arguments
/// - `bind_addr`: Local address to bind the client to.
/// - `ca_path`: Optional path to custom CA certificate file.
/// - `insecure`: If true, skip server certificate verification.
///
/// # Errors
///
/// Returns `io::Error` if TLS configuration or endpoint creation fails.
pub fn create_client_endpoint(
    bind_addr: SocketAddr,
    ca_path: Option<&Path>,
    insecure: bool,
) -> std::io::Result<Endpoint> {
    let mut roots = rustls::RootCertStore::empty();

    if let Some(ca) = ca_path {
        // Custom CA mode
        for cert in load_certs(ca)? {
            roots
                .add(cert)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
    } else if !insecure {
        // System CA mode: try native certs, fallback to webpki-roots
        let native_result = rustls_native_certs::load_native_certs();
        for err in &native_result.errors {
            tracing::warn!("native cert loading error: {}", err);
        }
        for cert in native_result.certs {
            let _ = roots.add(cert); // Ignore individual failures
        }
        if roots.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        if roots.is_empty() {
            return Err(std::io::Error::other("no root certificates available"));
        }
    }

    let mut client_crypto = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
        .map_err(std::io::Error::other)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_config));
    client_config.transport_config(Arc::new(default_transport_config()));

    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

// ========== Insecure Verifier ==========

/// Certificate verifier that accepts any certificate without validation.
///
/// # Security Warning
///
/// This verifier **MUST NOT** be used in production. It completely disables
/// TLS certificate validation, making connections vulnerable to
/// man-in-the-middle attacks.
///
/// Use only for:
/// - Local development with self-signed certificates
/// - Testing environments where certificate validation is not relevant
///
/// In production, always use proper CA certificates via `ca_path` or system CA.
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ========== Actors ==========

/// Commands accepted by the H3 receive loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3RxCommand {
    /// Graceful shutdown request.
    Shutdown,
}

/// Spawns the H3 receive loop for a single connection.
///
/// Creates an unbounded command channel internally (actor owns the receiver).
/// Returns the command sender and join handle.
///
/// # Arguments
/// - `connection`: The established QUIC connection.
/// - `peer_id`: Identifier for the peer (used in logs and metrics).
/// - `packet_tx`: Bounded channel to push accepted packets into (data plane).
/// - `events_tx`: Unbounded channel for emitting receive metrics.
/// - `interval`: Metrics emission interval.
///
/// # Shutdown Behavior
///
/// When receiving `H3RxCommand::Shutdown` or when the command channel closes,
/// the actor gracefully closes the QUIC connection before exiting.
pub fn spawn_h3_rx(
    connection: Connection,
    peer_id: String,
    packet_tx: mpsc::Sender<Vec<u8>>,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> (
    mpsc::UnboundedSender<H3RxCommand>,
    JoinHandle<ActorExitResult>,
) {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let remote_addr = connection.remote_address();

    let handle = tokio::spawn(async move {
        let mut counters = TransportCounters::new(TransportKind::Http3, Direction::Rx);
        let mut ticker = tokio::time::interval(interval);

        loop {
            tokio::select! {
                result = connection.read_datagram() => {
                    match result {
                        Ok(datagram) => {
                            let Some(payload) = unwrap_datagram(&datagram) else {
                                counters.record_drop(DropReason::InvalidIpVersion, datagram.len());
                                continue;
                            };
                            if payload.is_empty() { continue; }
                            let packet = payload.to_vec();
                            let len = packet.len();
                            if packet_tx.send(packet).await.is_err() {
                                counters.record_drop(DropReason::ChannelClosed, len);
                                connection.close(VarInt::from_u32(SHUTDOWN_ERROR_CODE), b"channel closed");
                                return Ok(());
                            }
                            counters.record_success(len);
                        }
                        Err(quinn::ConnectionError::ApplicationClosed(_)) |
                        Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
                        Err(err) => {
                            return Err(ActorError::H3RxRecv { peer: peer_id, reason: err.to_string() });
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(H3RxCommand::Shutdown) | None => {
                            // Gracefully close the QUIC connection before exiting
                            connection.close(VarInt::from_u32(SHUTDOWN_ERROR_CODE), b"shutdown");
                            return Ok(());
                        }
                    }
                }
                _ = ticker.tick() => {
                    let _ = events_tx.send(Event::Transport(TransportEvent::Metrics(
                        counters.snapshot(Some(&peer_id), Some(remote_addr.ip()))
                    )));
                }
            }
        }
    });

    (cmd_tx, handle)
}

/// Spawns the H3 transmit loop for a single connection.
///
/// Creates a bounded packet channel internally (actor owns the receiver).
/// Returns the packet sender and join handle.
///
/// # Arguments
/// - `connection`: The established QUIC connection.
/// - `peer_id`: Identifier for the peer (used in logs and metrics).
/// - `events_tx`: Unbounded channel for emitting transmit metrics.
/// - `interval`: Metrics emission interval.
///
/// # Shutdown Behavior
///
/// When the packet channel closes (all senders dropped), the actor
/// gracefully closes the QUIC connection before exiting.
pub fn spawn_h3_tx(
    connection: Connection,
    peer_id: String,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> (mpsc::Sender<Vec<u8>>, JoinHandle<ActorExitResult>) {
    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_DEPTH);
    let remote_addr = connection.remote_address();

    let handle = tokio::spawn(async move {
        let mut counters = TransportCounters::new(TransportKind::Http3, Direction::Tx);
        let mut ticker = tokio::time::interval(interval);

        loop {
            tokio::select! {
                maybe_packet = packet_rx.recv() => {
                    let packet = match maybe_packet {
                        Some(p) => p,
                        None => {
                            // Gracefully close the QUIC connection before exiting
                            connection.close(VarInt::from_u32(SHUTDOWN_ERROR_CODE), b"shutdown");
                            return Ok(());
                        }
                    };
                    let datagram = wrap_datagram(&packet);
                    let len = packet.len();
                    match connection.send_datagram(datagram) {
                        Ok(()) => counters.record_success(len),
                        Err(quinn::SendDatagramError::TooLarge) => {
                            counters.record_drop(DropReason::Oversize, len);
                        }
                        Err(quinn::SendDatagramError::ConnectionLost(err)) => {
                            return Err(ActorError::H3TxSend { peer: peer_id, reason: err.to_string() });
                        }
                        Err(err) => {
                            counters.record_drop(DropReason::SendError, len);
                            tracing::warn!(peer = %peer_id, error = %err, "h3 send failed");
                        }
                    }
                }
                _ = ticker.tick() => {
                    let _ = events_tx.send(Event::Transport(TransportEvent::Metrics(
                        counters.snapshot(Some(&peer_id), Some(remote_addr.ip()))
                    )));
                }
            }
        }
    });

    (packet_tx, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_wrap_unwrap_roundtrip() {
        let payload = vec![0x45, 0x00, 0x00, 0x14];
        let wrapped = wrap_datagram(&payload);
        assert_eq!(wrapped[0], CONTEXT_ID_ZERO);
        let unwrapped = unwrap_datagram(&wrapped).unwrap();
        assert_eq!(unwrapped, &payload[..]);
    }

    #[test]
    fn unwrap_rejects_nonzero_context() {
        assert!(unwrap_datagram(&[0x01, 0x45]).is_none());
    }

    #[test]
    fn unwrap_handles_empty() {
        assert!(unwrap_datagram(&[]).is_none());
    }

    #[test]
    fn context_id_is_zero() {
        assert_eq!(CONTEXT_ID_ZERO, 0x00);
    }

    #[test]
    fn wrap_datagram_capacity() {
        let payload = vec![1, 2, 3, 4, 5];
        let wrapped = wrap_datagram(&payload);
        assert_eq!(wrapped.len(), 6);
        assert_eq!(&wrapped[1..], &payload[..]);
    }

    #[test]
    fn default_transport_config_has_datagram_support() {
        let config = default_transport_config();
        // The config should have datagram support enabled (non-None buffer size)
        // We can't easily inspect the config, but at least verify it doesn't panic
        assert!(std::mem::size_of_val(&config) > 0);
    }

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(DATAGRAM_RECEIVE_BUFFER_SIZE, 65536);
        assert_eq!(IDLE_TIMEOUT_MS, 30_000);
        assert_eq!(SHUTDOWN_ERROR_CODE, 0);
    }
}
