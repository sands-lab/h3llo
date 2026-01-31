//! Actor error types for supervision and error propagation.
//!
//! Provides a unified error type for all actors, enabling the orchestrator
//! to distinguish between graceful shutdowns and actual errors.

use std::io;
use thiserror::Error;

/// Classifies actors by their supervision policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    /// Critical actors whose failure should exit h3llo.
    /// Includes: tun_rx, tun_tx, bare_rx, dns_resolver
    Critical,
    /// Restartable actors that could be reconnected on failure.
    /// Includes: bare_tx, h3_tx, h3_rx
    /// Note: Reconnection logic is not yet implemented.
    Restartable,
}

/// Exit result type for all actors.
///
/// - `Ok(())` indicates graceful shutdown (e.g., command channel closed).
/// - `Err(ActorError)` indicates an error exit requiring orchestrator action.
pub type ActorExitResult = Result<(), ActorError>;

/// Unified actor error type for orchestrator supervision.
///
/// Captures the actor identity and exit reason. Designed to be simple
/// (no per-actor subtypes) while still enabling pattern matching.
#[derive(Debug, Error)]
pub enum ActorError {
    /// TUN receive loop exited with I/O error.
    #[error("tun_rx[{name}]: recv failed: {source}")]
    TunRxRecv {
        /// TUN interface name.
        name: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// TUN transmit loop exited with I/O error.
    #[error("tun_tx[{name}]: send failed: {source}")]
    TunTxSend {
        /// TUN interface name.
        name: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// BareUDP receive loop exited with I/O error.
    #[error("bare_rx[{addr}]: recv failed: {source}")]
    BareRxRecv {
        /// Local socket address.
        addr: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// BareUDP transmit loop exited with I/O error.
    #[error("bare_tx[{dest}]: send failed: {source}")]
    BareTxSend {
        /// Destination address.
        dest: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// DNS resolver exited with I/O error.
    #[error("dns_resolver[{server}]: recv failed: {source}")]
    DnsRecv {
        /// DNS server address.
        server: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// HTTP/3 receive loop exited with error.
    #[error("h3_rx[{peer_id}]: recv failed: {reason}")]
    H3RxRecv {
        /// Peer identifier.
        peer_id: String,
        /// Failure reason.
        reason: String,
    },

    /// HTTP/3 transmit failed.
    #[error("h3_tx[{peer_id}]: send failed: {reason}")]
    H3TxSend {
        /// Peer identifier.
        peer_id: String,
        /// Failure reason.
        reason: String,
    },
}

impl ActorError {
    /// Returns the supervision classification for this error type.
    pub fn kind(&self) -> ActorKind {
        match self {
            // Critical actors - failure exits h3llo
            ActorError::TunRxRecv { .. } => ActorKind::Critical,
            ActorError::TunTxSend { .. } => ActorKind::Critical,
            ActorError::BareRxRecv { .. } => ActorKind::Critical,
            ActorError::DnsRecv { .. } => ActorKind::Critical,
            // Restartable actors - could be reconnected (future work)
            ActorError::BareTxSend { .. } => ActorKind::Restartable,
            ActorError::H3RxRecv { .. } => ActorKind::Restartable,
            ActorError::H3TxSend { .. } => ActorKind::Restartable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_kind_critical_for_infrastructure() {
        let errors = vec![
            ActorError::TunRxRecv {
                name: "tun0".into(),
                source: io::Error::new(io::ErrorKind::Other, "test"),
            },
            ActorError::TunTxSend {
                name: "tun0".into(),
                source: io::Error::new(io::ErrorKind::Other, "test"),
            },
            ActorError::BareRxRecv {
                addr: "0.0.0.0:5353".into(),
                source: io::Error::new(io::ErrorKind::Other, "test"),
            },
            ActorError::DnsRecv {
                server: "8.8.8.8:53".into(),
                source: io::Error::new(io::ErrorKind::Other, "test"),
            },
        ];
        for err in errors {
            assert_eq!(
                err.kind(),
                ActorKind::Critical,
                "expected Critical for {}",
                err
            );
        }
    }

    #[test]
    fn actor_kind_restartable_for_peer_actors() {
        let errors = vec![
            ActorError::BareTxSend {
                dest: "1.2.3.4:5353".into(),
                source: io::Error::new(io::ErrorKind::Other, "test"),
            },
            ActorError::H3RxRecv {
                peer_id: "peer-1".into(),
                reason: "connection reset".into(),
            },
            ActorError::H3TxSend {
                peer_id: "peer-1".into(),
                reason: "flow control".into(),
            },
        ];
        for err in errors {
            assert_eq!(
                err.kind(),
                ActorKind::Restartable,
                "expected Restartable for {}",
                err
            );
        }
    }

    #[test]
    fn actor_error_display_includes_context() {
        let err = ActorError::TunRxRecv {
            name: "tun0".to_string(),
            source: io::Error::new(io::ErrorKind::Other, "test"),
        };
        let msg = err.to_string();
        assert!(msg.contains("tun_rx"));
        assert!(msg.contains("tun0"));
        assert!(msg.contains("recv failed"));
    }

    #[test]
    fn actor_error_bare_tx_includes_dest() {
        let err = ActorError::BareTxSend {
            dest: "192.168.1.1:5353".to_string(),
            source: io::Error::new(io::ErrorKind::Other, "test"),
        };
        let msg = err.to_string();
        assert!(msg.contains("bare_tx"));
        assert!(msg.contains("192.168.1.1:5353"));
    }

    #[test]
    fn actor_error_dns_recv_includes_server() {
        let err = ActorError::DnsRecv {
            server: "8.8.8.8:53".to_string(),
            source: io::Error::new(io::ErrorKind::TimedOut, "timeout"),
        };
        let msg = err.to_string();
        assert!(msg.contains("dns_resolver"));
        assert!(msg.contains("8.8.8.8:53"));
        assert!(msg.contains("recv failed"));
    }

    #[test]
    fn actor_error_h3_rx_includes_peer() {
        let err = ActorError::H3RxRecv {
            peer_id: "node-2".to_string(),
            reason: "connection reset".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("h3_rx"));
        assert!(msg.contains("node-2"));
        assert!(msg.contains("connection reset"));
    }

    #[test]
    fn actor_error_h3_tx_includes_peer() {
        let err = ActorError::H3TxSend {
            peer_id: "node-3".to_string(),
            reason: "flow control blocked".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("h3_tx"));
        assert!(msg.contains("node-3"));
        assert!(msg.contains("flow control blocked"));
    }
}
