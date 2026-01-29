//! Actor error types for supervision and error propagation.
//!
//! Provides a unified error type for all actors, enabling the orchestrator
//! to distinguish between graceful shutdowns and actual errors.

use std::io;
use thiserror::Error;

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
    #[error("h3_rx[{peer}]: recv failed: {reason}")]
    H3RxRecv {
        /// Peer identifier.
        peer: String,
        /// Error description.
        reason: String,
    },

    /// HTTP/3 transmit loop exited with error.
    #[error("h3_tx[{peer}]: send failed: {reason}")]
    H3TxSend {
        /// Peer identifier.
        peer: String,
        /// Error description.
        reason: String,
    },

    /// HTTP/3 dial failed.
    #[error("h3_dial[{peer}]: dial failed: {reason}")]
    H3Dial {
        /// Peer identifier.
        peer: String,
        /// Error description.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
