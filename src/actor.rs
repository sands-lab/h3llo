//! Actor infrastructure: error types, supervision policy, and dedicated runtimes.
//!
//! Provides a unified error type for all actors, enabling the orchestrator
//! to distinguish between graceful shutdowns and actual errors. Also provides
//! [`DedicatedRuntime`] for thread-per-core actor scheduling.

use std::io;

use thiserror::Error;
use tokio::runtime::{Builder, Handle};
use tokio::sync::oneshot;
use tracing::error;

/// Determines how the orchestrator handles an actor failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisionPolicy {
    /// Critical actors whose failure should exit h3llo.
    /// Includes: `tun_rx`, `tun_tx`, `udp_rx`, `dns_resolver`
    Critical,
    /// Restartable actors that could be reconnected on failure.
    /// Includes: `udp_tx`, `h3_tx`, `h3_rx`
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

    /// UDP receive loop exited with I/O error.
    #[error("udp_rx[{addr}]: recv failed: {source}")]
    UdpRxRecv {
        /// Local socket address of the UDP actor.
        addr: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// UDP transmit loop exited with I/O error.
    #[error("udp_tx[{addr}]: send failed: {source}")]
    UdpTxSend {
        /// Local socket address of the UDP actor.
        addr: String,
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

    /// HTTP/3 transmit failed.
    #[error("h3_tx[{peer_id}]: send failed: {reason}")]
    H3TxSend {
        /// Peer identifier.
        peer_id: String,
        /// Failure reason.
        reason: String,
    },

    /// H3 engine actor exited with error.
    #[error("h3[{peer_id}]: {reason}")]
    H3Engine {
        /// Peer identifier.
        peer_id: String,
        /// Failure reason.
        reason: String,
    },

    /// Management API server exited with I/O error.
    #[error("api[{addr}]: server failed: {reason}")]
    ApiServer {
        /// Listen address.
        addr: String,
        /// Failure reason.
        reason: String,
    },

    /// Router actor exited unexpectedly.
    #[error("router: fatal error: {reason}")]
    RouterFailed {
        /// Failure reason.
        reason: String,
    },
}

impl ActorError {
    /// Returns the supervision classification for this error type.
    #[must_use]
    pub fn kind(&self) -> SupervisionPolicy {
        match self {
            // Critical actors - failure exits h3llo
            ActorError::TunRxRecv { .. }
            | ActorError::TunTxSend { .. }
            | ActorError::UdpRxRecv { .. }
            | ActorError::DnsRecv { .. }
            | ActorError::ApiServer { .. }
            | ActorError::RouterFailed { .. } => SupervisionPolicy::Critical,
            // Restartable actors - could be reconnected (future work)
            ActorError::UdpTxSend { .. }
            | ActorError::H3TxSend { .. }
            | ActorError::H3Engine { .. } => SupervisionPolicy::Restartable,
        }
    }
}

/// A `current_thread` Tokio runtime pinned to a dedicated OS thread.
///
/// The background thread runs `Runtime::block_on`, which drives the I/O
/// reactor and task scheduler. Tasks are submitted via [`handle()`](Self::handle)
/// or by entering the runtime context with `handle().enter()` before calling
/// `tokio::spawn`.
///
/// # Shutdown
///
/// On drop, the shutdown signal is sent (causing `block_on` to return),
/// the runtime is dropped (cancelling all tasks), and the thread is joined.
pub(crate) struct DedicatedRuntime {
    handle: Handle,
    /// Dropping this sender signals the runtime to shut down.
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl DedicatedRuntime {
    /// Creates a new dedicated runtime on a fresh OS thread.
    ///
    /// # Arguments
    ///
    /// * `name` - Thread name (visible in `top`, `htop`, debuggers).
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if the Tokio runtime or OS thread cannot be created.
    pub(crate) fn new(name: &str) -> io::Result<Self> {
        let rt = Builder::new_current_thread().enable_all().build()?;

        let handle = rt.handle().clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let thread_name = name.to_string();

        let thread = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                // block_on drives the I/O reactor and executes spawned tasks.
                // Returns when shutdown_rx resolves (sender dropped or sent).
                rt.block_on(async {
                    let _ = shutdown_rx.await;
                });
                // Runtime dropped here -> all remaining tasks cancelled.
            })?;

        Ok(Self {
            handle,
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    /// Returns a handle for spawning tasks or entering this runtime's context.
    pub(crate) fn handle(&self) -> &Handle {
        &self.handle
    }
}

impl Drop for DedicatedRuntime {
    fn drop(&mut self) {
        // Signal shutdown -- receiver resolves, block_on returns, runtime drops.
        drop(self.shutdown_tx.take());
        // Join the thread to ensure clean exit.
        if let Some(thread) = self.thread.take() {
            if let Err(payload) = thread.join() {
                // Extract a useful message from the panic payload.
                let msg = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("<non-string panic>");
                error!("dedicated runtime thread panicked: {msg}");
            }
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
                source: io::Error::other("test"),
            },
            ActorError::TunTxSend {
                name: "tun0".into(),
                source: io::Error::other("test"),
            },
            ActorError::UdpRxRecv {
                addr: "0.0.0.0:5353".into(),
                source: io::Error::other("test"),
            },
            ActorError::DnsRecv {
                server: "8.8.8.8:53".into(),
                source: io::Error::other("test"),
            },
            ActorError::ApiServer {
                addr: "127.0.0.1:9090".into(),
                reason: "bind failed".into(),
            },
        ];
        for err in errors {
            assert_eq!(
                err.kind(),
                SupervisionPolicy::Critical,
                "expected Critical for {}",
                err
            );
        }
    }

    #[test]
    fn actor_kind_restartable_for_peer_actors() {
        let errors = vec![
            ActorError::UdpTxSend {
                addr: "1.2.3.4:5353".into(),
                source: io::Error::other("test"),
            },
            ActorError::H3TxSend {
                peer_id: "peer-1".into(),
                reason: "flow control".into(),
            },
        ];
        for err in errors {
            assert_eq!(
                err.kind(),
                SupervisionPolicy::Restartable,
                "expected Restartable for {}",
                err
            );
        }
    }

    #[test]
    fn actor_error_display_includes_context() {
        let err = ActorError::TunRxRecv {
            name: "tun0".to_string(),
            source: io::Error::other("test"),
        };
        let msg = err.to_string();
        assert!(msg.contains("tun_rx"));
        assert!(msg.contains("tun0"));
        assert!(msg.contains("recv failed"));
    }

    #[test]
    fn actor_error_udp_tx_includes_addr() {
        let err = ActorError::UdpTxSend {
            addr: "192.168.1.1:5353".to_string(),
            source: io::Error::other("test"),
        };
        let msg = err.to_string();
        assert!(msg.contains("udp_tx"));
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

    #[test]
    fn actor_kind_restartable_for_h3_engine() {
        let err = ActorError::H3Engine {
            peer_id: "client-1".into(),
            reason: "connection reset".into(),
        };
        assert_eq!(err.kind(), SupervisionPolicy::Restartable);
        let msg = err.to_string();
        assert!(msg.contains("h3[client-1]"));
    }

    #[tokio::test]
    async fn dedicated_runtime_spawns_and_completes_tasks() {
        let rt = DedicatedRuntime::new("test-rt").expect("test runtime");
        let result = rt
            .handle()
            .spawn(async { 42 })
            .await
            .expect("task should complete");
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn cross_runtime_join_handle_await() {
        let rt = DedicatedRuntime::new("test-cross").expect("test runtime");
        let join = rt.handle().spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            "hello"
        });
        let result = join.await.expect("cross-runtime await should work");
        assert_eq!(result, "hello");
    }
}
