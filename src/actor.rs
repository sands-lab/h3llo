//! Actor infrastructure: errors, runtimes, spawning, and supervision.
//!
//! [`ActorBus`] owns all Tokio runtimes and is the only production entry point
//! for spawning asynchronous tasks. Supervision policy is attached to an actor
//! instance at spawn time instead of being inferred from its error variant.

use std::future::Future;
use std::io;

use thiserror::Error;
use tokio::runtime::{Builder, Handle};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinSet};
use tokio_util::task::AbortOnDropHandle;
use tracing::error;

/// Determines how the orchestrator handles an actor instance's exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisionPolicy {
    /// An unexpected exit terminates h3llo.
    ///
    /// Used for infrastructure shared by the process or a listener bundle.
    Critical,
    /// An exit asks the orchestrator to reconcile peer connections.
    ///
    /// Used for actors whose lifetime is scoped to one peer connection.
    Restartable,
    /// Short-lived tasks whose exit is logged but requires no recovery action.
    Detached,
}

/// Runtime selected for an actor task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorRuntime {
    /// The runtime driving the orchestrator.
    Main,
    /// Dedicated runtime for TUN I/O.
    Tun,
    /// Dedicated runtime for routing and protocol work.
    Crypto,
    /// Dedicated runtime for UDP I/O.
    Udp,
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

    /// H3 dispatcher actor exited unexpectedly.
    #[error("h3_dispatcher[{addr}]: {reason}")]
    H3Dispatcher {
        /// Listener address.
        addr: String,
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

/// A `current_thread` Tokio runtime pinned to a dedicated OS thread.
///
/// The background thread runs `Runtime::block_on`, which drives the I/O
/// reactor and task scheduler. Tasks are submitted via [`handle()`](Self::handle)
/// or by entering the runtime context with `handle().enter()` before creating
/// runtime-bound I/O resources.
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

#[derive(Clone)]
struct RuntimeHandles {
    main: Handle,
    tun: Handle,
    crypto: Handle,
    udp: Handle,
}

impl RuntimeHandles {
    fn get(&self, runtime: ActorRuntime) -> &Handle {
        match runtime {
            ActorRuntime::Main => &self.main,
            ActorRuntime::Tun => &self.tun,
            ActorRuntime::Crypto => &self.crypto,
            ActorRuntime::Udp => &self.udp,
        }
    }
}

struct ActorRegistration {
    name: String,
    policy: SupervisionPolicy,
    task: AbortOnDropHandle<ActorExitResult>,
}

type MonitoredActor = (String, Result<ActorExitResult, JoinError>);

/// Cloneable actor spawning handle.
///
/// Every production task must be spawned through this handle so its runtime
/// and supervision policy are registered together.
#[derive(Clone)]
pub struct ActorBusHandle {
    runtimes: RuntimeHandles,
    registrations_tx: mpsc::UnboundedSender<ActorRegistration>,
}

impl ActorBusHandle {
    /// Spawns and registers an actor on the selected runtime.
    ///
    /// # Arguments
    ///
    /// * `name` - Stable diagnostic name for the actor instance.
    /// * `runtime` - Runtime on which the future is executed.
    /// * `policy` - Action category reported when the task exits.
    /// * `future` - Actor future returning the common actor exit result.
    pub fn spawn<F>(
        &self,
        name: impl Into<String>,
        runtime: ActorRuntime,
        policy: SupervisionPolicy,
        future: F,
    ) where
        F: Future<Output = ActorExitResult> + Send + 'static,
    {
        let name = name.into();
        let task = AbortOnDropHandle::new(self.runtimes.get(runtime).spawn(future));
        if let Err(registration) =
            self.registrations_tx
                .send(ActorRegistration { name, policy, task })
        {
            error!(
                actor = %registration.0.name,
                "actor bus closed while registering task; aborting actor"
            );
            // `AbortOnDropHandle` aborts the unregistered task here.
        }
    }

    /// Returns the Tokio handle for constructing runtime-bound I/O resources.
    ///
    /// Actor tasks must still be started with [`spawn`](Self::spawn); this
    /// escape hatch only exists because types such as `UdpSocket` and
    /// `AsyncFd` must be registered while the target runtime is entered.
    #[must_use]
    pub(crate) fn runtime_handle(&self, runtime: ActorRuntime) -> &Handle {
        self.runtimes.get(runtime)
    }
}

/// Actor exit notification returned by [`ActorBus::next_exit`].
#[derive(Debug)]
pub struct ActorBusExit {
    /// Stable diagnostic actor name supplied at spawn time.
    pub name: String,
    /// Spawn-time supervision policy for this actor instance.
    pub policy: SupervisionPolicy,
    /// Actor completion or Tokio join failure.
    pub result: Result<ActorExitResult, JoinError>,
}

/// Owns actor runtimes and supervises every production asynchronous task.
///
/// The initial implementation intentionally covers only runtime ownership,
/// spawning, and exit classification. Future work should add typed command and
/// event endpoints, metrics handles, cancellation, and actor-group lifecycle
/// propagation here so communication availability follows actor lifetime.
pub struct ActorBus {
    // Drop monitor sets before runtimes. Their AbortOnDropHandle futures abort
    // the underlying actor tasks instead of silently detaching them.
    critical_tasks: JoinSet<MonitoredActor>,
    restartable_tasks: JoinSet<MonitoredActor>,
    detached_tasks: JoinSet<MonitoredActor>,
    registrations_rx: mpsc::UnboundedReceiver<ActorRegistration>,
    handle: ActorBusHandle,
    _dedicated: Option<[DedicatedRuntime; 3]>,
}

impl ActorBus {
    /// Creates the production actor bus and its dedicated runtimes.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a Tokio runtime or its OS thread cannot be
    /// created.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime.
    pub fn new() -> io::Result<Self> {
        let tun = DedicatedRuntime::new("h3llo-tun")?;
        let crypto = DedicatedRuntime::new("h3llo-crypto")?;
        let udp = DedicatedRuntime::new("h3llo-udp")?;
        let runtimes = RuntimeHandles {
            main: Handle::current(),
            tun: tun.handle().clone(),
            crypto: crypto.handle().clone(),
            udp: udp.handle().clone(),
        };
        let (registrations_tx, registrations_rx) = mpsc::unbounded_channel();
        Ok(Self {
            critical_tasks: JoinSet::new(),
            restartable_tasks: JoinSet::new(),
            detached_tasks: JoinSet::new(),
            registrations_rx,
            handle: ActorBusHandle {
                runtimes,
                registrations_tx,
            },
            _dedicated: Some([tun, crypto, udp]),
        })
    }

    /// Creates an actor bus that maps every runtime class to the current runtime.
    ///
    /// This is intended for tests and embedders that do not need dedicated
    /// data-plane threads.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime.
    #[must_use]
    pub fn on_current_runtime() -> Self {
        let current = Handle::current();
        let (registrations_tx, registrations_rx) = mpsc::unbounded_channel();
        Self {
            critical_tasks: JoinSet::new(),
            restartable_tasks: JoinSet::new(),
            detached_tasks: JoinSet::new(),
            registrations_rx,
            handle: ActorBusHandle {
                runtimes: RuntimeHandles {
                    main: current.clone(),
                    tun: current.clone(),
                    crypto: current.clone(),
                    udp: current,
                },
                registrations_tx,
            },
            _dedicated: None,
        }
    }

    /// Returns a cloneable actor spawning handle.
    #[must_use]
    pub fn handle(&self) -> ActorBusHandle {
        self.handle.clone()
    }

    /// Waits for the next actor exit, registering concurrently spawned actors.
    ///
    /// # Returns
    ///
    /// The actor name, its spawn-time policy, and either its exit result or a
    /// Tokio join error.
    pub async fn next_exit(&mut self) -> ActorBusExit {
        loop {
            tokio::select! {
                Some(registration) = self.registrations_rx.recv() => {
                    let ActorRegistration { name, policy, task } = registration;
                    let monitor = async move { (name, task.await) };
                    let main = self.handle.runtimes.get(ActorRuntime::Main);
                    match policy {
                        SupervisionPolicy::Critical => {
                            self.critical_tasks.spawn_on(monitor, main);
                        }
                        SupervisionPolicy::Restartable => {
                            self.restartable_tasks.spawn_on(monitor, main);
                        }
                        SupervisionPolicy::Detached => {
                            self.detached_tasks.spawn_on(monitor, main);
                        }
                    }
                }
                result = self.critical_tasks.join_next(), if !self.critical_tasks.is_empty() => {
                    return Self::completed(SupervisionPolicy::Critical, result);
                }
                result = self.restartable_tasks.join_next(), if !self.restartable_tasks.is_empty() => {
                    return Self::completed(SupervisionPolicy::Restartable, result);
                }
                result = self.detached_tasks.join_next(), if !self.detached_tasks.is_empty() => {
                    return Self::completed(SupervisionPolicy::Detached, result);
                }
            }
        }
    }

    fn completed(
        policy: SupervisionPolicy,
        result: Option<Result<MonitoredActor, JoinError>>,
    ) -> ActorBusExit {
        match result {
            Some(Ok((name, Ok(actor_result)))) => ActorBusExit {
                name,
                policy,
                result: Ok(actor_result),
            },
            Some(Ok((name, Err(join_error)))) => ActorBusExit {
                name,
                policy,
                result: Err(join_error),
            },
            Some(Err(join_error)) => ActorBusExit {
                name: "actor-monitor".to_string(),
                policy,
                result: Err(join_error),
            },
            None => unreachable!("guarded JoinSet cannot be empty"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn actor_error_h3_dispatcher_includes_addr() {
        let err = ActorError::H3Dispatcher {
            addr: "0.0.0.0:443".into(),
            reason: "watcher channel closed".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("h3_dispatcher[0.0.0.0:443]"));
        assert!(msg.contains("watcher channel closed"));
    }

    #[tokio::test]
    async fn spawn_policy_is_independent_of_error_variant() {
        let mut bus = ActorBus::on_current_runtime();
        let handle = bus.handle();
        handle.spawn(
            "listener-udp-tx",
            ActorRuntime::Main,
            SupervisionPolicy::Critical,
            async {
                Err(ActorError::UdpTxSend {
                    addr: "0.0.0.0:443".into(),
                    source: io::Error::other("test"),
                })
            },
        );

        let exit = bus.next_exit().await;
        assert_eq!(exit.name, "listener-udp-tx");
        assert_eq!(exit.policy, SupervisionPolicy::Critical);
        assert!(matches!(exit.result, Ok(Err(ActorError::UdpTxSend { .. }))));

        handle.spawn(
            "peer-udp-tx",
            ActorRuntime::Main,
            SupervisionPolicy::Restartable,
            async {
                Err(ActorError::UdpTxSend {
                    addr: "192.0.2.1:443".into(),
                    source: io::Error::other("test"),
                })
            },
        );

        let exit = bus.next_exit().await;
        assert_eq!(exit.name, "peer-udp-tx");
        assert_eq!(exit.policy, SupervisionPolicy::Restartable);
        assert!(matches!(exit.result, Ok(Err(ActorError::UdpTxSend { .. }))));
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
