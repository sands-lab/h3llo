//! Actor infrastructure: errors, runtimes, spawning, and supervision.
//!
//! [`ActorBus`] owns all Tokio runtimes and drives supervision. Actors spawn
//! children through their [`ActorContext`], attaching supervision policy to
//! each instance instead of inferring it from the returned error.

use std::future::Future;
use std::io;

use crate::events::Event;
use tokio::runtime::{Builder, Handle};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinSet};
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, error};

/// Determines how an actor owner handles an actor instance's exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisionPolicy {
    /// An unexpected exit terminates h3llo.
    ///
    /// Used for infrastructure shared by the process or a listener bundle.
    Critical,
    /// An exit asks the owner to reconcile peer connections.
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
/// - `Ok(())` indicates graceful shutdown (e.g., after receiving [`Event::Stop`]).
/// - `Err(error)` indicates an error exit requiring owner action.
pub type ActorExitResult = anyhow::Result<()>;

/// Address used to send control-plane events to one actor instance.
#[derive(Clone)]
pub struct ActorRef {
    name: String,
    tx: mpsc::UnboundedSender<Event>,
}

/// Inbox and bus access owned by a running actor.
pub struct ActorContext {
    myself: ActorRef,
    owner: ActorRef,
    inbox: mpsc::UnboundedReceiver<Event>,
    runtimes: RuntimeHandles,
    registrations_tx: mpsc::UnboundedSender<ActorRegistration>,
}

impl ActorContext {
    /// Returns this actor's address.
    #[must_use]
    pub fn myself(&self) -> &ActorRef {
        &self.myself
    }

    /// Sends a control-plane event directly to an actor.
    ///
    /// # Errors
    ///
    /// Returns the unsent event when the target actor's inbox is closed.
    pub fn send(
        &self,
        target: &ActorRef,
        message: Event,
    ) -> Result<(), mpsc::error::SendError<Event>> {
        target.tx.send(message)
    }

    /// Sends a control-plane event to this actor's inherited owner.
    ///
    /// # Errors
    ///
    /// Returns the unsent event when the owner's inbox is closed.
    pub fn notify_owner(&self, message: Event) -> Result<(), mpsc::error::SendError<Event>> {
        self.owner.tx.send(message)
    }

    /// Spawns and registers an actor on the selected runtime.
    ///
    /// The new context inherits this context's owner. Events sent with
    /// [`notify_owner`](Self::notify_owner) and exit notifications therefore
    /// reach the same owner without passing an [`ActorRef`] through actor code.
    ///
    /// # Arguments
    ///
    /// * `name` - Stable diagnostic name for the actor instance.
    /// * `runtime` - Runtime on which the future is executed.
    /// * `policy` - Action category reported when the task exits.
    /// * `actor` - Factory receiving the child actor's context and returning its future.
    ///
    /// # Returns
    ///
    /// An address for sending control-plane events to the spawned actor.
    #[must_use]
    pub fn spawn<F, Fut>(
        &self,
        name: impl Into<String>,
        runtime: ActorRuntime,
        policy: SupervisionPolicy,
        actor: F,
    ) -> ActorRef
    where
        F: FnOnce(ActorContext) -> Fut,
        Fut: Future<Output = ActorExitResult> + Send + 'static,
    {
        let (tx, inbox) = mpsc::unbounded_channel();
        let actor_ref = ActorRef {
            name: name.into(),
            tx,
        };
        let ctx = Self {
            myself: actor_ref.clone(),
            owner: self.owner.clone(),
            inbox,
            runtimes: self.runtimes.clone(),
            registrations_tx: self.registrations_tx.clone(),
        };
        let task = AbortOnDropHandle::new(self.runtimes.get(runtime).spawn(actor(ctx)));
        let registration = ActorRegistration {
            name: actor_ref.name.clone(),
            policy,
            owner: self.owner.clone(),
            task,
        };
        if let Err(registration) = self.registrations_tx.send(registration) {
            error!(
                actor = %registration.0.name,
                "actor bus closed while registering task; aborting actor"
            );
            // `AbortOnDropHandle` aborts the unregistered task here.
        }
        actor_ref
    }

    /// Runs a synchronous operation on the selected runtime.
    ///
    /// This is intended for short initialization that must construct an I/O
    /// resource inside a particular runtime's reactor. Actor tasks must still
    /// be started with [`spawn`](Self::spawn).
    ///
    /// # Arguments
    ///
    /// * `runtime` - Runtime on which the operation is executed.
    /// * `operation` - Synchronous operation to execute.
    ///
    /// # Errors
    ///
    /// Returns [`JoinError`] if the operation panics or its task is cancelled.
    pub(crate) async fn run_on<F, T>(
        &self,
        runtime: ActorRuntime,
        operation: F,
    ) -> Result<T, JoinError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        AbortOnDropHandle::new(self.runtimes.get(runtime).spawn(async move { operation() })).await
    }

    /// Receives the next control-plane event.
    ///
    /// Actors normally terminate on [`Event::Stop`]. The actor context retains
    /// its own address, so dropping external [`ActorRef`] values does not close
    /// the inbox while the actor is running.
    pub async fn recv(&mut self) -> Option<Event> {
        self.inbox.recv().await
    }

    /// Waits until the actor receives a stop event or its inbox closes.
    ///
    /// Non-stop events are logged and discarded. This method must only be
    /// used by actors whose control inbox accepts no events other than
    /// [`Event::Stop`].
    pub async fn wait_for_stop(&mut self) {
        loop {
            match self.recv().await {
                Some(Event::Stop) | None => return,
                Some(event) => {
                    debug!(
                        actor = %self.myself.name,
                        ?event,
                        "actor ignoring unexpected event"
                    );
                }
            }
        }
    }

    /// Runs an external asynchronous operation until it completes or the actor stops.
    ///
    /// Stop takes priority when both branches are ready. The operation future
    /// is dropped when stopping wins, so callers must ensure that cancelling
    /// the operation is valid during actor shutdown.
    ///
    /// This method is intended for external I/O whose lifetime is not governed
    /// by actor-owned channels. Internal channel operations should complete
    /// normally so they preserve backpressure and report endpoint closure.
    ///
    /// Non-stop events are logged and discarded. This method must only be
    /// used by actors whose control inbox accepts no events other than
    /// [`Event::Stop`].
    ///
    /// # Arguments
    ///
    /// * `operation` - Future to run while listening for a stop event.
    ///
    /// # Returns
    ///
    /// Returns `Some(output)` when the operation completes, or `None` when the
    /// actor stops first.
    pub async fn run_until_stopped<F>(&mut self, operation: F) -> Option<F::Output>
    where
        F: Future,
    {
        tokio::select! {
            biased;
            () = self.wait_for_stop() => None,
            output = operation => Some(output),
        }
    }

    /// Attempts to receive a control-plane event without waiting.
    ///
    /// # Errors
    ///
    /// Returns [`mpsc::error::TryRecvError::Empty`] when no message is ready,
    /// or [`mpsc::error::TryRecvError::Disconnected`] when the inbox is closed.
    #[cfg(test)]
    pub(crate) fn try_recv(&mut self) -> Result<Event, mpsc::error::TryRecvError> {
        self.inbox.try_recv()
    }
}

#[cfg(test)]
pub(crate) async fn next_actor_exit(
    bus: &mut ActorBus,
    supervisor: &mut ActorContext,
) -> ActorExit {
    loop {
        tokio::select! {
            message = supervisor.recv() => {
                if let Some(Event::ActorExited(exit)) = message {
                    return exit;
                }
            }
            result = bus.drive() => result.expect("actor bus monitor"),
        }
    }
}

/// A `current_thread` Tokio runtime pinned to a dedicated OS thread.
///
/// The background thread runs `Runtime::block_on`, which drives the I/O
/// reactor and task scheduler. `ActorBus` uses its handle internally to run
/// actors and construct runtime-bound I/O resources.
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
    owner: ActorRef,
    task: AbortOnDropHandle<ActorExitResult>,
}

/// Exit notification sent to an actor's owner.
#[derive(Debug)]
pub struct ActorExit {
    /// Diagnostic name supplied at spawn time.
    pub name: String,
    /// Spawn-time supervision policy for this actor instance.
    pub policy: SupervisionPolicy,
    /// Actor completion or Tokio join failure.
    pub result: Result<ActorExitResult, JoinError>,
}

/// Owns actor runtimes and supervises every production asynchronous task.
///
/// TODO: Add actor-group membership and propagate group exits through the same
/// event path. Metrics and coordinated cancellation can then share actor
/// identity without introducing a second lifecycle registry.
pub struct ActorBus {
    // Drop task monitors before runtimes. Their AbortOnDropHandle futures abort
    // the underlying actor tasks instead of silently detaching them.
    tasks: JoinSet<()>,
    runtimes: RuntimeHandles,
    registrations_tx: mpsc::UnboundedSender<ActorRegistration>,
    registrations_rx: mpsc::UnboundedReceiver<ActorRegistration>,
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
            tun: tun.handle.clone(),
            crypto: crypto.handle.clone(),
            udp: udp.handle.clone(),
        };
        let (registrations_tx, registrations_rx) = mpsc::unbounded_channel();
        Ok(Self {
            tasks: JoinSet::new(),
            runtimes,
            registrations_tx,
            registrations_rx,
            _dedicated: Some([tun, crypto, udp]),
        })
    }

    /// Creates a test actor bus that maps every runtime class to the current runtime.
    ///
    /// Available to unit tests and consumers of the `test-utils` feature.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn on_current_runtime() -> Self {
        let current = Handle::current();
        let (registrations_tx, registrations_rx) = mpsc::unbounded_channel();
        Self {
            tasks: JoinSet::new(),
            runtimes: RuntimeHandles {
                main: current.clone(),
                tun: current.clone(),
                crypto: current.clone(),
                udp: current,
            },
            registrations_tx,
            registrations_rx,
            _dedicated: None,
        }
    }

    /// Creates an addressable mailbox for an externally driven root actor.
    ///
    /// The returned context is not registered as a spawned task. This is used
    /// by the orchestrator, which is driven directly by [`crate::run`]. The
    /// root context owns itself, and spawned contexts inherit that ownership.
    ///
    /// # Arguments
    ///
    /// * `name` - Stable diagnostic name for the root actor.
    #[must_use]
    pub fn mailbox(&self, name: impl Into<String>) -> ActorContext {
        let (tx, inbox) = mpsc::unbounded_channel();
        let actor_ref = ActorRef {
            name: name.into(),
            tx,
        };
        ActorContext {
            myself: actor_ref.clone(),
            owner: actor_ref,
            inbox,
            runtimes: self.runtimes.clone(),
            registrations_tx: self.registrations_tx.clone(),
        }
    }

    /// Drives actor registration and exit notification delivery.
    ///
    /// # Errors
    ///
    /// Returns [`JoinError`] if an internal monitor task fails.
    pub async fn drive(&mut self) -> Result<(), JoinError> {
        tokio::select! {
            Some(registration) = self.registrations_rx.recv() => {
                let ActorRegistration { name, policy, owner, task } = registration;
                let monitor = async move {
                    let exit = ActorExit {
                        name,
                        policy,
                        result: task.await,
                    };
                    if let Err(error) = owner.tx.send(Event::ActorExited(exit)) {
                        error!(
                            owner = %owner.name,
                            message = ?error.0,
                            "actor owner inbox closed"
                        );
                    }
                };
                let main = self.runtimes.get(ActorRuntime::Main);
                self.tasks.spawn_on(monitor, main);
                Ok(())
            }
            result = self.tasks.join_next(), if !self.tasks.is_empty() => {
                result.expect("guarded JoinSet cannot be empty").map(drop)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawn_policy_is_independent_of_error_value() {
        let mut bus = ActorBus::on_current_runtime();
        let mut supervisor = bus.mailbox("test-supervisor");
        let _actor_ref = supervisor.spawn(
            "listener-udp-tx",
            ActorRuntime::Main,
            SupervisionPolicy::Critical,
            |_context| async { Err(anyhow::anyhow!("listener send failed")) },
        );

        let exit = next_actor_exit(&mut bus, &mut supervisor).await;
        assert_eq!(exit.name, "listener-udp-tx");
        assert_eq!(exit.policy, SupervisionPolicy::Critical);
        assert!(matches!(exit.result, Ok(Err(_))));

        let _actor_ref = supervisor.spawn(
            "peer-udp-tx",
            ActorRuntime::Main,
            SupervisionPolicy::Restartable,
            |_context| async { Err(anyhow::anyhow!("peer send failed")) },
        );

        let exit = next_actor_exit(&mut bus, &mut supervisor).await;
        assert_eq!(exit.name, "peer-udp-tx");
        assert_eq!(exit.policy, SupervisionPolicy::Restartable);
        assert!(matches!(exit.result, Ok(Err(_))));
    }

    #[tokio::test]
    async fn send_reports_closed_actor_inbox() {
        let mut bus = ActorBus::on_current_runtime();
        let mut supervisor = bus.mailbox("test-supervisor");
        let actor = supervisor.spawn(
            "short-lived",
            ActorRuntime::Main,
            SupervisionPolicy::Detached,
            |_context| async { Ok(()) },
        );

        next_actor_exit(&mut bus, &mut supervisor).await;
        assert!(supervisor.send(&actor, Event::Stop).is_err());
    }

    #[tokio::test]
    async fn nested_actor_exit_is_reported_to_root_owner() {
        let mut bus = ActorBus::on_current_runtime();
        let mut owner = bus.mailbox("test-owner");
        let _parent = owner.spawn(
            "parent",
            ActorRuntime::Main,
            SupervisionPolicy::Detached,
            |ctx| async move {
                let _child = ctx.spawn(
                    "child",
                    ActorRuntime::Main,
                    SupervisionPolicy::Critical,
                    |_ctx| async { Err(anyhow::anyhow!("child failed")) },
                );
                std::future::pending::<()>().await;
                Ok(())
            },
        );

        let exit = next_actor_exit(&mut bus, &mut owner).await;
        assert_eq!(exit.name, "child");
        assert_eq!(exit.policy, SupervisionPolicy::Critical);
        assert!(matches!(exit.result, Ok(Err(_))));
    }

    #[tokio::test]
    async fn dedicated_runtime_spawns_and_completes_tasks() {
        let rt = DedicatedRuntime::new("test-rt").expect("test runtime");
        let result = rt
            .handle
            .spawn(async { 42 })
            .await
            .expect("task should complete");
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn cross_runtime_join_handle_await() {
        let rt = DedicatedRuntime::new("test-cross").expect("test runtime");
        let join = rt.handle.spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            "hello"
        });
        let result = join.await.expect("cross-runtime await should work");
        assert_eq!(result, "hello");
    }

    #[tokio::test]
    async fn run_on_executes_on_selected_runtime() {
        let bus = ActorBus::new().expect("actor bus");
        let ctx = bus.mailbox("test-root");
        let thread_name = ctx
            .run_on(ActorRuntime::Tun, || {
                std::thread::current().name().map(str::to_owned)
            })
            .await
            .expect("operation should complete");

        assert_eq!(thread_name.as_deref(), Some("h3llo-tun"));
    }

    #[tokio::test]
    async fn run_until_stopped_ignores_other_events_and_prioritizes_stop() {
        let bus = ActorBus::on_current_runtime();
        let mut ctx = bus.mailbox("test-root");
        let actor = ctx.myself().clone();
        ctx.send(
            &actor,
            Event::SetHostnames {
                hosts: Default::default(),
            },
        )
        .unwrap();

        let output = ctx.run_until_stopped(async { 42 }).await;
        assert_eq!(output, Some(42));

        ctx.send(&actor, Event::Stop).unwrap();

        let output = ctx.run_until_stopped(async { 42 }).await;
        assert_eq!(output, None);
    }
}
