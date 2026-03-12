//! Dedicated single-threaded runtimes for thread-per-core actor scheduling.
//!
//! Each [`DedicatedRuntime`] owns a `current_thread` Tokio runtime on a
//! dedicated OS thread. Data-plane actors are pinned to these runtimes to
//! eliminate cross-thread task migration and reduce cache pollution.

use tokio::runtime::{Builder, Handle};
use tokio::sync::oneshot;

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
    /// # Panics
    ///
    /// Panics if the runtime or thread cannot be created.
    pub(crate) fn new(name: &str) -> Self {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("failed to build runtime '{name}': {e}"));

        let handle = rt.handle().clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let thread_name = name.to_string();

        let thread = std::thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || {
                // block_on drives the I/O reactor and executes spawned tasks.
                // Returns when shutdown_rx resolves (sender dropped or sent).
                rt.block_on(async {
                    let _ = shutdown_rx.await;
                });
                // Runtime dropped here -> all remaining tasks cancelled.
            })
            .unwrap_or_else(|e| panic!("failed to spawn thread '{thread_name}': {e}"));

        Self {
            handle,
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
        }
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
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dedicated_runtime_spawns_and_completes_tasks() {
        let rt = DedicatedRuntime::new("test-rt");
        let result = rt
            .handle()
            .spawn(async { 42 })
            .await
            .expect("task should complete");
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn cross_runtime_join_handle_await() {
        let rt = DedicatedRuntime::new("test-cross");
        let join = rt.handle().spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            "hello"
        });
        let result = join.await.expect("cross-runtime await should work");
        assert_eq!(result, "hello");
    }
}
