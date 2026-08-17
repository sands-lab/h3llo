//! Library entry point for h3llo.

pub mod actor;
pub mod api;
pub mod auth;
pub mod bare;
pub mod bind;
pub mod config;
pub mod dns;
pub mod events;
pub mod h3dialer;
pub mod h3engine;
pub mod h3listener;
pub mod h3session;
mod helpers;
pub mod metrics;
mod orch;
pub mod route;
pub mod router;
pub mod tun;
pub mod udp;

/// Runs h3llo with the supplied validated configuration.
///
/// # Arguments
///
/// * `config` - Runtime configuration used to initialize all actors and transports.
///
/// # Returns
///
/// Returns successfully when the orchestrator shuts down cleanly.
///
/// # Errors
///
/// Returns an error when initialization fails or a critical actor exits.
pub async fn run(config: config::Config) -> anyhow::Result<()> {
    let orchestrator = orch::Orchestrator::new(config).await?;
    orchestrator.run().await
}

/// Test-only support modules that depend on crate internals.
#[cfg(test)]
pub(crate) mod test_support;

/// Test utilities module exposed via the `test-utils` feature.
///
/// Provides test doubles for integration testing without elevated privileges
/// or real network devices:
/// - In-memory TUN implementations (`MemoryTun*`)
/// - Route probe test doubles (`FakeRouteProbe`)
#[cfg(feature = "test-utils")]
pub mod test_utils {
    pub use crate::bind::test_support::FakeRouteProbe;
    pub use crate::tun::test_support::{
        memory_tun, memory_tun_with_errors, MemoryTunRx, MemoryTunTx,
    };
}
