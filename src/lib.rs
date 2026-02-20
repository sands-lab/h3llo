//! Library entry point for h3llo.

pub mod actor;
pub mod api;
pub mod auth;
pub mod bare;
pub mod bind;
pub mod config;
pub mod dns;
pub mod events;
pub mod h3;
mod helpers;
mod metrics;
pub mod orch;
pub mod route;
pub mod router;
pub mod tun;

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
