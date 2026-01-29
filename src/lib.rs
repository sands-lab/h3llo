//! Library entry point for h3llo.

/// Data-plane packet queue depth for bounded backpressure channels.
///
/// Used by TUN-Tx and BareUDP-Tx actors when creating internal packet channels.
/// See `docs/internals.md` Channel Capacity Policy section for rationale.
pub(crate) const PACKET_QUEUE_DEPTH: usize = 256;

pub mod actor;
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
pub mod tun;

/// Test utilities module exposed via the `test-utils` feature.
///
/// Provides in-memory TUN implementations for integration testing without
/// elevated privileges or real network devices.
#[cfg(feature = "test-utils")]
pub mod test_utils {
    pub use crate::tun::test_support::{
        memory_tun, memory_tun_with_errors, MemoryTunRx, MemoryTunTx,
    };
}
