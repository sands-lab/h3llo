//! Shared counters for transport receive/transmit loops.

use crate::events::{
    Direction, DropReason, TransportKind, TransportLabels, TransportMetrics, TransportStats,
};
use std::net::IpAddr;

/// Tracks counters for a transport direction.
pub(crate) struct TransportCounters {
    kind: TransportKind,
    direction: Direction,
    stats: TransportStats,
}

impl TransportCounters {
    /// Builds counters for the given transport kind and direction.
    pub(crate) fn new(transport: TransportKind, direction: Direction) -> Self {
        Self {
            kind: transport,
            direction,
            stats: TransportStats::default(),
        }
    }

    /// Records successfully handled packets with saturation.
    ///
    /// For single-packet recording, pass `count = 1`.
    pub(crate) fn record_success(&mut self, count: u64, total_bytes: u64) {
        self.stats.succeeded.record(count, total_bytes);
    }

    /// Records dropped packets for `reason` with saturation.
    ///
    /// For single-packet recording, pass `count = 1`.
    pub(crate) fn record_drop(&mut self, reason: DropReason, count: u64, total_bytes: u64) {
        self.stats.dropped.record(count, total_bytes);
        self.stats
            .drop_reasons
            .entry(reason)
            .or_default()
            .record(count, total_bytes);
    }

    /// Generates a metrics snapshot with optional peer and IP labels.
    pub(crate) fn snapshot(
        &self,
        peer_id: Option<&str>,
        ip_addr: Option<IpAddr>,
    ) -> TransportMetrics {
        TransportMetrics {
            labels: TransportLabels {
                kind: self.kind,
                direction: self.direction,
                peer_id: peer_id.map(str::to_string),
                ip_addr,
            },
            stats: self.stats.clone(),
        }
    }
}
