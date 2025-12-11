//! Shared counters for interface receive/transmit loops.

use crate::events::{Direction, DropReason, InterfaceMetrics, InterfaceStats, TransportKind};

/// Tracks counters for an interface direction and transport.
pub(crate) struct InterfaceCounters {
    transport: TransportKind,
    direction: Direction,
    stats: InterfaceStats,
}

impl InterfaceCounters {
    /// Builds counters for the given transport and direction.
    pub(crate) fn new(transport: TransportKind, direction: Direction) -> Self {
        Self {
            transport,
            direction,
            stats: InterfaceStats::default(),
        }
    }

    /// Records a successfully handled packet length with saturation.
    pub(crate) fn record_success(&mut self, len: usize) {
        self.stats.succeeded.record(len);
    }

    /// Records a dropped packet length for `reason` with saturation.
    pub(crate) fn record_drop(&mut self, reason: DropReason, len: usize) {
        self.stats.dropped.record(len);
        self.stats
            .drop_reasons
            .entry(reason)
            .or_default()
            .record(len);
    }

    /// Generates a metrics snapshot tagged with `iface`.
    pub(crate) fn snapshot(&self, iface: &str) -> InterfaceMetrics {
        InterfaceMetrics {
            iface: iface.to_string(),
            transport: self.transport,
            direction: self.direction,
            stats: self.stats.clone(),
        }
    }
}
