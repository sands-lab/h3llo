//! Shared counters for interface receive/transmit loops.

use crate::events::{Direction, InterfaceMetrics};

/// Tracks counters for an interface direction.
pub(crate) struct InterfaceCounters {
    direction: Direction,
    packets: u64,
    bytes: u64,
    dropped_packets: u64,
    dropped_bytes: u64,
}

impl InterfaceCounters {
    /// Builds counters for the given direction.
    pub(crate) fn new(direction: Direction) -> Self {
        Self {
            direction,
            packets: 0,
            bytes: 0,
            dropped_packets: 0,
            dropped_bytes: 0,
        }
    }

    /// Records a successfully handled packet length with saturation.
    pub(crate) fn record_success(&mut self, len: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len as u64);
    }

    /// Records a dropped packet length with saturation.
    pub(crate) fn record_drop(&mut self, len: usize) {
        self.dropped_packets = self.dropped_packets.saturating_add(1);
        self.dropped_bytes = self.dropped_bytes.saturating_add(len as u64);
    }

    /// Generates a metrics snapshot tagged with `iface`.
    pub(crate) fn snapshot(&self, iface: &str) -> InterfaceMetrics {
        InterfaceMetrics {
            iface: iface.to_string(),
            direction: self.direction,
            packets: self.packets,
            bytes: self.bytes,
            dropped_packets: self.dropped_packets,
            dropped_bytes: self.dropped_bytes,
        }
    }
}
