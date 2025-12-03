//! Shared counters for interface receive/transmit loops.

use crate::events::{RxMetrics, TxMetrics};

/// Tracks receive-side counters for interfaces.
#[derive(Default)]
pub(crate) struct RxCounters {
    packets: u64,
    bytes: u64,
}

impl RxCounters {
    /// Records a received packet length with saturation.
    pub(crate) fn record(&mut self, len: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len as u64);
    }

    /// Generates a metrics snapshot tagged with `iface`.
    pub(crate) fn snapshot(&self, iface: &str) -> RxMetrics {
        RxMetrics {
            iface: iface.to_string(),
            packets: self.packets,
            bytes: self.bytes,
        }
    }
}

/// Tracks transmit-side counters for interfaces.
#[derive(Default)]
pub(crate) struct TxCounters {
    packets: u64,
    bytes: u64,
    dropped_packets: u64,
    dropped_bytes: u64,
}

impl TxCounters {
    /// Records a successfully transmitted packet length with saturation.
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
    pub(crate) fn snapshot(&self, iface: &str) -> TxMetrics {
        TxMetrics {
            iface: iface.to_string(),
            packets: self.packets,
            bytes: self.bytes,
            dropped_packets: self.dropped_packets,
            dropped_bytes: self.dropped_bytes,
        }
    }
}
