//! Shared counters for transport receive/transmit loops.
//!
//! Also provides formatting helpers for periodic metrics logging
//! and QUIC-level metrics collection via `foundations`.

use crate::events::{
    Direction, DropReason, TransportKind, TransportLabels, TransportMetrics, TransportStats,
};
use std::net::SocketAddr;
use tracing::debug;

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

    /// Generates a metrics snapshot with optional peer and remote address labels.
    pub(crate) fn snapshot(
        &self,
        peer_id: Option<&str>,
        remote_addr: Option<SocketAddr>,
    ) -> TransportMetrics {
        TransportMetrics {
            labels: TransportLabels {
                kind: self.kind,
                direction: self.direction,
                peer_id: peer_id.map(str::to_string),
                remote_addr,
            },
            stats: self.stats.clone(),
        }
    }
}

/// Logs a transport metrics snapshot at `debug!` level.
///
/// Prints succeeded/dropped batch/packet/byte totals and per-reason
/// drop breakdowns when any drops are present.
pub(crate) fn log_transport_metrics(metrics: &TransportMetrics) {
    let labels = &metrics.labels;
    let stats = &metrics.stats;
    debug!(
        "{:?} {:?} {}: {} batches/{} pkts/{} bytes ok, \
         {} batches/{} pkts/{} bytes dropped",
        labels.kind,
        labels.direction,
        labels.peer_id.as_deref().unwrap_or("local"),
        stats.succeeded.batches,
        stats.succeeded.packets,
        stats.succeeded.bytes,
        stats.dropped.batches,
        stats.dropped.packets,
        stats.dropped.bytes,
    );
    if stats.dropped.packets > 0 {
        for (reason, counters) in &stats.drop_reasons {
            if counters.packets > 0 {
                debug!(
                    "  drop reason {:?}: {} pkts/{} bytes",
                    reason, counters.packets, counters.bytes
                );
            }
        }
    }
}

/// Collects QUIC-level metrics from the `foundations` global registry as Prometheus text.
///
/// Returns Prometheus text format with `# EOF\n` termination.
/// `encode_metrics_snapshot` relies on this termination convention when
/// concatenating transport and QUIC metric blocks.
pub(crate) fn collect_quic_metrics() -> String {
    foundations::telemetry::metrics::collect(
        &foundations::telemetry::settings::MetricsSettings::default(),
    )
    .unwrap_or_default()
}

/// Logs QUIC-level metrics from the `foundations` global registry at `debug!` level.
pub(crate) fn log_quic_metrics() {
    let text = collect_quic_metrics();
    if !text.is_empty() {
        debug!("QUIC metrics:\n{text}");
    }
}
