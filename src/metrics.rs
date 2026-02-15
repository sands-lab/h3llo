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

    /// Records a WouldBlock congestion event with the elapsed retry duration.
    pub(crate) fn record_would_block(&mut self, dur: std::time::Duration) {
        self.stats.congestion.record_would_block(dur);
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

    /// Records a queue-full congestion event with the elapsed wait duration.
    fn record_queue_full(&mut self, dur: std::time::Duration) {
        self.stats.congestion.record_queue_full(dur);
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

/// Sends a value through a bounded channel, recording queue-full backpressure.
///
/// Attempts `try_send` first. If the channel is full, records one queue-full
/// event with the elapsed wait time on `counters`. Returns `Err` only when
/// the channel is closed.
pub(crate) async fn send_or_backpressure<T>(
    tx: &tokio::sync::mpsc::Sender<T>,
    value: T,
    counters: &mut TransportCounters,
) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
    match tx.try_send(value) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(val)) => {
            let start = std::time::Instant::now();
            let result = tx.send(val).await;
            counters.record_queue_full(start.elapsed());
            result
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(val)) => {
            Err(tokio::sync::mpsc::error::SendError(val))
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
    let cg = &stats.congestion;
    if cg.queue_full_count > 0 || cg.would_block_count > 0 {
        debug!(
            "  congestion: queue_full {}x/{:?} total, would_block {}x/{:?} total",
            cg.queue_full_count,
            cg.queue_full_duration,
            cg.would_block_count,
            cg.would_block_duration,
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn send_or_backpressure_fast_path() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut counters = TransportCounters::new(TransportKind::Tun, Direction::Rx);
        send_or_backpressure(&tx, 42u32, &mut counters)
            .await
            .unwrap();
        assert_eq!(rx.recv().await, Some(42));
        assert_eq!(counters.stats.congestion.queue_full_count, 0);
    }

    #[tokio::test]
    async fn send_or_backpressure_full_channel_records_event() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut counters = TransportCounters::new(TransportKind::Tun, Direction::Rx);
        tx.send(1u32).await.unwrap();

        let drain = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            rx.recv().await;
            rx
        });

        send_or_backpressure(&tx, 2u32, &mut counters)
            .await
            .unwrap();
        assert_eq!(counters.stats.congestion.queue_full_count, 1);
        assert!(counters.stats.congestion.queue_full_duration > Duration::ZERO);
        let _rx = drain.await.unwrap();
    }

    fn make_labels(kind: TransportKind, direction: Direction) -> TransportLabels {
        TransportLabels {
            kind,
            direction,
            peer_id: None,
            remote_addr: None,
        }
    }

    #[test]
    fn log_transport_metrics_zero_stats() {
        let metrics = TransportMetrics {
            labels: make_labels(TransportKind::Tun, Direction::Rx),
            stats: TransportStats::default(),
        };
        // Should not panic; exercises the zero-drops fast path (skips drop_reasons).
        log_transport_metrics(&metrics);
    }

    #[test]
    fn log_transport_metrics_with_drops() {
        let mut stats = TransportStats::default();
        stats.succeeded.record(10, 5000);
        stats.dropped.record(2, 300);
        stats
            .drop_reasons
            .entry(DropReason::DisallowedSource)
            .or_default()
            .record(2, 300);

        let metrics = TransportMetrics {
            labels: TransportLabels {
                kind: TransportKind::BareUdp,
                direction: Direction::Tx,
                peer_id: Some("peer1".to_string()),
                remote_addr: None,
            },
            stats,
        };
        // Should not panic; exercises the drop-reason iteration branch.
        log_transport_metrics(&metrics);
    }

    #[tokio::test]
    async fn send_or_backpressure_closed_returns_err() {
        let (tx, rx) = mpsc::channel::<u32>(4);
        drop(rx);
        let mut counters = TransportCounters::new(TransportKind::Tun, Direction::Rx);
        let result = send_or_backpressure(&tx, 1, &mut counters).await;
        assert!(result.is_err());
        assert_eq!(counters.stats.congestion.queue_full_count, 0);
        assert_eq!(
            counters.stats.congestion.queue_full_duration,
            Duration::ZERO
        );
    }
}
