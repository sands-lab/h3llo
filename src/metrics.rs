//! Shared counters for transport receive/transmit loops.
//!
//! Also provides formatting helpers for periodic metrics logging
//! and QUIC-level metrics collection via `foundations`.

use crate::events::{Direction, DropReason, Source, Stats, Labels, Metrics};
use std::net::SocketAddr;
use tracing::debug;

/// Tracks counters for a source direction.
pub(crate) struct Counters {
    source: Source,
    direction: Direction,
    stats: Stats,
}

impl Counters {
    /// Builds counters for the given source and direction.
    pub(crate) fn new(source: Source, direction: Direction) -> Self {
        Self {
            source,
            direction,
            stats: Stats::default(),
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
    pub(crate) fn record_queue_full(&mut self, dur: std::time::Duration) {
        self.stats.congestion.record_queue_full(dur);
    }

    /// Generates a metrics snapshot with optional peer and remote address labels.
    pub(crate) fn snapshot(
        &self,
        peer_id: Option<&str>,
        remote_addr: Option<SocketAddr>,
    ) -> Metrics {
        Metrics {
            labels: Labels {
                source: self.source,
                direction: self.direction,
                peer_id: peer_id.map(str::to_string),
                remote_addr,
            },
            stats: self.stats.clone(),
        }
    }
}

/// Event stream emitted by `send_with_backpressure`.
pub(crate) enum SendEvent {
    /// Emitted when `try_send` succeeds on the fast path.
    Fast,
    /// Emitted when `try_send` returns `Full`.
    Full,
    /// Emitted after a successful awaited send with the wait duration.
    Waited(std::time::Duration),
}

/// Sends a value through a bounded channel and exposes backpressure events.
///
/// Event order:
/// - Fast path: `Fast`
/// - Full then success: `Full` -> `Waited(duration)`
pub(crate) async fn send_with_backpressure<T, F>(
    tx: &tokio::sync::mpsc::Sender<T>,
    value: T,
    mut on_event: F,
) -> Result<(), tokio::sync::mpsc::error::SendError<T>>
where
    F: FnMut(SendEvent),
{
    match tx.try_send(value) {
        Ok(()) => {
            on_event(SendEvent::Fast);
            Ok(())
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(val)) => {
            on_event(SendEvent::Full);
            let start = std::time::Instant::now();
            match tx.send(val).await {
                Ok(()) => {
                    on_event(SendEvent::Waited(start.elapsed()));
                    Ok(())
                }
                Err(tokio::sync::mpsc::error::SendError(val)) => {
                    Err(tokio::sync::mpsc::error::SendError(val))
                }
            }
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
pub(crate) fn log_transport_metrics(metrics: &Metrics) {
    let labels = &metrics.labels;
    let stats = &metrics.stats;
    let remote = labels
        .remote_addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "-".into());
    debug!(
        "{:?} {:?} {} {}: {} batches/{} pkts/{} bytes ok, \
         {} batches/{} pkts/{} bytes dropped",
        labels.source,
        labels.direction,
        labels.peer_id.as_deref().unwrap_or("local"),
        remote,
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

    #[test]
    fn log_transport_metrics_zero_stats() {
        let metrics = Metrics {
            labels: Labels {
                source: Source::Tun,
                direction: Direction::Rx,
                peer_id: None,
                remote_addr: None,
            },
            stats: Stats::default(),
        };
        // Should not panic; exercises the zero-drops fast path (skips drop_reasons).
        log_transport_metrics(&metrics);
    }

    #[test]
    fn log_transport_metrics_with_drops() {
        let mut stats = Stats::default();
        stats.succeeded.record(10, 5000);
        stats.dropped.record(2, 300);
        stats
            .drop_reasons
            .entry(DropReason::DisallowedSource)
            .or_default()
            .record(2, 300);

        let metrics = Metrics {
            labels: Labels {
                source: Source::BareUdp,
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
    async fn send_with_backpressure_fast_path() {
        let (tx, mut rx) = mpsc::channel::<u32>(4);
        let mut saw_fast = false;
        let mut saw_full = false;
        let mut waited = Duration::ZERO;

        send_with_backpressure(&tx, 7, |event| match event {
            SendEvent::Fast => saw_fast = true,
            SendEvent::Full => saw_full = true,
            SendEvent::Waited(d) => waited = d,
        })
        .await
        .unwrap();

        assert_eq!(rx.recv().await, Some(7));
        assert!(saw_fast);
        assert!(!saw_full);
        assert_eq!(waited, Duration::ZERO);
    }

    #[tokio::test]
    async fn send_with_backpressure_waited_path() {
        let (tx, mut rx) = mpsc::channel::<u32>(1);
        tx.send(1).await.unwrap();

        let drain = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            rx.recv().await;
            rx
        });

        let mut saw_fast = false;
        let mut saw_full = false;
        let mut waited = Duration::ZERO;

        send_with_backpressure(&tx, 2, |event| match event {
            SendEvent::Fast => saw_fast = true,
            SendEvent::Full => saw_full = true,
            SendEvent::Waited(d) => waited = d,
        })
        .await
        .unwrap();

        assert!(!saw_fast);
        assert!(saw_full);
        assert!(waited > Duration::ZERO);
        let _rx = drain.await.unwrap();
    }

    #[tokio::test]
    async fn send_with_backpressure_closed_path() {
        let (tx, rx) = mpsc::channel::<u32>(1);
        drop(rx);

        let mut saw_fast = false;
        let mut saw_full = false;
        let mut waited = Duration::ZERO;

        let err = send_with_backpressure(&tx, 9, |event| match event {
            SendEvent::Fast => saw_fast = true,
            SendEvent::Full => saw_full = true,
            SendEvent::Waited(d) => waited = d,
        })
        .await
        .unwrap_err();

        assert_eq!(err.0, 9);
        assert!(!saw_fast);
        assert!(!saw_full);
        assert_eq!(waited, Duration::ZERO);
    }
}
