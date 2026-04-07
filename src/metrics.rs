//! Metrics data model and shared counters for transport receive/transmit loops.
//!
//! Owns the metrics type hierarchy (`Source`, `Direction`, `DropReason`,
//! `PktCounters`, `CongestionStats`, `Stats`, `Labels`, `Metrics`) and
//! provides formatting helpers for periodic metrics logging and QUIC-level
//! metrics collection via `foundations`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::helpers::{send_with_backpressure, SendEvent};

// ---------------------------------------------------------------------------
// Metrics data model
// ---------------------------------------------------------------------------

/// Identifies the origin of packets for metrics and routing policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// TUN interface.
    Tun,
    /// BareUDP socket.
    BareUdp,
    /// HTTP/3 transport.
    Http3,
    /// Router actor (forwarding path).
    Router,
}

/// Indicates whether metrics were collected on the receive or transmit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Metrics from the receive side.
    Rx,
    /// Metrics from the transmit side.
    Tx,
}

/// Enumerates reasons for packet drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// Packet exceeded the MTU.
    Oversize,
    /// Packet failed allowlist checks (e.g., source IP).
    DisallowedSource,
    /// Sending the packet failed.
    SendError,
    /// Packet could not be forwarded because the channel closed.
    ChannelClosed,
    /// Packet has unknown or invalid IP version.
    InvalidIpVersion,
    /// DATAGRAM framing error (e.g., invalid Context ID).
    InvalidFraming,
    /// No route found for destination IP.
    NoRoute,
    /// No peer channel available for the route.
    NoPeerChannel,
    /// PooledBuf lacked headroom for datagram prefix insertion.
    NoHeadroom,
    /// QUIC DATAGRAM queue is full (direction distinguished by rx/tx counters).
    QueueFull,
    /// Packet's TTL/hop limit reached zero (forwarded to TUN for ICMP generation).
    TtlExpired,
}

/// Tracks cumulative wait events caused by backpressure or I/O congestion.
///
/// Each field pair captures an event count and the total time spent waiting.
/// These metrics are separate from drop accounting because the affected packets
/// are ultimately delivered — they are merely delayed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CongestionStats {
    /// Number of times a bounded mpsc `try_send` found the queue full.
    pub queue_full_count: u64,
    /// Cumulative wall-clock time spent waiting for queue capacity
    /// (from `try_send` failure to `send().await` completion).
    pub queue_full_duration: Duration,
    /// Number of times a socket I/O operation returned `WouldBlock`.
    pub would_block_count: u64,
    /// Cumulative wall-clock time spent retrying after `WouldBlock`
    /// (from first `WouldBlock` to eventual I/O success).
    pub would_block_duration: Duration,
}

impl CongestionStats {
    /// Records a queue-full wait event with its duration, saturating on overflow.
    pub fn record_queue_full(&mut self, wait: Duration) {
        self.queue_full_count = self.queue_full_count.saturating_add(1);
        self.queue_full_duration = self.queue_full_duration.saturating_add(wait);
    }

    /// Records a WouldBlock wait event with its duration, saturating on overflow.
    pub fn record_would_block(&mut self, wait: Duration) {
        self.would_block_count = self.would_block_count.saturating_add(1);
        self.would_block_duration = self.would_block_duration.saturating_add(wait);
    }
}

/// Aggregates packet counters by outcome.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PktCounters {
    /// Number of batch operations (`record()` invocations).
    pub batches: u64,
    /// Number of packets observed.
    pub packets: u64,
    /// Total bytes observed.
    pub bytes: u64,
}

impl PktCounters {
    /// Records a batch of packets, saturating on overflow.
    ///
    /// For single-packet recording, pass `count = 1`.
    /// Each call increments `batches` by 1, representing one `record()`
    /// invocation for GSO/GRO effectiveness tracking.
    pub fn record(&mut self, count: u64, total_bytes: u64) {
        self.batches = self.batches.saturating_add(1);
        self.packets = self.packets.saturating_add(count);
        self.bytes = self.bytes.saturating_add(total_bytes);
    }
}

/// Collects per-source statistics including drop breakdowns.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Stats {
    /// Successful packet counters.
    pub succeeded: PktCounters,
    /// Dropped packet counters.
    pub dropped: PktCounters,
    /// Drop counters keyed by reason.
    pub drop_reasons: HashMap<DropReason, PktCounters>,
    /// Backpressure and I/O congestion wait counters.
    pub congestion: CongestionStats,
}

/// Labels attached to transport metrics for grouping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Labels {
    /// Packet source (TUN, BareUDP, HTTP/3, Router).
    pub source: Source,
    /// Direction (receive or transmit) of the collected metrics.
    pub direction: Direction,
    /// Optional peer identifier when the transport is peer-scoped.
    pub peer_id: Option<String>,
    /// Optional remote socket address for per-connection disambiguation.
    pub remote_addr: Option<SocketAddr>,
}

/// Carries cumulative counters collected from a transport loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metrics {
    /// Labels describing the metric dimensions.
    pub labels: Labels,
    /// Aggregated statistics with drop breakdown.
    pub stats: Stats,
}

// ---------------------------------------------------------------------------
// Counters (operational layer)
// ---------------------------------------------------------------------------

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

    /// Sends `value` via `tx` with backpressure, recording queue-full,
    /// success, or [`DropReason::ChannelClosed`] drop automatically.
    ///
    /// Returns `true` on success, `false` on channel close (drop recorded).
    pub(crate) async fn send_and_record<T>(
        &mut self,
        tx: &tokio::sync::mpsc::Sender<T>,
        value: T,
        count: u64,
        bytes: u64,
    ) -> bool {
        if send_with_backpressure(tx, value, |event| match event {
            SendEvent::Waited(waited) => self.record_queue_full(waited),
            SendEvent::Fast | SendEvent::Full => {}
        })
        .await
        .is_err()
        {
            self.record_drop(DropReason::ChannelClosed, count, bytes);
            false
        } else {
            self.record_success(count, bytes);
            true
        }
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

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

/// Logs a transport metrics snapshot at `info!` level.
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
    info!(
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
                info!(
                    "  drop reason {:?}: {} pkts/{} bytes",
                    reason, counters.packets, counters.bytes
                );
            }
        }
    }
    let cg = &stats.congestion;
    if cg.queue_full_count > 0 || cg.would_block_count > 0 {
        info!(
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
/// On success, returns Prometheus text format with `# EOF\n` termination.
/// On collection error, logs a warning and returns an empty string.
/// Callers should check for empty before concatenating.
pub(crate) fn collect_quic_metrics() -> String {
    match foundations::telemetry::metrics::collect(
        &foundations::telemetry::settings::MetricsSettings::default(),
    ) {
        Ok(text) => text,
        Err(e) => {
            warn!(error = %e, "failed to collect QUIC metrics");
            String::new()
        }
    }
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

    // -- PktCounters tests --

    #[test]
    fn pkt_counters_record_batch() {
        let mut c = PktCounters::default();
        c.record(3, 150);
        assert_eq!(c.batches, 1);
        assert_eq!(c.packets, 3);
        assert_eq!(c.bytes, 150);
    }

    #[test]
    fn pkt_counters_record_single() {
        let mut c = PktCounters::default();
        c.record(1, 64);
        assert_eq!(c.batches, 1);
        assert_eq!(c.packets, 1);
        assert_eq!(c.bytes, 64);
    }

    #[test]
    fn pkt_counters_saturates() {
        let mut c = PktCounters {
            batches: u64::MAX - 1,
            packets: u64::MAX - 1,
            bytes: u64::MAX - 1,
        };
        c.record(5, 100);
        assert_eq!(c.batches, u64::MAX);
        assert_eq!(c.packets, u64::MAX);
        assert_eq!(c.bytes, u64::MAX);
    }

    #[test]
    fn pkt_counters_multiple_batches() {
        let mut c = PktCounters::default();
        c.record(10, 1000);
        c.record(5, 500);
        c.record(1, 100);
        assert_eq!(c.batches, 3);
        assert_eq!(c.packets, 16);
        assert_eq!(c.bytes, 1600);
    }

    // -- CongestionStats tests --

    #[test]
    fn congestion_stats_record_queue_full() {
        let mut c = CongestionStats::default();
        c.record_queue_full(Duration::from_millis(5));
        c.record_queue_full(Duration::from_millis(10));
        assert_eq!(c.queue_full_count, 2);
        assert_eq!(c.queue_full_duration, Duration::from_millis(15));
        assert_eq!(c.would_block_count, 0);
    }

    #[test]
    fn congestion_stats_record_would_block() {
        let mut c = CongestionStats::default();
        c.record_would_block(Duration::from_micros(100));
        assert_eq!(c.would_block_count, 1);
        assert_eq!(c.would_block_duration, Duration::from_micros(100));
        assert_eq!(c.queue_full_count, 0);
    }

    #[test]
    fn congestion_stats_saturates() {
        let mut c = CongestionStats {
            queue_full_count: u64::MAX - 1,
            queue_full_duration: Duration::MAX,
            would_block_count: u64::MAX - 1,
            would_block_duration: Duration::MAX,
        };
        c.record_queue_full(Duration::from_secs(1));
        assert_eq!(c.queue_full_count, u64::MAX);
        assert_eq!(c.queue_full_duration, Duration::MAX);
        c.record_would_block(Duration::from_secs(1));
        assert_eq!(c.would_block_count, u64::MAX);
        assert_eq!(c.would_block_duration, Duration::MAX);
    }

    // -- log_transport_metrics tests --

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

    // -- send_and_record tests --

    #[tokio::test]
    async fn send_and_record_success() {
        let (tx, mut rx) = mpsc::channel::<u32>(4);
        let mut counters = Counters::new(Source::Tun, Direction::Tx);

        let ok = counters.send_and_record(&tx, 42, 1, 100).await;
        assert!(ok);
        assert_eq!(rx.recv().await, Some(42));

        let snap = counters.snapshot(None, None);
        assert_eq!(snap.stats.succeeded.packets, 1);
        assert_eq!(snap.stats.succeeded.bytes, 100);
        assert_eq!(snap.stats.dropped.packets, 0);
    }

    #[tokio::test]
    async fn send_and_record_channel_closed() {
        let (tx, rx) = mpsc::channel::<u32>(4);
        drop(rx);
        let mut counters = Counters::new(Source::Tun, Direction::Tx);

        let ok = counters.send_and_record(&tx, 42, 3, 300).await;
        assert!(!ok);

        let snap = counters.snapshot(None, None);
        assert_eq!(snap.stats.succeeded.packets, 0);
        assert_eq!(snap.stats.dropped.packets, 3);
        assert_eq!(snap.stats.dropped.bytes, 300);
        assert_eq!(
            snap.stats
                .drop_reasons
                .get(&DropReason::ChannelClosed)
                .map(|c| (c.packets, c.bytes)),
            Some((3, 300))
        );
    }

    #[tokio::test]
    async fn send_and_record_queue_full_records_congestion() {
        let (tx, mut rx) = mpsc::channel::<u32>(1);
        tx.send(1).await.unwrap(); // fill the channel

        let drain = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            rx.recv().await;
            rx
        });

        let mut counters = Counters::new(Source::Tun, Direction::Tx);
        let ok = counters.send_and_record(&tx, 2, 1, 64).await;
        assert!(ok);

        let snap = counters.snapshot(None, None);
        assert_eq!(snap.stats.succeeded.packets, 1);
        assert!(snap.stats.congestion.queue_full_count > 0);
        assert!(snap.stats.congestion.queue_full_duration > Duration::ZERO);
        let _rx = drain.await.unwrap();
    }
}
