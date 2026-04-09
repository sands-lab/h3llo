//! Metrics data model, Prometheus encoding, and shared counters.
//!
//! Owns the metrics type hierarchy (`Source`, `Direction`, `DropReason`,
//! `PktCounters`, `CongestionStats`, `Stats`, `Labels`, `Metrics`),
//! Prometheus/OpenMetrics text encoding (`encode_metrics_snapshot`),
//! and provides formatting helpers for periodic metrics logging and
//! QUIC-level metrics collection via `foundations`.

use enum_map::{Enum, EnumMap};
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{
    DescriptorEncoder, EncodeCounterValue, EncodeLabelSet, EncodeLabelValue, EncodeMetric,
};
use prometheus_client::metrics::counter::ConstCounter;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::fmt;
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
///
/// Derives [`Enum`] for O(1) [`EnumMap`] counter lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Enum)]
pub enum DropReason {
    /// Packet exceeded the MTU.
    Oversize,
    /// Packet failed allowlist checks (e.g., source IP).
    DisallowedSource,
    /// OS-level send/write failed (e.g., TUN write error).
    SendError,
    /// QUIC protocol error from quiche (recv or dgram_send failed).
    QuicError,
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
    /// QUIC DATAGRAM queue is full. TX: precise (dgram_send returned Done).
    /// RX: heuristic — may over-count when non-datagram packets arrive while
    /// the queue is full, since not every `conn.recv()` adds a datagram.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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
    /// Drop counters indexed by [`DropReason`] variant (O(1) lookup).
    pub drop_reasons: EnumMap<DropReason, PktCounters>,
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
        self.stats.drop_reasons[reason].record(count, total_bytes);
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

    /// Emits a metrics snapshot via the events channel.
    ///
    /// Returns `true` if the event was sent, `false` if the channel is closed.
    pub(crate) fn emit(
        &self,
        events_tx: &tokio::sync::mpsc::UnboundedSender<crate::events::Event>,
        peer_id: Option<&str>,
        remote_addr: Option<SocketAddr>,
    ) -> bool {
        events_tx
            .send(crate::events::Event::Metrics(Box::new(
                self.snapshot(peer_id, remote_addr),
            )))
            .is_ok()
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

// ---------------------------------------------------------------------------
// Prometheus encoding (OpenMetrics text format)
// ---------------------------------------------------------------------------

/// OpenMetrics text format EOF marker.
const OPENMETRICS_EOF: &str = "# EOF\n";

/// Collector that owns a snapshot of metrics data for one-shot encoding.
///
/// Created per scrape from the snapshot received via `ApiEvent::GetMetricsSnapshot`.
/// No `Arc`, no `Mutex` — the collector owns the `HashMap` directly.
#[derive(Debug)]
struct SnapshotCollector(HashMap<Labels, Metrics>);

/// Encodes a metrics snapshot into OpenMetrics text format.
///
/// Combines application-level transport metrics (via `prometheus-client`) with
/// QUIC-level metrics (via `foundations::telemetry::metrics`) into a single
/// Prometheus-compatible text response.
pub(crate) fn encode_metrics_snapshot(snapshot: HashMap<Labels, Metrics>) -> String {
    let mut registry = Registry::default();
    registry.register_collector(Box::new(SnapshotCollector(snapshot)));
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry)
        .expect("infallible: encoding to String cannot fail");

    // Append QUIC-level metrics from foundations global registry.
    let quic_text = collect_quic_metrics();
    if !quic_text.is_empty() {
        // Strip EOF from both sources and re-add a single EOF at the end.
        if text.ends_with(OPENMETRICS_EOF) {
            text.truncate(text.len() - OPENMETRICS_EOF.len());
        }
        let quic_text = quic_text
            .strip_suffix(OPENMETRICS_EOF)
            .unwrap_or(&quic_text);
        text.push_str(quic_text);
        text.push_str(OPENMETRICS_EOF);
    }

    text
}

impl SnapshotCollector {
    /// Encodes a counter family by applying `entry_fn` to each metric in the snapshot.
    fn encode_family<'a, L, N, I>(
        &'a self,
        encoder: &mut DescriptorEncoder,
        name: &str,
        help: &str,
        entry_fn: impl Fn(&'a Metrics) -> I,
    ) -> Result<(), fmt::Error>
    where
        L: EncodeLabelSet,
        N: EncodeCounterValue + Default,
        I: IntoIterator<Item = (L, N)>,
    {
        let counter = ConstCounter::new(N::default());
        let mut enc = encoder.encode_descriptor(name, help, None, counter.metric_type())?;
        for m in self.0.values() {
            for (labels, value) in entry_fn(m) {
                ConstCounter::new(value).encode(enc.encode_family(&labels)?)?;
            }
        }
        Ok(())
    }
}

impl Collector for SnapshotCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        // Succeeded/dropped counter families.
        for (name, help, extractor) in [
            (
                "h3llo_transport_packets",
                "Cumulative packet count.",
                (|s: &Stats| (s.succeeded.packets, s.dropped.packets)) as fn(&Stats) -> (u64, u64),
            ),
            ("h3llo_transport_bytes", "Cumulative byte count.", |s| {
                (s.succeeded.bytes, s.dropped.bytes)
            }),
            (
                "h3llo_transport_batches",
                "Cumulative batch count (record() invocations for GSO/GRO tracking).",
                |s| (s.succeeded.batches, s.dropped.batches),
            ),
        ] {
            self.encode_family(&mut encoder, name, help, |m| {
                let (ok, drop) = extractor(&m.stats);
                [
                    (PacketLabelSet::from_metrics(m, "succeeded"), ok),
                    (PacketLabelSet::from_metrics(m, "dropped"), drop),
                ]
            })?;
        }

        // Drop-reason counter families.
        for (name, help, field) in [
            (
                "h3llo_transport_drops",
                "Cumulative drop count by reason.",
                (|c: &PktCounters| c.packets) as fn(&PktCounters) -> u64,
            ),
            (
                "h3llo_transport_drop_bytes",
                "Cumulative drop bytes by reason.",
                |c| c.bytes,
            ),
        ] {
            self.encode_family(&mut encoder, name, help, |m| {
                m.stats
                    .drop_reasons
                    .iter()
                    .map(move |(reason, c)| (DropLabelSet::from_metrics(m, reason), field(c)))
            })?;
        }

        // Congestion counter families.
        self.encode_family(
            &mut encoder,
            "h3llo_transport_congestion",
            "Cumulative congestion event count.",
            |m| {
                let cg = &m.stats.congestion;
                [
                    (
                        CongestionLabelSet::from_metrics(m, "queue_full"),
                        cg.queue_full_count,
                    ),
                    (
                        CongestionLabelSet::from_metrics(m, "would_block"),
                        cg.would_block_count,
                    ),
                ]
            },
        )?;
        self.encode_family(
            &mut encoder,
            "h3llo_transport_congestion_wait_milliseconds",
            "Cumulative congestion wait time in milliseconds.",
            |m| {
                let cg = &m.stats.congestion;
                [
                    (
                        CongestionLabelSet::from_metrics(m, "queue_full"),
                        cg.queue_full_duration.as_secs_f64() * 1000.0,
                    ),
                    (
                        CongestionLabelSet::from_metrics(m, "would_block"),
                        cg.would_block_duration.as_secs_f64() * 1000.0,
                    ),
                ]
            },
        )?;

        Ok(())
    }
}

/// Generates a Prometheus label set struct with 4 common metric labels
/// (`source`, `direction`, `peer_id`, `remote_addr`) plus one extra field.
macro_rules! label_set {
    ($name:ident, $field:ident: $ty:ty) => {
        #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
        struct $name {
            source: Source,
            direction: Direction,
            peer_id: String,
            remote_addr: String,
            $field: $ty,
        }

        impl $name {
            fn from_metrics(m: &Metrics, $field: impl Into<$ty>) -> Self {
                Self {
                    source: m.labels.source,
                    direction: m.labels.direction,
                    peer_id: m.labels.peer_id.clone().unwrap_or_default(),
                    remote_addr: m
                        .labels
                        .remote_addr
                        .map(|a| a.to_string())
                        .unwrap_or_default(),
                    $field: $field.into(),
                }
            }
        }
    };
}

label_set!(PacketLabelSet, outcome: String);
label_set!(DropLabelSet, reason: DropReason);
label_set!(CongestionLabelSet, event: String);

impl EncodeLabelValue for Source {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        let s = match self {
            Source::Tun => "tun",
            Source::BareUdp => "bare_udp",
            Source::Http3 => "http3",
            Source::Router => "router",
        };
        EncodeLabelValue::encode(&s, encoder)
    }
}

impl EncodeLabelValue for Direction {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        let s = match self {
            Direction::Rx => "rx",
            Direction::Tx => "tx",
        };
        EncodeLabelValue::encode(&s, encoder)
    }
}

impl EncodeLabelValue for DropReason {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        let s = match self {
            DropReason::Oversize => "oversize",
            DropReason::DisallowedSource => "disallowed_source",
            DropReason::SendError => "send_error",
            DropReason::QuicError => "quic_error",
            DropReason::ChannelClosed => "channel_closed",
            DropReason::InvalidIpVersion => "invalid_ip_version",
            DropReason::InvalidFraming => "invalid_framing",
            DropReason::NoRoute => "no_route",
            DropReason::NoPeerChannel => "no_peer_channel",
            DropReason::NoHeadroom => "no_headroom",
            DropReason::QueueFull => "queue_full",
            DropReason::TtlExpired => "ttl_expired",
        };
        EncodeLabelValue::encode(&s, encoder)
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
        stats.drop_reasons[DropReason::DisallowedSource].record(2, 300);

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
        let c = &snap.stats.drop_reasons[DropReason::ChannelClosed];
        assert_eq!((c.packets, c.bytes), (3, 300));
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

    // -- encode_metrics_snapshot tests --

    #[test]
    fn encode_empty_snapshot() {
        let text = encode_metrics_snapshot(HashMap::new());
        assert!(text.contains("# EOF"), "should contain EOF: {text}");
    }

    #[test]
    fn encode_snapshot_includes_succeeded_and_dropped() {
        let mut snapshot = HashMap::new();
        let metrics = Metrics {
            labels: Labels {
                source: Source::Tun,
                direction: Direction::Rx,
                peer_id: None,
                remote_addr: None,
            },
            stats: Stats {
                succeeded: PktCounters {
                    packets: 100,
                    bytes: 50000,
                    ..Default::default()
                },
                dropped: PktCounters {
                    packets: 2,
                    bytes: 128,
                    ..Default::default()
                },
                drop_reasons: EnumMap::default(),
                ..Default::default()
            },
        };
        snapshot.insert(metrics.labels.clone(), metrics);
        let text = encode_metrics_snapshot(snapshot);
        assert!(
            text.contains("h3llo_transport_packets_total"),
            "missing packets: {text}"
        );
        assert!(text.contains("100"), "missing succeeded count: {text}");
        assert!(
            text.contains("h3llo_transport_bytes_total"),
            "missing bytes: {text}"
        );
        assert!(text.contains("50000"), "missing succeeded bytes: {text}");
        assert!(
            text.contains("h3llo_transport_batches_total"),
            "missing batches: {text}"
        );
    }

    #[test]
    fn encode_snapshot_includes_drop_reasons() {
        let mut drop_reasons = EnumMap::default();
        drop_reasons[DropReason::Oversize] = PktCounters {
            packets: 3,
            bytes: 4500,
            ..Default::default()
        };
        let mut snapshot = HashMap::new();
        let metrics = Metrics {
            labels: Labels {
                source: Source::BareUdp,
                direction: Direction::Tx,
                peer_id: Some("peer-1".to_string()),
                remote_addr: None,
            },
            stats: Stats {
                succeeded: PktCounters {
                    packets: 50,
                    bytes: 25000,
                    ..Default::default()
                },
                dropped: PktCounters {
                    packets: 3,
                    bytes: 4500,
                    ..Default::default()
                },
                drop_reasons,
                ..Default::default()
            },
        };
        snapshot.insert(metrics.labels.clone(), metrics);
        let text = encode_metrics_snapshot(snapshot);
        assert!(
            text.contains("h3llo_transport_drops_total"),
            "missing drops: {text}"
        );
        assert!(
            text.contains("reason=\"oversize\""),
            "missing oversize: {text}"
        );
        assert!(
            text.contains("h3llo_transport_drop_bytes_total"),
            "missing drop bytes: {text}"
        );
    }

    #[test]
    fn encode_snapshot_is_openmetrics_format() {
        let mut snapshot = HashMap::new();
        let metrics = Metrics {
            labels: Labels {
                source: Source::Tun,
                direction: Direction::Rx,
                peer_id: None,
                remote_addr: None,
            },
            stats: Stats::default(),
        };
        snapshot.insert(metrics.labels.clone(), metrics);
        let text = encode_metrics_snapshot(snapshot);
        assert!(text.ends_with("# EOF\n"), "must end with # EOF: {text}");
        assert!(
            text.contains("_total{"),
            "counters must have _total suffix: {text}"
        );
    }

    #[test]
    fn encode_snapshot_includes_remote_addr_label() {
        let mut snapshot = HashMap::new();
        let addr: std::net::SocketAddr = "1.2.3.4:5353".parse().unwrap();
        let metrics = Metrics {
            labels: Labels {
                source: Source::BareUdp,
                direction: Direction::Tx,
                peer_id: Some("peer-x".to_string()),
                remote_addr: Some(addr),
            },
            stats: Stats {
                succeeded: PktCounters {
                    packets: 10,
                    bytes: 1000,
                    ..Default::default()
                },
                dropped: PktCounters::default(),
                drop_reasons: EnumMap::default(),
                ..Default::default()
            },
        };
        snapshot.insert(metrics.labels.clone(), metrics);
        let text = encode_metrics_snapshot(snapshot);
        assert!(
            text.contains("remote_addr=\"1.2.3.4:5353\""),
            "missing remote_addr label: {text}"
        );
        assert!(
            text.contains("peer_id=\"peer-x\""),
            "missing peer_id label: {text}"
        );
    }

    #[test]
    fn encode_snapshot_ends_with_eof() {
        let text = encode_metrics_snapshot(HashMap::new());
        assert!(text.ends_with("# EOF\n"), "must end with # EOF: {text}");
    }

    #[test]
    fn encode_snapshot_has_single_eof() {
        let text = encode_metrics_snapshot(HashMap::new());
        let eof_count = text.matches("# EOF").count();
        assert_eq!(eof_count, 1, "should have exactly one EOF marker: {text}");
    }

    #[test]
    fn encode_snapshot_with_congestion_metrics() {
        let mut snapshot = HashMap::new();
        let mut stats = Stats::default();
        stats.congestion.record_queue_full(Duration::from_millis(5));
        stats
            .congestion
            .record_would_block(Duration::from_micros(200));
        let labels = Labels {
            source: Source::Tun,
            direction: Direction::Rx,
            peer_id: None,
            remote_addr: None,
        };
        let metrics = Metrics {
            labels: labels.clone(),
            stats,
        };
        snapshot.insert(labels, metrics);
        let text = encode_metrics_snapshot(snapshot);
        assert!(
            text.contains("h3llo_transport_congestion_total"),
            "missing congestion: {text}"
        );
        assert!(
            text.contains("event=\"queue_full\""),
            "missing queue_full label: {text}"
        );
        assert!(
            text.contains("event=\"would_block\""),
            "missing would_block label: {text}"
        );
        assert!(
            text.contains("h3llo_transport_congestion_wait_milliseconds_total"),
            "missing wait: {text}"
        );
    }
}
