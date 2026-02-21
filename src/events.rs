//! Shared events flowing into the orchestrator.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::actor::ActorExitResult;
use crate::config::{Config, H3Endpoint, Peer, UdpEndpoint};
use crate::h3::H3Connection;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_quiche::buf_factory::PooledBuf;

/// Endpoint type discriminator for bound connections.
///
/// Captures the configured endpoint that originated an outbound connection,
/// enabling prune logic to detect endpoint reconfiguration and DNS staleness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// BareUDP endpoint (host:port).
    Udp(UdpEndpoint),
    /// HTTP/3 endpoint (host:port/path).
    H3(H3Endpoint),
}

/// Indicates connection establishment direction.
///
/// Distinct from `Direction` (Rx/Tx) which describes data flow for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    /// Connection accepted by listener (server-side).
    Inbound,
    /// Connection established by dialer (client-side).
    Outbound,
}

/// Carries high-level events emitted by modules to the orchestrator.
#[derive(Debug)]
pub enum Event {
    /// Cumulative metrics snapshot from any source.
    Metrics(Metrics),
    /// Events originating from transports (BareUDP, HTTP/3).
    Transport(TransportEvent),
    /// Events originating from DNS resolution.
    Dns(DnsEvent),
    /// Events originating from the management API.
    Api(ApiEvent),
}

/// Events emitted by the management API actor.
pub enum ApiEvent {
    /// GET /config — orchestrator replies with current config snapshot.
    GetConfig {
        /// Reply channel carrying the full `Config` struct for API-side serialization.
        reply_tx: oneshot::Sender<Config>,
    },
    /// POST /config — upsert peers; orchestrator validates and replies.
    PostConfig {
        /// Parsed peer definitions from the request body.
        peers: Vec<Peer>,
        /// Reply channel carrying updated config on success, or error string on failure.
        reply_tx: oneshot::Sender<Result<Config, String>>,
    },
    /// DELETE /config — remove peers by ID; orchestrator confirms.
    DeleteConfig {
        /// Peer IDs to remove.
        peer_ids: Vec<String>,
        /// Reply channel carrying updated config on success, or error string on failure.
        reply_tx: oneshot::Sender<Result<Config, String>>,
    },
    /// GET /metrics — orchestrator replies with raw metrics snapshot for API-side rendering.
    GetMetricsSnapshot {
        /// Reply channel carrying cloned metrics data. Rendering happens in the API actor.
        reply_tx: oneshot::Sender<HashMap<Labels, Metrics>>,
    },
}

impl std::fmt::Debug for ApiEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetConfig { .. } => f.debug_struct("GetConfig").finish_non_exhaustive(),
            Self::PostConfig { peers, .. } => f
                .debug_struct("PostConfig")
                .field("peers_count", &peers.len())
                .finish_non_exhaustive(),
            Self::DeleteConfig { peer_ids, .. } => f
                .debug_struct("DeleteConfig")
                .field("peer_ids", peer_ids)
                .finish_non_exhaustive(),
            Self::GetMetricsSnapshot { .. } => {
                f.debug_struct("GetMetricsSnapshot").finish_non_exhaustive()
            }
        }
    }
}

/// Dial failure notification from a spawned connection task.
///
/// Sent back to the orchestrator when `make_bare_tx` or `dial_h3` fails,
/// allowing the orchestrator to clear the in-flight flag and advance backoff.
#[derive(Debug)]
pub struct DialFailedEvent {
    /// Peer identifier from configuration.
    pub peer_id: String,
    /// The IP address that failed to connect.
    pub ip: IpAddr,
}

/// Describes transport-level events (connection lifecycle).
pub enum TransportEvent {
    /// HTTP/3 connection established, ready for actor spawning.
    H3Connected(H3ConnectedEvent),
    /// BareUDP TX connection established, ready for bound registration.
    BareConnected(BareConnectedEvent),
    /// A dial attempt failed; orchestrator should clear in-flight state and update backoff.
    DialFailed(DialFailedEvent),
}

impl std::fmt::Debug for TransportEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::H3Connected(e) => f.debug_tuple("H3Connected").field(e).finish(),
            Self::BareConnected(e) => f.debug_tuple("BareConnected").field(e).finish(),
            Self::DialFailed(e) => f.debug_tuple("DialFailed").field(e).finish(),
        }
    }
}

/// BareUDP TX connection established event.
///
/// Emitted by the async connection task when `make_bare_tx` + `spawn_udp_tx`
/// succeed. Carries the TX channel sender and actor JoinHandle for
/// orchestrator registration.
pub struct BareConnectedEvent {
    /// Peer identifier from configuration.
    pub peer_id: String,
    /// Configured endpoint that originated this connection.
    pub endpoint: Endpoint,
    /// Destination socket address.
    pub dest: SocketAddr,
    /// TX channel for sending packet batches to the bare TX actor.
    pub tx: mpsc::Sender<Vec<PooledBuf>>,
    /// Join handle for the spawned bare TX actor.
    pub tx_handle: JoinHandle<ActorExitResult>,
}

impl std::fmt::Debug for BareConnectedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BareConnectedEvent")
            .field("peer_id", &self.peer_id)
            .field("dest", &self.dest)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// HTTP/3 connection established event with full connection object.
///
/// Emitted by listener (inbound) and dialer (outbound) when connection is
/// established and ready for RX/TX actors to be spawned.
#[derive(Debug)]
pub struct H3ConnectedEvent {
    /// The established connection.
    pub connection: H3Connection,
    /// Whether this is an inbound or outbound connection.
    pub direction: ConnectionDirection,
}

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

#[cfg(test)]
mod tests {
    use super::*;

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

/// DNS resolution state change notification.
///
/// Emitted by the DNS resolver when the resolution state changes.
/// Contains the complete hostname→IP mapping snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEvent {
    /// Complete resolution state: hostname -> resolved IPs.
    ///
    /// Each hostname maps to its currently valid IPs (TTL not expired).
    /// Empty set indicates hostname is registered but has no valid IPs.
    pub state: HashMap<String, HashSet<IpAddr>>,
}
