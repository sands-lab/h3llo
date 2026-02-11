//! Shared events flowing into the orchestrator.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::actor::ActorExitResult;
use crate::config::{H3Endpoint, UdpEndpoint};
use crate::h3::H3Connection;
use tokio::sync::mpsc;
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
    /// Events originating from transports (TUN, BareUDP, HTTP/3).
    Transport(TransportEvent),
    /// Events originating from DNS resolution.
    Dns(DnsEvent),
    /// Placeholder for future modules to extend the event stream without changing the channel type.
    Other(String),
}

/// Describes transport-level events.
pub enum TransportEvent {
    /// Latest cumulative metrics for a transport direction.
    Metrics(TransportMetrics),
    /// HTTP/3 connection established, ready for actor spawning.
    H3Connected(H3ConnectedEvent),
    /// BareUDP TX connection established, ready for bound registration.
    BareConnected(BareConnectedEvent),
}

impl std::fmt::Debug for TransportEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Metrics(m) => f.debug_tuple("Metrics").field(m).finish(),
            Self::H3Connected(e) => f.debug_tuple("H3Connected").field(e).finish(),
            Self::BareConnected(e) => f.debug_tuple("BareConnected").field(e).finish(),
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

/// Indicates which transport produced the metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    /// TUN interface.
    Tun,
    /// BareUDP socket.
    BareUdp,
    /// HTTP/3 transport.
    Http3,
}

/// Indicates whether metrics were collected on the receive or transmit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

/// Aggregates packet counters by outcome.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PktCounters {
    /// Number of packets observed.
    pub packets: u64,
    /// Total bytes observed.
    pub bytes: u64,
}

impl PktCounters {
    /// Records a batch of packets, saturating on overflow.
    ///
    /// For single-packet recording, pass `count = 1`.
    pub fn record(&mut self, count: u64, total_bytes: u64) {
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
        assert_eq!(c.packets, 3);
        assert_eq!(c.bytes, 150);
    }

    #[test]
    fn pkt_counters_record_single() {
        let mut c = PktCounters::default();
        c.record(1, 64);
        assert_eq!(c.packets, 1);
        assert_eq!(c.bytes, 64);
    }

    #[test]
    fn pkt_counters_saturates() {
        let mut c = PktCounters {
            packets: u64::MAX - 1,
            bytes: u64::MAX - 1,
        };
        c.record(5, 100);
        assert_eq!(c.packets, u64::MAX);
        assert_eq!(c.bytes, u64::MAX);
    }
}

/// Collects per-transport statistics including drop breakdowns.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransportStats {
    /// Successful packet counters.
    pub succeeded: PktCounters,
    /// Dropped packet counters.
    pub dropped: PktCounters,
    /// Drop counters keyed by reason.
    pub drop_reasons: HashMap<DropReason, PktCounters>,
}

/// Labels attached to transport metrics for grouping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportLabels {
    /// Transport kind (TUN, BareUDP, HTTP/3).
    pub kind: TransportKind,
    /// Direction (receive or transmit) of the collected metrics.
    pub direction: Direction,
    /// Optional peer identifier when the transport is peer-scoped.
    pub peer_id: Option<String>,
    /// Optional IP address associated with the transport.
    pub ip_addr: Option<IpAddr>,
}

/// Carries cumulative counters collected from a transport loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportMetrics {
    /// Labels describing the metric dimensions.
    pub labels: TransportLabels,
    /// Aggregated statistics with drop breakdown.
    pub stats: TransportStats,
}

/// DNS resolution state change notification.
///
/// Emitted by the DNS resolver when the resolution state changes.
/// Contains the complete hostname→IP mapping snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEvent {
    /// DNS server socket address.
    pub server: SocketAddr,
    /// Complete resolution state: hostname -> resolved IPs.
    ///
    /// Each hostname maps to its currently valid IPs (TTL not expired).
    /// Empty Vec indicates hostname is registered but has no valid IPs.
    pub state: HashMap<String, Vec<IpAddr>>,
}
