//! Shared events flowing into the orchestrator.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::h3::H3Connection;

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
#[derive(Debug)]
pub enum TransportEvent {
    /// Latest cumulative metrics for a transport direction.
    Metrics(TransportMetrics),
    /// HTTP/3 connection established, ready for actor spawning.
    H3Connected(H3ConnectedEvent),
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
    /// Records a packet with length `len`, saturating on overflow.
    pub fn record(&mut self, len: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len as u64);
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
