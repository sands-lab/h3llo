//! Shared events flowing into the orchestrator.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Carries high-level events emitted by modules to the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Events originating from transports (TUN, BareUDP, HTTP/3).
    Transport(TransportEvent),
    /// Events originating from DNS resolution.
    Dns(DnsEvent),
    /// Placeholder for future modules to extend the event stream without changing the channel type.
    Other(String),
}

/// Describes transport-level events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportEvent {
    /// Latest cumulative metrics for a transport direction.
    Metrics(TransportMetrics),
    /// HTTP/3 connection established.
    H3Connected(H3ConnectedEvent),
    /// HTTP/3 connection closed.
    H3Closed(H3ClosedEvent),
}

/// HTTP/3 connection established event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3ConnectedEvent {
    /// Authenticated peer identifier.
    pub peer_id: String,
    /// Remote socket address.
    pub remote_addr: SocketAddr,
    /// Whether inbound (listener) or outbound (dialer).
    pub direction: Direction,
}

/// HTTP/3 connection closed event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3ClosedEvent {
    /// Peer identifier.
    pub peer_id: String,
    /// Reason for closure.
    pub reason: Option<String>,
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

/// Captures DNS observations per packet or timer tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEvent {
    /// DNS server socket address.
    pub server: SocketAddr,
    /// Detail of the DNS observation.
    pub detail: DnsEventDetail,
}

/// Enumerates DNS outcomes emitted by the resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsEventDetail {
    /// A new IP address was resolved for a hostname.
    IpResolved(DnsIpResolved),
    /// An IP address has expired and should no longer be used.
    IpExpired(DnsIpExpired),
}

/// Notification that a new IP was resolved for a hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsIpResolved {
    /// The hostname that was resolved.
    pub host: String,
    /// The resolved IP address.
    pub address: IpAddr,
}

/// Notification that an IP has expired for a hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsIpExpired {
    /// The hostname whose IP expired.
    pub host: String,
    /// The expired IP address.
    pub address: IpAddr,
}
