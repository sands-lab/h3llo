//! Shared events flowing into the orchestrator.

use crate::bind::BindWarning;
use std::net::{IpAddr, SocketAddr};

/// Carries high-level events emitted by modules to the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Events originating from network interfaces (TUN or otherwise).
    Interface(InterfaceEvent),
    /// Events originating from DNS resolution.
    Dns(DnsEvent),
    /// Placeholder for future modules to extend the event stream without changing the channel type.
    Other(String),
}

/// Describes interface-level events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceEvent {
    /// Latest cumulative metrics for an interface.
    Metrics(InterfaceMetrics),
}

/// Indicates whether metrics were collected on the receive or transmit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Metrics from the receive side.
    Rx,
    /// Metrics from the transmit side.
    Tx,
}

/// Carries cumulative counters collected from an interface loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceMetrics {
    /// Interface name that produced the metrics.
    pub iface: String,
    /// Direction (receive or transmit) of the collected metrics.
    pub direction: Direction,
    /// Total packets observed on the interface.
    pub packets: u64,
    /// Total bytes observed on the interface.
    pub bytes: u64,
    /// Packets dropped in this direction.
    pub dropped_packets: u64,
    /// Bytes dropped in this direction.
    pub dropped_bytes: u64,
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
    /// Answer or status for a pending query.
    Answer(DnsAnswer),
    /// Query timed out and was retransmitted.
    Timeout(DnsTimeout),
    /// Packet failed validation or did not match pending queries.
    Unexpected(DnsUnexpected),
    /// Bind-related warning encountered during socket setup.
    BindWarning(BindWarning),
}

/// Describes a DNS answer and any attached warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    /// Queried hostname.
    pub host: String,
    /// Record type of the query.
    pub record_type: DnsRecordType,
    /// Resolved IP addresses for the record type.
    pub addresses: Vec<IpAddr>,
    /// Warnings derived from the DNS response.
    pub warnings: Vec<DnsAnswerWarning>,
}

/// Warnings extracted from a DNS answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAnswerWarning {
    /// DNS server reported NXDOMAIN.
    NxDomain,
    /// Response was truncated.
    Truncated,
    /// Server refused recursive resolution or recursion was unavailable.
    RecursionUnavailable,
    /// Server refused to answer.
    Refused,
    /// Unexpected response code.
    ResponseCode(String),
}

/// Notes that a query timed out and was retried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTimeout {
    /// Hostname whose query timed out.
    pub host: String,
    /// Record type of the timed-out query.
    pub record_type: DnsRecordType,
}

/// Records unexpected DNS responses or decoding failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsUnexpected {
    /// Transaction ID present in the packet (if parsed).
    pub id: Option<u16>,
    /// Hostname associated with the packet, when known.
    pub host: Option<String>,
    /// Record type associated with the packet, when known.
    pub record_type: Option<DnsRecordType>,
    /// Reason for flagging the packet.
    pub warning: DnsUnexpectedKind,
}

/// Reasons for unexpected DNS traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsUnexpectedKind {
    /// Packet referenced a transaction ID that is not pending.
    UnknownTransaction,
    /// Packet could not be decoded.
    DecodeFailed(String),
    /// Packet answered with a non-A/AAAA record type.
    UnexpectedRecordType(DnsRecordType),
    /// Sending the query failed.
    SendFailed(String),
}

/// Represents DNS record types supported by the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    /// IPv4 A record.
    A,
    /// IPv6 AAAA record.
    Aaaa,
    /// Non-A/AAAA record type.
    Other(u16),
}
