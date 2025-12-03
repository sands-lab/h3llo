//! Shared events flowing into the orchestrator.

/// Carries high-level events emitted by modules to the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Events originating from network interfaces (TUN or otherwise).
    Interface(InterfaceEvent),
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
