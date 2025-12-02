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
    /// Latest cumulative receive metrics for an interface.
    RxMetrics(RxMetrics),
    /// Latest cumulative transmit metrics for an interface.
    TxMetrics(TxMetrics),
}

/// Carries cumulative receive counters collected from an interface loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxMetrics {
    /// Interface name that produced the metrics.
    pub iface: String,
    /// Total packets read from the interface.
    pub packets: u64,
    /// Total bytes read from the interface.
    pub bytes: u64,
}

/// Carries cumulative transmit counters collected from an interface loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxMetrics {
    /// Interface name that produced the metrics.
    pub iface: String,
    /// Total packets written to the interface.
    pub packets: u64,
    /// Total bytes written to the interface.
    pub bytes: u64,
    /// Packets dropped because they exceeded the interface MTU.
    pub dropped_packets: u64,
    /// Bytes dropped because packets exceeded the interface MTU.
    pub dropped_bytes: u64,
}
