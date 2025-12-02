//! Shared events flowing into the orchestrator.

/// High-level events emitted by modules to the orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Events originating from the TUN module.
    Tun(TunEvent),
    /// Placeholder for future modules to extend the event stream without changing the channel type.
    Other(String),
}

/// TUN-specific events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunEvent {
    /// Latest TUN metrics snapshot emitted on a fixed cadence.
    Metrics(TunMetricsUpdate),
}

/// Carries counters collected from the TUN coroutines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunMetricsUpdate {
    /// Total packets read from the TUN.
    pub rx_packets: u64,
    /// Total packets written to the TUN.
    pub tx_packets: u64,
    /// Total bytes read from the TUN.
    pub rx_bytes: u64,
    /// Total bytes written to the TUN.
    pub tx_bytes: u64,
    /// Number of packets dropped because they exceeded the TUN MTU.
    pub dropped_tx_packets: u64,
    /// Number of bytes dropped because packets exceeded the TUN MTU.
    pub dropped_tx_bytes: u64,
}
