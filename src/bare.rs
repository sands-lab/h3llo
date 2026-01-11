//! BareUDP transport: socket setup, source-IP filtering, and send/receive loops.

pub use crate::udp::bind_socket;

use crate::bind::{BindWarning, RouteProbe};
use crate::events::{Direction, DropReason, Event, TransportEvent, TransportKind};
use crate::helpers::retry_on_interrupted;
use crate::metrics::TransportCounters;
use crate::udp::UdpError;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;

/// Warning from PeerEndpoints construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEndpointsWarning {
    /// DNS resolved multiple addresses; using first for outbound.
    MultipleAddresses {
        /// The selected outbound destination address.
        destination: SocketAddr,
        /// All resolved source IPs (used for filtering).
        all_sources: Vec<IpAddr>,
    },
}

/// Collects resolved peer addresses, preserving the first entry as outbound destination and all IPs for source filtering.
#[derive(Debug, Clone)]
pub struct PeerEndpoints {
    destination: SocketAddr,
    allowed_sources: HashSet<IpAddr>,
}

impl PeerEndpoints {
    /// Builds endpoint selection from resolved addresses, returning a warning when multiple unique IPs exist.
    ///
    /// # Errors
    ///
    /// Returns `UdpError::NoResolvedAddresses` when `endpoints` is empty.
    pub fn new(
        endpoints: Vec<SocketAddr>,
    ) -> Result<(Self, Option<PeerEndpointsWarning>), UdpError> {
        if endpoints.is_empty() {
            return Err(UdpError::NoResolvedAddresses);
        }

        let destination = endpoints[0];
        let mut allowed_sources = HashSet::new();
        for addr in endpoints {
            allowed_sources.insert(addr.ip());
        }

        let warning = if allowed_sources.len() > 1 {
            Some(PeerEndpointsWarning::MultipleAddresses {
                destination,
                all_sources: allowed_sources.iter().copied().collect(),
            })
        } else {
            None
        };

        Ok((
            Self {
                destination,
                allowed_sources,
            },
            warning,
        ))
    }

    /// Returns the outbound destination socket address (first resolved entry).
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Returns the set of source IPs allowed for inbound packets.
    pub fn allowed_sources(&self) -> &HashSet<IpAddr> {
        &self.allowed_sources
    }
}

/// Commands accepted by the BareUDP receive loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BareUdpRxCommand {
    /// Replace the allowed source IP filter set.
    UpdateAllowedSources(HashSet<IpAddr>),
}

/// Provides receive-only access to a BareUDP socket.
#[derive(Debug)]
pub struct BareUdpRx {
    socket: UdpSocket,
    mtu: usize,
}

impl BareUdpRx {
    /// Builds a BareUDP RX socket from a resolved listen address.
    ///
    /// # Errors
    ///
    /// Returns `UdpError::Socket` when socket binding fails.
    pub async fn from_config(listen: SocketAddr, mtu: usize) -> Result<Self, UdpError> {
        let socket = UdpSocket::bind(listen)
            .await
            .map_err(|err| UdpError::Socket(err.to_string()))?;
        Ok(Self { socket, mtu })
    }
}

/// Provides send-only access to a BareUDP socket.
#[derive(Debug)]
pub struct BareUdpTx {
    socket: UdpSocket,
}

impl BareUdpTx {
    /// Builds a BareUDP TX socket from a resolved destination address.
    ///
    /// # Errors
    ///
    /// Returns `UdpError::Socket` when socket creation or binding fails.
    pub async fn from_config<P: RouteProbe>(
        destination: SocketAddr,
        bindif: Option<&str>,
        tun_if: Option<&str>,
        probe: &P,
    ) -> Result<(Self, Vec<BindWarning>), UdpError> {
        let bind_addr = if destination.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
        };
        let (socket, warnings) =
            bind_socket(bind_addr, bindif, destination.ip(), tun_if, probe).await?;
        Ok((Self { socket }, warnings))
    }
}

/// Spawns the BareUDP receive loop, filtering on source IPs, emitting metrics, and forwarding packets.
///
/// # Arguments
/// - `rx`: Receive-only socket and MTU.
/// - `allowed_sources`: Initial allowed source IP set.
/// - `command_rx`: Channel delivering commands to the receive loop.
/// - `packet_tx`: Channel to push accepted packets into.
/// - `events_tx`: Channel for emitting receive metrics.
/// - `interval`: Metrics emission interval.
pub fn spawn_udp_rx(
    rx: BareUdpRx,
    mut allowed_sources: HashSet<IpAddr>,
    mut command_rx: mpsc::Receiver<BareUdpRxCommand>,
    packet_tx: mpsc::Sender<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()> {
    let BareUdpRx { socket, mtu } = rx;

    tokio::spawn(async move {
        let mut buf = vec![0u8; mtu];
        let mut counters = TransportCounters::new(TransportKind::BareUdp, Direction::Rx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, remote)) => {
                            if len == 0 {
                                continue;
                            }
                            if !allowed_sources.contains(&remote.ip()) {
                                counters.record_drop(DropReason::DisallowedSource, len);
                                continue;
                            }
                            let packet = buf[..len].to_vec();
                            if packet_tx.send(packet).await.is_err() {
                                counters.record_drop(DropReason::ChannelClosed, len);
                                break;
                            }
                            counters.record_success(len);
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                Some(command) = command_rx.recv() => {
                    match command {
                        BareUdpRxCommand::UpdateAllowedSources(update) => {
                            allowed_sources = update;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Transport(TransportEvent::Metrics(counters.snapshot(None, None)))).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// Spawns the BareUDP send loop, emitting metrics while forwarding packets to `destination`.
///
/// # Arguments
/// - `tx`: Send-only socket.
/// - `destination`: Remote peer socket address.
/// - `packet_rx`: Channel supplying packets to send.
/// - `events_tx`: Channel for emitting transmit metrics.
/// - `interval`: Metrics emission interval.
pub fn spawn_udp_tx(
    tx: BareUdpTx,
    destination: SocketAddr,
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()> {
    let BareUdpTx { socket } = tx;

    tokio::spawn(async move {
        let mut counters = TransportCounters::new(TransportKind::BareUdp, Direction::Tx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                maybe_packet = packet_rx.recv() => {
                    let packet = match maybe_packet {
                        Some(packet) => packet,
                        None => break,
                    };

                    match retry_on_interrupted!(socket.send_to(&packet, destination).await) {
                        Ok(written) => counters.record_success(written),
                        Err(_) => {
                            counters.record_drop(DropReason::SendError, packet.len());
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Transport(TransportEvent::Metrics(counters.snapshot(None, None)))).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    #[test]
    fn udp_selects_destination_and_returns_warning_for_multiple_answers() {
        let endpoints = vec![
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 6635)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 6635)),
        ];
        let (set, warning) = PeerEndpoints::new(endpoints).expect("peer endpoints should build");
        assert_eq!(
            set.destination(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 6635))
        );
        assert!(set
            .allowed_sources()
            .contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(set
            .allowed_sources()
            .contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

        // Verify warning is returned for multiple addresses
        let warning = warning.expect("should return warning for multiple addresses");
        match warning {
            PeerEndpointsWarning::MultipleAddresses {
                destination,
                all_sources,
            } => {
                assert_eq!(
                    destination,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 6635))
                );
                assert_eq!(all_sources.len(), 2);
                assert!(all_sources.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
                assert!(all_sources.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
            }
        }
    }

    #[test]
    fn udp_single_address_returns_no_warning() {
        let endpoints = vec![SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 1),
            6635,
        ))];
        let (set, warning) = PeerEndpoints::new(endpoints).expect("peer endpoints should build");
        assert_eq!(
            set.destination(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 6635))
        );
        assert!(
            warning.is_none(),
            "single address should not produce warning"
        );
    }

    #[test]
    fn udp_empty_endpoints_returns_error() {
        let result = PeerEndpoints::new(vec![]);
        assert!(matches!(result, Err(UdpError::NoResolvedAddresses)));
    }

    #[tokio::test]
    async fn udp_rx_filters_disallowed_sources() {
        let (socket, addr) = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            (sock, addr)
        };

        let (packet_tx, mut packet_rx) = mpsc::channel(4);
        let allowed = HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
        let (_cmd_tx, command_rx) = mpsc::channel(1);
        let (events_tx, mut _events_rx) = mpsc::channel(4);
        let context = BareUdpRx { socket, mtu: 64 };
        let handle = spawn_udp_rx(
            context,
            allowed,
            command_rx,
            packet_tx,
            events_tx,
            Duration::from_millis(200),
        );

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(&[1, 2, 3], addr)
            .await
            .expect("send should succeed");

        // Packet should be dropped because source IP is not allowed.
        let result = tokio::time::timeout(Duration::from_millis(50), packet_rx.recv()).await;
        assert!(result.is_err(), "no packet should be delivered");

        handle.abort();
    }

    #[tokio::test]
    async fn udp_rx_updates_allowed_sources() {
        let (socket, addr) = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            (sock, addr)
        };

        let (packet_tx, mut packet_rx) = mpsc::channel(4);
        let (cmd_tx, command_rx) = mpsc::channel(1);
        let (events_tx, mut _events_rx) = mpsc::channel(4);
        let context = BareUdpRx { socket, mtu: 64 };
        let handle = spawn_udp_rx(
            context,
            HashSet::new(),
            command_rx,
            packet_tx,
            events_tx,
            Duration::from_millis(200),
        );

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(&[5, 4, 3], addr)
            .await
            .expect("initial send should succeed");

        // First packet should be dropped.
        let first = tokio::time::timeout(Duration::from_millis(50), packet_rx.recv()).await;
        assert!(
            first.is_err(),
            "no packet should be delivered before update"
        );

        cmd_tx
            .send(BareUdpRxCommand::UpdateAllowedSources(HashSet::from([
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            ])))
            .await
            .unwrap();

        sender
            .send_to(&[7, 8, 9], addr)
            .await
            .expect("second send should succeed");

        let second = tokio::time::timeout(Duration::from_millis(100), packet_rx.recv())
            .await
            .expect("packet should arrive after update")
            .expect("channel should carry packet");
        assert_eq!(second, vec![7, 8, 9]);

        handle.abort();
    }

    #[tokio::test]
    async fn udp_tx_forwards_packets_to_destination() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (packet_tx, packet_rx) = mpsc::channel(4);
        let (events_tx, mut _events_rx) = mpsc::channel(4);
        let context = BareUdpTx {
            socket: sender_socket,
        };
        let handle = spawn_udp_tx(
            context,
            dest,
            packet_rx,
            events_tx,
            Duration::from_millis(200),
        );

        packet_tx.send(vec![9, 8, 7]).await.unwrap();

        let mut buf = vec![0u8; 64];
        let (len, _) = receiver
            .recv_from(&mut buf)
            .await
            .expect("receiver should get packet");
        assert_eq!(&buf[..len], &[9, 8, 7]);

        handle.abort();
    }

    #[tokio::test]
    async fn udp_rx_emits_metrics() {
        let (socket, addr) = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            (sock, addr)
        };

        let (packet_tx, mut packet_rx) = mpsc::channel(4);
        let (_cmd_tx, command_rx) = mpsc::channel(1);
        let (events_tx, mut events_rx) = mpsc::channel(4);
        let context = BareUdpRx { socket, mtu: 128 };
        let handle = spawn_udp_rx(
            context,
            HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
            command_rx,
            packet_tx,
            events_tx,
            Duration::from_millis(10),
        );

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(&[1, 2, 3, 4], addr)
            .await
            .expect("send should succeed");

        // Drain the forwarded packet to avoid channel backpressure.
        let forwarded = packet_rx.recv().await.expect("packet should be forwarded");
        assert_eq!(forwarded, vec![1, 2, 3, 4]);

        let metrics = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Transport(TransportEvent::Metrics(m)) = event {
                    if m.labels.direction == Direction::Rx && m.stats.succeeded.packets >= 1 {
                        return Some(m);
                    }
                }
            }
            None
        })
        .await
        .expect("rx metrics should arrive")
        .expect("rx metrics should not be None");

        assert_eq!(metrics.labels.kind, TransportKind::BareUdp);
        assert_eq!(metrics.labels.direction, Direction::Rx);
        assert_eq!(metrics.labels.peer_id, None);
        assert_eq!(metrics.labels.ip_addr, None);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.succeeded.bytes, 4);

        handle.abort();
    }

    #[tokio::test]
    async fn udp_tx_emits_metrics() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (packet_tx, packet_rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::channel(4);
        let context = BareUdpTx {
            socket: sender_socket,
        };
        let handle = spawn_udp_tx(
            context,
            dest,
            packet_rx,
            events_tx,
            Duration::from_millis(10),
        );

        packet_tx.send(vec![5, 4, 3, 2]).await.unwrap();

        let mut buf = vec![0u8; 16];
        let _ = receiver
            .recv_from(&mut buf)
            .await
            .expect("receiver should get packet");

        let metrics = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Transport(TransportEvent::Metrics(m)) = event {
                    if m.labels.direction == Direction::Tx && m.stats.succeeded.packets >= 1 {
                        return Some(m);
                    }
                }
            }
            None
        })
        .await
        .expect("tx metrics should arrive")
        .expect("tx metrics should not be None");

        assert_eq!(metrics.labels.kind, TransportKind::BareUdp);
        assert_eq!(metrics.labels.direction, Direction::Tx);
        assert_eq!(metrics.labels.peer_id, None);
        assert_eq!(metrics.labels.ip_addr, None);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.succeeded.bytes, 4);
        assert_eq!(metrics.stats.dropped.packets, 0);
        assert_eq!(metrics.stats.dropped.bytes, 0);

        handle.abort();
    }
}
