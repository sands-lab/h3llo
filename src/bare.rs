//! BareUDP transport: socket setup, source-IP filtering, and send/receive loops.

pub use crate::bind::bind_udp_socket;
use crate::bind::{RouteProbe, UdpError};
use crate::events::{Direction, DropReason, Event, TransportEvent, TransportKind};
use crate::helpers::retry_on_interrupted;
use crate::metrics::TransportCounters;
use crate::PACKET_QUEUE_DEPTH;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;

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
    ) -> Result<Self, UdpError> {
        let bind_addr = if destination.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
        };
        let socket = bind_udp_socket(bind_addr, bindif, destination.ip(), tun_if, probe).await?;
        Ok(Self { socket })
    }
}

/// Spawns the BareUDP receive loop.
///
/// Creates an unbounded command channel internally (actor owns the receiver).
/// Returns the command sender and join handle.
///
/// # Arguments
/// - `rx`: Receive-only socket and MTU.
/// - `allowed_sources`: Initial allowed source IP set.
/// - `packet_tx`: Bounded channel to push accepted packets into (data plane).
/// - `events_tx`: Unbounded channel for emitting receive metrics.
/// - `interval`: Metrics emission interval.
pub fn spawn_udp_rx(
    rx: BareUdpRx,
    mut allowed_sources: HashSet<IpAddr>,
    packet_tx: mpsc::Sender<Vec<u8>>,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> (mpsc::UnboundedSender<BareUdpRxCommand>, JoinHandle<()>) {
    // Actor creates and owns its command channel receiver
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

    let BareUdpRx { socket, mtu } = rx;

    let handle = tokio::spawn(async move {
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
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(command) => {
                            match command {
                                BareUdpRxCommand::UpdateAllowedSources(update) => {
                                    allowed_sources = update;
                                }
                            }
                        }
                        None => break, // Channel closed, exit gracefully
                    }
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Transport(TransportEvent::Metrics(counters.snapshot(None, None)))).is_err() {
                        break;
                    }
                }
            }
        }
    });

    (cmd_tx, handle)
}

/// Spawns the BareUDP send loop, emitting metrics while forwarding packets to `destination`.
///
/// Creates a bounded packet channel internally (actor owns the receiver).
/// Returns the packet sender and join handle.
///
/// # Arguments
/// - `tx`: Send-only socket.
/// - `destination`: Remote peer socket address.
/// - `events_tx`: Unbounded channel for emitting transmit metrics.
/// - `interval`: Metrics emission interval.
pub fn spawn_udp_tx(
    tx: BareUdpTx,
    destination: SocketAddr,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> (mpsc::Sender<Vec<u8>>, JoinHandle<()>) {
    // Actor creates and owns its data-plane channel receiver
    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(PACKET_QUEUE_DEPTH);

    let BareUdpTx { socket } = tx;

    let handle = tokio::spawn(async move {
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
                    if events_tx.send(Event::Transport(TransportEvent::Metrics(counters.snapshot(None, None)))).is_err() {
                        break;
                    }
                }
            }
        }
    });

    (packet_tx, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[tokio::test]
    async fn udp_rx_filters_disallowed_sources() {
        let (socket, addr) = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            (sock, addr)
        };

        let (packet_tx, mut packet_rx) = mpsc::channel(4);
        let allowed = HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
        let (events_tx, mut _events_rx) = mpsc::unbounded_channel();
        let context = BareUdpRx { socket, mtu: 64 };
        let (_cmd_tx, handle) = spawn_udp_rx(
            context,
            allowed,
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
        let (events_tx, mut _events_rx) = mpsc::unbounded_channel();
        let context = BareUdpRx { socket, mtu: 64 };
        let (cmd_tx, handle) = spawn_udp_rx(
            context,
            HashSet::new(),
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
        let (events_tx, mut _events_rx) = mpsc::unbounded_channel();
        let context = BareUdpTx {
            socket: sender_socket,
        };
        let (packet_tx, handle) =
            spawn_udp_tx(context, dest, events_tx, Duration::from_millis(200));

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
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let context = BareUdpRx { socket, mtu: 128 };
        let (_cmd_tx, handle) = spawn_udp_rx(
            context,
            HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
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
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let context = BareUdpTx {
            socket: sender_socket,
        };
        let (packet_tx, handle) = spawn_udp_tx(context, dest, events_tx, Duration::from_millis(10));

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

    // ========== Actor Lifecycle Tests ==========

    #[tokio::test]
    async fn spawn_udp_rx_returns_working_cmd_tx() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (packet_tx, _packet_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let context = BareUdpRx { socket, mtu: 64 };

        let (cmd_tx, handle) = spawn_udp_rx(
            context,
            HashSet::new(),
            packet_tx,
            events_tx,
            Duration::from_secs(60),
        );

        // Verify cmd_tx is functional by sending an allowed sources update
        assert!(cmd_tx
            .send(BareUdpRxCommand::UpdateAllowedSources(HashSet::from([
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
            ])))
            .is_ok());

        handle.abort();
    }

    #[tokio::test]
    async fn udp_rx_actor_exits_when_sender_dropped() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (packet_tx, _packet_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let context = BareUdpRx { socket, mtu: 64 };

        let (cmd_tx, join_handle) = spawn_udp_rx(
            context,
            HashSet::new(),
            packet_tx,
            events_tx,
            Duration::from_secs(60),
        );

        // Drop sender to signal shutdown
        drop(cmd_tx);

        // Actor should exit gracefully (check both timeout and join result)
        let result = tokio::time::timeout(Duration::from_millis(200), join_handle).await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "udp_rx actor should shut down cleanly after sender dropped, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn spawn_udp_tx_returns_working_packet_tx() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let context = BareUdpTx {
            socket: sender_socket,
        };

        let (packet_tx, handle) = spawn_udp_tx(context, dest, events_tx, Duration::from_secs(60));

        // Verify packet_tx is functional by sending a packet
        assert!(packet_tx.send(vec![1, 2, 3]).await.is_ok());

        handle.abort();
    }

    #[tokio::test]
    async fn udp_tx_actor_exits_when_sender_dropped() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let context = BareUdpTx {
            socket: sender_socket,
        };

        let (packet_tx, join_handle) =
            spawn_udp_tx(context, dest, events_tx, Duration::from_secs(60));

        // Drop sender to signal shutdown
        drop(packet_tx);

        // Actor should exit gracefully (check both timeout and join result)
        let result = tokio::time::timeout(Duration::from_millis(200), join_handle).await;
        assert!(
            matches!(result, Ok(Ok(()))),
            "udp_tx actor should shut down cleanly after sender dropped, got {:?}",
            result
        );
    }
}
