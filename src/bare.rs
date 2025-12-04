//! BareUDP transport: socket setup, source-IP filtering, and send/receive loops.

pub use crate::udp::bind_socket;

use crate::events::{Direction, Event, InterfaceEvent};
use crate::metrics::InterfaceCounters;
use crate::udp::UdpError;
use log::warn;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;

/// Collects resolved peer addresses, preserving the first entry as outbound destination and all IPs for source filtering.
#[derive(Debug, Clone)]
pub struct PeerEndpoints {
    destination: SocketAddr,
    allowed_sources: HashSet<IpAddr>,
    multiple_answers: bool,
}

impl PeerEndpoints {
    /// Builds endpoint selection from resolved addresses, warning when multiple unique IPs exist.
    ///
    /// # Errors
    ///
    /// Returns `UdpError::NoResolvedAddresses` when `endpoints` is empty.
    pub fn new(endpoints: Vec<SocketAddr>) -> Result<Self, UdpError> {
        if endpoints.is_empty() {
            return Err(UdpError::NoResolvedAddresses);
        }

        let destination = endpoints[0];
        let mut allowed_sources = HashSet::new();
        for addr in endpoints {
            allowed_sources.insert(addr.ip());
        }
        let multiple_answers = allowed_sources.len() > 1;
        if multiple_answers {
            warn!(
                "bareudp resolved multiple addresses; using {} for outbound and filtering on {:?}",
                destination, allowed_sources
            );
        }

        Ok(Self {
            destination,
            allowed_sources,
            multiple_answers,
        })
    }

    /// Returns the outbound destination socket address (first resolved entry).
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Returns the set of source IPs allowed for inbound packets.
    pub fn allowed_sources(&self) -> &HashSet<IpAddr> {
        &self.allowed_sources
    }

    /// Indicates whether multiple unique IPs were provided.
    pub fn had_multiple_answers(&self) -> bool {
        self.multiple_answers
    }
}

/// Collects socket, MTU, and interface label shared by BareUDP loops.
#[derive(Debug)]
pub struct UdpCtx {
    /// Shared UDP socket for BareUDP traffic.
    pub socket: Arc<UdpSocket>,
    /// Buffer size for inbound packets, typically the TUN MTU.
    pub mtu: usize,
    /// Label used in metrics emission.
    pub iface: String,
}

/// Spawns the BareUDP receive loop, filtering on source IPs, emitting metrics, and forwarding packets.
///
/// # Arguments
/// - `context`: Bundled socket, MTU, and interface label.
/// - `allowed_sources`: Initial allowed source IP set.
/// - `allowed_updates`: Channel delivering full replacements for the allowed source set.
/// - `outbound`: Channel to push accepted packets into.
/// - `events_tx`: Channel for emitting receive metrics.
/// - `interval`: Metrics emission interval.
pub fn spawn_receiver(
    context: UdpCtx,
    mut allowed_sources: HashSet<IpAddr>,
    mut allowed_updates: mpsc::Receiver<HashSet<IpAddr>>,
    outbound: mpsc::Sender<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()> {
    let UdpCtx { socket, mtu, iface } = context;

    tokio::spawn(async move {
        let mut buf = vec![0u8; mtu];
        let mut counters = InterfaceCounters::new(Direction::Rx);
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
                                counters.record_drop(len);
                                continue;
                            }
                            let packet = buf[..len].to_vec();
                            if outbound.send(packet).await.is_err() {
                                break;
                            }
                            counters.record_success(len);
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                Some(update) = allowed_updates.recv() => {
                    allowed_sources = update;
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Interface(InterfaceEvent::Metrics(counters.snapshot(&iface)))).await.is_err() {
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
/// - `context`: Bundled socket, MTU, and interface label.
/// - `destination`: Remote peer socket address.
/// - `inbound`: Channel supplying packets to send.
/// - `events_tx`: Channel for emitting transmit metrics.
/// - `interval`: Metrics emission interval.
pub fn spawn_sender(
    context: UdpCtx,
    destination: SocketAddr,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()> {
    let UdpCtx { socket, iface, .. } = context;

    tokio::spawn(async move {
        let mut counters = InterfaceCounters::new(Direction::Tx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                maybe_packet = inbound.recv() => {
                    let packet = match maybe_packet {
                        Some(packet) => packet,
                        None => break,
                    };

                    match socket.send_to(&packet, destination).await {
                        Ok(written) => counters.record_success(written),
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            counters.record_drop(packet.len());
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Interface(InterfaceEvent::Metrics(counters.snapshot(&iface)))).await.is_err() {
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
    fn selects_destination_and_flags_multiple_answers() {
        let endpoints = vec![
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 6635)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 6635)),
        ];
        let set = PeerEndpoints::new(endpoints).expect("peer endpoints should build");
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
        assert!(set.had_multiple_answers());
    }

    #[tokio::test]
    async fn receiver_filters_disallowed_sources() {
        let (socket, addr) = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            (sock, addr)
        };

        let (tx, mut rx) = mpsc::channel(4);
        let allowed = HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
        let (_allow_tx, allowed_updates) = mpsc::channel(1);
        let (events_tx, mut _events_rx) = mpsc::channel(4);
        let context = UdpCtx {
            socket: Arc::new(socket),
            mtu: 64,
            iface: "bare0".to_string(),
        };
        let handle = spawn_receiver(
            context,
            allowed,
            allowed_updates,
            tx,
            events_tx,
            Duration::from_millis(200),
        );

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(&[1, 2, 3], addr)
            .await
            .expect("send should succeed");

        // Packet should be dropped because source IP is not allowed.
        let result = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(result.is_err(), "no packet should be delivered");

        handle.abort();
    }

    #[tokio::test]
    async fn receiver_updates_allowed_sources() {
        let (socket, addr) = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            (sock, addr)
        };

        let (tx, mut rx) = mpsc::channel(4);
        let (update_tx, allowed_updates) = mpsc::channel(1);
        let (events_tx, mut _events_rx) = mpsc::channel(4);
        let context = UdpCtx {
            socket: Arc::new(socket),
            mtu: 64,
            iface: "bare1".to_string(),
        };
        let handle = spawn_receiver(
            context,
            HashSet::new(),
            allowed_updates,
            tx,
            events_tx,
            Duration::from_millis(200),
        );

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(&[5, 4, 3], addr)
            .await
            .expect("initial send should succeed");

        // First packet should be dropped.
        let first = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(
            first.is_err(),
            "no packet should be delivered before update"
        );

        update_tx
            .send(HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]))
            .await
            .unwrap();

        sender
            .send_to(&[7, 8, 9], addr)
            .await
            .expect("second send should succeed");

        let second = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("packet should arrive after update")
            .expect("channel should carry packet");
        assert_eq!(second, vec![7, 8, 9]);

        handle.abort();
    }

    #[tokio::test]
    async fn sender_forwards_packets_to_destination() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (tx, rx) = mpsc::channel(4);
        let (events_tx, mut _events_rx) = mpsc::channel(4);
        let context = UdpCtx {
            socket: Arc::new(sender_socket),
            mtu: 64,
            iface: "bare2".to_string(),
        };
        let handle = spawn_sender(context, dest, rx, events_tx, Duration::from_millis(200));

        tx.send(vec![9, 8, 7]).await.unwrap();

        let mut buf = vec![0u8; 64];
        let (len, _) = receiver
            .recv_from(&mut buf)
            .await
            .expect("receiver should get packet");
        assert_eq!(&buf[..len], &[9, 8, 7]);

        handle.abort();
    }

    #[tokio::test]
    async fn receiver_emits_metrics() {
        let (socket, addr) = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            (sock, addr)
        };

        let (tx, mut rx) = mpsc::channel(4);
        let (_update_tx, allowed_updates) = mpsc::channel(1);
        let (events_tx, mut events_rx) = mpsc::channel(4);
        let context = UdpCtx {
            socket: Arc::new(socket),
            mtu: 128,
            iface: "bare-metrics-rx".to_string(),
        };
        let handle = spawn_receiver(
            context,
            HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]),
            allowed_updates,
            tx,
            events_tx,
            Duration::from_millis(10),
        );

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(&[1, 2, 3, 4], addr)
            .await
            .expect("send should succeed");

        // Drain the forwarded packet to avoid channel backpressure.
        let forwarded = rx.recv().await.expect("packet should be forwarded");
        assert_eq!(forwarded, vec![1, 2, 3, 4]);

        let metrics = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Interface(InterfaceEvent::Metrics(m)) = event {
                    if m.direction == Direction::Rx && m.packets >= 1 {
                        return Some(m);
                    }
                }
            }
            None
        })
        .await
        .expect("rx metrics should arrive")
        .expect("rx metrics should not be None");

        assert_eq!(metrics.iface, "bare-metrics-rx");
        assert_eq!(metrics.packets, 1);
        assert_eq!(metrics.bytes, 4);

        handle.abort();
    }

    #[tokio::test]
    async fn sender_emits_metrics() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (tx, rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::channel(4);
        let context = UdpCtx {
            socket: Arc::new(sender_socket),
            mtu: 64,
            iface: "bare-metrics-tx".to_string(),
        };
        let handle = spawn_sender(context, dest, rx, events_tx, Duration::from_millis(10));

        tx.send(vec![5, 4, 3, 2]).await.unwrap();

        let mut buf = vec![0u8; 16];
        let _ = receiver
            .recv_from(&mut buf)
            .await
            .expect("receiver should get packet");

        let metrics = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Interface(InterfaceEvent::Metrics(m)) = event {
                    if m.direction == Direction::Tx && m.packets >= 1 {
                        return Some(m);
                    }
                }
            }
            None
        })
        .await
        .expect("tx metrics should arrive")
        .expect("tx metrics should not be None");

        assert_eq!(metrics.iface, "bare-metrics-tx");
        assert_eq!(metrics.packets, 1);
        assert_eq!(metrics.bytes, 4);
        assert_eq!(metrics.dropped_packets, 0);
        assert_eq!(metrics.dropped_bytes, 0);

        handle.abort();
    }
}
