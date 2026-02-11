//! BareUDP transport: socket setup, source-IP filtering, and send/receive loops.

use crate::actor::{ActorError, ActorExitResult};
use crate::bind::{make_server_udp_socket, make_unbound_udp_socket, RouteProbe, UdpError};
use crate::events::{Direction, DropReason, Event, TransportEvent, TransportKind};
use crate::helpers::retry_on_transient;
use crate::metrics::TransportCounters;
use crate::tun::alloc_packet_buf;
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use std::collections::HashSet;
use std::io;
use std::io::IoSliceMut;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_quiche::buf_factory::PooledBuf;

/// Commands accepted by the BareUDP receive loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BareUdpRxCommand {
    /// Replace the accepted source IP filter set.
    ///
    /// "Accepted sources" controls which source IPs are permitted for inbound
    /// BareUDP packets, distinct from TUN's "allowed IPs" (routing prefixes).
    UpdateAcceptedSources(HashSet<IpAddr>),
}

/// Provides receive-only access to a BareUDP socket with quinn-udp GRO support.
#[derive(Debug)]
pub struct BareUdpRx {
    socket: UdpSocket,
    state: UdpSocketState,
    mtu: usize,
}

/// Creates a BareUDP RX actor state from resolved listen address.
///
/// # Arguments
///
/// * `listen` - Resolved socket address to bind.
/// * `mtu` - MTU for buffer sizing.
///
/// # Errors
///
/// Returns `UdpError::Socket` when socket binding fails.
pub fn make_bare_rx(listen: SocketAddr, mtu: usize) -> Result<BareUdpRx, UdpError> {
    let socket = make_server_udp_socket(listen)?;
    let state = UdpSocketState::new(UdpSockRef::from(&socket))
        .map_err(|e| UdpError::Socket(format!("quinn-udp state init: {e}")))?;
    Ok(BareUdpRx { socket, state, mtu })
}

/// Provides send-only access to an unconnected BareUDP socket with quinn-udp GSO support.
///
/// See [`make_bare_tx`] for socket creation and rationale.
#[derive(Debug)]
pub struct BareUdpTx {
    socket: UdpSocket,
    state: UdpSocketState,
    destination: SocketAddr,
}

/// Creates a BareUDP TX actor state with an unconnected socket.
///
/// The socket is unconnected; quinn-udp's `Transmit.destination` provides explicit
/// addressing via `sendmsg`. This avoids macOS `EISCONN` errors that occur when
/// `sendmsg` specifies a destination on a connected socket.
///
/// # Arguments
///
/// * `destination` - Resolved destination socket address.
/// * `bindif` - Optional interface name to bind.
/// * `tun_if` - Optional TUN interface name to exclude from routing.
/// * `probe` - Route probe for interface selection.
///
/// # Errors
///
/// Returns `UdpError::Socket` if socket creation fails.
///
/// Note: interface binding is best-effort; failures are logged and the
/// socket continues unbound.
pub async fn make_bare_tx<P: RouteProbe>(
    destination: SocketAddr,
    bindif: Option<&str>,
    tun_if: Option<&str>,
    probe: &P,
) -> Result<BareUdpTx, UdpError> {
    let socket = make_unbound_udp_socket(destination, tun_if, bindif, probe).await?;
    let state = UdpSocketState::new(UdpSockRef::from(&socket))
        .map_err(|e| UdpError::Socket(format!("quinn-udp state init: {e}")))?;
    Ok(BareUdpTx {
        socket,
        state,
        destination,
    })
}

/// Spawns the BareUDP receive loop.
///
/// Creates an unbounded command channel internally (actor owns the receiver).
/// Returns the command sender and join handle.
///
/// # Arguments
/// - `rx`: Receive-only socket and MTU.
/// - `accepted_sources`: Initial accepted source IP set.
/// - `packet_tx`: Bounded channel to push accepted packets into (data plane).
/// - `events_tx`: Unbounded channel for emitting receive metrics.
/// - `interval`: Metrics emission interval.
pub fn spawn_udp_rx(
    rx: BareUdpRx,
    mut accepted_sources: HashSet<IpAddr>,
    packet_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> (
    mpsc::UnboundedSender<BareUdpRxCommand>,
    JoinHandle<ActorExitResult>,
) {
    // Actor creates and owns its command channel receiver
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

    let BareUdpRx { socket, state, mtu } = rx;
    let local_addr = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();

    let handle = tokio::spawn(async move {
        let gro_segments = state.gro_segments();
        let mut buf = vec![0u8; mtu * gro_segments];
        let mut counters = TransportCounters::new(TransportKind::BareUdp, Direction::Rx);
        let mut ticker = time::interval(interval);
        let mut meta = RecvMeta::default();

        loop {
            tokio::select! {
                _ = socket.readable() => {
                    let result = socket.try_io(Interest::READABLE, || {
                        state.recv(
                            UdpSockRef::from(&socket),
                            &mut [IoSliceMut::new(&mut buf)],
                            std::slice::from_mut(&mut meta),
                        )
                    });
                    match result {
                        Ok(0) => continue,
                        Ok(_) => {
                            if meta.len == 0 {
                                continue;
                            }
                            let remote = meta.addr;
                            let stride = meta.stride.min(meta.len);

                            // All GRO chunks share the same source addr;
                            // check IP filter once for the entire batch.
                            if !accepted_sources.contains(&remote.ip()) {
                                let chunk_count = meta.len.div_ceil(stride);
                                counters.record_drop(DropReason::DisallowedSource, chunk_count as u64, meta.len as u64);
                                continue;
                            }

                            let mut batch = Vec::new();
                            for chunk in buf[..meta.len].chunks(stride) {
                                batch.push(alloc_packet_buf(chunk));
                            }

                            if batch.is_empty() {
                                continue;
                            }

                            // Pre-send metrics (Option 3A): channel send failure
                            // means shutdown, so pre-recording is acceptable.
                            let count = batch.len() as u64;
                            let total_bytes: u64 = batch.iter().map(|p| p.len() as u64).sum();
                            counters.record_success(count, total_bytes);
                            if packet_tx.send(batch).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(err) => {
                            return Err(ActorError::BareRxRecv { addr: local_addr, source: err });
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    let Some(command) = cmd else {
                        return Ok(()); // Channel closed, exit gracefully
                    };
                    // Single-variant enum: destructure directly
                    let BareUdpRxCommand::UpdateAcceptedSources(update) = command;
                    accepted_sources = update;
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Transport(TransportEvent::Metrics(counters.snapshot(None, None)))).is_err() {
                        return Ok(()); // Events channel closed during shutdown
                    }
                }
            }
        }
    });

    (cmd_tx, handle)
}

/// Spawns the BareUDP send loop using quinn-udp for GSO offload.
///
/// The socket is unconnected; each packet is sent via `sendmsg` with explicit
/// destination from `Transmit.destination`. Creates a bounded packet channel
/// internally (actor owns the receiver). Returns the packet sender and join handle.
///
/// # Arguments
/// - `tx`: Send-only socket with quinn-udp state and destination.
/// - `events_tx`: Unbounded channel for emitting transmit metrics.
/// - `interval`: Metrics emission interval.
/// - `packet_queue_depth`: Bounded channel capacity.
pub fn spawn_udp_tx(
    tx: BareUdpTx,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
    packet_queue_depth: usize,
) -> (mpsc::Sender<Vec<PooledBuf>>, JoinHandle<ActorExitResult>) {
    // Actor creates and owns its data-plane channel receiver
    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<PooledBuf>>(packet_queue_depth);
    let dest_str = tx.destination.to_string();

    let BareUdpTx {
        socket,
        state,
        destination,
    } = tx;

    let handle = tokio::spawn(async move {
        let mut counters = TransportCounters::new(TransportKind::BareUdp, Direction::Tx);
        let mut ticker = time::interval(interval);
        let mut gso_buf = Vec::with_capacity(u16::MAX as usize);

        loop {
            tokio::select! {
                maybe_batch = packet_rx.recv() => {
                    let packets = match maybe_batch {
                        Some(batch) => batch,
                        None => return Ok(()), // Channel closed, exit gracefully
                    };

                    if packets.is_empty() {
                        continue;
                    }

                    let max_segs = state.max_gso_segments();
                    // TUN GSO guarantees all non-tail packets in a batch share
                    // the same size; segment_size from the first packet is safe.
                    let segment_size = packets[0].len();
                    debug_assert!(segment_size > 0, "TUN GSO must not produce empty packets");

                    // Cap segments per sendmsg so the total payload fits in
                    // one UDP message (u16::MAX bytes). Without this, large
                    // batches (e.g. 64 × 1393 = 89 KB) exceed the limit and
                    // the kernel returns EMSGSIZE.
                    let max_segs = max_segs.min(u16::MAX as usize / segment_size);

                    for chunk in packets.chunks(max_segs.max(1)) {
                        gso_buf.clear();
                        for pkt in chunk {
                            gso_buf.extend_from_slice(pkt);
                        }

                        // segment_size tells the kernel to split contents into
                        // datagrams. When chunk has a single packet or
                        // max_gso_segments == 1, quinn-udp's prepare_msg skips
                        // the GSO cmsg automatically (segment_size >= contents.len()).
                        let transmit = Transmit {
                            destination,
                            ecn: None,
                            contents: &gso_buf,
                            segment_size: Some(segment_size),
                            src_ip: None,
                        };

                        match retry_on_transient!({
                            socket.writable().await.map_err(|err| {
                                ActorError::BareTxSend { dest: dest_str.clone(), source: err }
                            })?;
                            socket.try_io(Interest::WRITABLE, || {
                                state.try_send(UdpSockRef::from(&socket), &transmit)
                            })
                        }) {
                            Ok(()) => {
                                counters.record_success(chunk.len() as u64, gso_buf.len() as u64);
                            }
                            Err(err) => {
                                // quinn-udp may internally disable GSO
                                // (max_gso_segments -> 1) on EIO/EINVAL before
                                // returning the error. The actor terminates here;
                                // on respawn, max_gso_segments == 1 avoids GSO.
                                counters.record_drop(DropReason::SendError, chunk.len() as u64, gso_buf.len() as u64);
                                return Err(ActorError::BareTxSend { dest: dest_str, source: err });
                            }
                        }
                    }
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Transport(TransportEvent::Metrics(counters.snapshot(None, None)))).is_err() {
                        return Ok(()); // Events channel closed during shutdown
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
    use tokio_quiche::buf_factory::BufFactory;

    /// Creates a `BareUdpRx` directly from a socket for testing.
    fn test_bare_rx(socket: UdpSocket, mtu: usize) -> BareUdpRx {
        let state = UdpSocketState::new(UdpSockRef::from(&socket)).unwrap();
        BareUdpRx { socket, state, mtu }
    }

    /// Creates a `BareUdpTx` with an unconnected socket for testing.
    fn test_bare_tx(socket: UdpSocket, destination: SocketAddr) -> BareUdpTx {
        let state = UdpSocketState::new(UdpSockRef::from(&socket)).unwrap();
        BareUdpTx {
            socket,
            state,
            destination,
        }
    }

    // ========== make_bare_rx Tests ==========

    #[tokio::test]
    async fn make_bare_rx_creates_valid_state() {
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = make_bare_rx(listen, 1500);
        assert!(result.is_ok());
        let rx = result.unwrap();
        assert_eq!(rx.mtu, 1500);
    }

    // ========== make_bare_tx Tests ==========

    #[tokio::test]
    async fn make_bare_tx_creates_unconnected_socket() {
        use crate::bind::test_support::FakeRouteProbe;

        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let probe = FakeRouteProbe::noop();
        let result = make_bare_tx(dest, None, None, &probe).await;
        assert!(result.is_ok());
        let tx = result.unwrap();
        assert_eq!(tx.destination, dest);
    }

    #[tokio::test]
    async fn udp_rx_filters_non_accepted_sources() {
        let (socket, addr) = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            (sock, addr)
        };

        let (packet_tx, mut packet_rx) = mpsc::channel(4);
        let accepted = HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
        let (events_tx, mut _events_rx) = mpsc::unbounded_channel();
        let context = test_bare_rx(socket, 64);
        let (_cmd_tx, handle) = spawn_udp_rx(
            context,
            accepted,
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
    async fn udp_rx_updates_accepted_sources() {
        let (socket, addr) = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            (sock, addr)
        };

        let (packet_tx, mut packet_rx) = mpsc::channel(4);
        let (events_tx, mut _events_rx) = mpsc::unbounded_channel();
        let context = test_bare_rx(socket, 64);
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
            .send(BareUdpRxCommand::UpdateAcceptedSources(HashSet::from([
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            ])))
            .unwrap();

        sender
            .send_to(&[7, 8, 9], addr)
            .await
            .expect("second send should succeed");

        let batch = tokio::time::timeout(Duration::from_millis(100), packet_rx.recv())
            .await
            .expect("packet should arrive after update")
            .expect("channel should carry packet");
        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &[7, 8, 9]);

        handle.abort();
    }

    #[tokio::test]
    async fn udp_tx_forwards_packets_to_destination() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let (events_tx, mut _events_rx) = mpsc::unbounded_channel();
        let context = test_bare_tx(sender_socket, dest);
        let (packet_tx, handle) = spawn_udp_tx(context, events_tx, Duration::from_millis(200), 256);

        packet_tx
            .send(vec![BufFactory::buf_from_slice(&[9, 8, 7])])
            .await
            .unwrap();

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
        let context = test_bare_rx(socket, 128);
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
        let batch = packet_rx.recv().await.expect("packet should be forwarded");
        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &[1, 2, 3, 4]);

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
        let context = test_bare_tx(sender_socket, dest);
        let (packet_tx, handle) = spawn_udp_tx(context, events_tx, Duration::from_millis(10), 256);

        packet_tx
            .send(vec![BufFactory::buf_from_slice(&[5, 4, 3, 2])])
            .await
            .unwrap();

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
        let context = test_bare_rx(socket, 64);

        let (cmd_tx, handle) = spawn_udp_rx(
            context,
            HashSet::new(),
            packet_tx,
            events_tx,
            Duration::from_secs(60),
        );

        // Verify cmd_tx is functional by sending an accepted sources update
        assert!(cmd_tx
            .send(BareUdpRxCommand::UpdateAcceptedSources(HashSet::from([
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
        let context = test_bare_rx(socket, 64);

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
            matches!(result, Ok(Ok(Ok(())))),
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
        let context = test_bare_tx(sender_socket, dest);

        let (packet_tx, handle) = spawn_udp_tx(context, events_tx, Duration::from_secs(60), 256);

        // Verify packet_tx is functional by sending a batch
        assert!(packet_tx
            .send(vec![BufFactory::buf_from_slice(&[1, 2, 3])])
            .await
            .is_ok());

        handle.abort();
    }

    #[tokio::test]
    async fn udp_tx_actor_exits_when_sender_dropped() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let context = test_bare_tx(sender_socket, dest);

        let (packet_tx, join_handle) =
            spawn_udp_tx(context, events_tx, Duration::from_secs(60), 256);

        // Drop sender to signal shutdown
        drop(packet_tx);

        // Actor should exit gracefully (check both timeout and join result)
        let result = tokio::time::timeout(Duration::from_millis(200), join_handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "udp_tx actor should shut down cleanly after sender dropped, got {:?}",
            result
        );
    }

    /// Verifies RX output can be wired directly to TX input for packet forwarding.
    #[tokio::test]
    async fn udp_loopback_rx_to_tx_round_trip() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let rx_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx_addr = rx_socket.local_addr().unwrap();

        let tx_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        // Spawn TX first to get its packet_tx channel
        let (packet_tx, tx_handle) = spawn_udp_tx(
            test_bare_tx(tx_socket, dest),
            events_tx.clone(),
            Duration::from_secs(60),
            256,
        );

        // Spawn RX with TX's packet channel as output (direct wiring, no forwarder)
        let accepted = HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
        let (_cmd_tx, rx_handle) = spawn_udp_rx(
            test_bare_rx(rx_socket, 64),
            accepted,
            packet_tx,
            events_tx,
            Duration::from_secs(60),
        );

        // Send packet to RX, expect it at external receiver via TX
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(&[1, 2, 3], rx_addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (len, _) =
            tokio::time::timeout(Duration::from_millis(200), receiver.recv_from(&mut buf))
                .await
                .expect("timeout")
                .expect("recv");
        assert_eq!(&buf[..len], &[1, 2, 3]);

        rx_handle.abort();
        tx_handle.abort();
    }

    /// Verifies that a multi-packet batch is delivered correctly via GSO
    /// (or per-packet fallback on non-GSO platforms).
    #[tokio::test]
    async fn udp_tx_batch_gso_delivers_all_packets() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let context = test_bare_tx(sender_socket, dest);
        let (packet_tx, handle) = spawn_udp_tx(context, events_tx, Duration::from_millis(200), 256);

        // Send a batch of 3 equal-sized packets (simulates TUN GSO output)
        let batch = vec![
            BufFactory::buf_from_slice(&[1, 2, 3, 4]),
            BufFactory::buf_from_slice(&[5, 6, 7, 8]),
            BufFactory::buf_from_slice(&[9, 10, 11, 12]),
        ];
        packet_tx.send(batch).await.unwrap();

        let mut received = Vec::new();
        for _ in 0..3 {
            let mut buf = vec![0u8; 64];
            let (len, _) =
                tokio::time::timeout(Duration::from_millis(200), receiver.recv_from(&mut buf))
                    .await
                    .expect("should receive packet")
                    .expect("recv_from");
            received.push(buf[..len].to_vec());
        }
        received.sort();
        assert_eq!(
            received,
            vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]]
        );

        handle.abort();
    }

    /// Verifies that a batch with a shorter last packet (common in TCP flows)
    /// is delivered correctly.
    #[tokio::test]
    async fn udp_tx_batch_gso_short_last_packet() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let context = test_bare_tx(sender_socket, dest);
        let (packet_tx, handle) = spawn_udp_tx(context, events_tx, Duration::from_millis(200), 256);

        // Last packet is shorter (e.g., TCP stream tail)
        let batch = vec![
            BufFactory::buf_from_slice(&[1, 2, 3, 4]),
            BufFactory::buf_from_slice(&[5, 6, 7, 8]),
            BufFactory::buf_from_slice(&[9, 10]),
        ];
        packet_tx.send(batch).await.unwrap();

        let mut received = Vec::new();
        for _ in 0..3 {
            let mut buf = vec![0u8; 64];
            let (len, _) =
                tokio::time::timeout(Duration::from_millis(200), receiver.recv_from(&mut buf))
                    .await
                    .expect("should receive packet")
                    .expect("recv_from");
            received.push(buf[..len].to_vec());
        }
        received.sort();
        assert_eq!(
            received,
            vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10]]
        );

        handle.abort();
    }

    /// Verifies that metrics count each packet individually in a GSO batch.
    #[tokio::test]
    async fn udp_tx_gso_batch_metrics() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let context = test_bare_tx(sender_socket, dest);
        let (packet_tx, handle) = spawn_udp_tx(context, events_tx, Duration::from_millis(10), 256);

        let batch = vec![
            BufFactory::buf_from_slice(&[1, 2, 3]),
            BufFactory::buf_from_slice(&[4, 5, 6]),
        ];
        packet_tx.send(batch).await.unwrap();

        // Drain packets
        let mut buf = vec![0u8; 64];
        for _ in 0..2 {
            let _ = receiver.recv_from(&mut buf).await.unwrap();
        }

        let metrics = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Transport(TransportEvent::Metrics(m)) = event {
                    if m.labels.direction == Direction::Tx && m.stats.succeeded.packets >= 2 {
                        return Some(m);
                    }
                }
            }
            None
        })
        .await
        .expect("tx metrics should arrive")
        .expect("tx metrics should not be None");

        assert_eq!(metrics.stats.succeeded.packets, 2);
        assert_eq!(metrics.stats.succeeded.bytes, 6);

        handle.abort();
    }
}
