//! BareUDP protocol actors: source-IP filtering (RX) and destination stamping (TX).
//!
//! These actors sit between the generic UDP I/O layer ([`crate::udp`]) and the
//! router, adding BareUDP-specific behavior without touching sockets directly.

use crate::actor::ActorExitResult;
use crate::bind::{make_unbound_udp_socket, RouteProbe, UdpError};
use crate::config::UdpEndpoint;
use crate::events::{BareConnectedEvent, DialContext, Endpoint, Event};
use crate::metrics::{Counters, Direction, DropReason, Source};
use crate::udp;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
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

/// Spawns the BareUDP source-filter receive actor.
///
/// Creates its own input channel and returns the `Sender` for upstream
/// (e.g. `udp::spawn_udp_rx`) to send tagged batches into. Filters by
/// accepted source IPs and forwards accepted batches to the router.
///
/// # Arguments
///
/// * `accepted_sources` - Initial set of accepted source IPs.
/// * `ingress_tx` - Bounded channel to the router actor.
/// * `events_tx` - Metrics event channel.
/// * `interval` - Metrics emission interval.
/// * `packet_queue_depth` - Bounded input channel capacity.
#[allow(clippy::type_complexity)]
pub fn spawn_bare_rx(
    mut accepted_sources: HashSet<IpAddr>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
    packet_queue_depth: usize,
) -> (
    mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    mpsc::UnboundedSender<BareUdpRxCommand>,
    JoinHandle<ActorExitResult>,
) {
    let (input_tx, mut udp_rx) = mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(packet_queue_depth);
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

    let handle = tokio::spawn(async move {
        let mut counters = Counters::new(Source::BareUdp, Direction::Rx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                maybe = udp_rx.recv() => {
                    let Some((remote, batch)) = maybe else { return Ok(()); };
                    let count = batch.len() as u64;
                    let bytes: u64 = batch.iter().map(|p| p.len() as u64).sum();
                    if !accepted_sources.contains(&remote.ip()) {
                        counters.record_drop(DropReason::DisallowedSource, count, bytes);
                        continue;
                    }
                    if !counters.send_and_record(&ingress_tx, batch, count, bytes).await {
                        return Ok(());
                    }
                }
                cmd = cmd_rx.recv() => {
                    let Some(command) = cmd else {
                        return Ok(());
                    };
                    // Single-variant enum: destructure directly
                    let BareUdpRxCommand::UpdateAcceptedSources(update) = command;
                    accepted_sources = update;
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Metrics(counters.snapshot(None, None))).is_err() {
                        return Ok(());
                    }
                }
            }
        }
    });

    (input_tx, cmd_tx, handle)
}

/// Spawns a BareUDP transmit adapter actor.
///
/// Creates a BareUDP outbound TX path: socket → UDP TX actor → bare TX actor.
///
/// Returns a [`BareConnectedEvent`] on success. The caller is responsible
/// for sending the event and handling errors.
///
/// `ctx.udp_rt` is used for socket registration and the UDP TX actor;
/// `ctx.crypto_rt` is used for the bare TX adapter actor.
pub async fn dial_bare_tx<P: RouteProbe>(
    endpoint: UdpEndpoint,
    destination: SocketAddr,
    ctx: &DialContext,
    probe: &P,
    bindif: Option<&str>,
) -> Result<BareConnectedEvent, UdpError> {
    let std_socket = make_unbound_udp_socket(
        destination,
        Some(ctx.tun_if.as_str()),
        bindif,
        probe,
        ctx.tuning.socket_buffer_bytes(),
    )
    .await?;

    let (udp_send_tx, udp_tx_handle) = {
        let _guard = ctx.udp_rt.enter();
        let socket =
            UdpSocket::from_std(std_socket).map_err(|e| UdpError::Socket(e.to_string()))?;
        let (_rx, tx) = udp::make_udp(socket, ctx.tun_mtu, ctx.tuning.udp_enable_offload)?;
        udp::spawn_udp_tx(tx, ctx.tuning.packet_queue_depth)
    };
    let (egress_tx, bare_tx_handle) = {
        let _guard = ctx.crypto_rt.enter();
        spawn_bare_tx(
            udp_send_tx,
            destination,
            ctx.peer_id.clone(),
            ctx.events_tx.clone(),
            ctx.tuning.metrics_push_interval,
            ctx.tuning.packet_queue_depth,
        )
    };

    Ok(BareConnectedEvent {
        peer_id: ctx.peer_id.clone(),
        endpoint: Endpoint::Udp(endpoint),
        dest: destination,
        tx: egress_tx,
        tx_handle: bare_tx_handle,
        udp_tx_handle,
    })
}

/// Spawns the BareUDP destination-stamping transmit actor.
///
/// Receives `Vec<PooledBuf>` from the router, stamps each batch with the
/// peer's destination address, and forwards to the UDP TX actor.
/// Records metrics after successful channel send to avoid inflating
/// counters when the downstream actor is unavailable.
///
/// # Arguments
///
/// * `udp_tx` - Tagged channel to `udp::spawn_udp_tx`.
/// * `destination` - Peer destination socket address.
/// * `peer_id` - Peer identifier for metrics labels.
/// * `events_tx` - Metrics event channel.
/// * `metrics_interval` - Metrics emission interval.
/// * `packet_queue_depth` - Bounded channel capacity for router → bare TX.
pub fn spawn_bare_tx(
    udp_tx: mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    destination: SocketAddr,
    peer_id: String,
    events_tx: mpsc::UnboundedSender<Event>,
    metrics_interval: Duration,
    packet_queue_depth: usize,
) -> (mpsc::Sender<Vec<PooledBuf>>, JoinHandle<ActorExitResult>) {
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<PooledBuf>>(packet_queue_depth);

    let handle = tokio::spawn(async move {
        let mut counters = Counters::new(Source::BareUdp, Direction::Tx);
        let mut ticker = time::interval(metrics_interval);

        loop {
            tokio::select! {
                maybe_batch = egress_rx.recv() => {
                    let Some(packets) = maybe_batch else { return Ok(()); };
                    if packets.is_empty() { continue; }
                    let count = packets.len() as u64;
                    let bytes: u64 = packets.iter().map(|p| p.len() as u64).sum();
                    // Record success AFTER send — avoids inflating metrics on channel close.
                    match udp_tx.send((destination, packets)).await {
                        Ok(()) => counters.record_success(count, bytes),
                        Err(_) => return Ok(()),
                    }
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Metrics(
                        counters.snapshot(Some(&peer_id), Some(destination))
                    )).is_err() {
                        return Ok(());
                    }
                }
            }
        }
    });

    (egress_tx, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Event;
    use crate::metrics::Direction;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio_quiche::buf_factory::BufFactory;

    #[tokio::test]
    async fn bare_rx_filters_non_accepted_sources() {
        let (ingress_tx, mut ingress_rx) = mpsc::channel(4);
        let accepted = HashSet::from([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let (udp_tx, _cmd_tx, handle) = spawn_bare_rx(
            accepted,
            ingress_tx,
            events_tx,
            Duration::from_millis(200),
            4,
        );

        // Send from a non-accepted source
        let remote: SocketAddr = "192.168.1.1:5353".parse().unwrap();
        let batch = vec![BufFactory::buf_from_slice(&[1, 2, 3])];
        udp_tx.send((remote, batch)).await.unwrap();

        let result = tokio::time::timeout(Duration::from_millis(50), ingress_rx.recv()).await;
        assert!(
            result.is_err(),
            "packet from non-accepted source should be dropped"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn bare_rx_forwards_accepted_sources() {
        let (ingress_tx, mut ingress_rx) = mpsc::channel(4);
        let accepted = HashSet::from([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let (udp_tx, _cmd_tx, handle) = spawn_bare_rx(
            accepted,
            ingress_tx,
            events_tx,
            Duration::from_millis(200),
            4,
        );

        let remote: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let batch = vec![BufFactory::buf_from_slice(&[7, 8, 9])];
        udp_tx.send((remote, batch)).await.unwrap();

        let received = tokio::time::timeout(Duration::from_millis(100), ingress_rx.recv())
            .await
            .expect("should receive within timeout")
            .expect("channel should carry message");
        assert_eq!(received.len(), 1);
        assert_eq!(&received[0][..], &[7, 8, 9]);

        handle.abort();
    }

    #[tokio::test]
    async fn bare_rx_updates_accepted_sources() {
        let (ingress_tx, mut ingress_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let (udp_tx, cmd_tx, handle) = spawn_bare_rx(
            HashSet::new(),
            ingress_tx,
            events_tx,
            Duration::from_millis(200),
            4,
        );

        // Initially no sources accepted — packet should be dropped.
        let remote: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        udp_tx
            .send((remote, vec![BufFactory::buf_from_slice(&[1])]))
            .await
            .unwrap();
        let first = tokio::time::timeout(Duration::from_millis(50), ingress_rx.recv()).await;
        assert!(first.is_err(), "should be dropped before update");

        // Update accepted sources.
        cmd_tx
            .send(BareUdpRxCommand::UpdateAcceptedSources(HashSet::from([
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ])))
            .unwrap();

        // Yield to let the actor process the command before sending the next packet.
        tokio::task::yield_now().await;

        // Now the same source should be accepted.
        udp_tx
            .send((remote, vec![BufFactory::buf_from_slice(&[2])]))
            .await
            .unwrap();
        let batch = tokio::time::timeout(Duration::from_millis(100), ingress_rx.recv())
            .await
            .expect("should arrive after update")
            .expect("channel should carry message");
        assert_eq!(&batch[0][..], &[2]);

        handle.abort();
    }

    #[tokio::test]
    async fn bare_rx_emits_metrics() {
        let (ingress_tx, mut ingress_rx) = mpsc::channel(4);
        let accepted = HashSet::from([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let (udp_tx, _cmd_tx, handle) = spawn_bare_rx(
            accepted,
            ingress_tx,
            events_tx,
            Duration::from_millis(10),
            4,
        );

        let remote: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        udp_tx
            .send((remote, vec![BufFactory::buf_from_slice(&[1, 2, 3, 4])]))
            .await
            .unwrap();

        // Drain forwarded message.
        let _ = ingress_rx.recv().await;

        let metrics = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Metrics(m) = event {
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

        assert_eq!(metrics.labels.source, Source::BareUdp);
        assert_eq!(metrics.labels.direction, Direction::Rx);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.succeeded.bytes, 4);

        handle.abort();
    }

    #[tokio::test]
    async fn bare_tx_tags_and_forwards() {
        let dest: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let (udp_tx, mut udp_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let (egress_tx, handle) = spawn_bare_tx(
            udp_tx,
            dest,
            "test-peer".to_string(),
            events_tx,
            Duration::from_millis(200),
            4,
        );

        let batch = vec![BufFactory::buf_from_slice(&[9, 8, 7])];
        egress_tx.send(batch).await.unwrap();

        let (tagged_dest, packets) =
            tokio::time::timeout(Duration::from_millis(100), udp_rx.recv())
                .await
                .expect("should receive within timeout")
                .expect("channel should carry message");

        assert_eq!(tagged_dest, dest);
        assert_eq!(packets.len(), 1);
        assert_eq!(&packets[0][..], &[9, 8, 7]);

        handle.abort();
    }

    #[tokio::test]
    async fn bare_tx_emits_metrics() {
        let dest: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let (udp_tx, mut udp_rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let (egress_tx, handle) = spawn_bare_tx(
            udp_tx,
            dest,
            "test-peer".to_string(),
            events_tx,
            Duration::from_millis(10),
            4,
        );

        egress_tx
            .send(vec![BufFactory::buf_from_slice(&[5, 4, 3, 2])])
            .await
            .unwrap();

        // Drain forwarded message.
        let _ = udp_rx.recv().await;

        let metrics = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Metrics(m) = event {
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

        assert_eq!(metrics.labels.source, Source::BareUdp);
        assert_eq!(metrics.labels.direction, Direction::Tx);
        assert_eq!(metrics.labels.peer_id, Some("test-peer".to_string()));
        assert_eq!(metrics.labels.remote_addr, Some(dest));
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.succeeded.bytes, 4);

        handle.abort();
    }

    #[tokio::test]
    async fn bare_rx_exits_when_cmd_channel_closed() {
        let (ingress_tx, _ingress_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let (_udp_tx, cmd_tx, handle) = spawn_bare_rx(
            HashSet::new(),
            ingress_tx,
            events_tx,
            Duration::from_secs(60),
            4,
        );

        // Drop cmd_tx to signal shutdown via command channel closure.
        drop(cmd_tx);

        let result = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "bare_rx should exit gracefully when cmd channel closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn bare_tx_exits_when_egress_closed() {
        let dest: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let (egress_tx, handle) = spawn_bare_tx(
            udp_tx,
            dest,
            "test-peer".to_string(),
            events_tx,
            Duration::from_secs(60),
            4,
        );

        drop(egress_tx);

        let result = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "bare_tx should exit gracefully when egress closed, got {result:?}"
        );
    }
}
