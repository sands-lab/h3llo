//! BareUDP protocol actors: source-IP filtering (RX) and destination stamping (TX).
//!
//! These actors sit between the generic UDP I/O layer ([`crate::udp`]) and the
//! router, adding BareUDP-specific behavior without touching sockets directly.

use crate::actor::ActorExitResult;
use crate::bind::{make_server_udp_socket, make_unbound_udp_socket, RouteProbe, UdpError};
use crate::config::{Tuning, UdpEndpoint};
use crate::events::{ConnectedEvent, DialContext, Endpoint, Event};
use crate::helpers::batch_stats;
use crate::metrics::{Counters, Direction, DropReason, Source};
use crate::udp;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_quiche::buf_factory::PooledBuf;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Commands accepted by the BareUDP receive loop.
#[derive(Debug, PartialEq, Eq)]
pub enum BareUdpRxCommand {
    /// Replace the accepted source IP filter set.
    ///
    /// "Accepted sources" controls which source IPs are permitted for inbound
    /// BareUDP packets, distinct from TUN's "allowed IPs" (routing prefixes).
    UpdateAcceptedSources(HashSet<IpAddr>),
}

/// Creates the BareUDP listen socket and UDP RX state.
///
/// Performs fallible I/O: socket binding and quinn-udp initialization.
/// The returned [`udp::UdpRx`] is consumed by [`spawn_bare_rx`].
pub fn make_bare_rx(
    listen_addr: SocketAddr,
    tun_mtu: usize,
    tuning: &Tuning,
    udp_rt: &RuntimeHandle,
) -> Result<udp::UdpRx, UdpError> {
    let _guard = udp_rt.enter();
    let socket = make_server_udp_socket(listen_addr, tuning.io.socket_buffer_bytes())?;
    let (udp_rx, _udp_tx) = udp::make_udp(socket, tun_mtu, tuning.io.udp_enable_offload)?;
    Ok(udp_rx)
}

/// Spawns the BareUDP receive pipeline: UDP RX actor + source-filter actor.
///
/// The UDP RX actor runs on `udp_rt`, the filter actor on `crypto_rt`.
/// Returns command sender and both join handles for orchestrator supervision.
#[allow(clippy::too_many_arguments)]
pub fn spawn_bare_rx(
    udp_rx: udp::UdpRx,
    accepted_sources: HashSet<IpAddr>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    tuning: &Tuning,
    udp_rt: &RuntimeHandle,
    crypto_rt: &RuntimeHandle,
) -> (
    mpsc::UnboundedSender<BareUdpRxCommand>,
    JoinHandle<ActorExitResult>,
    JoinHandle<ActorExitResult>,
) {
    let (udp_output_tx, cmd_tx, bare_rx_handle) = {
        let _guard = crypto_rt.enter();
        spawn_bare_filter(accepted_sources, ingress_tx, events_tx, tuning)
    };

    let udp_rx_handle = {
        let _guard = udp_rt.enter();
        udp::spawn_udp_rx(udp_rx, udp_output_tx, CancellationToken::new())
    };

    (cmd_tx, bare_rx_handle, udp_rx_handle)
}

/// Spawns the BareUDP source-filter actor on `crypto_rt`.
///
/// Internal building block for [`spawn_bare_rx`]. Creates its own input
/// channel and returns the `Sender` for the upstream UDP RX actor.
#[allow(clippy::type_complexity)]
fn spawn_bare_filter(
    mut accepted_sources: HashSet<IpAddr>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    tuning: &Tuning,
) -> (
    mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    mpsc::UnboundedSender<BareUdpRxCommand>,
    JoinHandle<ActorExitResult>,
) {
    let (input_tx, mut udp_rx) =
        mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(tuning.io.packet_queue_depth);
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let interval = tuning.io.metrics_push_interval;

    let handle = tokio::spawn(async move {
        info!("bare RX filter actor started");
        let mut counters = Counters::new(Source::BareUdp, Direction::Rx);
        let mut ticker = time::interval(interval);
        loop {
            tokio::select! {
                maybe = udp_rx.recv() => {
                    let Some((remote, batch)) = maybe else {
                        info!("bare RX: UDP channel closed, shutting down");
                        return Ok(());
                    };
                    let (count, bytes) = batch_stats(&batch);
                    if !accepted_sources.contains(&remote.ip()) {
                        counters.record_drop(DropReason::DisallowedSource, count, bytes);
                        continue;
                    }
                    if !counters.send_and_record(&ingress_tx, batch, count, bytes).await {
                        info!("bare RX: ingress channel closed, shutting down");
                        return Ok(());
                    }
                }
                cmd = cmd_rx.recv() => {
                    let Some(command) = cmd else {
                        info!("bare RX: command channel closed, shutting down");
                        return Ok(());
                    };
                    let BareUdpRxCommand::UpdateAcceptedSources(update) = command;
                    debug!(count = update.len(), "bare RX: accepted sources updated");
                    accepted_sources = update;
                }
                _ = ticker.tick() => {
                    if !counters.emit(&events_tx, None, None) {
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
/// Returns a [`ConnectedEvent`] on success. The caller is responsible
/// for sending the event and handling errors.
///
/// `ctx.udp_rt` is used for socket registration and the UDP TX actor;
/// `ctx.crypto_rt` is used for the bare TX adapter actor.
pub(crate) async fn dial_bare_tx<P: RouteProbe>(
    endpoint: UdpEndpoint,
    destination: SocketAddr,
    ctx: &DialContext,
    probe: &P,
    bindif: Option<&str>,
) -> Result<ConnectedEvent, UdpError> {
    let std_socket = make_unbound_udp_socket(
        destination,
        Some(ctx.tun_if.as_str()),
        bindif,
        probe,
        ctx.tuning.io.socket_buffer_bytes(),
    )
    .await?;

    let (udp_send_tx, udp_tx_handle) = {
        let _guard = ctx.udp_rt.enter();
        let (_rx, tx) = udp::make_udp(std_socket, ctx.tun_mtu, ctx.tuning.io.udp_enable_offload)?;
        udp::spawn_udp_tx(tx, ctx.tuning.io.packet_queue_depth)
    };
    let (egress_tx, bare_tx_handle) = {
        let _guard = ctx.crypto_rt.enter();
        spawn_bare_tx(
            udp_send_tx,
            destination,
            ctx.peer_id.clone(),
            ctx.events_tx.clone(),
            &ctx.tuning,
        )
    };

    Ok(ConnectedEvent {
        peer_id: ctx.peer_id.clone(),
        remote_addr: destination,
        tx: egress_tx,
        endpoint: Some(Endpoint::Udp(endpoint)),
        main_handle: Some(bare_tx_handle),
        udp_tx_handle: Some(udp_tx_handle),
        udp_rx_handle: None,
    })
}

/// Spawns the BareUDP destination-stamping transmit actor.
///
/// Receives `Vec<PooledBuf>` from the router, stamps each batch with the
/// peer's destination address, and forwards to the UDP TX actor.
/// Records metrics after successful channel send to avoid inflating
/// counters when the downstream actor is unavailable.
pub(crate) fn spawn_bare_tx(
    udp_tx: mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    destination: SocketAddr,
    peer_id: String,
    events_tx: mpsc::UnboundedSender<Event>,
    tuning: &Tuning,
) -> (mpsc::Sender<Vec<PooledBuf>>, JoinHandle<ActorExitResult>) {
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<PooledBuf>>(tuning.io.packet_queue_depth);
    let metrics_interval = tuning.io.metrics_push_interval;

    let handle = tokio::spawn(async move {
        info!(peer = %peer_id, dest = %destination, "bare TX actor started");
        let mut counters = Counters::new(Source::BareUdp, Direction::Tx);
        let mut ticker = time::interval(metrics_interval);

        loop {
            tokio::select! {
                maybe_batch = egress_rx.recv() => {
                    let Some(packets) = maybe_batch else {
                        info!(peer = %peer_id, "bare TX: egress channel closed, shutting down");
                        return Ok(());
                    };
                    if packets.is_empty() { continue; }
                    let (count, bytes) = batch_stats(&packets);
                    // Record success AFTER send — avoids inflating metrics on channel close.
                    match udp_tx.send((destination, packets)).await {
                        Ok(()) => counters.record_success(count, bytes),
                        Err(_) => {
                            info!(peer = %peer_id, "bare TX: UDP channel closed, shutting down");
                            return Ok(());
                        }
                    }
                }
                _ = ticker.tick() => {
                    if !counters.emit(&events_tx, Some(&peer_id), Some(destination)) {
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
    use crate::config::IoTuning;
    use crate::events::Event;
    use crate::metrics::Direction;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use tokio_quiche::buf_factory::BufFactory;

    fn test_tuning(interval: Duration) -> Tuning {
        Tuning {
            io: IoTuning {
                metrics_push_interval: interval,
                packet_queue_depth: 4,
                ..IoTuning::default()
            },
            ..Tuning::default()
        }
    }

    #[tokio::test]
    async fn bare_rx_filters_non_accepted_sources() {
        let (ingress_tx, mut ingress_rx) = mpsc::channel(4);
        let accepted = HashSet::from([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let tuning = test_tuning(Duration::from_millis(200));
        let (udp_tx, _cmd_tx, handle) = spawn_bare_filter(accepted, ingress_tx, events_tx, &tuning);

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

        let tuning = test_tuning(Duration::from_millis(200));
        let (udp_tx, _cmd_tx, handle) = spawn_bare_filter(accepted, ingress_tx, events_tx, &tuning);

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

        let tuning = test_tuning(Duration::from_millis(200));
        let (udp_tx, cmd_tx, handle) =
            spawn_bare_filter(HashSet::new(), ingress_tx, events_tx, &tuning);

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

        let tuning = test_tuning(Duration::from_millis(10));
        let (udp_tx, _cmd_tx, handle) = spawn_bare_filter(accepted, ingress_tx, events_tx, &tuning);

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

        let tuning = test_tuning(Duration::from_millis(200));
        let (egress_tx, handle) =
            spawn_bare_tx(udp_tx, dest, "test-peer".to_string(), events_tx, &tuning);

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

        let tuning = test_tuning(Duration::from_millis(10));
        let (egress_tx, handle) =
            spawn_bare_tx(udp_tx, dest, "test-peer".to_string(), events_tx, &tuning);

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

        let tuning = test_tuning(Duration::from_secs(60));
        let (_udp_tx, cmd_tx, handle) =
            spawn_bare_filter(HashSet::new(), ingress_tx, events_tx, &tuning);

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

        let tuning = test_tuning(Duration::from_secs(60));
        let (egress_tx, handle) =
            spawn_bare_tx(udp_tx, dest, "test-peer".to_string(), events_tx, &tuning);

        drop(egress_tx);

        let result = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "bare_tx should exit gracefully when egress closed, got {result:?}"
        );
    }
}
