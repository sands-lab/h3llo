//! `BareUDP` protocol actors: source-IP filtering (RX) and destination stamping (TX).
//!
//! These actors sit between the generic UDP I/O layer ([`crate::udp`]) and the
//! router, adding BareUDP-specific behavior without touching sockets directly.

use crate::actor::{ActorBusHandle, ActorRuntime, SupervisionPolicy};
use crate::bind::{make_server_udp_socket, make_unbound_udp_socket, RouteProbe, UdpError};
use crate::config::{PeerBare, Tuning};
use crate::events::{ConnectedEvent, DialContext, Endpoint, Event};
use crate::helpers::{batch_stats, make_interval};
use crate::metrics::{Counters, Direction, DropReason, Source};
use crate::udp;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_quiche::buf_factory::PooledBuf;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Commands accepted by the `BareUDP` receive loop.
#[derive(Debug, PartialEq, Eq)]
pub enum BareUdpRxCommand {
    /// Replace the accepted source IP filter set.
    ///
    /// "Accepted sources" controls which source IPs are permitted for inbound
    /// `BareUDP` packets, distinct from TUN's "allowed IPs" (routing prefixes).
    UpdateAcceptedSources(HashSet<IpAddr>),
}

/// State owned exclusively by the `BareUDP` source-filter actor.
struct BareRx {
    accepted_sources: HashSet<IpAddr>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    metrics_interval: Duration,
}

/// Prepared state for the actors that implement the `BareUDP` receive pipeline.
///
/// Created by [`make_bare_rx`] and consumed by [`spawn_bare_rx`]. Each field is
/// moved directly into its corresponding actor.
pub struct BareRxGroup {
    filter: BareRx,
    udp_rx: udp::UdpRx,
}

/// Creates the `BareUDP` receive pipeline state.
///
/// Performs fallible I/O: socket binding and quinn-udp initialization.
/// The returned [`BareRxGroup`] is consumed by [`spawn_bare_rx`].
///
/// # Arguments
///
/// * `listen_addr` - Local address for the shared `BareUDP` receive socket.
/// * `tun_mtu` - Maximum packet size accepted from the UDP receive path.
/// * `accepted_sources` - Initial set of source IPs allowed by the filter actor.
/// * `ingress_tx` - Router ingress channel for accepted packet batches.
/// * `events_tx` - Orchestrator event channel used for metrics snapshots.
/// * `tuning` - Socket, queue, offload, and metrics configuration.
/// * `actor_bus` - Actor runtime owner used for UDP socket initialization.
///
/// # Returns
///
/// Returns prepared state for the UDP receive and source-filter actors.
///
/// # Errors
///
/// Returns [`UdpError`] if the UDP socket cannot be bound or configured.
pub async fn make_bare_rx(
    listen_addr: SocketAddr,
    tun_mtu: u16,
    accepted_sources: HashSet<IpAddr>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    tuning: &Tuning,
    actor_bus: &ActorBusHandle,
) -> Result<BareRxGroup, UdpError> {
    let socket = make_server_udp_socket(listen_addr, tuning.io.socket_buffer_bytes())?;
    let max_udp_payload = tun_mtu.into();
    let enable_offload = tuning.io.udp_enable_offload;
    let (udp_rx, _udp_tx) = actor_bus
        .run_on(ActorRuntime::Udp, move || {
            udp::make_udp(socket, max_udp_payload, enable_offload)
        })
        .await
        .map_err(|error| UdpError::Socket(format!("UDP runtime task failed: {error}")))??;
    let filter = BareRx {
        accepted_sources,
        ingress_tx,
        events_tx,
        metrics_interval: tuning.io.metrics_push_interval,
    };
    Ok(BareRxGroup { filter, udp_rx })
}

/// Spawns the `BareUDP` receive pipeline: UDP RX actor + source-filter actor.
///
/// The UDP RX actor runs on the UDP runtime and the filter actor on the crypto
/// runtime. Both actors register with `ActorBus` at spawn time.
pub fn spawn_bare_rx(
    group: BareRxGroup,
    packet_queue_depth: usize,
    actor_bus: &ActorBusHandle,
) -> mpsc::UnboundedSender<BareUdpRxCommand> {
    let BareRxGroup { filter, udp_rx } = group;
    let (udp_output_tx, cmd_tx) = spawn_bare_filter(filter, packet_queue_depth, actor_bus);

    udp::spawn_udp_rx(
        udp_rx,
        udp_output_tx,
        CancellationToken::new(),
        actor_bus,
        SupervisionPolicy::Critical,
    );

    cmd_tx
}

/// Spawns the `BareUDP` source-filter actor on the crypto runtime.
///
/// Internal building block for [`spawn_bare_rx`]. Creates its own input
/// channel and returns the `Sender` for the upstream UDP RX actor.
fn spawn_bare_filter(
    filter: BareRx,
    packet_queue_depth: usize,
    actor_bus: &ActorBusHandle,
) -> (
    mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    mpsc::UnboundedSender<BareUdpRxCommand>,
) {
    let BareRx {
        mut accepted_sources,
        ingress_tx,
        events_tx,
        metrics_interval,
    } = filter;
    let (input_tx, mut udp_rx) = mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(packet_queue_depth);
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

    actor_bus.spawn(
        "bare-rx-filter",
        ActorRuntime::Crypto,
        SupervisionPolicy::Critical,
        async move {
            info!("bare RX filter actor started");
            let mut counters = Counters::new(Source::BareUdp, Direction::Rx);
            let mut ticker = make_interval(metrics_interval);
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
        },
    );

    (input_tx, cmd_tx)
}

/// Spawns a `BareUDP` transmit adapter actor.
///
/// Creates a `BareUDP` outbound TX path: socket → UDP TX actor → bare TX actor.
///
/// Returns a [`ConnectedEvent`] on success. The caller is responsible
/// for sending the event and handling errors.
///
/// `ctx.actor_bus` places socket registration and UDP TX on the UDP runtime,
/// then places the BareUDP TX adapter on the crypto runtime.
pub(crate) async fn dial_bare_tx<P: RouteProbe>(
    bare: &PeerBare,
    ctx: &DialContext<P>,
) -> Result<ConnectedEvent, UdpError> {
    let destination = SocketAddr::new(ctx.dial_ip, bare.endpoint.port);
    let std_socket = make_unbound_udp_socket(
        destination,
        Some(ctx.tun_if.as_str()),
        bare.bindif.as_deref(),
        &ctx.probe,
        ctx.tuning.io.socket_buffer_bytes(),
    )
    .await?;

    let max_udp_payload = ctx.tun_mtu.into();
    let enable_offload = ctx.tuning.io.udp_enable_offload;
    let (_udp_rx, udp_tx) = ctx
        .actor_bus
        .run_on(ActorRuntime::Udp, move || {
            udp::make_udp(std_socket, max_udp_payload, enable_offload)
        })
        .await
        .map_err(|error| UdpError::Socket(format!("UDP runtime task failed: {error}")))??;
    let udp_send_tx = udp::spawn_udp_tx(
        udp_tx,
        ctx.tuning.io.packet_queue_depth,
        &ctx.actor_bus,
        SupervisionPolicy::Restartable,
    );
    let egress_tx = spawn_bare_tx(
        udp_send_tx,
        destination,
        ctx.peer_id.clone(),
        ctx.events_tx.clone(),
        &ctx.tuning,
        &ctx.actor_bus,
    );

    Ok(ConnectedEvent {
        peer_id: ctx.peer_id.clone(),
        remote_addr: destination,
        tx: egress_tx,
        endpoint: Some(Endpoint::Udp(bare.endpoint.clone())),
    })
}

/// Spawns the `BareUDP` destination-stamping transmit actor.
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
    actor_bus: &ActorBusHandle,
) -> mpsc::Sender<Vec<PooledBuf>> {
    let (egress_tx, mut egress_rx) = mpsc::channel::<Vec<PooledBuf>>(tuning.io.packet_queue_depth);
    let metrics_interval = tuning.io.metrics_push_interval;

    actor_bus.spawn(
        format!("bare-tx[{peer_id}]"),
        ActorRuntime::Crypto,
        SupervisionPolicy::Restartable,
        async move {
        info!(peer = %peer_id, dest = %destination, "bare TX actor started");
        let mut counters = Counters::new(Source::BareUdp, Direction::Tx);
        let mut ticker = make_interval(metrics_interval);

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
                    if let Ok(()) = udp_tx.send((destination, packets)).await { counters.record_success(count, bytes) } else {
                        info!(peer = %peer_id, "bare TX: UDP channel closed, shutting down");
                        return Ok(());
                    }
                }
                _ = ticker.tick() => {
                    if !counters.emit(&events_tx, Some(&peer_id), Some(destination)) {
                        return Ok(());
                    }
                }
            }
        }
        },
    );

    egress_tx
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

    fn test_bare_rx(
        accepted_sources: HashSet<IpAddr>,
        ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
        events_tx: mpsc::UnboundedSender<Event>,
        tuning: &Tuning,
    ) -> BareRx {
        BareRx {
            accepted_sources,
            ingress_tx,
            events_tx,
            metrics_interval: tuning.io.metrics_push_interval,
        }
    }

    #[tokio::test]
    async fn bare_rx_filters_non_accepted_sources() {
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let actor_bus = actor_bus_owner.handle();
        let (ingress_tx, mut ingress_rx) = mpsc::channel(4);
        let accepted = HashSet::from([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let tuning = test_tuning(Duration::from_millis(200));
        let filter = test_bare_rx(accepted, ingress_tx, events_tx, &tuning);
        let (udp_tx, _cmd_tx) = spawn_bare_filter(filter, tuning.io.packet_queue_depth, &actor_bus);

        // Send from a non-accepted source
        let remote: SocketAddr = "192.168.1.1:5353".parse().unwrap();
        let batch = vec![BufFactory::buf_from_slice(&[1, 2, 3])];
        udp_tx.send((remote, batch)).await.unwrap();

        let result = tokio::time::timeout(Duration::from_millis(50), ingress_rx.recv()).await;
        assert!(
            result.is_err(),
            "packet from non-accepted source should be dropped"
        );
    }

    #[tokio::test]
    async fn bare_rx_forwards_accepted_sources() {
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let actor_bus = actor_bus_owner.handle();
        let (ingress_tx, mut ingress_rx) = mpsc::channel(4);
        let accepted = HashSet::from([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let tuning = test_tuning(Duration::from_millis(200));
        let filter = test_bare_rx(accepted, ingress_tx, events_tx, &tuning);
        let (udp_tx, _cmd_tx) = spawn_bare_filter(filter, tuning.io.packet_queue_depth, &actor_bus);

        let remote: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let batch = vec![BufFactory::buf_from_slice(&[7, 8, 9])];
        udp_tx.send((remote, batch)).await.unwrap();

        let received = tokio::time::timeout(Duration::from_millis(100), ingress_rx.recv())
            .await
            .expect("should receive within timeout")
            .expect("channel should carry message");
        assert_eq!(received.len(), 1);
        assert_eq!(&received[0][..], &[7, 8, 9]);
    }

    #[tokio::test]
    async fn bare_rx_updates_accepted_sources() {
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let actor_bus = actor_bus_owner.handle();
        let (ingress_tx, mut ingress_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let tuning = test_tuning(Duration::from_millis(200));
        let filter = test_bare_rx(HashSet::new(), ingress_tx, events_tx, &tuning);
        let (udp_tx, cmd_tx) = spawn_bare_filter(filter, tuning.io.packet_queue_depth, &actor_bus);

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
    }

    #[tokio::test]
    async fn bare_rx_emits_metrics() {
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let actor_bus = actor_bus_owner.handle();
        let (ingress_tx, mut ingress_rx) = mpsc::channel(4);
        let accepted = HashSet::from([IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let tuning = test_tuning(Duration::from_millis(10));
        let filter = test_bare_rx(accepted, ingress_tx, events_tx, &tuning);
        let (udp_tx, _cmd_tx) = spawn_bare_filter(filter, tuning.io.packet_queue_depth, &actor_bus);

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
    }

    #[tokio::test]
    async fn bare_tx_tags_and_forwards() {
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let actor_bus = actor_bus_owner.handle();
        let dest: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let (udp_tx, mut udp_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let tuning = test_tuning(Duration::from_millis(200));
        let egress_tx = spawn_bare_tx(
            udp_tx,
            dest,
            "test-peer".to_string(),
            events_tx,
            &tuning,
            &actor_bus,
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
    }

    #[tokio::test]
    async fn bare_tx_emits_metrics() {
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let actor_bus = actor_bus_owner.handle();
        let dest: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let (udp_tx, mut udp_rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let tuning = test_tuning(Duration::from_millis(10));
        let egress_tx = spawn_bare_tx(
            udp_tx,
            dest,
            "test-peer".to_string(),
            events_tx,
            &tuning,
            &actor_bus,
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
    }

    #[tokio::test]
    async fn bare_rx_exits_when_cmd_channel_closed() {
        let mut actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let actor_bus = actor_bus_owner.handle();
        let (ingress_tx, _ingress_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let tuning = test_tuning(Duration::from_secs(60));
        let filter = test_bare_rx(HashSet::new(), ingress_tx, events_tx, &tuning);
        let (_udp_tx, cmd_tx) = spawn_bare_filter(filter, tuning.io.packet_queue_depth, &actor_bus);

        // Drop cmd_tx to signal shutdown via command channel closure.
        drop(cmd_tx);

        let result =
            tokio::time::timeout(Duration::from_millis(200), actor_bus_owner.next_exit()).await;
        assert!(
            matches!(
                result,
                Ok(crate::actor::ActorBusExit {
                    result: Ok(Ok(())),
                    ..
                })
            ),
            "bare_rx should exit gracefully when cmd channel closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn bare_tx_exits_when_egress_closed() {
        let mut actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let actor_bus = actor_bus_owner.handle();
        let dest: SocketAddr = "10.0.0.1:5353".parse().unwrap();
        let (udp_tx, _udp_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let tuning = test_tuning(Duration::from_secs(60));
        let egress_tx = spawn_bare_tx(
            udp_tx,
            dest,
            "test-peer".to_string(),
            events_tx,
            &tuning,
            &actor_bus,
        );

        drop(egress_tx);

        let result =
            tokio::time::timeout(Duration::from_millis(200), actor_bus_owner.next_exit()).await;
        assert!(
            matches!(
                result,
                Ok(crate::actor::ActorBusExit {
                    result: Ok(Ok(())),
                    ..
                })
            ),
            "bare_tx should exit gracefully when egress closed, got {result:?}"
        );
    }
}
