//! Router actor: centralized packet forwarding with LPM, TTL management,
//! and batch splitting for userspace L3 forwarding.

use crate::actor::ActorExitResult;
use crate::events::{Direction, DropReason, Event, Source};
use crate::helpers::{decrement_ttl, extract_dst_ip};
use crate::metrics::{send_with_backpressure, Counters, SendEvent};
use crate::tun::RoutingTable;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_quiche::buf_factory::PooledBuf;

/// Message sent from RX actors to the router.
#[derive(Debug)]
pub struct RouterMsg {
    /// Origin of the batch (determines routing policy).
    pub source: Source,
    /// Packet batch.
    pub packets: Vec<PooledBuf>,
}

/// Commands accepted by the router actor's control-plane channel.
#[derive(Debug)]
pub enum RouterCommand {
    /// Replace the routing table atomically.
    UpdateRouting {
        /// New routing table with embedded TX channels.
        routing: RoutingTable,
    },
}

/// Spawns the router actor.
///
/// Creates a bounded data-plane inbound channel and an unbounded command
/// channel internally (actor owns both receivers). Returns senders and handle.
///
/// # Arguments
///
/// * `routing` - Initial routing table.
/// * `tun_tx` - Sender to TUN Tx for TTL-expired and locally-destined packets.
/// * `events_tx` - Unbounded channel for emitting router metrics.
/// * `interval` - Metrics emission interval.
/// * `packet_queue_depth` - Bounded capacity for the inbound data-plane channel.
pub fn spawn_router(
    mut routing: RoutingTable,
    tun_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
    packet_queue_depth: usize,
) -> (
    mpsc::Sender<RouterMsg>,
    mpsc::UnboundedSender<RouterCommand>,
    JoinHandle<ActorExitResult>,
) {
    let (router_tx, mut router_rx) = mpsc::channel::<RouterMsg>(packet_queue_depth);
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

    let handle = tokio::spawn(async move {
        let mut counters = Counters::new(Source::Router, Direction::Rx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                msg = router_rx.recv() => {
                    let Some(RouterMsg { source, packets }) = msg else {
                        return Ok(());
                    };
                    match source {
                        Source::Tun => {
                            handle_tun_batch(packets, &routing, &mut counters).await;
                        }
                        Source::BareUdp | Source::Http3 | Source::Router => {
                            handle_transport_batch(
                                packets, &routing, &tun_tx, &mut counters,
                            ).await;
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    let Some(command) = cmd else {
                        return Ok(());
                    };
                    let RouterCommand::UpdateRouting { routing: new_routing } = command;
                    routing = new_routing;
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Metrics(
                        counters.snapshot(None, None)
                    )).is_err() {
                        return Ok(());
                    }
                }
            }
        }
    });

    (router_tx, cmd_tx, handle)
}

/// Handles a batch from TUN Rx: first-packet routing, no TTL mutation.
async fn handle_tun_batch(
    batch: Vec<PooledBuf>,
    routing: &RoutingTable,
    counters: &mut Counters,
) {
    let total_bytes: u64 = batch.iter().map(|p| p.len() as u64).sum();
    let pkt_count = batch.len() as u64;

    let Some(first) = batch.first() else {
        return;
    };
    let Some(dest) = extract_dst_ip(first) else {
        counters.record_drop(DropReason::InvalidIpVersion, pkt_count, total_bytes);
        return;
    };
    let Some(route) = routing.lookup(dest) else {
        counters.record_drop(DropReason::NoRoute, pkt_count, total_bytes);
        return;
    };
    if send_with_backpressure(route.tx, batch, |event| match event {
        SendEvent::Waited(waited) => counters.record_queue_full(waited),
        SendEvent::Fast | SendEvent::Full => {}
    })
    .await
    .is_err()
    {
        counters.record_drop(DropReason::ChannelClosed, pkt_count, total_bytes);
    } else {
        counters.record_success(pkt_count, total_bytes);
    }
}

/// Handles a batch from a transport peer: per-packet dst-IP scanning,
/// consecutive-group splitting, LPM lookup, TTL decrement + checksum.
///
/// Uses `drain`-based group extraction (always draining from index 0),
/// `same_channel()` for TUN detection, and old-TTL return semantics
/// (`Some(1)` signals expired).
async fn handle_transport_batch(
    mut batch: Vec<PooledBuf>,
    routing: &RoutingTable,
    tun_tx: &mpsc::Sender<Vec<PooledBuf>>,
    counters: &mut Counters,
) {
    // Process batch by draining consecutive groups from the front.
    // After each drain, indices shift — but we always drain from index 0
    // because previous groups have been removed.
    while !batch.is_empty() {
        let Some(dst) = extract_dst_ip(&batch[0]) else {
            let pkt = batch.drain(..1).next().unwrap();
            counters.record_drop(DropReason::InvalidIpVersion, 1, pkt.len() as u64);
            continue;
        };

        // Find consecutive run with same dst IP (starting from index 0).
        let mut group_end = 1;
        while group_end < batch.len() {
            if extract_dst_ip(&batch[group_end]) != Some(dst) {
                break;
            }
            group_end += 1;
        }

        // Drain the group out of the batch.
        let group: Vec<PooledBuf> = batch.drain(..group_end).collect();
        let group_count = group.len() as u64;
        let group_bytes: u64 = group.iter().map(|p| p.len() as u64).sum();

        let Some(route) = routing.lookup(dst) else {
            counters.record_drop(DropReason::NoRoute, group_count, group_bytes);
            continue;
        };

        // TUN detection via channel pointer comparison. If the route's TX
        // channel is the same as the dedicated tun_tx, this is a locally-
        // destined group — no TTL decrement needed.
        let is_tun_dest = route.tx.same_channel(tun_tx);

        if is_tun_dest {
            // TUN destination: no TTL decrement, forward directly.
            if send_with_backpressure(route.tx, group, |event| match event {
                SendEvent::Waited(waited) => counters.record_queue_full(waited),
                SendEvent::Fast | SendEvent::Full => {}
            })
            .await
            .is_err()
            {
                counters.record_drop(DropReason::ChannelClosed, group_count, group_bytes);
            } else {
                counters.record_success(group_count, group_bytes);
            }
        } else {
            // Single-pass: decrement TTL, partition expired vs forward.
            let mut forward = Vec::with_capacity(group.len());
            let mut expired = Vec::new();
            for mut pkt in group {
                match decrement_ttl(&mut pkt) {
                    Some(1) => {
                        // Was TTL=1, now 0 → expired; forward to TUN for ICMP.
                        expired.push(pkt);
                    }
                    Some(_) => {
                        forward.push(pkt);
                    }
                    None => {
                        counters.record_drop(DropReason::InvalidIpVersion, 1, pkt.len() as u64);
                    }
                }
            }

            if !forward.is_empty() {
                let fwd_count = forward.len() as u64;
                let fwd_bytes: u64 = forward.iter().map(|p| p.len() as u64).sum();
                if send_with_backpressure(route.tx, forward, |event| match event {
                    SendEvent::Waited(waited) => counters.record_queue_full(waited),
                    SendEvent::Fast | SendEvent::Full => {}
                })
                .await
                .is_err()
                {
                    counters.record_drop(DropReason::ChannelClosed, fwd_count, fwd_bytes);
                } else {
                    counters.record_success(fwd_count, fwd_bytes);
                }
            }

            if !expired.is_empty() {
                let exp_count = expired.len() as u64;
                let exp_bytes: u64 = expired.iter().map(|p| p.len() as u64).sum();
                counters.record_drop(DropReason::TtlExpired, exp_count, exp_bytes);
                let _ = send_with_backpressure(tun_tx, expired, |_| {}).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::test_packets::{make_ipv4_packet, make_ipv4_with_ttl, make_ipv6_packet};
    use crate::tun::{alloc_packet_buf, RouteEntry, RoutingTable};
    use ipnet::IpNet;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::sync::mpsc;

    /// Builds a single-entry routing table for test purposes.
    fn make_test_routing(
        peer_id: &str,
        prefix: IpNet,
        tx: mpsc::Sender<Vec<PooledBuf>>,
    ) -> RoutingTable {
        let mut table = RoutingTable::new();
        table
            .insert(
                prefix,
                RouteEntry {
                    peer_id: peer_id.to_string(),
                    tx,
                },
            )
            .unwrap();
        table
    }

    #[tokio::test]
    async fn tun_batch_routes_via_first_packet() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let routing = make_test_routing("peer1", "10.0.0.0/8".parse().unwrap(), peer_tx);
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        let pkt_data = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_tun_batch(batch, &routing, &mut counters).await;

        let received = peer_rx.recv().await.expect("batch should arrive");
        assert_eq!(received.len(), 1);
        assert_eq!(&received[0][..], &pkt_data[..]);
    }

    #[tokio::test]
    async fn tun_batch_no_route_drops() {
        let routing = RoutingTable::new();
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        let pkt_data = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_tun_batch(batch, &routing, &mut counters).await;

        let snap = counters.snapshot(None, None);
        assert_eq!(snap.stats.dropped.packets, 1);
    }

    #[tokio::test]
    async fn transport_batch_splits_by_dst_ip() {
        let (peer1_tx, mut peer1_rx) = mpsc::channel(4);
        let (peer2_tx, mut peer2_rx) = mpsc::channel(4);
        let (tun_tx, _tun_rx) = mpsc::channel(4);

        let mut routing = RoutingTable::new();
        routing
            .insert(
                "10.0.0.0/8".parse().unwrap(),
                RouteEntry {
                    peer_id: "peer1".to_string(),
                    tx: peer1_tx,
                },
            )
            .unwrap();
        routing
            .insert(
                "192.168.0.0/16".parse().unwrap(),
                RouteEntry {
                    peer_id: "peer2".to_string(),
                    tx: peer2_tx,
                },
            )
            .unwrap();

        let mut counters = Counters::new(Source::Router, Direction::Rx);

        // Build batch: 2 packets to 10.x, then 1 packet to 192.168.x
        let mut batch = Vec::new();
        let pkt1 = make_ipv4_with_ttl(Ipv4Addr::new(10, 0, 0, 1), 64);
        let pkt2 = make_ipv4_with_ttl(Ipv4Addr::new(10, 0, 0, 1), 64);
        let pkt3 = make_ipv4_with_ttl(Ipv4Addr::new(192, 168, 1, 1), 64);
        batch.push(alloc_packet_buf(&pkt1));
        batch.push(alloc_packet_buf(&pkt2));
        batch.push(alloc_packet_buf(&pkt3));

        handle_transport_batch(batch, &routing, &tun_tx, &mut counters).await;

        let peer1_batch = peer1_rx.recv().await.expect("peer1 should receive");
        assert_eq!(peer1_batch.len(), 2);

        let peer2_batch = peer2_rx.recv().await.expect("peer2 should receive");
        assert_eq!(peer2_batch.len(), 1);
    }

    #[tokio::test]
    async fn transport_batch_ttl_expired_forwarded_to_tun() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (tun_tx, mut tun_rx) = mpsc::channel(4);

        let routing = make_test_routing("peer1", "10.0.0.0/8".parse().unwrap(), peer_tx);
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        // TTL=1 packet → should expire and go to tun_tx
        let pkt_data = make_ipv4_with_ttl(Ipv4Addr::new(10, 0, 0, 1), 1);
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_transport_batch(batch, &routing, &tun_tx, &mut counters).await;

        // Peer should NOT receive it
        assert!(peer_rx.try_recv().is_err());

        // TUN should receive the expired packet
        let expired_batch = tun_rx.recv().await.expect("tun should get expired");
        assert_eq!(expired_batch.len(), 1);

        let snap = counters.snapshot(None, None);
        assert!(snap
            .stats
            .drop_reasons
            .get(&DropReason::TtlExpired)
            .map_or(false, |c| c.packets == 1));
    }

    #[tokio::test]
    async fn transport_batch_tun_dest_no_ttl_decrement() {
        // Route points to tun_tx → should forward without TTL decrement
        let (tun_tx, mut tun_rx) = mpsc::channel(4);

        let routing = make_test_routing("local", "10.0.0.0/8".parse().unwrap(), tun_tx.clone());
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        let pkt_data = make_ipv4_with_ttl(Ipv4Addr::new(10, 0, 0, 1), 5);
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_transport_batch(batch, &routing, &tun_tx, &mut counters).await;

        let received = tun_rx.recv().await.expect("tun should receive");
        assert_eq!(received.len(), 1);
        // TTL should be unchanged (5, not decremented to 4)
        assert_eq!(received[0][8], 5);
    }

    #[tokio::test]
    async fn transport_batch_decrements_ttl_for_non_tun() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (tun_tx, _tun_rx) = mpsc::channel(4);

        let routing = make_test_routing("peer1", "10.0.0.0/8".parse().unwrap(), peer_tx);
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        let pkt_data = make_ipv4_with_ttl(Ipv4Addr::new(10, 0, 0, 1), 64);
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_transport_batch(batch, &routing, &tun_tx, &mut counters).await;

        let received = peer_rx.recv().await.expect("peer should receive");
        assert_eq!(received.len(), 1);
        // TTL should be decremented from 64 to 63
        assert_eq!(received[0][8], 63);
    }

    #[tokio::test]
    async fn transport_batch_ipv6_decrements_hop_limit() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (tun_tx, _tun_rx) = mpsc::channel(4);

        let routing = make_test_routing("peer1", "2001:db8::/32".parse().unwrap(), peer_tx);
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        let mut pkt_data = make_ipv6_packet("2001:db8::1".parse::<Ipv6Addr>().unwrap());
        pkt_data[7] = 128; // hop limit
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_transport_batch(batch, &routing, &tun_tx, &mut counters).await;

        let received = peer_rx.recv().await.expect("peer should receive");
        assert_eq!(received.len(), 1);
        assert_eq!(received[0][7], 127); // hop limit decremented
    }

    #[tokio::test]
    async fn routing_update_replaces_table() {
        let (peer1_tx, _peer1_rx) = mpsc::channel(4);
        let (peer2_tx, mut peer2_rx) = mpsc::channel(4);
        let (tun_tx, _tun_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let routing = make_test_routing("peer1", "10.0.0.0/8".parse().unwrap(), peer1_tx);

        let (router_tx, cmd_tx, handle) =
            spawn_router(routing, tun_tx, events_tx, Duration::from_secs(60), 16);

        // Update routing to point to peer2
        let new_routing = make_test_routing("peer2", "10.0.0.0/8".parse().unwrap(), peer2_tx);
        cmd_tx
            .send(RouterCommand::UpdateRouting {
                routing: new_routing,
            })
            .unwrap();

        // Allow the command to be processed
        tokio::task::yield_now().await;

        // Send a TUN batch
        let pkt_data = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        router_tx
            .send(RouterMsg {
                source: Source::Tun,
                packets: vec![alloc_packet_buf(&pkt_data)],
            })
            .await
            .unwrap();

        let received = peer2_rx.recv().await.expect("peer2 should receive");
        assert_eq!(received.len(), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn router_exits_when_senders_dropped() {
        let (tun_tx, _tun_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let routing = RoutingTable::new();

        let (router_tx, cmd_tx, handle) =
            spawn_router(routing, tun_tx, events_tx, Duration::from_secs(60), 16);

        drop(router_tx);
        drop(cmd_tx);

        let result = tokio::time::timeout(Duration::from_millis(200), handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "router should shut down cleanly, got {:?}",
            result
        );
    }
}
