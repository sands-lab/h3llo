//! Router actor: centralized packet forwarding with LPM, TTL management,
//! and batch splitting for userspace L3 forwarding.
//!
//! Also owns the routing table data structures (`RoutingTable`, `RouteEntry`,
//! `RouteMatch`, `RoutingError`) used for longest-prefix-match lookups.

use crate::actor::{ActorContext, ActorRef, ActorRuntime, SupervisionPolicy};
use crate::config::{LocalTun, Peer};
use crate::events::Event;
use crate::helpers::{batch_stats, make_interval, send_with_backpressure, SendEvent};
use crate::metrics::{Counters, Direction, DropReason, Source};
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_quiche::buf_factory::PooledBuf;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// IP packet utilities
// ---------------------------------------------------------------------------

/// IPv4 header field offsets.
const IPV4_TTL_OFFSET: usize = 8;
const IPV4_CHECKSUM_OFFSET: usize = 10;
/// IPv6 hop limit offset.
const IPV6_HOP_LIMIT_OFFSET: usize = 7;
/// Minimum IPv4 header length.
const IPV4_MIN_LEN: usize = 20;
/// Minimum IPv6 header length.
const IPV6_MIN_LEN: usize = 40;

/// Decrements the TTL (IPv4) or hop limit (IPv6) by 1 in-place.
///
/// For IPv4, also performs an RFC 1624 incremental checksum update.
/// Returns the **original** TTL/hop-limit value before decrement, or `None`
/// if the packet is malformed (too short, unrecognized version, or TTL already 0).
///
/// # IPv4 incremental checksum ([RFC 1624])
///
/// TTL occupies byte 8, the high byte of the 16-bit word `[TTL, Protocol]`.
/// Decrementing TTL by 1 subtracts `0x0100` from that word. The one's-complement
/// checksum update adds `0x0100` with carry folding.
///
/// # IPv6
///
/// IPv6 has no header checksum. Only the hop limit (byte 7) is decremented.
///
/// [RFC 1624]: https://www.rfc-editor.org/rfc/rfc1624
fn decrement_ttl(packet: &mut [u8]) -> Option<u8> {
    let version = packet.first().map(|b| b >> 4)?;
    match version {
        4 => {
            if packet.len() < IPV4_MIN_LEN {
                return None;
            }
            let old_ttl = packet[IPV4_TTL_OFFSET];
            if old_ttl == 0 {
                return Some(0);
            }
            packet[IPV4_TTL_OFFSET] = old_ttl - 1;

            // RFC 1624 incremental checksum update.
            let old_check = u16::from_be_bytes([
                packet[IPV4_CHECKSUM_OFFSET],
                packet[IPV4_CHECKSUM_OFFSET + 1],
            ]);
            let mut sum = u32::from(old_check) + 0x0100;
            sum = (sum & 0xFFFF) + (sum >> 16);
            sum = (sum & 0xFFFF) + (sum >> 16);
            // Handle -0 edge case (RFC 1624 Section 4).
            // Truncation is intentional: checksum fold guarantees sum fits u16.
            #[allow(clippy::cast_possible_truncation)]
            let new_check = if sum as u16 == 0xFFFF {
                0u16
            } else {
                sum as u16
            };
            packet[IPV4_CHECKSUM_OFFSET..IPV4_CHECKSUM_OFFSET + 2]
                .copy_from_slice(&new_check.to_be_bytes());

            Some(old_ttl)
        }
        6 => {
            if packet.len() < IPV6_MIN_LEN {
                return None;
            }
            let old_hl = packet[IPV6_HOP_LIMIT_OFFSET];
            if old_hl == 0 {
                return Some(0);
            }
            packet[IPV6_HOP_LIMIT_OFFSET] = old_hl - 1;
            Some(old_hl)
        }
        _ => None,
    }
}

/// Extracts the destination IP address from an IP packet.
///
/// Returns `None` if the packet is too short or has an unrecognized IP version.
fn extract_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    let first = *packet.first()?;
    match first >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let dst = [packet[16], packet[17], packet[18], packet[19]];
            Some(IpAddr::from(dst))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&packet[24..40]);
            Some(IpAddr::from(dst))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Routing table
// ---------------------------------------------------------------------------

/// Sentinel peer ID used for local TUN route entries.
pub const LOCAL_PEER_ID: &str = "__local__";

fn log_duplicate_allowed(peer_id: &str, cidr: &str) {
    warn!(
        "duplicate allowed_ips '{}' for peer '{}'; keeping the first entry",
        cidr, peer_id
    );
}

/// Stores routing metadata for a prefix, including the channel to forward packets.
pub struct RouteEntry {
    /// Identifier of the peer owning the prefix.
    pub peer_id: String,
    /// Channel to send packet batches to this peer.
    pub tx: mpsc::Sender<Vec<PooledBuf>>,
}

impl std::fmt::Debug for RouteEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteEntry")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

/// Represents the result of a longest-prefix lookup.
#[derive(Debug)]
pub struct RouteMatch<'a> {
    /// Matched prefix.
    pub prefix: IpNet,
    /// Identifier of the peer selected by the lookup.
    pub peer_id: &'a str,
    /// Channel to send packet batches to this peer.
    pub tx: &'a mpsc::Sender<Vec<PooledBuf>>,
}

/// In-memory routing table supporting IPv4 and IPv6 longest-prefix matches.
pub struct RoutingTable {
    trie: IpnetTrie<RouteEntry>,
}

impl std::fmt::Debug for RoutingTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingTable")
            .field("len", &self.trie.len())
            .finish()
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingTable {
    /// Creates an empty routing table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trie: IpnetTrie::new(),
        }
    }

    /// Builds a complete routing table from peer and local TUN configuration.
    ///
    /// Inserts peer `allowed_ips` prefixes first, then local TUN host routes
    /// (`/32` or `/128`) so that locally-destined traffic is delivered to the
    /// TUN device without TTL decrement.
    ///
    /// # Arguments
    ///
    /// * `peers` - Peer configurations.
    /// * `peer_txs` - Map of peer ID to TX channel. Peers without a channel are skipped.
    /// * `local_tun` - Local TUN configuration (uses `addrs` for host routes).
    /// * `input_tx` - Input channel for local delivery (TUN TX).
    ///
    /// # Errors
    ///
    /// Returns `RoutingError::ConflictingPrefix` when a peer prefix conflicts with another peer.
    pub fn make(
        peers: &[Peer],
        peer_txs: &HashMap<String, mpsc::Sender<Vec<PooledBuf>>>,
        local_tun: &LocalTun,
        input_tx: &mpsc::Sender<Vec<PooledBuf>>,
    ) -> Result<Self, RoutingError> {
        let mut table = RoutingTable::new();

        for peer in peers {
            let Some(tx) = peer_txs.get(&peer.id) else {
                warn!(
                    "peer '{}' has no TX channel; skipping route registration",
                    peer.id
                );
                continue;
            };

            // allowed_ips is pre-parsed as Vec<IpNet> during config deserialization
            for net in &peer.tun.allowed_ips {
                table.insert(
                    *net,
                    RouteEntry {
                        peer_id: peer.id.clone(),
                        tx: tx.clone(),
                    },
                )?;
            }
        }

        // Insert local host routes so peers can reach this node's TUN addresses.
        // Uses host prefix (/32 or /128) — only the address itself is local.
        for addr in &local_tun.addrs {
            let host_route = IpNet::from(addr.addr());
            if let Err(e) = table.insert(
                host_route,
                RouteEntry {
                    peer_id: LOCAL_PEER_ID.to_string(),
                    tx: input_tx.clone(),
                },
            ) {
                warn!(error = %e, "failed to insert local TUN route");
            }
        }

        Ok(table)
    }

    /// Inserts a prefix and associated peer into the table, rejecting conflicting owners.
    ///
    /// # Errors
    ///
    /// Returns `RoutingError::ConflictingPrefix` when the prefix already belongs to another peer.
    pub fn insert(&mut self, prefix: IpNet, entry: RouteEntry) -> Result<(), RoutingError> {
        if let Some(existing) = self.trie.exact_match(prefix) {
            if existing.peer_id == entry.peer_id {
                log_duplicate_allowed(&entry.peer_id, &prefix.to_string());
                return Ok(());
            }

            return Err(RoutingError::ConflictingPrefix {
                prefix,
                existing_peer_id: existing.peer_id.clone(),
                new_peer_id: entry.peer_id,
            });
        }

        self.trie.insert(prefix, entry);
        Ok(())
    }

    /// Performs a longest-prefix match for the provided address.
    pub fn lookup(&self, addr: IpAddr) -> Option<RouteMatch<'_>> {
        let net = IpNet::from(addr);
        self.trie
            .longest_match(&net)
            .map(|(prefix, entry)| RouteMatch {
                prefix,
                peer_id: entry.peer_id.as_str(),
                tx: &entry.tx,
            })
    }

    /// Returns the number of IPv4 and IPv6 prefixes stored.
    pub fn len(&self) -> (usize, usize) {
        self.trie.len()
    }

    /// Returns true when no prefixes are present.
    pub fn is_empty(&self) -> bool {
        self.trie.is_empty()
    }
}

/// Routing table construction or lookup error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RoutingError {
    /// Two peers claim the same prefix.
    #[error("prefix {prefix} already assigned to peer '{existing_peer_id}', cannot assign to '{new_peer_id}'")]
    ConflictingPrefix {
        /// Prefix that was duplicated.
        prefix: IpNet,
        /// Existing owner of the prefix.
        existing_peer_id: String,
        /// New peer that attempted to claim the prefix.
        new_peer_id: String,
    },
}

// ---------------------------------------------------------------------------
// Router actor
// ---------------------------------------------------------------------------

/// Spawns the router actor.
///
/// Creates two bounded data-plane channels (output from TUN, ingress from
/// transport peers). Control-plane events arrive through the actor inbox.
///
/// # Arguments
///
/// * `routing` - Initial routing table.
/// * `input_tx` - Sender for locally-destined and TTL-expired packets (TUN TX).
/// * `interval` - Metrics emission interval.
/// * `packet_queue_depth` - Bounded capacity for each data-plane channel.
pub fn spawn_router(
    mut routing: RoutingTable,
    input_tx: mpsc::Sender<Vec<PooledBuf>>,
    interval: Duration,
    packet_queue_depth: usize,
    ctx: &ActorContext,
) -> (
    mpsc::Sender<Vec<PooledBuf>>,
    mpsc::Sender<Vec<PooledBuf>>,
    ActorRef,
) {
    let (output_tx, mut output_rx) = mpsc::channel::<Vec<PooledBuf>>(packet_queue_depth);
    let (ingress_tx, mut ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(packet_queue_depth);

    let actor_ref = ctx.spawn(
        "router",
        ActorRuntime::Crypto,
        SupervisionPolicy::Critical,
        |mut ctx| async move {
            let mut counters = Counters::new(Source::Router, Direction::Rx);
            let mut ticker = make_interval(interval);

            loop {
                tokio::select! {
                    batch = output_rx.recv() => {
                        let Some(packets) = batch else {
                            return Ok(());
                        };
                        handle_output_batch(packets, &routing, &mut counters).await;
                    }
                    batch = ingress_rx.recv() => {
                        let Some(packets) = batch else {
                            return Ok(());
                        };
                        handle_ingress_batch(
                            packets, &routing, &input_tx, &mut counters,
                        ).await;
                    }
                    message = ctx.recv() => {
                        match message {
                            Some(Event::UpdateRouting { routing: new_routing }) => {
                                routing = new_routing;
                            }
                            Some(Event::Stop) | None => return Ok(()),
                            Some(message) => debug!(?message, "router: ignoring unexpected message"),
                        }
                    }
                    _ = ticker.tick() => {
                        if !counters.emit(&ctx, None, None) {
                            return Ok(());
                        }
                    }
                }
            }
        },
    );

    (output_tx, ingress_tx, actor_ref)
}

/// Handles an output batch (from TUN Rx): first-packet routing, no TTL mutation.
async fn handle_output_batch(
    batch: Vec<PooledBuf>,
    routing: &RoutingTable,
    counters: &mut Counters,
) {
    let (pkt_count, total_bytes) = batch_stats(&batch);

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
    counters
        .send_and_record(route.tx, batch, pkt_count, total_bytes)
        .await;
}

/// Handles an ingress batch (from transport peers): per-packet dst-IP scanning,
/// consecutive-group splitting, LPM lookup, TTL decrement + checksum.
///
/// Uses `drain`-based group extraction (always draining from index 0),
/// `same_channel()` for TUN detection, and old-TTL return semantics
/// (`Some(1)` signals expired).
async fn handle_ingress_batch(
    mut batch: Vec<PooledBuf>,
    routing: &RoutingTable,
    input_tx: &mpsc::Sender<Vec<PooledBuf>>,
    counters: &mut Counters,
) {
    // Process batch by draining consecutive groups from the front.
    // After each drain, indices shift — but we always drain from index 0
    // because previous groups have been removed.
    while !batch.is_empty() {
        let Some(dst) = extract_dst_ip(&batch[0]) else {
            let pkt = batch.remove(0);
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
        // When the entire batch shares the same dst, take the whole Vec in O(1).
        let group: Vec<PooledBuf> = if group_end == batch.len() {
            std::mem::take(&mut batch)
        } else {
            batch.drain(..group_end).collect()
        };
        let (group_count, group_bytes) = batch_stats(&group);

        let Some(route) = routing.lookup(dst) else {
            counters.record_drop(DropReason::NoRoute, group_count, group_bytes);
            continue;
        };

        // TUN detection via channel pointer comparison. If the route's TX
        // channel is the same as the dedicated input_tx, this is a locally-
        // destined group — no TTL decrement needed.
        let is_tun_dest = route.tx.same_channel(input_tx);

        if is_tun_dest {
            // TUN destination: no TTL decrement, forward directly.
            counters
                .send_and_record(route.tx, group, group_count, group_bytes)
                .await;
            continue;
        }

        // Single-pass: decrement TTL, partition expired vs forward.
        let mut forward = Vec::with_capacity(group.len());
        let mut expired = Vec::new();
        for mut pkt in group {
            match decrement_ttl(&mut pkt) {
                Some(0 | 1) => {
                    // TTL expired (was 0 or 1); forward to TUN for ICMP.
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
            let (fwd_count, fwd_bytes) = batch_stats(&forward);
            counters
                .send_and_record(route.tx, forward, fwd_count, fwd_bytes)
                .await;
        }

        if !expired.is_empty() {
            let (exp_count, exp_bytes) = batch_stats(&expired);
            counters.record_drop(DropReason::TtlExpired, exp_count, exp_bytes);
            if send_with_backpressure(input_tx, expired, |event| match event {
                SendEvent::Waited(waited) => counters.record_queue_full(waited),
                SendEvent::Fast | SendEvent::Full => {}
            })
            .await
            .is_err()
            {
                counters.record_drop(DropReason::ChannelClosed, exp_count, exp_bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PeerBare, PeerTransport, PeerTun, UdpEndpoint};
    use crate::helpers::alloc_packet_buf;
    use crate::helpers::test_packets::{make_ipv4_packet, make_ipv4_with_ttl, make_ipv6_packet};
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

    fn bare_peer(id: &str, allowed: &[&str]) -> Peer {
        Peer {
            id: id.to_string(),
            transport: PeerTransport::Bare(PeerBare {
                endpoint: UdpEndpoint {
                    host: "127.0.0.1".to_string(),
                    port: 5353,
                },
                bindif: None,
            }),
            tun: PeerTun {
                allowed_ips: allowed.iter().map(|s| s.parse().unwrap()).collect(),
            },
        }
    }

    /// Creates dummy peer TX channels for routing table tests.
    fn dummy_peer_txs(peer_ids: &[&str]) -> HashMap<String, mpsc::Sender<Vec<PooledBuf>>> {
        peer_ids
            .iter()
            .map(|id| {
                let (tx, _rx) = mpsc::channel(1);
                (id.to_string(), tx)
            })
            .collect()
    }

    /// Empty LocalTun for tests that don't need local routes.
    fn empty_local_tun() -> LocalTun {
        LocalTun {
            ifname: "test0".to_string(),
            addrs: vec![],
            mtu: 1291,
        }
    }

    // -- Routing table tests --

    #[test]
    fn chooses_longest_prefix() {
        let peers = vec![
            bare_peer("peer-a", &["10.0.0.0/16"]),
            bare_peer("peer-b", &["10.0.0.0/24"]),
        ];
        let peer_txs = dummy_peer_txs(&["peer-a", "peer-b"]);
        let (input_tx, _) = mpsc::channel(1);
        let table = RoutingTable::make(&peers, &peer_txs, &empty_local_tun(), &input_tx)
            .expect("table should build");
        let result = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)))
            .expect("lookup should succeed");
        assert_eq!(result.peer_id, "peer-b");
        assert_eq!(result.prefix, "10.0.0.0/24".parse::<IpNet>().unwrap());
    }

    #[test]
    fn errors_on_conflicting_prefix_ownership() {
        let peers = vec![
            bare_peer("peer-a", &["10.0.0.0/24"]),
            bare_peer("peer-b", &["10.0.0.0/24"]),
        ];
        let peer_txs = dummy_peer_txs(&["peer-a", "peer-b"]);
        let (input_tx, _) = mpsc::channel(1);
        let err = RoutingTable::make(&peers, &peer_txs, &empty_local_tun(), &input_tx).unwrap_err();
        assert!(matches!(
            err,
            RoutingError::ConflictingPrefix {
                existing_peer_id,
                new_peer_id,
                ..
            } if existing_peer_id == "peer-a" && new_peer_id == "peer-b"
        ));
    }

    #[test]
    fn skips_duplicate_prefixes_within_peer() {
        let peers = vec![bare_peer("peer-a", &["10.0.0.0/24", "10.0.0.0/24"])];
        let peer_txs = dummy_peer_txs(&["peer-a"]);
        let (input_tx, _) = mpsc::channel(1);
        let table = RoutingTable::make(&peers, &peer_txs, &empty_local_tun(), &input_tx)
            .expect("table should build");
        assert_eq!(table.len(), (1, 0));
        let result = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .expect("lookup should succeed");
        assert_eq!(result.peer_id, "peer-a");
    }

    #[test]
    fn make_inserts_local_tun_host_routes() {
        let peers = vec![bare_peer("peer-a", &["10.0.0.0/24"])];
        let peer_txs = dummy_peer_txs(&["peer-a"]);
        let (input_tx, _) = mpsc::channel(1);
        let local_tun = LocalTun {
            ifname: "test0".to_string(),
            addrs: vec!["10.0.0.1/24".parse().unwrap()],
            mtu: 1291,
        };
        let table = RoutingTable::make(&peers, &peer_txs, &local_tun, &input_tx)
            .expect("table should build");

        // Local host route (/32) wins over peer subnet (/24) for the local address
        let local = table
            .lookup("10.0.0.1".parse().unwrap())
            .expect("local addr should match");
        assert_eq!(local.peer_id, LOCAL_PEER_ID);
        assert_eq!(local.prefix, "10.0.0.1/32".parse::<IpNet>().unwrap());

        // Other addresses in the subnet still route to the peer
        let peer = table
            .lookup("10.0.0.2".parse().unwrap())
            .expect("peer addr should match");
        assert_eq!(peer.peer_id, "peer-a");
    }

    // -- Router actor tests --

    #[tokio::test]
    async fn tun_batch_routes_via_first_packet() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let routing = make_test_routing("peer1", "10.0.0.0/8".parse().unwrap(), peer_tx);
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        let pkt_data = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_output_batch(batch, &routing, &mut counters).await;

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

        handle_output_batch(batch, &routing, &mut counters).await;

        let snap = counters.snapshot(None, None);
        assert_eq!(snap.stats.dropped.packets, 1);
    }

    #[tokio::test]
    async fn transport_batch_splits_by_dst_ip() {
        let (peer1_tx, mut peer1_rx) = mpsc::channel(4);
        let (peer2_tx, mut peer2_rx) = mpsc::channel(4);
        let (input_tx, _input_rx) = mpsc::channel(4);

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

        handle_ingress_batch(batch, &routing, &input_tx, &mut counters).await;

        let peer1_batch = peer1_rx.recv().await.expect("peer1 should receive");
        assert_eq!(peer1_batch.len(), 2);

        let peer2_batch = peer2_rx.recv().await.expect("peer2 should receive");
        assert_eq!(peer2_batch.len(), 1);
    }

    #[tokio::test]
    async fn transport_batch_ttl_expired_forwarded_to_tun() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (input_tx, mut input_rx) = mpsc::channel(4);

        let routing = make_test_routing("peer1", "10.0.0.0/8".parse().unwrap(), peer_tx);
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        // TTL=1 packet → should expire and go to input_tx
        let pkt_data = make_ipv4_with_ttl(Ipv4Addr::new(10, 0, 0, 1), 1);
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_ingress_batch(batch, &routing, &input_tx, &mut counters).await;

        // Peer should NOT receive it
        assert!(peer_rx.try_recv().is_err());

        // TUN should receive the expired packet
        let expired_batch = input_rx.recv().await.expect("tun should get expired");
        assert_eq!(expired_batch.len(), 1);

        let snap = counters.snapshot(None, None);
        assert_eq!(snap.stats.drop_reasons[DropReason::TtlExpired].packets, 1);
    }

    #[tokio::test]
    async fn transport_batch_tun_dest_no_ttl_decrement() {
        // Route points to input_tx → should forward without TTL decrement
        let (input_tx, mut input_rx) = mpsc::channel(4);

        let routing = make_test_routing("local", "10.0.0.0/8".parse().unwrap(), input_tx.clone());
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        let pkt_data = make_ipv4_with_ttl(Ipv4Addr::new(10, 0, 0, 1), 5);
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_ingress_batch(batch, &routing, &input_tx, &mut counters).await;

        let received = input_rx.recv().await.expect("tun should receive");
        assert_eq!(received.len(), 1);
        // TTL should be unchanged (5, not decremented to 4)
        assert_eq!(received[0][8], 5);
    }

    #[tokio::test]
    async fn transport_batch_decrements_ttl_for_non_tun() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (input_tx, _input_rx) = mpsc::channel(4);

        let routing = make_test_routing("peer1", "10.0.0.0/8".parse().unwrap(), peer_tx);
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        let pkt_data = make_ipv4_with_ttl(Ipv4Addr::new(10, 0, 0, 1), 64);
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_ingress_batch(batch, &routing, &input_tx, &mut counters).await;

        let received = peer_rx.recv().await.expect("peer should receive");
        assert_eq!(received.len(), 1);
        // TTL should be decremented from 64 to 63
        assert_eq!(received[0][8], 63);
    }

    #[tokio::test]
    async fn transport_batch_ipv6_hop_limit_expired_forwarded_to_tun() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (input_tx, mut input_rx) = mpsc::channel(4);

        let routing = make_test_routing("peer1", "2001:db8::/32".parse().unwrap(), peer_tx);
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        // Hop limit = 1 → should expire and go to input_tx
        let mut pkt_data = make_ipv6_packet("2001:db8::1".parse::<Ipv6Addr>().unwrap());
        pkt_data[7] = 1; // hop limit
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_ingress_batch(batch, &routing, &input_tx, &mut counters).await;

        // Peer should NOT receive it
        assert!(peer_rx.try_recv().is_err());

        // TUN should receive the expired packet
        let expired_batch = input_rx.recv().await.expect("tun should get expired");
        assert_eq!(expired_batch.len(), 1);

        let snap = counters.snapshot(None, None);
        assert_eq!(snap.stats.drop_reasons[DropReason::TtlExpired].packets, 1);
    }

    #[tokio::test]
    async fn transport_batch_ipv6_decrements_hop_limit() {
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (input_tx, _input_rx) = mpsc::channel(4);

        let routing = make_test_routing("peer1", "2001:db8::/32".parse().unwrap(), peer_tx);
        let mut counters = Counters::new(Source::Router, Direction::Rx);

        let mut pkt_data = make_ipv6_packet("2001:db8::1".parse::<Ipv6Addr>().unwrap());
        pkt_data[7] = 128; // hop limit
        let batch = vec![alloc_packet_buf(&pkt_data)];

        handle_ingress_batch(batch, &routing, &input_tx, &mut counters).await;

        let received = peer_rx.recv().await.expect("peer should receive");
        assert_eq!(received.len(), 1);
        assert_eq!(received[0][7], 127); // hop limit decremented
    }

    #[tokio::test]
    async fn routing_update_replaces_table() {
        let actor_bus = crate::actor::ActorBus::on_current_runtime();
        let orchestrator = actor_bus.mailbox("test-orchestrator");
        let (peer1_tx, _peer1_rx) = mpsc::channel(4);
        let (peer2_tx, mut peer2_rx) = mpsc::channel(4);
        let (input_tx, _input_rx) = mpsc::channel(4);

        let routing = make_test_routing("peer1", "10.0.0.0/8".parse().unwrap(), peer1_tx);

        let (output_tx, _ingress_tx, router) = spawn_router(
            routing,
            input_tx,
            Duration::from_secs(60),
            16,
            &orchestrator,
        );

        // Update routing to point to peer2
        let new_routing = make_test_routing("peer2", "10.0.0.0/8".parse().unwrap(), peer2_tx);
        orchestrator
            .send(
                &router,
                Event::UpdateRouting {
                    routing: new_routing,
                },
            )
            .unwrap();

        // Allow the event to be processed.
        tokio::task::yield_now().await;

        // Send an output (TUN) batch
        let pkt_data = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        output_tx
            .send(vec![alloc_packet_buf(&pkt_data)])
            .await
            .unwrap();

        let received = peer2_rx.recv().await.expect("peer2 should receive");
        assert_eq!(received.len(), 1);
    }

    #[tokio::test]
    async fn router_exits_when_senders_dropped() {
        let mut actor_bus = crate::actor::ActorBus::on_current_runtime();
        let mut orchestrator = actor_bus.mailbox("test-orchestrator");
        let (input_tx, _input_rx) = mpsc::channel(4);
        let routing = RoutingTable::new();

        let (output_tx, ingress_tx, _router) = spawn_router(
            routing,
            input_tx,
            Duration::from_secs(60),
            16,
            &orchestrator,
        );

        drop(output_tx);
        drop(ingress_tx);

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            crate::actor::next_actor_exit(&mut actor_bus, &mut orchestrator),
        )
        .await;
        assert!(
            matches!(
                result,
                Ok(crate::actor::ActorExit {
                    result: Ok(Ok(())),
                    ..
                })
            ),
            "router should shut down cleanly, got {:?}",
            result
        );
    }

    // -- extract_dst_ip tests --

    #[test]
    fn extract_dst_ip_parses_ipv4() {
        let dst = Ipv4Addr::new(10, 20, 30, 40);
        let packet = make_ipv4_packet(dst);
        assert_eq!(extract_dst_ip(&packet), Some(IpAddr::V4(dst)));
    }

    #[test]
    fn extract_dst_ip_parses_ipv6() {
        let dst: Ipv6Addr = "fe80::1".parse().unwrap();
        let packet = make_ipv6_packet(dst);
        assert_eq!(extract_dst_ip(&packet), Some(IpAddr::V6(dst)));
    }

    #[test]
    fn extract_dst_ip_returns_none_for_invalid_packets() {
        assert_eq!(extract_dst_ip(&[]), None);
        assert_eq!(extract_dst_ip(&[0x45; 10]), None); // Truncated IPv4
        assert_eq!(extract_dst_ip(&[0x60; 30]), None); // Truncated IPv6
        assert_eq!(extract_dst_ip(&[0x30; 20]), None); // Unknown version
    }

    // -- decrement_ttl tests --

    /// Compute IPv4 header checksum from scratch for test verification.
    fn compute_ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn decrement_ttl_ipv4_updates_checksum() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[8] = 64;
        pkt[10] = 0;
        pkt[11] = 0;
        let initial = compute_ipv4_checksum(&pkt);
        pkt[10..12].copy_from_slice(&initial.to_be_bytes());

        let old_ttl = decrement_ttl(&mut pkt);
        assert_eq!(old_ttl, Some(64));
        assert_eq!(pkt[8], 63);

        let stored = u16::from_be_bytes([pkt[10], pkt[11]]);
        pkt[10] = 0;
        pkt[11] = 0;
        let recomputed = compute_ipv4_checksum(&pkt);
        assert_eq!(stored, recomputed);
    }

    #[test]
    fn decrement_ttl_ipv4_ttl_one_becomes_zero() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[8] = 1;
        assert_eq!(decrement_ttl(&mut pkt), Some(1));
        assert_eq!(pkt[8], 0);
    }

    #[test]
    fn decrement_ttl_ipv4_checksum_carry_folds() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[8] = 10;
        pkt[10] = 0xFF;
        pkt[11] = 0x00;
        let old = decrement_ttl(&mut pkt).unwrap();
        assert_eq!(old, 10);
        assert_eq!(u16::from_be_bytes([pkt[10], pkt[11]]), 0x0001);
    }

    #[test]
    fn decrement_ttl_ipv6_decrements_hop_limit() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[7] = 128;
        assert_eq!(decrement_ttl(&mut pkt), Some(128));
        assert_eq!(pkt[7], 127);
    }

    #[test]
    fn decrement_ttl_returns_none_for_malformed() {
        assert!(decrement_ttl(&mut [0x45; 10]).is_none()); // IPv4 too short
        assert!(decrement_ttl(&mut [0x60; 20]).is_none()); // IPv6 too short
        assert!(decrement_ttl(&mut [0x30; 20]).is_none()); // Unknown version
    }

    #[test]
    fn decrement_ttl_zero_ttl_returns_some_zero() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[8] = 0;
        assert_eq!(decrement_ttl(&mut pkt), Some(0));
        assert_eq!(pkt[8], 0); // Not decremented further.

        let mut pkt6 = vec![0u8; 40];
        pkt6[0] = 0x60;
        pkt6[7] = 0;
        assert_eq!(decrement_ttl(&mut pkt6), Some(0));
        assert_eq!(pkt6[7], 0);
    }
}
