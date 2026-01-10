//! TUN management: device creation, read/write loops with backpressure, and metrics reporting.

use crate::config::{LocalTun, Peer};
use crate::events::{Direction, DropReason, Event, TransportEvent, TransportKind};
use crate::helpers::retry_on_interrupted;
use crate::metrics::TransportCounters;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use ipnet_trie::IpnetTrie;
use log::warn;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

/// Provides receive-only access to a TUN device for a single coroutine.
pub trait TunRx: Send + 'static {
    /// Returns the configured MTU for sizing buffers.
    fn mtu(&self) -> usize;
    /// Returns the interface name.
    fn name(&self) -> &str;
    /// Receives a packet into `buf`, returning the number of bytes read.
    fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send;
}

/// Provides send-only access to a TUN device for a single coroutine.
pub trait TunTx: Send + 'static {
    /// Returns the configured MTU for sizing buffers.
    fn mtu(&self) -> usize;
    /// Returns the interface name.
    fn name(&self) -> &str;
    /// Sends a packet from `buf`, returning the number of bytes written.
    fn send(&mut self, buf: &[u8]) -> impl std::future::Future<Output = io::Result<usize>> + Send;
}

/// Creates a TUN device from `local_tun` and returns exclusive RX/TX handles.
pub async fn from_config(local_tun: &LocalTun) -> Result<(TunReader, TunWriter), TunError> {
    let (v4_addrs, v6_addrs) = parse_addrs(&local_tun.addrs)?;

    let mut builder = DeviceBuilder::new()
        .name(local_tun.ifname.as_str())
        .mtu(local_tun.mtu)
        .enable(true)
        .layer(Layer::L3);

    if let Some(first_v4) = v4_addrs.first() {
        builder = builder.ipv4(first_v4.addr(), first_v4.prefix_len(), None);
    }

    if !v6_addrs.is_empty() {
        let ipv6_pairs: Vec<(Ipv6Addr, u8)> = v6_addrs
            .iter()
            .map(|net| (net.addr(), net.prefix_len()))
            .collect();
        builder = builder.ipv6_tuple(&ipv6_pairs);
    }

    let device = builder
        .build_async()
        .map_err(|e| TunError::DeviceBuild(e.to_string()))?;

    // Add remaining IPv4 addresses after initial build to avoid overwriting.
    for extra in v4_addrs.iter().skip(1) {
        device
            .add_address_v4(extra.addr(), extra.prefix_len())
            .map_err(|e| TunError::DeviceBuild(e.to_string()))?;
    }

    let name = device.name().unwrap_or_else(|_| local_tun.ifname.clone());
    let mtu = device
        .mtu()
        .map(|m| m as usize)
        .unwrap_or(local_tun.mtu as usize);

    let device = Arc::new(device);
    let reader = TunReader {
        device: device.clone(),
        mtu,
        name: name.clone(),
    };
    let writer = TunWriter { device, mtu, name };

    Ok((reader, writer))
}

/// Provides a receive-only handle for a TUN device.
pub struct TunReader {
    device: Arc<AsyncDevice>,
    mtu: usize,
    name: String,
}

impl TunRx for TunReader {
    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.device.recv(buf).await
    }
}

/// Provides a send-only handle for a TUN device.
pub struct TunWriter {
    device: Arc<AsyncDevice>,
    mtu: usize,
    name: String,
}

impl TunTx for TunWriter {
    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.device.send(buf).await
    }
}

/// Describes TUN errors for creation and operation.
#[derive(Debug, Error)]
pub enum TunError {
    /// A configured address could not be parsed.
    #[error("invalid TUN address '{addr}': {error}")]
    InvalidAddress { addr: String, error: String },
    /// Device creation or address assignment failed.
    #[error("failed to build TUN device: {0}")]
    DeviceBuild(String),
}

// ============================================================================
// Routing table (migrated from routing.rs)
// ============================================================================

fn log_duplicate_allowed(peer_id: &str, cidr: &str) {
    warn!(
        "duplicate allowedIPs '{}' for peer '{}'; keeping the first entry",
        cidr, peer_id
    );
}

/// Stores routing metadata for a prefix, including the channel to forward packets.
#[derive(Clone)]
pub struct RouteEntry {
    /// Identifier of the peer owning the prefix.
    pub peer_id: String,
    /// Channel to send packets to this peer.
    pub tx: mpsc::Sender<Vec<u8>>,
}

impl std::fmt::Debug for RouteEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteEntry")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

impl PartialEq for RouteEntry {
    fn eq(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id
    }
}

impl Eq for RouteEntry {}

/// Represents the result of a longest-prefix lookup.
#[derive(Debug, Clone)]
pub struct RouteMatch<'a> {
    /// Matched prefix.
    pub prefix: IpNet,
    /// Identifier of the peer selected by the lookup.
    pub peer_id: &'a str,
    /// Channel to send packets to this peer.
    pub tx: &'a mpsc::Sender<Vec<u8>>,
}

/// In-memory routing table supporting IPv4 and IPv6 longest-prefix matches.
#[derive(Clone)]
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
    pub fn new() -> Self {
        Self {
            trie: IpnetTrie::new(),
        }
    }

    /// Builds a routing table from enabled peers with their TX channels.
    ///
    /// # Arguments
    ///
    /// * `peers` - Peer configurations.
    /// * `peer_txs` - Map of peer ID to TX channel. Peers without a channel are skipped.
    ///
    /// # Errors
    ///
    /// Returns `RoutingError` when a prefix is invalid or conflicts with an existing peer.
    pub fn from_peers(
        peers: &[Peer],
        peer_txs: &HashMap<String, mpsc::Sender<Vec<u8>>>,
    ) -> Result<Self, RoutingError> {
        let mut table = RoutingTable::new();

        for peer in peers.iter().filter(|peer| peer.enabled) {
            let Some(tx) = peer_txs.get(&peer.id) else {
                continue;
            };

            for cidr in &peer.tun.allowed_ips {
                let net: IpNet =
                    cidr.parse::<IpNet>()
                        .map_err(|err| RoutingError::InvalidAllowedIp {
                            peer_id: peer.id.clone(),
                            cidr: cidr.clone(),
                            error: err.to_string(),
                        })?;

                table.insert(
                    net,
                    RouteEntry {
                        peer_id: peer.id.clone(),
                        tx: tx.clone(),
                    },
                )?;
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

/// Commands accepted by the TUN receive loop.
#[derive(Debug, Clone)]
pub enum TunRxCommand {
    /// Replace the routing table atomically.
    UpdateRouting {
        /// New routing table (includes embedded TX channels).
        routing: RoutingTable,
    },
}

/// Routing table construction or lookup error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoutingError {
    /// Allowed IP entry cannot be parsed.
    #[error("peer '{peer_id}' has invalid allowedIPs entry '{cidr}': {error}")]
    InvalidAllowedIp {
        /// Identifier of the owning peer.
        peer_id: String,
        /// Raw CIDR string that failed to parse.
        cidr: String,
        /// Parsing failure detail.
        error: String,
    },
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

// Parses raw address strings and groups them by IP version.
fn parse_addrs(raw_addrs: &[String]) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), TunError> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for addr in raw_addrs {
        match addr.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                let net = Ipv4Net::new(ip, 32).map_err(|e| TunError::InvalidAddress {
                    addr: addr.clone(),
                    error: e.to_string(),
                })?;
                v4.push(net);
            }
            Ok(IpAddr::V6(ip)) => {
                let net = Ipv6Net::new(ip, 128).map_err(|e| TunError::InvalidAddress {
                    addr: addr.clone(),
                    error: e.to_string(),
                })?;
                v6.push(net);
            }
            Err(e) => {
                return Err(TunError::InvalidAddress {
                    addr: addr.clone(),
                    error: e.to_string(),
                })
            }
        };
    }
    Ok((v4, v6))
}

/// Spawns the TUN read loop, pushing packets into peer TX channels with backpressure and emitting RX metrics.
///
/// # Arguments
///
/// * `tun` - TUN device reader.
/// * `routing` - Initial routing table for destination lookups (includes embedded TX channels).
/// * `command_rx` - Channel for receiving runtime commands (e.g., routing updates).
/// * `events_tx` - Channel for emitting receive metrics.
/// * `interval` - Metrics emission interval.
#[allow(dead_code)]
pub(crate) fn spawn_tun_rx<T: TunRx>(
    mut tun: T,
    mut routing: RoutingTable,
    mut command_rx: mpsc::Receiver<TunRxCommand>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mtu = tun.mtu();
        let mut counters = TransportCounters::new(TransportKind::Tun, Direction::Rx);
        let mut ticker = time::interval(interval);
        let mut buf = vec![0u8; mtu];

        loop {
            tokio::select! {
                result = tun.recv(&mut buf) => {
                    match result {
                        Ok(len) => {
                            if len == 0 {
                                continue;
                            }
                            let packet = buf[..len].to_vec();

                            // Inline routing dispatch
                            let dest = match extract_dst_ip(&packet) {
                                Some(ip) => ip,
                                None => {
                                    counters.record_drop(DropReason::InvalidIpVersion, len);
                                    continue;
                                }
                            };

                            let route = match routing.lookup(dest) {
                                Some(route) => route,
                                None => {
                                    counters.record_drop(DropReason::NoRoute, len);
                                    continue;
                                }
                            };

                            // Send directly via embedded TX channel
                            if route.tx.send(packet).await.is_err() {
                                counters.record_drop(DropReason::ChannelClosed, len);
                            } else {
                                counters.record_success(len);
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                Some(command) = command_rx.recv() => {
                    match command {
                        TunRxCommand::UpdateRouting { routing: new_routing } => {
                            routing = new_routing;
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

/// Extracts the destination IP address from an IP packet.
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

/// Spawns the TUN write loop, dropping oversize packets with counting and emitting TX metrics.
#[allow(dead_code)]
pub(crate) fn spawn_tun_tx<T: TunTx>(
    mut tun: T,
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mtu = tun.mtu();
        let mut counters = TransportCounters::new(TransportKind::Tun, Direction::Tx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                maybe_packet = packet_rx.recv() => {
                    let packet = match maybe_packet {
                        Some(packet) => packet,
                        None => break,
                    };

                    if packet.len() > mtu {
                        counters.record_drop(DropReason::Oversize, packet.len());
                        continue;
                    }

                    match retry_on_interrupted!(tun.send(&packet).await) {
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
    use std::collections::VecDeque;
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;
    use tokio::sync::mpsc;

    struct MemoryTunRx {
        name: String,
        mtu: usize,
        packet_rx: mpsc::Receiver<Vec<u8>>,
    }

    struct MemoryTunTx {
        name: String,
        mtu: usize,
        packet_tx: mpsc::Sender<Vec<u8>>,
        send_errors: VecDeque<io::ErrorKind>,
    }

    fn memory_tun(name: &str, mtu: usize) -> (MemoryTunRx, MemoryTunTx) {
        let (packet_tx, packet_rx) = mpsc::channel(4);
        (
            MemoryTunRx {
                name: name.to_string(),
                mtu,
                packet_rx,
            },
            MemoryTunTx {
                name: name.to_string(),
                mtu,
                packet_tx,
                send_errors: VecDeque::new(),
            },
        )
    }

    fn memory_tun_with_errors(
        name: &str,
        mtu: usize,
        send_errors: Vec<io::ErrorKind>,
    ) -> (MemoryTunRx, MemoryTunTx) {
        let (packet_tx, packet_rx) = mpsc::channel(4);
        (
            MemoryTunRx {
                name: name.to_string(),
                mtu,
                packet_rx,
            },
            MemoryTunTx {
                name: name.to_string(),
                mtu,
                packet_tx,
                send_errors: send_errors.into(),
            },
        )
    }

    impl TunRx for MemoryTunRx {
        fn mtu(&self) -> usize {
            self.mtu
        }

        fn name(&self) -> &str {
            &self.name
        }

        async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.packet_rx.recv().await {
                Some(packet) => {
                    let len = packet.len().min(buf.len());
                    buf[..len].copy_from_slice(&packet[..len]);
                    Ok(len)
                }
                None => Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "channel closed",
                )),
            }
        }
    }

    impl TunTx for MemoryTunTx {
        fn mtu(&self) -> usize {
            self.mtu
        }

        fn name(&self) -> &str {
            &self.name
        }

        async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Some(kind) = self.send_errors.pop_front() {
                return Err(io::Error::new(kind, "injected send error"));
            }
            self.packet_tx
                .send(buf.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "packet_tx closed"))?;
            Ok(buf.len())
        }
    }

    #[tokio::test]
    async fn parses_addresses_and_normalizes_to_host_prefix() {
        let addrs = vec!["192.168.1.1".to_string(), "2001:db8::1".to_string()];
        let (v4, v6) = parse_addrs(&addrs).unwrap();
        assert_eq!(v4.len(), 1);
        assert_eq!(v4[0].addr(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(v4[0].prefix_len(), 32);
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].addr(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v6[0].prefix_len(), 128);
    }

    #[tokio::test]
    async fn tun_rx_pushes_packets_and_counts() {
        let (rx_tun, mut tx_tun) = memory_tun("mem0", 64);
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::channel(8);

        // Create a simple IPv4 packet (version 4, dst 192.0.2.1)
        let mut ipv4_packet = vec![0u8; 20];
        ipv4_packet[0] = 0x45; // Version 4, header length 5
        ipv4_packet[16] = 192; // Destination IP: 192.0.2.1
        ipv4_packet[17] = 0;
        ipv4_packet[18] = 2;
        ipv4_packet[19] = 1;

        // Setup routing: 192.0.2.0/24 -> peer1
        let peer_config = Peer {
            id: "peer1".to_string(),
            enabled: true,
            h3: None,
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["192.0.2.0/24".parse().unwrap()],
            },
        };
        let mut peer_txs = HashMap::new();
        peer_txs.insert("peer1".to_string(), peer_tx);
        let routing = RoutingTable::from_peers(&[peer_config], &peer_txs).unwrap();

        let (_cmd_tx, command_rx) = mpsc::channel::<TunRxCommand>(1);

        let tun_rx_task = spawn_tun_rx(
            rx_tun,
            routing,
            command_rx,
            events_tx,
            Duration::from_millis(10),
        );

        tx_tun.send(&ipv4_packet).await.unwrap();
        let packet = peer_rx
            .recv()
            .await
            .expect("packet should be routed to peer");
        assert_eq!(packet, ipv4_packet);

        let mut snapshot = None;
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Transport(TransportEvent::Metrics(m)) = event {
                    if m.labels.direction == Direction::Rx && m.stats.succeeded.packets >= 1 {
                        snapshot = Some(m);
                        break;
                    }
                }
            }
        })
        .await;

        tun_rx_task.abort();

        let metrics = snapshot.expect("rx metrics should arrive");
        assert_eq!(metrics.labels.kind, TransportKind::Tun);
        assert_eq!(metrics.labels.direction, Direction::Rx);
        assert_eq!(metrics.labels.peer_id, None);
        assert_eq!(metrics.labels.ip_addr, None);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.succeeded.bytes, 20);
    }

    #[tokio::test]
    async fn tun_tx_drops_oversize_and_reports_metrics() {
        let (mut rx_tun, tx_tun) = memory_tun("mem1", 4);
        let (packet_tx, packet_rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let tun_tx_task = spawn_tun_tx(tx_tun, packet_rx, events_tx, Duration::from_millis(10));

        packet_tx.send(vec![0, 1, 2, 3, 4, 5]).await.unwrap();
        packet_tx.send(vec![9, 9, 9]).await.unwrap();

        // First packet should be dropped; second should be emitted.
        let mut buf = vec![0u8; 8];
        let len = rx_tun
            .recv(&mut buf)
            .await
            .expect("should receive one packet");
        assert_eq!(buf[..len], [9, 9, 9]);

        let mut snapshot = None;
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Transport(TransportEvent::Metrics(m)) = event {
                    if m.labels.direction == Direction::Tx
                        && m.stats.succeeded.packets >= 1
                        && m.stats.dropped.packets >= 1
                    {
                        snapshot = Some(m);
                        break;
                    }
                }
            }
        })
        .await;

        tun_tx_task.abort();

        let metrics = snapshot.expect("tx metrics should arrive");
        assert_eq!(metrics.labels.kind, TransportKind::Tun);
        assert_eq!(metrics.labels.direction, Direction::Tx);
        assert_eq!(metrics.labels.peer_id, None);
        assert_eq!(metrics.labels.ip_addr, None);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.succeeded.bytes, 3);
        assert_eq!(metrics.stats.dropped.packets, 1);
        assert_eq!(metrics.stats.dropped.bytes, 6);
        assert_eq!(
            metrics
                .stats
                .drop_reasons
                .get(&DropReason::Oversize)
                .map(|c| (c.packets, c.bytes)),
            Some((1, 6))
        );
    }

    #[tokio::test]
    async fn tun_tx_retries_interrupted_send() {
        let (mut rx_tun, tx_tun) =
            memory_tun_with_errors("mem-interrupt", 16, vec![io::ErrorKind::Interrupted]);
        let (packet_tx, packet_rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let tun_tx_task = spawn_tun_tx(tx_tun, packet_rx, events_tx, Duration::from_millis(5));

        packet_tx.send(vec![1, 2, 3]).await.unwrap();

        let mut buf = vec![0u8; 16];
        let len = rx_tun
            .recv(&mut buf)
            .await
            .expect("should receive after retry");
        assert_eq!(&buf[..len], &[1, 2, 3]);

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

        tun_tx_task.abort();

        assert_eq!(metrics.labels.kind, TransportKind::Tun);
        assert_eq!(metrics.labels.direction, Direction::Tx);
        assert_eq!(metrics.labels.peer_id, None);
        assert_eq!(metrics.labels.ip_addr, None);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.dropped.packets, 0);
    }

    // ========================================================================
    // Routing table tests (migrated from routing.rs)
    // ========================================================================

    use crate::config::{PeerBare, PeerTun};

    fn bare_peer(id: &str, enabled: bool, allowed: &[&str]) -> Peer {
        Peer {
            id: id.to_string(),
            enabled,
            h3: None,
            bare: Some(PeerBare {
                endpoint: "udp://127.0.0.1:5353".to_string(),
                bindif: None,
            }),
            tun: PeerTun {
                allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            },
        }
    }

    /// Creates dummy peer TX channels for routing table tests.
    fn dummy_peer_txs(peer_ids: &[&str]) -> HashMap<String, mpsc::Sender<Vec<u8>>> {
        peer_ids
            .iter()
            .map(|id| {
                let (tx, _rx) = mpsc::channel(1);
                (id.to_string(), tx)
            })
            .collect()
    }

    #[test]
    fn chooses_longest_prefix() {
        let peers = vec![
            bare_peer("peer-a", true, &["10.0.0.0/16"]),
            bare_peer("peer-b", true, &["10.0.0.0/24"]),
        ];
        let peer_txs = dummy_peer_txs(&["peer-a", "peer-b"]);
        let table = RoutingTable::from_peers(&peers, &peer_txs).expect("table should build");
        let result = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)))
            .expect("lookup should succeed");
        assert_eq!(result.peer_id, "peer-b");
        assert_eq!(result.prefix, "10.0.0.0/24".parse::<IpNet>().unwrap());
    }

    #[test]
    fn ignores_disabled_peers() {
        let peers = vec![
            bare_peer("peer-disabled", false, &["10.1.0.0/16"]),
            bare_peer("peer-active", true, &["10.0.0.0/8"]),
        ];
        let peer_txs = dummy_peer_txs(&["peer-disabled", "peer-active"]);
        let table = RoutingTable::from_peers(&peers, &peer_txs).expect("table should build");
        assert_eq!(table.len(), (1, 0));
        let result = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4)))
            .expect("lookup should succeed");
        assert_eq!(result.peer_id, "peer-active");
    }

    #[test]
    fn errors_on_conflicting_prefix_ownership() {
        let peers = vec![
            bare_peer("peer-a", true, &["10.0.0.0/24"]),
            bare_peer("peer-b", true, &["10.0.0.0/24"]),
        ];
        let peer_txs = dummy_peer_txs(&["peer-a", "peer-b"]);
        let err = RoutingTable::from_peers(&peers, &peer_txs).unwrap_err();
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
        let peers = vec![bare_peer("peer-a", true, &["10.0.0.0/24", "10.0.0.0/24"])];
        let peer_txs = dummy_peer_txs(&["peer-a"]);
        let table = RoutingTable::from_peers(&peers, &peer_txs).expect("table should build");
        assert_eq!(table.len(), (1, 0));
        let result = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .expect("lookup should succeed");
        assert_eq!(result.peer_id, "peer-a");
    }

    #[tokio::test]
    async fn tun_rx_updates_routing_via_command() {
        let (rx_tun, mut tx_tun) = memory_tun("mem-cmd", 64);
        let (peer1_tx, mut peer1_rx) = mpsc::channel(4);
        let (peer2_tx, mut peer2_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::channel(8);

        // Create IPv4 packet destined to 192.0.2.1
        let mut ipv4_packet = vec![0u8; 20];
        ipv4_packet[0] = 0x45;
        ipv4_packet[16] = 192;
        ipv4_packet[17] = 0;
        ipv4_packet[18] = 2;
        ipv4_packet[19] = 1;

        // Initial routing: 192.0.2.0/24 -> peer1
        let peer1_config = Peer {
            id: "peer1".to_string(),
            enabled: true,
            h3: None,
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["192.0.2.0/24".to_string()],
            },
        };
        let mut peer_txs = HashMap::new();
        peer_txs.insert("peer1".to_string(), peer1_tx);
        let routing = RoutingTable::from_peers(&[peer1_config], &peer_txs).unwrap();

        let (cmd_tx, command_rx) = mpsc::channel::<TunRxCommand>(1);

        let tun_rx_task = spawn_tun_rx(
            rx_tun,
            routing,
            command_rx,
            events_tx,
            Duration::from_secs(60),
        );

        // Send packet - should go to peer1
        tx_tun.send(&ipv4_packet).await.unwrap();
        let packet = peer1_rx.recv().await.expect("packet should route to peer1");
        assert_eq!(packet, ipv4_packet);

        // Update routing: 192.0.2.0/24 -> peer2
        let peer2_config = Peer {
            id: "peer2".to_string(),
            enabled: true,
            h3: None,
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["192.0.2.0/24".to_string()],
            },
        };
        let mut new_peer_txs = HashMap::new();
        new_peer_txs.insert("peer2".to_string(), peer2_tx);
        let new_routing = RoutingTable::from_peers(&[peer2_config], &new_peer_txs).unwrap();

        cmd_tx
            .send(TunRxCommand::UpdateRouting {
                routing: new_routing,
            })
            .await
            .unwrap();

        // Allow command to be processed
        tokio::task::yield_now().await;

        // Send another packet - should now go to peer2
        tx_tun.send(&ipv4_packet).await.unwrap();
        let packet = peer2_rx.recv().await.expect("packet should route to peer2");
        assert_eq!(packet, ipv4_packet);

        // Verify peer1 did not receive the second packet
        assert!(peer1_rx.try_recv().is_err());

        tun_rx_task.abort();
    }
}
