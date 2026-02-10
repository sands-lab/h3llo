//! TUN management: device creation, read/write loops with backpressure, and metrics reporting.

use crate::actor::{ActorError, ActorExitResult};
use crate::config::{LocalTun, Peer};
use crate::events::{Direction, DropReason, Event, TransportEvent, TransportKind};
use crate::helpers::{extract_dst_ip, retry_on_transient};
use crate::metrics::TransportCounters;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use ipnet_trie::IpnetTrie;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{info, warn};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};
#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

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

    /// Maximum number of packets receivable in a single batch.
    ///
    /// Returns 1 by default (no batching). Offload-capable devices override this
    /// to return `IDEAL_BATCH_SIZE`.
    fn batch_size(&self) -> usize {
        1
    }

    /// Required scratch buffer size for [`recv_batch`](Self::recv_batch).
    ///
    /// Defaults to [`mtu()`](Self::mtu). Offload-capable devices override this
    /// to return `VIRTIO_NET_HDR_LEN + 65535`.
    fn scratch_buf_size(&self) -> usize {
        self.mtu()
    }

    /// Receives multiple packets in batch, returning the packet count.
    ///
    /// On offload-capable devices, reads a single large segment from the kernel
    /// and splits it into individual packets stored in `bufs[0..n]` with their
    /// lengths in `sizes[0..n]`. On non-offload devices, falls back to single `recv`.
    ///
    /// # Arguments
    ///
    /// * `scratch` - Scratch buffer for the raw kernel read (sized via
    ///   [`scratch_buf_size`](Self::scratch_buf_size)).
    /// * `bufs` - Pre-allocated packet buffers to receive into.
    /// * `sizes` - Output lengths for each received packet.
    fn recv_batch(
        &mut self,
        _scratch: &mut [u8],
        bufs: &mut [Vec<u8>],
        sizes: &mut [usize],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send {
        async {
            let len = self.recv(&mut bufs[0]).await?;
            sizes[0] = len;
            Ok(1)
        }
    }
}

/// Provides send-only access to a TUN device for a single coroutine.
pub trait TunTx: Send + 'static {
    /// Returns the configured MTU for sizing buffers.
    fn mtu(&self) -> usize;
    /// Returns the interface name.
    fn name(&self) -> &str;
    /// Sends a packet from `buf`, returning the number of bytes written.
    fn send(&mut self, buf: &[u8]) -> impl std::future::Future<Output = io::Result<usize>> + Send;

    /// Maximum number of packets sendable in a single batch.
    ///
    /// Returns 1 by default (no batching). Offload-capable devices override this
    /// to return `IDEAL_BATCH_SIZE`.
    fn batch_size(&self) -> usize {
        1
    }

    /// Byte offset prepended to each buffer for transport headers (e.g., virtio_net_hdr).
    ///
    /// Returns 0 by default. Offload-capable devices override this to return
    /// `VIRTIO_NET_HDR_LEN`.
    fn hdr_offset(&self) -> usize {
        0
    }

    /// Sends multiple packets in batch using GRO coalescing.
    ///
    /// Each buffer in `bufs` must have `offset` zero-bytes prepended for the
    /// virtio_net_hdr. Returns the number of packets successfully sent.
    /// On non-offload devices, falls back to sending each packet individually
    /// with transient-error retry.
    fn send_batch(
        &mut self,
        bufs: &mut [Vec<u8>],
        offset: usize,
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send {
        async move {
            for buf in bufs.iter() {
                if offset > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "send_batch: buffer shorter than offset",
                    ));
                }
                retry_on_transient!(self.send(&buf[offset..]).await)?;
            }
            Ok(bufs.len())
        }
    }
}

/// Creates TUN device state from configuration.
///
/// # Arguments
///
/// * `local_tun` - TUN configuration including interface name, addresses, and MTU.
///
/// # Errors
///
/// Returns `TunError::DeviceBuild` when device creation or address assignment fails.
pub async fn make_tun(local_tun: &LocalTun) -> Result<(TunReader, TunWriter), TunError> {
    let (v4_addrs, v6_addrs) = split_addrs_by_version(&local_tun.addrs);

    let mut builder = DeviceBuilder::new()
        .name(local_tun.ifname.as_str())
        .mtu(local_tun.mtu)
        .enable(true)
        .layer(Layer::L3);

    // Enable GSO/GRO offload on Linux for batched TUN I/O.
    #[cfg(target_os = "linux")]
    {
        builder = builder.offload(true);
    }

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

    #[cfg(target_os = "linux")]
    info!(
        tun = %name,
        tcp_gso = device.tcp_gso(),
        udp_gso = device.udp_gso(),
        "TUN offload status"
    );

    let device = Arc::new(device);
    let reader = TunReader {
        device: device.clone(),
        mtu,
        name: name.clone(),
        #[cfg(target_os = "linux")]
        recv_scratch: vec![0u8; VIRTIO_NET_HDR_LEN + mtu],
    };
    let writer = TunWriter {
        device,
        mtu,
        name,
        #[cfg(target_os = "linux")]
        gro_table: GROTable::default(),
    };

    Ok((reader, writer))
}

/// Provides a receive-only handle for a TUN device.
pub struct TunReader {
    device: Arc<AsyncDevice>,
    mtu: usize,
    name: String,
    /// Scratch buffer for stripping virtio_net_hdr from single-packet recv on offload devices.
    #[cfg(target_os = "linux")]
    recv_scratch: Vec<u8>,
}

impl TunRx for TunReader {
    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }

    /// Receives a single IP packet, stripping the virtio_net_hdr on offload-enabled devices.
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            let n = self.device.recv(&mut self.recv_scratch).await?;
            if n <= VIRTIO_NET_HDR_LEN {
                return Ok(0);
            }
            let payload_len = n - VIRTIO_NET_HDR_LEN;
            let copy_len = payload_len.min(buf.len());
            buf[..copy_len].copy_from_slice(
                &self.recv_scratch[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + copy_len],
            );
            Ok(copy_len)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.device.recv(buf).await
        }
    }

    #[cfg(target_os = "linux")]
    fn batch_size(&self) -> usize {
        IDEAL_BATCH_SIZE
    }

    #[cfg(target_os = "linux")]
    fn scratch_buf_size(&self) -> usize {
        VIRTIO_NET_HDR_LEN + 65535
    }

    #[cfg(target_os = "linux")]
    async fn recv_batch(
        &mut self,
        scratch: &mut [u8],
        bufs: &mut [Vec<u8>],
        sizes: &mut [usize],
    ) -> io::Result<usize> {
        self.device.recv_multiple(scratch, bufs, sizes, 0).await
    }
}

/// Provides a send-only handle for a TUN device.
pub struct TunWriter {
    device: Arc<AsyncDevice>,
    mtu: usize,
    name: String,
    #[cfg(target_os = "linux")]
    gro_table: GROTable,
}

impl TunTx for TunWriter {
    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }

    /// Sends a single IP packet, prepending a zeroed virtio_net_hdr on offload-enabled devices.
    async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            let mut hdr_buf = vec![0u8; VIRTIO_NET_HDR_LEN + buf.len()];
            hdr_buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(buf);
            let n = self.device.send(&hdr_buf).await?;
            Ok(n.saturating_sub(VIRTIO_NET_HDR_LEN))
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.device.send(buf).await
        }
    }

    #[cfg(target_os = "linux")]
    fn batch_size(&self) -> usize {
        IDEAL_BATCH_SIZE
    }

    #[cfg(target_os = "linux")]
    fn hdr_offset(&self) -> usize {
        VIRTIO_NET_HDR_LEN
    }

    #[cfg(target_os = "linux")]
    async fn send_batch(&mut self, bufs: &mut [Vec<u8>], offset: usize) -> io::Result<usize> {
        self.device
            .send_multiple(&mut self.gro_table, bufs, offset)
            .await?;
        Ok(bufs.len())
    }
}

/// Describes TUN errors for creation and operation.
#[derive(Debug, Error)]
pub enum TunError {
    // Note: InvalidAddress variant removed - parsing now happens during config deserialization.
    /// Device creation or address assignment failed.
    #[error("failed to build TUN device: {0}")]
    DeviceBuild(String),
}

// ============================================================================
// Routing table (migrated from routing.rs)
// ============================================================================

fn log_duplicate_allowed(peer_id: &str, cidr: &str) {
    warn!(
        "duplicate allowed_ips '{}' for peer '{}'; keeping the first entry",
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
    /// Returns `RoutingError::ConflictingPrefix` when a prefix conflicts with an existing peer.
    pub fn from_peers(
        peers: &[Peer],
        peer_txs: &HashMap<String, mpsc::Sender<Vec<u8>>>,
    ) -> Result<Self, RoutingError> {
        let mut table = RoutingTable::new();

        for peer in peers.iter().filter(|peer| peer.enabled) {
            let Some(tx) = peer_txs.get(&peer.id) else {
                warn!(
                    "enabled peer '{}' has no TX channel; skipping route registration",
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
    // Note: InvalidAllowedIp variant removed - parsing now happens during config deserialization.
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

/// Groups pre-parsed CIDR networks by IP version.
fn split_addrs_by_version(addrs: &[IpNet]) -> (Vec<Ipv4Net>, Vec<Ipv6Net>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for addr in addrs {
        match addr {
            IpNet::V4(net) => {
                v4.push(*net);
            }
            IpNet::V6(net) => {
                v6.push(*net);
            }
        }
    }
    (v4, v6)
}

/// Spawns the TUN read loop.
///
/// Creates an unbounded command channel internally (actor owns the receiver).
/// Returns the command sender and join handle.
///
/// # Arguments
///
/// * `tun` - TUN device reader.
/// * `routing` - Initial routing table for destination lookups.
/// * `events_tx` - Unbounded channel for emitting receive metrics.
/// * `interval` - Metrics emission interval.
#[allow(dead_code)]
pub(crate) fn spawn_tun_rx<T: TunRx>(
    mut tun: T,
    mut routing: RoutingTable,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> (
    mpsc::UnboundedSender<TunRxCommand>,
    JoinHandle<ActorExitResult>,
) {
    // Actor creates and owns its command channel receiver
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let tun_name = tun.name().to_string();
    let batch_size = tun.batch_size();
    let scratch_buf_size = tun.scratch_buf_size();

    let handle = tokio::spawn(async move {
        let mtu = tun.mtu();
        let mut counters = TransportCounters::new(TransportKind::Tun, Direction::Rx);
        let mut ticker = time::interval(interval);

        let mut scratch = vec![0u8; scratch_buf_size];
        let mut bufs = vec![vec![0u8; mtu]; batch_size];
        let mut sizes = vec![0usize; batch_size];

        loop {
            tokio::select! {
                result = tun.recv_batch(&mut scratch, &mut bufs, &mut sizes) => {
                    match result {
                        Ok(count) => {
                            let count = count.min(batch_size);
                            for i in 0..count {
                                let len = sizes[i];
                                if len == 0 {
                                    continue;
                                }
                                let packet = bufs[i][..len].to_vec();

                                // Inline routing dispatch
                                let Some(dest) = extract_dst_ip(&packet) else {
                                    counters.record_drop(DropReason::InvalidIpVersion, len);
                                    continue;
                                };

                                let Some(route) = routing.lookup(dest) else {
                                    counters.record_drop(DropReason::NoRoute, len);
                                    continue;
                                };

                                // Send directly via embedded TX channel
                                if route.tx.send(packet).await.is_err() {
                                    counters.record_drop(DropReason::ChannelClosed, len);
                                } else {
                                    counters.record_success(len);
                                }
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(err) => {
                            return Err(ActorError::TunRxRecv { name: tun_name, source: err });
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    let Some(command) = cmd else {
                        return Ok(()); // Channel closed, exit gracefully
                    };
                    // Single-variant enum: destructure directly
                    let TunRxCommand::UpdateRouting { routing: new_routing } = command;
                    routing = new_routing;
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

/// Spawns the TUN write loop, dropping oversize packets with counting and emitting TX metrics.
///
/// Creates a bounded packet channel internally (actor owns the receiver).
/// Returns the packet sender and join handle.
#[allow(dead_code)]
pub(crate) fn spawn_tun_tx<T: TunTx>(
    mut tun: T,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
    packet_queue_depth: usize,
) -> (mpsc::Sender<Vec<u8>>, JoinHandle<ActorExitResult>) {
    // Actor creates and owns its data-plane channel receiver
    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<u8>>(packet_queue_depth);
    let tun_name = tun.name().to_string();
    let hdr_offset = tun.hdr_offset();

    let handle = tokio::spawn(async move {
        let mtu = tun.mtu();
        let mut counters = TransportCounters::new(TransportKind::Tun, Direction::Tx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                maybe_packet = packet_rx.recv() => {
                    let packet = match maybe_packet {
                        Some(packet) => packet,
                        None => return Ok(()), // Channel closed, exit gracefully
                    };

                    if packet.len() > mtu {
                        counters.record_drop(DropReason::Oversize, packet.len());
                        continue;
                    }

                    let mut hdr_pkt = vec![0u8; hdr_offset + packet.len()];
                    hdr_pkt[hdr_offset..].copy_from_slice(&packet);
                    let mut batch = vec![hdr_pkt];

                    match tun.send_batch(&mut batch, hdr_offset).await {
                        Ok(_) => {
                            for b in &batch {
                                counters.record_success(b.len().saturating_sub(hdr_offset));
                            }
                        }
                        Err(err) => {
                            let total: usize =
                                batch.iter().map(|b| b.len().saturating_sub(hdr_offset)).sum();
                            counters.record_drop(DropReason::SendError, total);
                            return Err(ActorError::TunTxSend { name: tun_name, source: err });
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

// ============================================================================
// Test utilities (feature-gated)
// ============================================================================

/// In-memory TUN implementations for testing.
///
/// Available when compiled with `--features test-utils` or in test builds.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_support {
    use super::{TunRx, TunTx};
    use std::collections::VecDeque;
    use std::io;
    use tokio::sync::mpsc;

    /// In-memory TUN receiver for testing.
    pub struct MemoryTunRx {
        name: String,
        mtu: usize,
        packet_rx: mpsc::Receiver<Vec<u8>>,
    }

    /// In-memory TUN transmitter for testing.
    pub struct MemoryTunTx {
        name: String,
        mtu: usize,
        packet_tx: mpsc::Sender<Vec<u8>>,
        send_errors: VecDeque<io::ErrorKind>,
    }

    /// Creates a connected MemoryTun pair for testing.
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name for the simulated TUN device.
    /// * `mtu` - MTU value for sizing buffers.
    ///
    /// # Returns
    ///
    /// A tuple of `(rx, tx, inject_tx, output_rx)` where:
    /// - `rx`: TUN receiver implementing [`TunRx`].
    /// - `tx`: TUN transmitter implementing [`TunTx`].
    /// - `inject_tx`: Send packets into the TUN RX side (simulates incoming packets).
    /// - `output_rx`: Receive packets from the TUN TX side (captures outgoing packets).
    pub fn memory_tun(
        name: &str,
        mtu: usize,
    ) -> (
        MemoryTunRx,
        MemoryTunTx,
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
    ) {
        let (inject_tx, packet_rx) = mpsc::channel(16);
        let (packet_tx, output_rx) = mpsc::channel(16);
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
            inject_tx,
            output_rx,
        )
    }

    /// Creates a MemoryTun with pre-configured send errors for fault injection.
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name for the simulated TUN device.
    /// * `mtu` - MTU value for sizing buffers.
    /// * `send_errors` - Queue of error kinds to return on successive send calls.
    pub fn memory_tun_with_errors(
        name: &str,
        mtu: usize,
        send_errors: Vec<io::ErrorKind>,
    ) -> (
        MemoryTunRx,
        MemoryTunTx,
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
    ) {
        let (inject_tx, packet_rx) = mpsc::channel(16);
        let (packet_tx, output_rx) = mpsc::channel(16);
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
            inject_tx,
            output_rx,
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
}

#[cfg(test)]
mod tests {
    use super::test_support::{memory_tun, memory_tun_with_errors};
    use super::*;
    use crate::helpers::test_packets::make_ipv4_packet;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn splits_addresses_and_preserves_prefix_length() {
        let addrs: Vec<IpNet> = vec![
            "192.168.1.0/24".parse().unwrap(),
            "2001:db8::/64".parse().unwrap(),
        ];
        let (v4, v6) = split_addrs_by_version(&addrs);
        assert_eq!(v4.len(), 1);
        assert_eq!(v4[0].addr(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(v4[0].prefix_len(), 24);
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].addr(), "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v6[0].prefix_len(), 64);
    }

    #[tokio::test]
    async fn tun_rx_pushes_packets_and_counts() {
        let (rx_tun, _tx_tun, inject_tx, _output_rx) = memory_tun("mem0", 64);
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let ipv4_packet = make_ipv4_packet(Ipv4Addr::new(192, 0, 2, 1));

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

        let (_cmd_tx, tun_rx_task) =
            spawn_tun_rx(rx_tun, routing, events_tx, Duration::from_millis(10));

        inject_tx.send(ipv4_packet.clone()).await.unwrap();
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
        let (_rx_tun, tx_tun, _inject_tx, mut output_rx) = memory_tun("mem1", 4);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let (packet_tx, tun_tx_task) =
            spawn_tun_tx(tx_tun, events_tx, Duration::from_millis(10), 256);

        packet_tx.send(vec![0, 1, 2, 3, 4, 5]).await.unwrap();
        packet_tx.send(vec![9, 9, 9]).await.unwrap();

        // First packet should be dropped; second should be emitted.
        let received = output_rx.recv().await.expect("should receive one packet");
        assert_eq!(received, vec![9, 9, 9]);

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
        let (_rx_tun, tx_tun, _inject_tx, mut output_rx) =
            memory_tun_with_errors("mem-interrupt", 16, vec![std::io::ErrorKind::Interrupted]);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let (packet_tx, tun_tx_task) =
            spawn_tun_tx(tx_tun, events_tx, Duration::from_millis(5), 256);

        packet_tx.send(vec![1, 2, 3]).await.unwrap();

        let received = output_rx.recv().await.expect("should receive after retry");
        assert_eq!(received, vec![1, 2, 3]);

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

    use crate::config::{PeerBare, PeerTun, UdpEndpoint};

    fn bare_peer(id: &str, enabled: bool, allowed: &[&str]) -> Peer {
        Peer {
            id: id.to_string(),
            enabled,
            h3: None,
            bare: Some(PeerBare {
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
        let (rx_tun, _tx_tun, inject_tx, _output_rx) = memory_tun("mem-cmd", 64);
        let (peer1_tx, mut peer1_rx) = mpsc::channel(4);
        let (peer2_tx, mut peer2_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let ipv4_packet = make_ipv4_packet(Ipv4Addr::new(192, 0, 2, 1));

        // Initial routing: 192.0.2.0/24 -> peer1
        let peer1_config = Peer {
            id: "peer1".to_string(),
            enabled: true,
            h3: None,
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["192.0.2.0/24".parse().unwrap()],
            },
        };
        let mut peer_txs = HashMap::new();
        peer_txs.insert("peer1".to_string(), peer1_tx);
        let routing = RoutingTable::from_peers(&[peer1_config], &peer_txs).unwrap();

        let (cmd_tx, tun_rx_task) =
            spawn_tun_rx(rx_tun, routing, events_tx, Duration::from_secs(60));

        // Send packet - should go to peer1
        inject_tx.send(ipv4_packet.clone()).await.unwrap();
        let packet = peer1_rx.recv().await.expect("packet should route to peer1");
        assert_eq!(packet, ipv4_packet);

        // Update routing: 192.0.2.0/24 -> peer2
        let peer2_config = Peer {
            id: "peer2".to_string(),
            enabled: true,
            h3: None,
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["192.0.2.0/24".parse().unwrap()],
            },
        };
        let mut new_peer_txs = HashMap::new();
        new_peer_txs.insert("peer2".to_string(), peer2_tx);
        let new_routing = RoutingTable::from_peers(&[peer2_config], &new_peer_txs).unwrap();

        cmd_tx
            .send(TunRxCommand::UpdateRouting {
                routing: new_routing,
            })
            .unwrap();

        // Allow command to be processed
        tokio::task::yield_now().await;

        // Send another packet - should now go to peer2
        inject_tx.send(ipv4_packet.clone()).await.unwrap();
        let packet = peer2_rx.recv().await.expect("packet should route to peer2");
        assert_eq!(packet, ipv4_packet);

        // Verify peer1 did not receive the second packet
        assert!(peer1_rx.try_recv().is_err());

        tun_rx_task.abort();
    }

    // ========== Actor Lifecycle Tests ==========

    #[tokio::test]
    async fn spawn_tun_rx_returns_working_cmd_tx() {
        let (rx_tun, _tx_tun, _inject_tx, _output_rx) = memory_tun("mem-lifecycle", 64);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let routing = RoutingTable::new();

        let (cmd_tx, handle) = spawn_tun_rx(rx_tun, routing, events_tx, Duration::from_secs(60));

        // Verify cmd_tx is functional by sending a routing update
        let new_routing = RoutingTable::new();
        assert!(cmd_tx
            .send(TunRxCommand::UpdateRouting {
                routing: new_routing
            })
            .is_ok());

        handle.abort();
    }

    #[tokio::test]
    async fn tun_rx_actor_exits_when_sender_dropped() {
        let (rx_tun, _tx_tun, _inject_tx, _output_rx) = memory_tun("mem-shutdown", 64);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let routing = RoutingTable::new();

        let (cmd_tx, join_handle) =
            spawn_tun_rx(rx_tun, routing, events_tx, Duration::from_secs(60));

        // Drop sender to signal shutdown
        drop(cmd_tx);

        // Actor should exit gracefully (check both timeout and join result)
        let result = tokio::time::timeout(Duration::from_millis(200), join_handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "tun_rx actor should shut down cleanly after sender dropped, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn spawn_tun_tx_returns_working_packet_tx() {
        let (_rx_tun, tx_tun, _inject_tx, _output_rx) = memory_tun("mem-tx-lifecycle", 64);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let (packet_tx, handle) = spawn_tun_tx(tx_tun, events_tx, Duration::from_secs(60), 256);

        // Verify packet_tx is functional by sending a packet
        assert!(packet_tx.send(vec![1, 2, 3]).await.is_ok());

        handle.abort();
    }

    #[tokio::test]
    async fn tun_tx_actor_exits_when_sender_dropped() {
        let (_rx_tun, tx_tun, _inject_tx, _output_rx) = memory_tun("mem-tx-shutdown", 64);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let (packet_tx, join_handle) =
            spawn_tun_tx(tx_tun, events_tx, Duration::from_secs(60), 256);

        // Drop sender to signal shutdown
        drop(packet_tx);

        // Actor should exit gracefully (check both timeout and join result)
        let result = tokio::time::timeout(Duration::from_millis(200), join_handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "tun_tx actor should shut down cleanly after sender dropped, got {:?}",
            result
        );
    }

    // ========== Offload / Batch Tests ==========

    #[test]
    fn memory_tun_batch_size_is_one() {
        let (rx, tx, _inject, _output) = memory_tun("mem-batch-check", 1500);
        assert_eq!(rx.batch_size(), 1);
        assert_eq!(rx.scratch_buf_size(), 1500);
        assert_eq!(tx.batch_size(), 1);
        assert_eq!(tx.hdr_offset(), 0);
    }

    #[tokio::test]
    async fn tun_rx_batch_fallback_dispatches_correctly() {
        // Verifies that the batch-aware spawn_tun_rx loop works
        // correctly when recv_batch falls back to single-packet recv.
        let (rx_tun, _tx_tun, inject_tx, _output_rx) = memory_tun("mem-batch-fb", 64);
        let (peer_tx, mut peer_rx) = mpsc::channel(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let ipv4_packet = make_ipv4_packet(Ipv4Addr::new(192, 0, 2, 1));

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

        let (_cmd_tx, tun_rx_task) =
            spawn_tun_rx(rx_tun, routing, events_tx, Duration::from_millis(10));

        inject_tx.send(ipv4_packet.clone()).await.unwrap();
        let packet = peer_rx
            .recv()
            .await
            .expect("packet should be routed via batch fallback");
        assert_eq!(packet, ipv4_packet);

        tun_rx_task.abort();
    }
}
