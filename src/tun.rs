//! TUN management: device creation, read/write loops with backpressure, and metrics reporting.

use crate::actor::{ActorError, ActorExitResult};
use crate::config::{LocalTun, Peer};
use crate::events::{Direction, DropReason, Event, TransportEvent, TransportKind};
use crate::helpers::retry_on_transient;
use crate::metrics::{send_with_backpressure, SendEvent, TransportCounters};
use crate::router::{BatchSource, RouterMsg};
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
use tokio_quiche::buf_factory::{BufFactory, PooledBuf};
use tracing::{info, warn};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};
#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

/// Headroom reserved in every datapath PooledBuf.
///
/// 9 bytes tokio-quiche DGRAM_PREFIX (flow ID + flow context encoding) +
/// 1 byte CONNECT-IP Context ID (0x00). If tokio-quiche `DGRAM_PREFIX`
/// changes, this value must be updated accordingly.
///
/// All packet-producing paths (TUN RX, BareUDP RX) reserve this headroom
/// so downstream consumers (H3 TX, TUN TX) can prepend headers in-place.
pub(crate) const HEADROOM: usize = 10;

// Compile-time guard: TunBuf::prepend_hdr relies on HEADROOM being sufficient
// to prepend a zeroed virtio_net_hdr via add_prefix without allocation.
#[cfg(target_os = "linux")]
const _: () = assert!(
    HEADROOM >= VIRTIO_NET_HDR_LEN,
    "HEADROOM must be >= VIRTIO_NET_HDR_LEN for zero-copy TUN TX"
);

/// Allocates an uninitialized pooled buffer with [`HEADROOM`] bytes reserved,
/// selecting the smallest pool that fits `length + HEADROOM`.
///
/// Uses the datagram pool (≤ [`BufFactory::MAX_DGRAM_SIZE`] bytes) for typical
/// packets and falls back to the generic pool for oversized payloads.
///
/// The returned buffer's visible length is `pool_capacity - HEADROOM`, which
/// may exceed `length`. Callers must [`truncate`](PooledBuf::truncate) to the
/// actual payload size.
///
/// # Arguments
///
/// * `length` - Expected payload size (excluding headroom).
pub(crate) fn alloc_uninit_packet_buf(length: usize) -> PooledBuf {
    if length + HEADROOM <= BufFactory::MAX_DGRAM_SIZE {
        let mut buf = BufFactory::get_max_datagram();
        // get_max_datagram() reserves an internal prefix (DGRAM_PREFIX) that
        // may differ from our HEADROOM.  Compute and consume the difference.
        let dgram_headroom = BufFactory::MAX_DGRAM_SIZE - buf.len();
        if dgram_headroom < HEADROOM {
            buf.pop_front(HEADROOM - dgram_headroom);
        }
        buf
    } else {
        let mut buf = BufFactory::get_max_buf();
        buf.pop_front(HEADROOM);
        buf
    }
}

/// Allocates a pooled buffer with headroom for in-place header prepending.
///
/// Data starts at offset `HEADROOM`, leaving room for downstream consumers
/// to prepend headers via `add_prefix` without reallocation.
pub(crate) fn alloc_packet_buf(data: &[u8]) -> PooledBuf {
    let mut buf = alloc_uninit_packet_buf(data.len());
    buf.truncate(data.len());
    buf[..data.len()].copy_from_slice(data);
    buf
}

/// Zero-copy wrapper around [`PooledBuf`] for TUN I/O (RX and TX).
///
/// RX: [`TunBuf::alloc_uninit`] allocates with headroom; [`into_pooled`](Self::into_pooled) truncates.
/// TX: `From<PooledBuf>` constructs; [`TunTx::send_batch`] prepends virtio_net_hdr.
pub struct TunBuf(PooledBuf);

impl TunBuf {
    /// Allocates a pooled buffer sized for `mtu` with [`HEADROOM`] bytes reserved.
    ///
    /// The caller must call [`into_pooled`](Self::into_pooled) after filling
    /// to set the actual length.
    ///
    /// # Arguments
    ///
    /// * `mtu` - Expected maximum payload size (excluding headroom).
    pub fn alloc_uninit(mtu: usize) -> Self {
        Self(alloc_uninit_packet_buf(mtu))
    }

    /// Truncates to `len` bytes and returns the underlying [`PooledBuf`].
    pub fn into_pooled(mut self, len: usize) -> PooledBuf {
        debug_assert!(
            len <= self.0.len(),
            "into_pooled: len {len} exceeds buffer visible length {}",
            self.0.len()
        );
        self.0.truncate(len);
        self.0
    }

    /// Ensures capacity for `additional` bytes, upgrading to a max-capacity
    /// pooled buffer when the current buffer crosses the single-datagram
    /// threshold. This avoids incremental Vec reallocations during GRO
    /// coalescing on the TUN TX path.
    #[cfg(target_os = "linux")]
    fn buf_extend(&mut self, additional: usize) {
        let current_len = self.0.len();
        if current_len <= BufFactory::MAX_DGRAM_SIZE
            && current_len + additional > BufFactory::MAX_DGRAM_SIZE
        {
            let mut new_buf = BufFactory::get_max_buf();
            new_buf.truncate(current_len);
            new_buf[..current_len].copy_from_slice(&self.0);
            self.0 = new_buf;
        }
    }

    /// Prepends a zeroed virtio_net_hdr using headroom when available,
    /// falling back to alloc + copy otherwise. Called by `send_batch`
    /// implementations, not by the TUN TX actor.
    #[cfg(target_os = "linux")]
    fn prepend_hdr(&mut self) {
        let zeroed = [0u8; VIRTIO_NET_HDR_LEN];
        if !self.0.add_prefix(&zeroed) {
            let mut buf = alloc_packet_buf(&self.0);
            let ok = buf.add_prefix(&zeroed);
            debug_assert!(ok, "alloc_packet_buf guarantees HEADROOM bytes");
            self.0 = buf;
        }
    }
}

impl From<PooledBuf> for TunBuf {
    fn from(packet: PooledBuf) -> Self {
        Self(packet)
    }
}

impl AsRef<[u8]> for TunBuf {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for TunBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

#[cfg(target_os = "linux")]
impl tun_rs::ExpandBuffer for TunBuf {
    fn buf_capacity(&self) -> usize {
        // PooledBuf is backed by a growable Vec<u8>, so GRO can always
        // extend it via buf_extend_from_slice(). Return usize::MAX to
        // let the GRO coalescing logic merge same-flow packets into GSO
        // super-packets (capped at ~65535 bytes by IP total length).
        usize::MAX
    }

    fn buf_resize(&mut self, new_len: usize, val: u8) {
        let current = self.0.len();
        if new_len <= current {
            self.0.truncate(new_len);
        } else {
            self.buf_extend(new_len - current);
            self.0.extend(std::iter::repeat_n(&val, new_len - current));
        }
    }

    fn buf_extend_from_slice(&mut self, src: &[u8]) {
        self.buf_extend(src.len());
        self.0.extend(src.iter());
    }
}

/// Provides receive-only access to a TUN device for a single coroutine.
pub trait TunRx: Send + 'static {
    /// Returns the configured MTU for sizing buffers.
    fn mtu(&self) -> usize;
    /// Returns the interface name.
    fn name(&self) -> &str;

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
    /// to return `VIRTIO_NET_HDR_LEN + u16::MAX`.
    fn scratch_buf_size(&self) -> usize {
        self.mtu()
    }

    /// Receives one or more packets in a single call, returning the packet count.
    ///
    /// On offload-capable devices, reads a single large segment from the kernel
    /// and splits it into individual packets stored in `bufs[0..n]` with their
    /// lengths in `sizes[0..n]`. On non-offload devices, reads one packet per call.
    ///
    /// # Arguments
    ///
    /// * `scratch` - Scratch buffer for the raw kernel read (sized via
    ///   [`scratch_buf_size`](Self::scratch_buf_size)).
    /// * `bufs` - Pre-allocated [`TunBuf`] packet buffers to receive into.
    /// * `sizes` - Output lengths for each received packet.
    fn recv_batch(
        &mut self,
        scratch: &mut [u8],
        bufs: &mut [TunBuf],
        sizes: &mut [usize],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send;
}

/// Provides send-only access to a TUN device for a single coroutine.
pub trait TunTx: Send + 'static {
    /// Returns the configured MTU for sizing buffers.
    fn mtu(&self) -> usize;
    /// Returns the interface name.
    fn name(&self) -> &str;

    /// Maximum number of packets sendable in a single batch.
    ///
    /// Returns 1 by default (no batching). Offload-capable devices override this
    /// to return `IDEAL_BATCH_SIZE`.
    fn batch_size(&self) -> usize {
        1
    }

    /// Sends one or more packets in a single call.
    ///
    /// Implementations prepend any required transport header (e.g.,
    /// `virtio_net_hdr` on Linux) internally.
    fn send_batch(
        &mut self,
        bufs: &mut [TunBuf],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send;
}

/// Creates TUN device state from configuration.
///
/// # Arguments
///
/// * `local_tun` - TUN configuration including interface name, addresses, and MTU.
/// * `tx_queue_len` - Transmit queue length in packets (applied on Linux only).
/// * `enable_offload` - Enable GSO/GRO offload (applied on Linux only).
///
/// # Errors
///
/// Returns `TunError::DeviceBuild` when device creation or address assignment fails.
pub async fn make_tun(
    local_tun: &LocalTun,
    tx_queue_len: u32,
    enable_offload: bool,
) -> Result<(TunReader, TunWriter), TunError> {
    let (v4_addrs, v6_addrs) = split_addrs_by_version(&local_tun.addrs);

    let mut builder = DeviceBuilder::new()
        .name(local_tun.ifname.as_str())
        .mtu(local_tun.mtu)
        .enable(true)
        .layer(Layer::L3);

    // Enable GSO/GRO offload on Linux for batched TUN I/O.
    #[cfg(target_os = "linux")]
    {
        builder = builder.offload(enable_offload).tx_queue_len(tx_queue_len);
    }

    #[cfg(not(target_os = "linux"))]
    let _ = (tx_queue_len, enable_offload);

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
        offload = enable_offload,
        "TUN offload status"
    );

    #[cfg(target_os = "linux")]
    let offload_active = enable_offload;
    #[cfg(not(target_os = "linux"))]
    let offload_active = false;

    let device = Arc::new(device);
    let reader = TunReader {
        device: device.clone(),
        mtu,
        name: name.clone(),
        offload: offload_active,
    };
    let writer = TunWriter {
        device,
        mtu,
        name,
        offload: offload_active,
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
    offload: bool,
}

impl TunRx for TunReader {
    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }

    #[cfg(target_os = "linux")]
    fn batch_size(&self) -> usize {
        if self.offload {
            IDEAL_BATCH_SIZE
        } else {
            1
        }
    }

    #[cfg(target_os = "linux")]
    fn scratch_buf_size(&self) -> usize {
        if self.offload {
            VIRTIO_NET_HDR_LEN + u16::MAX as usize
        } else {
            self.mtu
        }
    }

    async fn recv_batch(
        &mut self,
        scratch: &mut [u8],
        bufs: &mut [TunBuf],
        sizes: &mut [usize],
    ) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            if self.offload {
                self.device.recv_multiple(scratch, bufs, sizes, 0).await
            } else {
                let _ = scratch;
                let len = self.device.recv(bufs[0].as_mut()).await?;
                sizes[0] = len;
                Ok(1)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = scratch;
            let len = self.device.recv(bufs[0].as_mut()).await?;
            sizes[0] = len;
            Ok(1)
        }
    }
}

/// Provides a send-only handle for a TUN device.
pub struct TunWriter {
    device: Arc<AsyncDevice>,
    mtu: usize,
    name: String,
    offload: bool,
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

    #[cfg(target_os = "linux")]
    fn batch_size(&self) -> usize {
        if self.offload {
            IDEAL_BATCH_SIZE
        } else {
            1
        }
    }

    async fn send_batch(&mut self, bufs: &mut [TunBuf]) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            if self.offload {
                for buf in bufs.iter_mut() {
                    buf.prepend_hdr();
                }
                self.device
                    .send_multiple(&mut self.gro_table, bufs, VIRTIO_NET_HDR_LEN)
                    .await?;
                Ok(bufs.len())
            } else {
                for buf in bufs.iter() {
                    retry_on_transient!(self.device.send(buf.as_ref()).await, |_| {})?;
                }
                Ok(bufs.len())
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            for buf in bufs.iter() {
                retry_on_transient!(self.device.send(buf.as_ref()).await, |_| {})?;
            }
            Ok(bufs.len())
        }
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
    /// Channel to send packet batches to this peer.
    pub tx: &'a mpsc::Sender<Vec<PooledBuf>>,
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

    /// Builds a routing table from peers with their TX channels.
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
        peer_txs: &HashMap<String, mpsc::Sender<Vec<PooledBuf>>>,
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
        match *addr {
            IpNet::V4(n) => v4.push(n),
            IpNet::V6(n) => v6.push(n),
        }
    }
    (v4, v6)
}

/// Spawns the TUN read loop.
///
/// TUN Rx is a pure packet producer. Reads batches from the TUN device
/// and forwards them to the router actor. No routing logic.
///
/// # Arguments
///
/// * `tun` - TUN device reader.
/// * `router_tx` - Bounded sender to the router actor's inbound queue.
/// * `events_tx` - Unbounded channel for emitting receive metrics.
/// * `interval` - Metrics emission interval.
#[allow(dead_code)]
pub(crate) fn spawn_tun_rx<T: TunRx>(
    mut tun: T,
    router_tx: mpsc::Sender<RouterMsg>,
    events_tx: mpsc::UnboundedSender<Event>,
    interval: Duration,
) -> JoinHandle<ActorExitResult> {
    let tun_name = tun.name().to_string();
    let batch_size = tun.batch_size();
    let scratch_buf_size = tun.scratch_buf_size();

    tokio::spawn(async move {
        let mut counters = TransportCounters::new(TransportKind::Tun, Direction::Rx);
        let mut ticker = time::interval(interval);
        let mtu = tun.mtu();

        let mut scratch = vec![0u8; scratch_buf_size];
        let mut bufs: Vec<TunBuf> = (0..batch_size).map(|_| TunBuf::alloc_uninit(mtu)).collect();
        let mut sizes = vec![0usize; batch_size];

        loop {
            tokio::select! {
                result = tun.recv_batch(&mut scratch, &mut bufs, &mut sizes) => {
                    match result {
                        Ok(count) => {
                            let count = count.min(batch_size);
                            let mut batch = Vec::with_capacity(count);
                            for i in 0..count {
                                if sizes[i] > 0 {
                                    batch.push(
                                        std::mem::replace(&mut bufs[i], TunBuf::alloc_uninit(mtu))
                                            .into_pooled(sizes[i]),
                                    );
                                }
                            }
                            if batch.is_empty() {
                                continue;
                            }
                            let total_bytes: u64 = batch.iter().map(|p| p.len() as u64).sum();
                            let pkt_count = batch.len() as u64;
                            let msg = RouterMsg { source: BatchSource::Tun, packets: batch };
                            if send_with_backpressure(&router_tx, msg, |event| match event {
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
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(err) => {
                            return Err(ActorError::TunRxRecv { name: tun_name, source: err });
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
    })
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
) -> (mpsc::Sender<Vec<PooledBuf>>, JoinHandle<ActorExitResult>) {
    // Actor creates and owns its data-plane channel receiver
    let (packet_tx, mut packet_rx) = mpsc::channel::<Vec<PooledBuf>>(packet_queue_depth);
    let tun_name = tun.name().to_string();

    let handle = tokio::spawn(async move {
        let mtu = tun.mtu();
        let mut counters = TransportCounters::new(TransportKind::Tun, Direction::Tx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                maybe_batch = packet_rx.recv() => {
                    let Some(packets) = maybe_batch else {
                        return Ok(()); // Channel closed, exit gracefully
                    };

                    let mut tun_bufs: Vec<TunBuf> = Vec::with_capacity(packets.len());
                    let mut ok_count: u64 = 0;
                    let mut ok_bytes: u64 = 0;
                    for packet in packets {
                        if packet.len() > mtu {
                            counters.record_drop(DropReason::Oversize, 1, packet.len() as u64);
                            continue;
                        }
                        ok_count += 1;
                        ok_bytes += packet.len() as u64;
                        tun_bufs.push(TunBuf::from(packet));
                    }

                    if tun_bufs.is_empty() {
                        continue;
                    }

                    match tun.send_batch(&mut tun_bufs).await {
                        Ok(_) => {
                            counters.record_success(ok_count, ok_bytes);
                        }
                        Err(err) => {
                            counters.record_drop(DropReason::SendError, ok_count, ok_bytes);
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
    use super::{TunBuf, TunRx, TunTx};
    use crate::helpers::retry_on_transient;
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
        memory_tun_with_errors(name, mtu, vec![])
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

        async fn recv_batch(
            &mut self,
            _scratch: &mut [u8],
            bufs: &mut [TunBuf],
            sizes: &mut [usize],
        ) -> io::Result<usize> {
            match self.packet_rx.recv().await {
                Some(packet) => {
                    let dst = bufs[0].as_mut();
                    let len = packet.len().min(dst.len());
                    dst[..len].copy_from_slice(&packet[..len]);
                    sizes[0] = len;
                    Ok(1)
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

        async fn send_batch(&mut self, bufs: &mut [TunBuf]) -> io::Result<usize> {
            for buf in bufs.iter() {
                retry_on_transient!(
                    {
                        if let Some(kind) = self.send_errors.pop_front() {
                            Err(io::Error::new(kind, "injected send error"))
                        } else {
                            self.packet_tx
                                .send(buf.as_ref().to_vec())
                                .await
                                .map_err(|_| {
                                    io::Error::new(io::ErrorKind::BrokenPipe, "packet_tx closed")
                                })
                        }
                    },
                    |_| {}
                )?;
            }
            Ok(bufs.len())
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
    async fn tun_rx_forwards_batch_to_router() {
        let (rx_tun, _tx_tun, inject_tx, _output_rx) = memory_tun("mem0", 64);
        let (router_tx, mut router_rx) = mpsc::channel::<RouterMsg>(4);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();

        let ipv4_packet = make_ipv4_packet(Ipv4Addr::new(192, 0, 2, 1));

        let tun_rx_task = spawn_tun_rx(rx_tun, router_tx, events_tx, Duration::from_millis(10));

        inject_tx.send(ipv4_packet.clone()).await.unwrap();
        let msg = router_rx
            .recv()
            .await
            .expect("router should receive message");
        assert_eq!(msg.source, BatchSource::Tun);
        assert_eq!(msg.packets.len(), 1);
        assert_eq!(&msg.packets[0][..], &ipv4_packet[..]);

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
        assert_eq!(metrics.stats.succeeded.batches, 1);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.succeeded.bytes, 20);
    }

    #[tokio::test]
    async fn tun_tx_drops_oversize_and_reports_metrics() {
        let (_rx_tun, tx_tun, _inject_tx, mut output_rx) = memory_tun("mem1", 4);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let (packet_tx, tun_tx_task) =
            spawn_tun_tx(tx_tun, events_tx, Duration::from_millis(10), 256);

        packet_tx
            .send(vec![BufFactory::buf_from_slice(&[0, 1, 2, 3, 4, 5])])
            .await
            .unwrap();
        packet_tx
            .send(vec![BufFactory::buf_from_slice(&[9, 9, 9])])
            .await
            .unwrap();

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
        assert_eq!(metrics.labels.remote_addr, None);
        assert_eq!(metrics.stats.succeeded.batches, 1);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.succeeded.bytes, 3);
        assert_eq!(metrics.stats.dropped.batches, 1);
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

        packet_tx
            .send(vec![BufFactory::buf_from_slice(&[1, 2, 3])])
            .await
            .unwrap();

        let received = output_rx.recv().await.expect("should receive after retry");
        assert_eq!(received, vec![1, 2, 3]); // output_rx is Vec<u8> from MemoryTunTx

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
        assert_eq!(metrics.labels.remote_addr, None);
        assert_eq!(metrics.stats.succeeded.batches, 1);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.dropped.packets, 0);
    }

    // ========================================================================
    // Routing table tests (migrated from routing.rs)
    // ========================================================================

    use crate::config::{PeerBare, PeerTun, UdpEndpoint};

    fn bare_peer(id: &str, allowed: &[&str]) -> Peer {
        Peer {
            id: id.to_string(),
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
    fn dummy_peer_txs(peer_ids: &[&str]) -> HashMap<String, mpsc::Sender<Vec<PooledBuf>>> {
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
            bare_peer("peer-a", &["10.0.0.0/16"]),
            bare_peer("peer-b", &["10.0.0.0/24"]),
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
    fn errors_on_conflicting_prefix_ownership() {
        let peers = vec![
            bare_peer("peer-a", &["10.0.0.0/24"]),
            bare_peer("peer-b", &["10.0.0.0/24"]),
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
        let peers = vec![bare_peer("peer-a", &["10.0.0.0/24", "10.0.0.0/24"])];
        let peer_txs = dummy_peer_txs(&["peer-a"]);
        let table = RoutingTable::from_peers(&peers, &peer_txs).expect("table should build");
        assert_eq!(table.len(), (1, 0));
        let result = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .expect("lookup should succeed");
        assert_eq!(result.peer_id, "peer-a");
    }

    // ========== Actor Lifecycle Tests ==========

    #[tokio::test]
    async fn spawn_tun_tx_returns_working_packet_tx() {
        let (_rx_tun, tx_tun, _inject_tx, _output_rx) = memory_tun("mem-tx-lifecycle", 64);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let (packet_tx, handle) = spawn_tun_tx(tx_tun, events_tx, Duration::from_secs(60), 256);

        // Verify packet_tx is functional by sending a batch
        assert!(packet_tx
            .send(vec![BufFactory::buf_from_slice(&[1, 2, 3])])
            .await
            .is_ok());

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
    }

    #[tokio::test]
    async fn tun_rx_batch_fallback_dispatches_correctly() {
        // Verifies that the batch-aware spawn_tun_rx loop works
        // correctly when recv_batch falls back to single-packet recv.
        let (rx_tun, _tx_tun, inject_tx, _output_rx) = memory_tun("mem-batch-fb", 64);
        let (router_tx, mut router_rx) = mpsc::channel::<RouterMsg>(4);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let ipv4_packet = make_ipv4_packet(Ipv4Addr::new(192, 0, 2, 1));

        let tun_rx_task = spawn_tun_rx(rx_tun, router_tx, events_tx, Duration::from_millis(10));

        inject_tx.send(ipv4_packet.clone()).await.unwrap();
        let msg = router_rx
            .recv()
            .await
            .expect("packet should be forwarded to router");
        assert_eq!(msg.source, BatchSource::Tun);
        assert_eq!(msg.packets.len(), 1);
        assert_eq!(&msg.packets[0][..], &ipv4_packet[..]);

        tun_rx_task.abort();
    }

    #[tokio::test]
    async fn memory_tun_rx_recv_batch_returns_packet() {
        let (mut rx, _tx, inject, _output) = memory_tun("mem-rx-batch", 64);
        let mut scratch = vec![0u8; rx.scratch_buf_size()];
        let mut bufs = vec![TunBuf::alloc_uninit(rx.mtu())];
        let mut sizes = vec![0usize; 1];
        inject.send(vec![10, 20, 30]).await.unwrap();
        let count = rx
            .recv_batch(&mut scratch, &mut bufs, &mut sizes)
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(sizes[0], 3);
        assert_eq!(&bufs[0].as_ref()[..3], &[10, 20, 30]);
    }

    #[tokio::test]
    async fn memory_tun_tx_send_batch_delivers_packet() {
        let (_rx, mut tx, _inject, mut output) = memory_tun("mem-tx-batch", 64);
        let mut batch = [TunBuf::from(BufFactory::buf_from_slice(&[4, 5, 6]))];
        tx.send_batch(&mut batch).await.unwrap();
        let received = output.recv().await.unwrap();
        assert_eq!(received, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn memory_tun_rx_recv_batch_channel_closed() {
        let (mut rx, _tx, inject, _output) = memory_tun("mem-rx-close", 64);
        drop(inject);
        let mut scratch = vec![0u8; rx.scratch_buf_size()];
        let mut bufs = vec![TunBuf::alloc_uninit(rx.mtu())];
        let mut sizes = vec![0usize; 1];
        let result = rx.recv_batch(&mut scratch, &mut bufs, &mut sizes).await;
        assert!(result.is_err());
    }

    // ========== TunBuf Tests ==========

    #[test]
    fn tun_buf_into_pooled_truncates() {
        let mut tun_buf = TunBuf::alloc_uninit(1400);
        tun_buf.as_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);
        let pooled = tun_buf.into_pooled(4);
        assert_eq!(&pooled[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn tun_buf_new_has_headroom() {
        let tun_buf = TunBuf::alloc_uninit(1400);
        let mut buf = tun_buf.into_pooled(0);
        assert!(buf.add_prefix(&[0u8; HEADROOM]));
    }

    #[test]
    fn alloc_uninit_packet_buf_small_uses_datagram_pool() {
        let buf = alloc_uninit_packet_buf(1400);
        // Datagram pool: visible = MAX_DGRAM_SIZE - HEADROOM = 1490
        assert_eq!(buf.len(), BufFactory::MAX_DGRAM_SIZE - HEADROOM);
        let mut buf = buf;
        buf.truncate(0);
        assert!(buf.add_prefix(&[0u8; HEADROOM]));
    }

    #[test]
    fn alloc_uninit_packet_buf_large_uses_generic_pool() {
        let buf = alloc_uninit_packet_buf(BufFactory::MAX_DGRAM_SIZE);
        assert_eq!(buf.len(), BufFactory::MAX_BUF_SIZE - HEADROOM);
        let mut buf = buf;
        buf.truncate(0);
        assert!(buf.add_prefix(&[0u8; HEADROOM]));
    }

    #[test]
    fn alloc_packet_buf_small_has_correct_data_and_headroom() {
        let data = [1u8, 2, 3, 4, 5];
        let buf = alloc_packet_buf(&data);
        assert_eq!(&buf[..], &data);
        let mut buf = buf;
        assert!(buf.add_prefix(&[0u8; HEADROOM]));
    }

    #[test]
    fn alloc_uninit_packet_buf_boundary() {
        // Exactly at the threshold: length + HEADROOM == MAX_DGRAM_SIZE
        let boundary_len = BufFactory::MAX_DGRAM_SIZE - HEADROOM;
        let buf = alloc_uninit_packet_buf(boundary_len);
        assert_eq!(buf.len(), boundary_len);

        // One byte over: falls back to generic pool
        let buf = alloc_uninit_packet_buf(boundary_len + 1);
        assert_eq!(buf.len(), BufFactory::MAX_BUF_SIZE - HEADROOM);
    }

    #[test]
    fn tun_buf_from_wraps_unchanged() {
        let buf = BufFactory::buf_from_slice(&[10, 20]);
        let tun_buf = TunBuf::from(buf);
        assert_eq!(tun_buf.as_ref(), &[10, 20]);
    }

    #[test]
    fn tun_buf_as_mut_modifies_payload() {
        let buf = BufFactory::buf_from_slice(&[10, 20, 30]);
        let mut tun_buf = TunBuf::from(buf);
        tun_buf.as_mut()[0] = 99;
        assert_eq!(tun_buf.as_ref()[0], 99);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_buf_expand_upgrades_buffer_on_threshold_crossing() {
        let small_data = vec![0xABu8; BufFactory::MAX_DGRAM_SIZE];
        let buf = BufFactory::buf_from_slice(&small_data);
        let mut tun_buf = TunBuf::from(buf);
        assert_eq!(tun_buf.as_ref().len(), BufFactory::MAX_DGRAM_SIZE);

        let extra = [0xCDu8; 100];
        tun_rs::ExpandBuffer::buf_extend_from_slice(&mut tun_buf, &extra);

        let result = tun_buf.as_ref();
        assert_eq!(result.len(), BufFactory::MAX_DGRAM_SIZE + 100);
        assert_eq!(&result[..BufFactory::MAX_DGRAM_SIZE], &small_data[..]);
        assert_eq!(&result[BufFactory::MAX_DGRAM_SIZE..], &extra[..]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_buf_expand_no_upgrade_when_already_large() {
        let large_data = vec![0xABu8; BufFactory::MAX_DGRAM_SIZE + 1];
        let buf = BufFactory::buf_from_slice(&large_data);
        let mut tun_buf = TunBuf::from(buf);

        let extra = [0xCDu8; 50];
        tun_rs::ExpandBuffer::buf_extend_from_slice(&mut tun_buf, &extra);

        let result = tun_buf.as_ref();
        assert_eq!(result.len(), BufFactory::MAX_DGRAM_SIZE + 1 + 50);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_buf_expand_no_upgrade_when_below_threshold() {
        let small_data = vec![0xABu8; 100];
        let buf = BufFactory::buf_from_slice(&small_data);
        let mut tun_buf = TunBuf::from(buf);

        let extra = [0xCDu8; 50];
        tun_rs::ExpandBuffer::buf_extend_from_slice(&mut tun_buf, &extra);

        let result = tun_buf.as_ref();
        assert_eq!(result.len(), 150);
        assert_eq!(&result[..100], &small_data[..]);
        assert_eq!(&result[100..], &extra[..]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_buf_resize_triggers_upgrade() {
        let small_data = vec![0xABu8; 500];
        let buf = BufFactory::buf_from_slice(&small_data);
        let mut tun_buf = TunBuf::from(buf);

        tun_rs::ExpandBuffer::buf_resize(&mut tun_buf, BufFactory::MAX_DGRAM_SIZE + 100, 0xFF);

        let result = tun_buf.as_ref();
        assert_eq!(result.len(), BufFactory::MAX_DGRAM_SIZE + 100);
        assert_eq!(&result[..500], &small_data[..]);
        assert!(result[500..].iter().all(|&b| b == 0xFF));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_buf_prepend_hdr_zero_copy_with_headroom() {
        let buf = alloc_packet_buf(&[1, 2, 3, 4]);
        let mut tun_buf = TunBuf::from(buf);
        tun_buf.prepend_hdr();
        let data = tun_buf.as_ref();
        assert_eq!(&data[..VIRTIO_NET_HDR_LEN], &[0u8; VIRTIO_NET_HDR_LEN]);
        assert_eq!(&data[VIRTIO_NET_HDR_LEN..], &[1, 2, 3, 4]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_buf_prepend_hdr_fallback_without_headroom() {
        let buf = BufFactory::buf_from_slice(&[5, 6, 7]);
        let mut tun_buf = TunBuf::from(buf);
        tun_buf.prepend_hdr();
        let data = tun_buf.as_ref();
        assert_eq!(&data[..VIRTIO_NET_HDR_LEN], &[0u8; VIRTIO_NET_HDR_LEN]);
        assert_eq!(&data[VIRTIO_NET_HDR_LEN..], &[5, 6, 7]);
    }
}
