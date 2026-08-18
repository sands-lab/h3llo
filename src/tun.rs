//! TUN management: device creation, read/write loops with backpressure, and metrics reporting.

use crate::actor::{ActorContext, ActorRef, ActorRuntime, SupervisionPolicy};
use crate::config::{IoTuning, LocalTun};
#[cfg(test)]
use crate::events::Event;
use crate::helpers::retry_on_transient;
use crate::metrics::{Counters, Direction, DropReason, Source};
use anyhow::Context;
#[cfg(target_os = "linux")]
use bytes::BufMut;
use datagram_socket::DgramBuffer;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::io;
use std::net::Ipv6Addr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{info, warn};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};
#[cfg(target_os = "linux")]
use tun_rs::{GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

/// Headroom reserved in every datapath `DgramBuffer`.
///
use crate::helpers::{
    alloc_packet_buf, alloc_uninit_packet_buf, batch_stats, make_interval, HEADROOM,
};

// Compile-time guard: TunBuf::prepend_hdr relies on HEADROOM being sufficient
// to prepend a zeroed virtio_net_hdr without allocation.
#[cfg(target_os = "linux")]
const _: () = assert!(
    HEADROOM >= VIRTIO_NET_HDR_LEN,
    "HEADROOM must be >= VIRTIO_NET_HDR_LEN for zero-copy TUN TX"
);

#[cfg(target_os = "linux")]
const MAX_GRO_BUFFER_SIZE: usize = VIRTIO_NET_HDR_LEN + u16::MAX as usize;

/// Zero-copy wrapper around [`DgramBuffer`] for TUN I/O (RX and TX).
///
/// RX: [`TunBuf::alloc_uninit`] allocates with headroom; [`into_packet`](Self::into_packet) truncates.
/// TX: `From<DgramBuffer>` constructs; [`TunTx::send_batch`] prepends `virtio_net_hdr`.
pub struct TunBuf(DgramBuffer);

impl TunBuf {
    /// Allocates a packet buffer sized for `mtu` with [`HEADROOM`] bytes reserved.
    ///
    /// The caller must call [`into_packet`](Self::into_packet) after filling
    /// to set the actual length.
    ///
    /// # Arguments
    ///
    /// * `mtu` - Expected maximum payload size (excluding headroom).
    #[must_use]
    pub fn alloc_uninit(mtu: usize) -> Self {
        Self(alloc_uninit_packet_buf(mtu))
    }

    /// Truncates to `len` bytes and returns the underlying packet buffer.
    #[must_use]
    pub fn into_packet(mut self, len: usize) -> DgramBuffer {
        debug_assert!(
            len <= self.0.len(),
            "into_packet: len {len} exceeds buffer visible length {}",
            self.0.len()
        );
        self.0.truncate(len);
        self.0
    }

    /// Reserves the maximum GRO buffer size on the first expansion.
    #[cfg(target_os = "linux")]
    fn reserve_for_gro(&mut self, additional: usize) {
        if self.0.spare_capacity() >= additional {
            return;
        }

        let (mut data, headroom) = std::mem::take(&mut self.0).into_parts();
        let required = data.len() + additional;
        let target = required.max(headroom + MAX_GRO_BUFFER_SIZE);
        data.reserve_exact(target - data.len());
        self.0 = DgramBuffer::from_vec_with_headroom(data, headroom);
    }

    /// Prepends a zeroed `virtio_net_hdr` using headroom when available,
    /// falling back to alloc + copy otherwise. Called by `send_batch`
    /// implementations, not by the TUN TX actor.
    #[cfg(target_os = "linux")]
    fn prepend_hdr(&mut self) {
        let zeroed = [0u8; VIRTIO_NET_HDR_LEN];
        if self.0.try_add_prefix(&zeroed).is_err() {
            let mut buf = alloc_packet_buf(self.0.as_ref());
            let result = buf.try_add_prefix(&zeroed);
            debug_assert!(result.is_ok(), "alloc_packet_buf guarantees HEADROOM bytes");
            self.0 = buf;
        }
    }
}

impl From<DgramBuffer> for TunBuf {
    fn from(packet: DgramBuffer) -> Self {
        Self(packet)
    }
}

impl AsRef<[u8]> for TunBuf {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for TunBuf {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

#[cfg(target_os = "linux")]
impl tun_rs::ExpandBuffer for TunBuf {
    fn buf_capacity(&self) -> usize {
        // DgramBuffer is backed by a growable Vec<u8>, so GRO can always
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
            self.reserve_for_gro(new_len - current);
            self.0.put_bytes(val, new_len - current);
        }
    }

    fn buf_extend_from_slice(&mut self, src: &[u8]) {
        self.reserve_for_gro(src.len());
        self.0.put_slice(src);
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
/// * `tx_queue_len` - Transmit queue length in packets. `None` leaves the OS
///   default. On non-Linux platforms, `Some(_)` logs a warning and is ignored.
/// * `enable_offload` - Enable GSO/GRO offload. On non-Linux platforms,
///   `true` logs a warning and is ignored.
///
/// # Errors
///
/// Returns `TunError::DeviceBuild` when device creation or address assignment fails.
pub fn make_tun(
    local_tun: &LocalTun,
    tx_queue_len: Option<u32>,
    enable_offload: bool,
) -> Result<(TunReader, TunWriter), TunError> {
    let (v4_addrs, v6_addrs) = split_addrs_by_version(&local_tun.addrs);

    let mut builder = DeviceBuilder::new()
        .name(local_tun.ifname.as_str())
        .mtu(local_tun.mtu)
        .enable(true)
        .layer(Layer::L3);

    // Enable GSO/GRO offload and TX queue len on Linux.
    #[cfg(target_os = "linux")]
    {
        builder = builder.offload(enable_offload);
        if let Some(len) = tx_queue_len {
            builder = builder.tx_queue_len(len);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        if enable_offload {
            warn!("TUN: offload is not supported on this platform, ignoring");
        }
        if tx_queue_len.is_some() {
            warn!("TUN: tx_queue_len is not supported on this platform, ignoring");
        }
        let _ = (tx_queue_len, enable_offload);
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

    let name = device.name().unwrap_or_else(|e| {
        warn!(error = %e, configured = %local_tun.ifname, "TUN: could not read device name, using config value");
        local_tun.ifname.clone()
    });
    let mtu = device.mtu().map_or_else(
        |e| {
            warn!(error = %e, configured = local_tun.mtu, "TUN: could not read device MTU, using config value");
            local_tun.mtu as usize
        },
        |m| m as usize,
    );

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
            MAX_GRO_BUFFER_SIZE
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
        if self.offload {
            return self.device.recv_multiple(scratch, bufs, sizes, 0).await;
        }
        let _ = scratch;
        let len = self.device.recv(bufs[0].as_mut()).await?;
        sizes[0] = len;
        Ok(1)
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
        if self.offload {
            for buf in bufs.iter_mut() {
                buf.prepend_hdr();
            }
            self.device
                .send_multiple(&mut self.gro_table, bufs, VIRTIO_NET_HDR_LEN)
                .await?;
            return Ok(bufs.len());
        }
        for buf in bufs.iter() {
            retry_on_transient!(self.device.send(buf.as_ref()).await, |_| {})?;
        }
        Ok(bufs.len())
    }
}

/// Describes TUN errors for creation and operation.
#[derive(Debug, Error)]
pub enum TunError {
    /// Device creation or address assignment failed.
    #[error("failed to build TUN device: {0}")]
    DeviceBuild(String),
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
/// * `output_tx` - Bounded sender to the router actor's outbound channel.
/// * `io_tuning` - I/O tuning parameters (uses `metrics_push_interval`).
pub(crate) fn spawn_tun_rx<T: TunRx>(
    mut tun: T,
    output_tx: mpsc::Sender<Vec<DgramBuffer>>,
    io_tuning: &IoTuning,
    ctx: &ActorContext,
) -> ActorRef {
    let tun_name = tun.name().to_string();
    let batch_size = tun.batch_size();
    let scratch_buf_size = tun.scratch_buf_size();
    let metrics_push_interval = io_tuning.metrics_push_interval;

    ctx.spawn(
        format!("tun-rx[{tun_name}]"),
        ActorRuntime::Tun,
        SupervisionPolicy::Critical,
        |mut ctx| async move {
        let mut counters = Counters::new(Source::Tun, Direction::Rx);
        let mut ticker = make_interval(metrics_push_interval);
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
                                            .into_packet(sizes[i]),
                                    );
                                }
                            }
                            if batch.is_empty() {
                                continue;
                            }
                            let (pkt_count, total_bytes) = batch_stats(&batch);
                            if !counters.send_and_record(&output_tx, batch, pkt_count, total_bytes).await {
                                info!(tun = %tun_name, "TUN RX: router channel closed, shutting down");
                                return Ok(());
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {},
                        Err(err) => {
                            return Err(err).context("receive packet batch from TUN interface");
                        }
                    }
                }
                () = ctx.wait_for_stop() => return Ok(()),
                _ = ticker.tick() => {
                    if !counters.emit(&ctx, None, None) {
                        return Ok(());
                    }
                }
            }
        }
        },
    )
}

/// Spawns the TUN write loop, dropping oversize packets with counting and emitting TX metrics.
///
/// Creates a bounded packet channel internally (actor owns the receiver) and
/// returns its sender. Lifecycle monitoring remains internal to `ActorBus`.
pub(crate) fn spawn_tun_tx<T: TunTx>(
    mut tun: T,
    io_tuning: &IoTuning,
    ctx: &ActorContext,
) -> mpsc::Sender<Vec<DgramBuffer>> {
    // Actor creates and owns its data-plane channel receiver
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<DgramBuffer>>(io_tuning.packet_queue_depth);
    let tun_name = tun.name().to_string();
    let metrics_push_interval = io_tuning.metrics_push_interval;

    let _actor_ref = ctx.spawn(
        format!("tun-tx[{tun_name}]"),
        ActorRuntime::Tun,
        SupervisionPolicy::Critical,
        |mut ctx| async move {
            let mtu = tun.mtu();
            let mut counters = Counters::new(Source::Tun, Direction::Tx);
            let mut ticker = make_interval(metrics_push_interval);

            loop {
                tokio::select! {
                    maybe_batch = input_rx.recv() => {
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
                                return Err(err).context("send packet batch to TUN interface");
                            }
                        }
                    }
                    () = ctx.wait_for_stop() => return Ok(()),
                    _ = ticker.tick() => {
                        if !counters.emit(&ctx, None, None) {
                            return Ok(());
                        }
                    }
                }
            }
        },
    );

    input_tx
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
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let mut orchestrator = actor_bus_owner.mailbox("test-orchestrator");
        let (rx_tun, _tx_tun, inject_tx, _output_rx) = memory_tun("mem0", 64);
        let (output_tx, mut output_rx) = mpsc::channel::<Vec<DgramBuffer>>(4);

        let ipv4_packet = make_ipv4_packet(Ipv4Addr::new(192, 0, 2, 1));

        let _tun_rx = spawn_tun_rx(
            rx_tun,
            output_tx,
            &IoTuning {
                metrics_push_interval: Duration::from_millis(10),
                ..Default::default()
            },
            &orchestrator,
        );

        inject_tx.send(ipv4_packet.clone()).await.unwrap();
        let batch = output_rx
            .recv()
            .await
            .expect("router should receive message");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].as_ref(), &ipv4_packet[..]);

        let mut snapshot = None;
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = orchestrator.recv().await {
                if let Event::Metrics(m) = event {
                    if m.labels.direction == Direction::Rx && m.stats.succeeded.packets >= 1 {
                        snapshot = Some(m);
                        break;
                    }
                }
            }
        })
        .await;

        let metrics = snapshot.expect("rx metrics should arrive");
        assert_eq!(metrics.labels.source, Source::Tun);
        assert_eq!(metrics.labels.direction, Direction::Rx);
        assert_eq!(metrics.stats.succeeded.batches, 1);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.succeeded.bytes, 20);
    }

    #[tokio::test]
    async fn tun_tx_drops_oversize_and_reports_metrics() {
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let mut orchestrator = actor_bus_owner.mailbox("test-orchestrator");
        let (_rx_tun, tx_tun, _inject_tx, mut output_rx) = memory_tun("mem1", 4);
        let input_tx = spawn_tun_tx(
            tx_tun,
            &IoTuning {
                metrics_push_interval: Duration::from_millis(10),
                packet_queue_depth: 256,
                ..Default::default()
            },
            &orchestrator,
        );

        input_tx
            .send(vec![DgramBuffer::from_slice(&[0, 1, 2, 3, 4, 5])])
            .await
            .unwrap();
        input_tx
            .send(vec![DgramBuffer::from_slice(&[9, 9, 9])])
            .await
            .unwrap();

        // First packet should be dropped; second should be emitted.
        let received = output_rx.recv().await.expect("should receive one packet");
        assert_eq!(received, vec![9, 9, 9]);

        let mut snapshot = None;
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = orchestrator.recv().await {
                if let Event::Metrics(m) = event {
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

        let metrics = snapshot.expect("tx metrics should arrive");
        assert_eq!(metrics.labels.source, Source::Tun);
        assert_eq!(metrics.labels.direction, Direction::Tx);
        assert_eq!(metrics.labels.peer_id, None);
        assert_eq!(metrics.labels.remote_addr, None);
        assert_eq!(metrics.stats.succeeded.batches, 1);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.succeeded.bytes, 3);
        assert_eq!(metrics.stats.dropped.batches, 1);
        assert_eq!(metrics.stats.dropped.packets, 1);
        assert_eq!(metrics.stats.dropped.bytes, 6);
        let c = &metrics.stats.drop_reasons[DropReason::Oversize];
        assert_eq!((c.packets, c.bytes), (1, 6));
    }

    #[tokio::test]
    async fn tun_tx_retries_interrupted_send() {
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let mut orchestrator = actor_bus_owner.mailbox("test-orchestrator");
        let (_rx_tun, tx_tun, _inject_tx, mut output_rx) =
            memory_tun_with_errors("mem-interrupt", 16, vec![std::io::ErrorKind::Interrupted]);
        let input_tx = spawn_tun_tx(
            tx_tun,
            &IoTuning {
                metrics_push_interval: Duration::from_millis(5),
                packet_queue_depth: 256,
                ..Default::default()
            },
            &orchestrator,
        );

        input_tx
            .send(vec![DgramBuffer::from_slice(&[1, 2, 3])])
            .await
            .unwrap();

        let received = output_rx.recv().await.expect("should receive after retry");
        assert_eq!(received, vec![1, 2, 3]); // output_rx is Vec<u8> from MemoryTunTx

        let metrics = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = orchestrator.recv().await {
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

        assert_eq!(metrics.labels.source, Source::Tun);
        assert_eq!(metrics.labels.direction, Direction::Tx);
        assert_eq!(metrics.labels.peer_id, None);
        assert_eq!(metrics.labels.remote_addr, None);
        assert_eq!(metrics.stats.succeeded.batches, 1);
        assert_eq!(metrics.stats.succeeded.packets, 1);
        assert_eq!(metrics.stats.dropped.packets, 0);
    }

    // ========== Actor Lifecycle Tests ==========

    #[tokio::test]
    async fn spawn_tun_tx_returns_working_input_tx() {
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let orchestrator = actor_bus_owner.mailbox("test-orchestrator");
        let (_rx_tun, tx_tun, _inject_tx, _output_rx) = memory_tun("mem-tx-lifecycle", 64);

        let input_tx = spawn_tun_tx(
            tx_tun,
            &IoTuning {
                metrics_push_interval: Duration::from_secs(60),
                packet_queue_depth: 256,
                ..Default::default()
            },
            &orchestrator,
        );

        // Verify input_tx is functional by sending a batch
        assert!(input_tx
            .send(vec![DgramBuffer::from_slice(&[1, 2, 3])])
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn tun_tx_actor_exits_when_sender_dropped() {
        let mut actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let mut orchestrator = actor_bus_owner.mailbox("test-orchestrator");
        let (_rx_tun, tx_tun, _inject_tx, _output_rx) = memory_tun("mem-tx-shutdown", 64);

        let input_tx = spawn_tun_tx(
            tx_tun,
            &IoTuning {
                metrics_push_interval: Duration::from_secs(60),
                packet_queue_depth: 256,
                ..Default::default()
            },
            &orchestrator,
        );

        // Drop sender to signal shutdown
        drop(input_tx);

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            crate::actor::next_actor_exit(&mut actor_bus_owner, &mut orchestrator),
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
        let actor_bus_owner = crate::actor::ActorBus::on_current_runtime();
        let orchestrator = actor_bus_owner.mailbox("test-orchestrator");
        // Verifies that the batch-aware spawn_tun_rx loop works
        // correctly when recv_batch falls back to single-packet recv.
        let (rx_tun, _tx_tun, inject_tx, _output_rx) = memory_tun("mem-batch-fb", 64);
        let (output_tx, mut output_rx) = mpsc::channel::<Vec<DgramBuffer>>(4);

        let ipv4_packet = make_ipv4_packet(Ipv4Addr::new(192, 0, 2, 1));

        let _tun_rx = spawn_tun_rx(
            rx_tun,
            output_tx,
            &IoTuning {
                metrics_push_interval: Duration::from_millis(10),
                ..Default::default()
            },
            &orchestrator,
        );

        inject_tx.send(ipv4_packet.clone()).await.unwrap();
        let batch = output_rx
            .recv()
            .await
            .expect("packet should be forwarded to router");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].as_ref(), &ipv4_packet[..]);
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
        let mut batch = [TunBuf::from(DgramBuffer::from_slice(&[4, 5, 6]))];
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
    fn tun_buf_into_packet_truncates() {
        let mut tun_buf = TunBuf::alloc_uninit(1400);
        tun_buf.as_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);
        let packet = tun_buf.into_packet(4);
        assert_eq!(packet.as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn tun_buf_new_has_headroom() {
        let tun_buf = TunBuf::alloc_uninit(1400);
        let mut buf = tun_buf.into_packet(0);
        assert!(buf.try_add_prefix(&[0u8; HEADROOM]).is_ok());
    }

    #[test]
    fn alloc_uninit_packet_buf_has_requested_length_and_headroom() {
        let length = 1400;
        let buf = alloc_uninit_packet_buf(length);
        assert_eq!(buf.len(), length);
        let mut buf = buf;
        buf.truncate(0);
        assert!(buf.try_add_prefix(&[0u8; HEADROOM]).is_ok());
    }

    #[test]
    fn alloc_packet_buf_small_has_correct_data_and_headroom() {
        let data = [1u8, 2, 3, 4, 5];
        let buf = alloc_packet_buf(&data);
        assert_eq!(buf.as_ref(), &data);
        let mut buf = buf;
        assert!(buf.try_add_prefix(&[0u8; HEADROOM]).is_ok());
    }

    #[test]
    fn tun_buf_from_wraps_unchanged() {
        let buf = DgramBuffer::from_slice(&[10, 20]);
        let tun_buf = TunBuf::from(buf);
        assert_eq!(tun_buf.as_ref(), &[10, 20]);
    }

    #[test]
    fn tun_buf_as_mut_modifies_payload() {
        let buf = DgramBuffer::from_slice(&[10, 20, 30]);
        let mut tun_buf = TunBuf::from(buf);
        tun_buf.as_mut()[0] = 99;
        assert_eq!(tun_buf.as_ref()[0], 99);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_buf_expand_preserves_data() {
        let data = vec![0xABu8; 1500];
        let buf = DgramBuffer::from_slice(&data);
        let mut tun_buf = TunBuf::from(buf);
        assert!(tun_buf.0.len() + tun_buf.0.spare_capacity() < MAX_GRO_BUFFER_SIZE);

        let extra = [0xCDu8; 100];
        tun_rs::ExpandBuffer::buf_extend_from_slice(&mut tun_buf, &extra);

        let result = tun_buf.as_ref();
        assert_eq!(&result[..1500], &data);
        assert_eq!(&result[1500..], &extra);
        assert!(tun_buf.0.len() + tun_buf.0.spare_capacity() >= MAX_GRO_BUFFER_SIZE);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_buf_resize_fills_new_bytes() {
        let small_data = vec![0xABu8; 500];
        let buf = DgramBuffer::from_slice(&small_data);
        let mut tun_buf = TunBuf::from(buf);

        tun_rs::ExpandBuffer::buf_resize(&mut tun_buf, 1600, 0xFF);

        let result = tun_buf.as_ref();
        assert_eq!(result.len(), 1600);
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
        let buf = DgramBuffer::from_slice(&[5, 6, 7]);
        let mut tun_buf = TunBuf::from(buf);
        tun_buf.prepend_hdr();
        let data = tun_buf.as_ref();
        assert_eq!(&data[..VIRTIO_NET_HDR_LEN], &[0u8; VIRTIO_NET_HDR_LEN]);
        assert_eq!(&data[VIRTIO_NET_HDR_LEN..], &[5, 6, 7]);
    }
}
