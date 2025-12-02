//! TUN management: device creation, read/write loops with backpressure, and metrics reporting.

use crate::config::LocalTun;
use crate::events::{Event, TunEvent, TunMetricsUpdate};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use log::warn;
use std::future::Future;
use std::io;
use std::net::Ipv6Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

type IoFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Defines the async I/O surface required from a TUN device, enabling test doubles.
pub trait TunIo: Send + Sync + 'static {
    /// Returns the configured MTU for sizing buffers.
    fn mtu(&self) -> usize;
    /// Returns the interface name.
    fn name(&self) -> &str;
    /// Receives a packet into `buf`, returning the number of bytes read.
    fn recv<'a>(&'a self, buf: &'a mut [u8]) -> IoFuture<'a, io::Result<usize>>;
    /// Sends a packet from `buf`, returning the number of bytes written.
    fn send<'a>(&'a self, buf: &'a [u8]) -> IoFuture<'a, io::Result<usize>>;
}

/// Wraps a tun-rs `AsyncDevice` and exposes the `TunIo` surface.
#[derive(Clone)]
pub struct TunIoAdapter {
    device: Arc<AsyncDevice>,
    mtu: usize,
    name: String,
}

impl TunIo for TunIoAdapter {
    fn mtu(&self) -> usize {
        self.mtu
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn recv<'a>(&'a self, buf: &'a mut [u8]) -> IoFuture<'a, io::Result<usize>> {
        let dev = self.device.clone();
        Box::pin(async move { dev.recv(buf).await })
    }

    fn send<'a>(&'a self, buf: &'a [u8]) -> IoFuture<'a, io::Result<usize>> {
        let dev = self.device.clone();
        Box::pin(async move { dev.send(buf).await })
    }
}

/// Represents a configured TUN device with helper constructors.
pub struct TunDevice {
    io: TunIoAdapter,
}

impl TunDevice {
    /// Creates a TUN device from `local_tun`, setting addresses and MTU via tun-rs.
    pub async fn from_config(local_tun: &LocalTun) -> Result<Self, TunError> {
        let (v4_addrs, v6_addrs) = parse_addrs(&local_tun.addr)?;

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

        Ok(Self {
            io: TunIoAdapter {
                device: Arc::new(device),
                mtu,
                name,
            },
        })
    }

    /// Returns the interface name.
    pub fn name(&self) -> &str {
        self.io.name()
    }

    /// Returns the MTU.
    pub fn mtu(&self) -> usize {
        self.io.mtu()
    }

    /// Returns an adapter usable by the read/write loops.
    pub fn io(&self) -> TunIoAdapter {
        self.io.clone()
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

// Parses raw address strings and groups them by IP version.
fn parse_addrs(raw_addrs: &[String]) -> Result<(Vec<Ipv4Net>, Vec<Ipv6Net>), TunError> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for addr in raw_addrs {
        match addr.parse::<IpNet>() {
            Ok(IpNet::V4(net)) => v4.push(net),
            Ok(IpNet::V6(net)) => v6.push(net),
            Err(e) => {
                return Err(TunError::InvalidAddress {
                    addr: addr.clone(),
                    error: e.to_string(),
                })
            }
        }
    }
    Ok((v4, v6))
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum MetricsInput {
    Rx { packets: u64, bytes: u64 },
    Tx { packets: u64, bytes: u64 },
    DroppedTx { packets: u64, bytes: u64 },
}

#[allow(dead_code)]
#[derive(Default)]
struct TunCounters {
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    dropped_tx_packets: u64,
    dropped_tx_bytes: u64,
}

impl TunCounters {
    fn apply(&mut self, input: MetricsInput) {
        match input {
            MetricsInput::Rx { packets, bytes } => {
                self.rx_packets = self.rx_packets.saturating_add(packets);
                self.rx_bytes = self.rx_bytes.saturating_add(bytes);
            }
            MetricsInput::Tx { packets, bytes } => {
                self.tx_packets = self.tx_packets.saturating_add(packets);
                self.tx_bytes = self.tx_bytes.saturating_add(bytes);
            }
            MetricsInput::DroppedTx { packets, bytes } => {
                self.dropped_tx_packets = self.dropped_tx_packets.saturating_add(packets);
                self.dropped_tx_bytes = self.dropped_tx_bytes.saturating_add(bytes);
            }
        }
    }

    fn snapshot(&self) -> TunMetricsUpdate {
        TunMetricsUpdate {
            rx_packets: self.rx_packets,
            tx_packets: self.tx_packets,
            rx_bytes: self.rx_bytes,
            tx_bytes: self.tx_bytes,
            dropped_tx_packets: self.dropped_tx_packets,
            dropped_tx_bytes: self.dropped_tx_bytes,
        }
    }
}

/// Spawns the TUN read loop, pushing packets into `outbound` with backpressure.
#[allow(dead_code)]
pub(crate) fn spawn_reader<T: TunIo>(
    tun: T,
    outbound: mpsc::Sender<Vec<u8>>,
    metrics_tx: mpsc::Sender<MetricsInput>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mtu = tun.mtu();
        loop {
            let mut buf = vec![0u8; mtu];
            match tun.recv(&mut buf).await {
                Ok(len) => {
                    if len == 0 {
                        continue;
                    }
                    buf.truncate(len);
                    if outbound.send(buf).await.is_err() {
                        break;
                    }
                    let _ = metrics_tx
                        .send(MetricsInput::Rx {
                            packets: 1,
                            bytes: len as u64,
                        })
                        .await;
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    })
}

/// Spawns the TUN write loop, dropping oversize packets with counting and a one-time warning.
#[allow(dead_code)]
pub(crate) fn spawn_writer<T: TunIo>(
    tun: T,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    metrics_tx: mpsc::Sender<MetricsInput>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mtu = tun.mtu();
        let mut warned_oversize = false;
        while let Some(packet) = inbound.recv().await {
            if packet.len() > mtu {
                if !warned_oversize {
                    warned_oversize = true;
                    warn!(
                        "dropping TUN packet larger than MTU (len={}, mtu={}, if={})",
                        packet.len(),
                        mtu,
                        tun.name()
                    );
                }
                let _ = metrics_tx
                    .send(MetricsInput::DroppedTx {
                        packets: 1,
                        bytes: packet.len() as u64,
                    })
                    .await;
                continue;
            }

            match tun.send(&packet).await {
                Ok(written) => {
                    let _ = metrics_tx
                        .send(MetricsInput::Tx {
                            packets: 1,
                            bytes: written as u64,
                        })
                        .await;
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    })
}

/// Spawns a task that aggregates metrics updates and emits snapshots to the orchestrator.
#[allow(dead_code)]
pub(crate) fn spawn_metrics_task(
    mut metrics_rx: mpsc::Receiver<MetricsInput>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut counters = TunCounters::default();
        let mut ticker = time::interval(interval);
        loop {
            tokio::select! {
                maybe_input = metrics_rx.recv() => {
                    match maybe_input {
                        Some(input) => counters.apply(input),
                        None => {
                            let _ = events_tx.send(Event::Tun(TunEvent::Metrics(counters.snapshot()))).await;
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if events_tx.is_closed() {
                        break;
                    }
                    let _ = events_tx.send(Event::Tun(TunEvent::Metrics(counters.snapshot()))).await;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[derive(Clone)]
    struct MemoryTun {
        name: String,
        mtu: usize,
        inbound: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
        outbound: mpsc::Sender<Vec<u8>>,
    }

    impl MemoryTun {
        fn new(name: &str, mtu: usize) -> (Self, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
            let (in_tx, in_rx) = mpsc::channel(4);
            let (out_tx, out_rx) = mpsc::channel(4);
            (
                MemoryTun {
                    name: name.to_string(),
                    mtu,
                    inbound: Arc::new(tokio::sync::Mutex::new(in_rx)),
                    outbound: out_tx,
                },
                in_tx,
                out_rx,
            )
        }
    }

    impl TunIo for MemoryTun {
        fn mtu(&self) -> usize {
            self.mtu
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn recv<'a>(&'a self, buf: &'a mut [u8]) -> IoFuture<'a, io::Result<usize>> {
            let inbound = self.inbound.clone();
            Box::pin(async move {
                let mut rx = inbound.lock().await;
                match rx.recv().await {
                    Some(packet) => {
                        let len = packet.len().min(buf.len());
                        buf[..len].copy_from_slice(&packet[..len]);
                        Ok(len)
                    }
                    None => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "channel closed")),
                }
            })
        }

        fn send<'a>(&'a self, buf: &'a [u8]) -> IoFuture<'a, io::Result<usize>> {
            let outbound = self.outbound.clone();
            Box::pin(async move {
                outbound
                    .send(buf.to_vec())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "outbound closed"))?;
                Ok(buf.len())
            })
        }
    }

    #[tokio::test]
    async fn parses_addresses_and_splits() {
        let addrs = vec![
            "192.168.1.1/24".to_string(),
            "2001:db8::1/64".to_string(),
        ];
        let (v4, v6) = parse_addrs(&addrs).unwrap();
        assert_eq!(v4.len(), 1);
        assert_eq!(v4[0].addr(), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].addr(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[tokio::test]
    async fn reader_pushes_packets_and_counts() {
        let (tun, feed_tx, _) = MemoryTun::new("mem0", 32);
        let (metrics_tx, metrics_rx) = mpsc::channel(8);
        let mut metrics_rx = metrics_rx;
        let (out_tx, mut out_rx) = mpsc::channel(4);
        let reader = spawn_reader(tun, out_tx, metrics_tx);

        feed_tx.send(vec![1, 2, 3]).await.unwrap();
        let packet = out_rx.recv().await.expect("packet should be forwarded");
        assert_eq!(packet, vec![1, 2, 3]);

        drop(feed_tx);
        reader.abort();

        let mut metrics = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(50), async {
            while let Some(update) = metrics_rx.recv().await {
                metrics.push(update);
            }
        })
        .await;

        assert!(metrics.iter().any(|m| matches!(m, MetricsInput::Rx { packets: 1, bytes: 3 })));
    }

    #[tokio::test]
    async fn writer_drops_oversize_and_reports_metrics() {
        let (tun, _feed_tx, mut device_out) = MemoryTun::new("mem1", 4);
        let (metrics_tx, mut metrics_rx) = mpsc::channel(8);
        let (tx, rx) = mpsc::channel(4);
        let writer = spawn_writer(tun, rx, metrics_tx);

        tx.send(vec![0, 1, 2, 3, 4, 5]).await.unwrap();
        tx.send(vec![9, 9, 9]).await.unwrap();

        // First packet should be dropped; second should be emitted.
        let received = device_out.recv().await.expect("should receive one packet");
        assert_eq!(received, vec![9, 9, 9]);

        drop(tx);
        writer.abort();

        let mut metrics = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(50), async {
            while let Some(update) = metrics_rx.recv().await {
                metrics.push(update);
            }
        })
        .await;

        assert!(metrics.iter().any(|m| matches!(m, MetricsInput::DroppedTx { packets: 1, bytes: 6 })));
        assert!(metrics.iter().any(|m| matches!(m, MetricsInput::Tx { packets: 1, bytes: 3 })));
    }

    #[tokio::test]
    async fn metrics_task_emits_snapshots() {
        let (metrics_tx, metrics_rx) = mpsc::channel(8);
        let (events_tx, mut events_rx) = mpsc::channel(8);

        let reporter = spawn_metrics_task(metrics_rx, events_tx, Duration::from_millis(20));

        metrics_tx
            .send(MetricsInput::Rx {
                packets: 2,
                bytes: 10,
            })
            .await
            .unwrap();
        metrics_tx
            .send(MetricsInput::DroppedTx {
                packets: 1,
                bytes: 5,
            })
            .await
            .unwrap();
        drop(metrics_tx);

        let mut snapshot = None;
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Tun(TunEvent::Metrics(m)) = event {
                    snapshot = Some(m);
                    break;
                }
            }
        })
        .await;

        reporter.abort();
        let metrics = snapshot.expect("metrics snapshot should arrive");
        assert_eq!(metrics.rx_packets, 2);
        assert_eq!(metrics.rx_bytes, 10);
        assert_eq!(metrics.dropped_tx_packets, 1);
        assert_eq!(metrics.dropped_tx_bytes, 5);
    }
}
