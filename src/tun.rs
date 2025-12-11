//! TUN management: device creation, read/write loops with backpressure, and metrics reporting.

use crate::config::LocalTun;
use crate::events::{Direction, Event, InterfaceEvent};
use crate::helpers::retry_on_interrupted;
use crate::metrics::InterfaceCounters;
use ipnet::{Ipv4Net, Ipv6Net};
use log::warn;
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

/// Spawns the TUN read loop, pushing packets into `outbound` with backpressure and emitting RX metrics.
#[allow(dead_code)]
pub(crate) fn spawn_reader<T: TunRx>(
    mut tun: T,
    outbound: mpsc::Sender<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mtu = tun.mtu();
        let iface = tun.name().to_string();
        let mut counters = InterfaceCounters::new(Direction::Rx);
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
                            if outbound.send(packet).await.is_err() {
                                break;
                            }
                            counters.record_success(len);
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Interface(InterfaceEvent::Metrics(counters.snapshot(&iface)))).await.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// Spawns the TUN write loop, dropping oversize packets with counting and emitting TX metrics.
#[allow(dead_code)]
pub(crate) fn spawn_writer<T: TunTx>(
    mut tun: T,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mtu = tun.mtu();
        let iface = tun.name().to_string();
        let mut warned_oversize = false;
        let mut counters = InterfaceCounters::new(Direction::Tx);
        let mut ticker = time::interval(interval);

        loop {
            tokio::select! {
                maybe_packet = inbound.recv() => {
                    let packet = match maybe_packet {
                        Some(packet) => packet,
                        None => break,
                    };

                    if packet.len() > mtu {
                        if !warned_oversize {
                            warned_oversize = true;
                            warn!(
                                "dropping TUN packet larger than MTU (len={}, mtu={}, if={})",
                                packet.len(),
                                mtu,
                                iface
                            );
                        }
                        counters.record_drop(packet.len());
                        continue;
                    }

                    match retry_on_interrupted!(tun.send(&packet).await) {
                        Ok(written) => counters.record_success(written),
                        Err(_) => {
                            counters.record_drop(packet.len());
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if events_tx.send(Event::Interface(InterfaceEvent::Metrics(counters.snapshot(&iface)))).await.is_err() {
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
        inbound: mpsc::Receiver<Vec<u8>>,
    }

    struct MemoryTunTx {
        name: String,
        mtu: usize,
        outbound: mpsc::Sender<Vec<u8>>,
        send_errors: VecDeque<io::ErrorKind>,
    }

    fn memory_tun(name: &str, mtu: usize) -> (MemoryTunRx, MemoryTunTx) {
        let (out_tx, out_rx) = mpsc::channel(4);
        (
            MemoryTunRx {
                name: name.to_string(),
                mtu,
                inbound: out_rx,
            },
            MemoryTunTx {
                name: name.to_string(),
                mtu,
                outbound: out_tx,
                send_errors: VecDeque::new(),
            },
        )
    }

    fn memory_tun_with_errors(
        name: &str,
        mtu: usize,
        send_errors: Vec<io::ErrorKind>,
    ) -> (MemoryTunRx, MemoryTunTx) {
        let (out_tx, out_rx) = mpsc::channel(4);
        (
            MemoryTunRx {
                name: name.to_string(),
                mtu,
                inbound: out_rx,
            },
            MemoryTunTx {
                name: name.to_string(),
                mtu,
                outbound: out_tx,
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
            match self.inbound.recv().await {
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
            self.outbound
                .send(buf.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "outbound closed"))?;
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
    async fn reader_pushes_packets_and_counts() {
        let (rx_tun, mut tx_tun) = memory_tun("mem0", 32);
        let (out_tx, mut out_rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let reader = spawn_reader(rx_tun, out_tx, events_tx, Duration::from_millis(10));

        tx_tun.send(&[1, 2, 3]).await.unwrap();
        let packet = out_rx.recv().await.expect("packet should be forwarded");
        assert_eq!(packet, vec![1, 2, 3]);

        let mut snapshot = None;
        let _ = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Interface(InterfaceEvent::Metrics(m)) = event {
                    if m.direction == Direction::Rx && m.packets >= 1 {
                        snapshot = Some(m);
                        break;
                    }
                }
            }
        })
        .await;

        reader.abort();

        let metrics = snapshot.expect("rx metrics should arrive");
        assert_eq!(metrics.iface, "mem0");
        assert_eq!(metrics.packets, 1);
        assert_eq!(metrics.bytes, 3);
    }

    #[tokio::test]
    async fn writer_drops_oversize_and_reports_metrics() {
        let (mut rx_tun, tx_tun) = memory_tun("mem1", 4);
        let (tx, rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let writer = spawn_writer(tx_tun, rx, events_tx, Duration::from_millis(10));

        tx.send(vec![0, 1, 2, 3, 4, 5]).await.unwrap();
        tx.send(vec![9, 9, 9]).await.unwrap();

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
                if let Event::Interface(InterfaceEvent::Metrics(m)) = event {
                    if m.direction == Direction::Tx && m.packets >= 1 && m.dropped_packets >= 1 {
                        snapshot = Some(m);
                        break;
                    }
                }
            }
        })
        .await;

        writer.abort();

        let metrics = snapshot.expect("tx metrics should arrive");
        assert_eq!(metrics.iface, "mem1");
        assert_eq!(metrics.packets, 1);
        assert_eq!(metrics.bytes, 3);
        assert_eq!(metrics.dropped_packets, 1);
        assert_eq!(metrics.dropped_bytes, 6);
    }

    #[tokio::test]
    async fn writer_retries_interrupted_send() {
        let (mut rx_tun, tx_tun) =
            memory_tun_with_errors("mem-interrupt", 16, vec![io::ErrorKind::Interrupted]);
        let (tx, rx) = mpsc::channel(4);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let writer = spawn_writer(tx_tun, rx, events_tx, Duration::from_millis(5));

        tx.send(vec![1, 2, 3]).await.unwrap();

        let mut buf = vec![0u8; 16];
        let len = rx_tun
            .recv(&mut buf)
            .await
            .expect("should receive after retry");
        assert_eq!(&buf[..len], &[1, 2, 3]);

        let metrics = tokio::time::timeout(Duration::from_millis(100), async {
            while let Some(event) = events_rx.recv().await {
                if let Event::Interface(InterfaceEvent::Metrics(m)) = event {
                    if m.direction == Direction::Tx && m.packets >= 1 {
                        return Some(m);
                    }
                }
            }
            None
        })
        .await
        .expect("tx metrics should arrive")
        .expect("tx metrics should not be None");

        writer.abort();

        assert_eq!(metrics.packets, 1);
        assert_eq!(metrics.dropped_packets, 0);
    }
}
