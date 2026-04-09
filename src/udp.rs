//! Protocol-agnostic UDP I/O actors with shared `Arc<UdpSocket>`.
//!
//! Provides GRO-aware receive and GSO-aware send loops that both `BareUDP`
//! and H3v2 transports share. The actors communicate via
//! `(SocketAddr, Vec<PooledBuf>)` channels, tagging each batch with
//! the remote address.

use crate::actor::{ActorError, ActorExitResult};
use crate::bind::UdpError;
use crate::helpers::alloc_packet_buf;
use crate::helpers::retry_on_transient;
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_quiche::buf_factory::PooledBuf;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Receive side of a shared UDP socket with quinn-udp GRO support.
#[derive(Debug)]
pub struct UdpRx {
    socket: Arc<UdpSocket>,
    state: UdpSocketState,
    max_udp_payload: usize,
}

/// Send side of a shared UDP socket with quinn-udp GSO support.
#[derive(Debug)]
pub struct UdpTx {
    socket: Arc<UdpSocket>,
    state: UdpSocketState,
    enable_offload: bool,
}

/// Creates shared UDP actor state from a standard library socket.
///
/// Converts the `std::net::UdpSocket` to a tokio socket, wraps it in `Arc`,
/// and returns both RX and TX halves sharing the same underlying socket.
/// Callers may use either or both; the unused half is cheaply dropped.
///
/// # Arguments
///
/// * `socket` - Standard library UDP socket (must be non-blocking).
/// * `max_udp_payload` - Maximum UDP payload size for GRO buffer sizing.
/// * `enable_offload` - Enable GSO on the TX side; `false` caps segments to 1.
///
/// # Errors
///
/// Returns `UdpError::Socket` if tokio conversion or quinn-udp state
/// initialization fails.
pub fn make_udp(
    socket: std::net::UdpSocket,
    max_udp_payload: usize,
    enable_offload: bool,
) -> Result<(UdpRx, UdpTx), UdpError> {
    let socket = UdpSocket::from_std(socket)
        .map_err(|e| UdpError::Socket(format!("tokio from_std: {e}")))?;
    let socket = Arc::new(socket);
    let state_rx = UdpSocketState::new(UdpSockRef::from(&*socket))
        .map_err(|e| UdpError::Socket(format!("quinn-udp rx state: {e}")))?;
    let state_tx = UdpSocketState::new(UdpSockRef::from(&*socket))
        .map_err(|e| UdpError::Socket(format!("quinn-udp tx state: {e}")))?;
    Ok((
        UdpRx {
            socket: socket.clone(),
            state: state_rx,
            max_udp_payload,
        },
        UdpTx {
            socket,
            state: state_tx,
            enable_offload,
        },
    ))
}

/// Spawns a UDP receive loop that tags each batch with its source address.
///
/// Pure I/O actor: no filtering, no metrics, no command channel.
/// Protocol-specific logic belongs in the consuming actor.
///
/// The `cancel` token allows the owner to signal immediate shutdown.
/// The caller must retain a clone and cancel it when done; without
/// cancellation the actor only exits when the output channel closes
/// **and** a packet arrives — which may never happen after the consumer
/// is gone, leaking the task.
pub fn spawn_udp_rx(
    rx: UdpRx,
    output: mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    cancel: CancellationToken,
) -> JoinHandle<ActorExitResult> {
    let UdpRx {
        socket,
        state,
        max_udp_payload,
    } = rx;
    let local_addr = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();

    tokio::spawn(async move {
        info!(addr = %local_addr, "UDP RX actor started");
        let gro_segments = state.gro_segments();
        let mut buf = vec![0u8; max_udp_payload * gro_segments];
        let mut meta = RecvMeta::default();

        loop {
            tokio::select! {
                result = socket.readable() => {
                    result.map_err(|e| ActorError::UdpRxRecv {
                        addr: local_addr.clone(),
                        source: e,
                    })?;
                }
                () = cancel.cancelled() => {
                    info!(addr = %local_addr, "UDP RX: cancelled, shutting down");
                    return Ok(());
                }
            }
            loop {
                let result = socket.try_io(Interest::READABLE, || {
                    state.recv(
                        UdpSockRef::from(&*socket),
                        &mut [IoSliceMut::new(&mut buf)],
                        std::slice::from_mut(&mut meta),
                    )
                });
                match result {
                    Ok(0) => break,
                    Ok(_) if meta.len == 0 => break,
                    Ok(_) => {
                        let remote = meta.addr;
                        let stride = meta.stride.min(meta.len);
                        let batch: Vec<PooledBuf> = buf[..meta.len]
                            .chunks(stride)
                            .map(alloc_packet_buf)
                            .collect();
                        if output.send((remote, batch)).await.is_err() {
                            info!(addr = %local_addr, "UDP RX: output channel closed, shutting down");
                            return Ok(());
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => break,
                    Err(e) => {
                        warn!(addr = %local_addr, error = %e, "UDP RX: fatal I/O error");
                        return Err(ActorError::UdpRxRecv {
                            addr: local_addr,
                            source: e,
                        });
                    }
                }
            }
        }
    })
}

/// Spawns a UDP send loop with GSO support for destination-tagged batches.
///
/// Pure I/O actor: no metrics, no protocol awareness.
/// Returns the input sender and join handle.
///
/// Exits when the input channel closes, draining all remaining batches
/// first. This guarantees that final packets (e.g. QUIC `CONNECTION_CLOSE`)
/// are sent before the actor stops. No `CancellationToken` is needed —
/// the caller controls shutdown by dropping the returned sender.
pub fn spawn_udp_tx(
    tx: UdpTx,
    queue_depth: usize,
) -> (
    mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    JoinHandle<ActorExitResult>,
) {
    let (input_tx, mut input_rx) = mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(queue_depth);
    let UdpTx {
        socket,
        state,
        enable_offload,
    } = tx;
    let local_addr = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();

    let handle = tokio::spawn(async move {
        info!(addr = %local_addr, "UDP TX actor started");
        let mut gso_buf = Vec::with_capacity(u16::MAX as usize);
        let max_segs = if enable_offload {
            state.max_gso_segments()
        } else {
            1
        };

        while let Some((dest, packets)) = input_rx.recv().await {
            if packets.is_empty() {
                continue;
            }
            // Split batch into consecutive runs of same-sized packets.
            // GSO requires uniform segment_size per sendmsg; QUIC batches
            // may mix sizes (e.g. 1393 vs 1394, data vs ACK).
            // Max UDP payload per sendmsg: IPv4 Total Length (16-bit)
            // includes the IP header, IPv6 Payload Length does not.
            let max_udp_payload: usize = if dest.is_ipv4() {
                65535 - 20 - 8 // 65507
            } else {
                65535 - 8 // 65527
            };
            let mut pos = 0;

            while pos < packets.len() {
                let segment_size = packets[pos].len();
                debug_assert!(segment_size > 0, "GSO must not produce empty packets");
                let max_segs_run = max_segs.min(max_udp_payload / segment_size).max(1);

                gso_buf.clear();

                // Accumulate consecutive same-sized packets up to max_segs.
                while pos < packets.len()
                    && packets[pos].len() == segment_size
                    && gso_buf.len() / segment_size < max_segs_run
                {
                    gso_buf.extend_from_slice(&packets[pos]);
                    pos += 1;
                }

                let transmit = Transmit {
                    destination: dest,
                    ecn: None,
                    contents: &gso_buf,
                    segment_size: Some(segment_size),
                    src_ip: None,
                };

                retry_on_transient!(
                    {
                        socket
                            .writable()
                            .await
                            .map_err(|err| ActorError::UdpTxSend {
                                addr: local_addr.clone(),
                                source: err,
                            })?;
                        socket.try_io(Interest::WRITABLE, || {
                            state.try_send(UdpSockRef::from(&*socket), &transmit)
                        })
                    },
                    |_dur| {
                        // No metrics at this layer; protocol actor tracks congestion.
                    }
                )
                .map_err(|err| ActorError::UdpTxSend {
                    addr: local_addr.clone(),
                    source: err,
                })?;
            }
        }
        info!(addr = %local_addr, "UDP TX: input channel closed, shutting down");
        Ok(())
    });

    (input_tx, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_quiche::buf_factory::BufFactory;
    use tokio_util::sync::CancellationToken;

    fn bind_std() -> std::net::UdpSocket {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_nonblocking(true).unwrap();
        s
    }

    #[tokio::test]
    async fn make_udp_creates_shared_socket() {
        let (rx, tx) = make_udp(bind_std(), 1500, false).unwrap();
        assert!(Arc::ptr_eq(&rx.socket, &tx.socket));
    }

    #[tokio::test]
    async fn udp_rx_tags_source_address() {
        let std_socket = bind_std();
        let addr = std_socket.local_addr().unwrap();
        let (rx, _tx) = make_udp(std_socket, 1500, false).unwrap();

        let (output_tx, mut output_rx) = mpsc::channel(4);
        let handle = spawn_udp_rx(rx, output_tx, CancellationToken::new());

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_addr = sender.local_addr().unwrap();
        sender.send_to(&[1, 2, 3], addr).await.unwrap();

        let (remote, batch) =
            tokio::time::timeout(std::time::Duration::from_millis(200), output_rx.recv())
                .await
                .expect("should receive within timeout")
                .expect("channel should carry message");

        assert_eq!(remote, sender_addr);
        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &[1, 2, 3]);

        handle.abort();
    }

    #[tokio::test]
    async fn udp_tx_sends_to_destination() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let (_rx, tx) = make_udp(bind_std(), 1500, false).unwrap();

        let (input_tx, tx_handle) = spawn_udp_tx(tx, 4);

        input_tx
            .send((dest, vec![BufFactory::buf_from_slice(&[9, 8, 7])]))
            .await
            .unwrap();

        let mut buf = vec![0u8; 64];
        let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], &[9, 8, 7]);

        tx_handle.abort();
    }

    #[tokio::test]
    async fn udp_tx_gso_batch() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let (_rx, tx) = make_udp(bind_std(), 1500, false).unwrap();

        let (input_tx, tx_handle) = spawn_udp_tx(tx, 4);

        // Send a batch of 3 packets.
        let batch = vec![
            BufFactory::buf_from_slice(&[1, 2]),
            BufFactory::buf_from_slice(&[3, 4]),
            BufFactory::buf_from_slice(&[5, 6]),
        ];
        input_tx.send((dest, batch)).await.unwrap();

        // With GSO disabled (max_segs=1), each packet is sent individually.
        let mut buf = vec![0u8; 64];
        for expected in [[1u8, 2], [3, 4], [5, 6]] {
            let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], &expected);
        }

        tx_handle.abort();
    }

    #[tokio::test]
    async fn udp_tx_mixed_size_batch() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let (_rx, tx) = make_udp(bind_std(), 1500, false).unwrap();

        let (input_tx, tx_handle) = spawn_udp_tx(tx, 4);

        // Mixed sizes: run of 2-byte, then 3-byte, then back to 2-byte.
        let batch = vec![
            BufFactory::buf_from_slice(&[1, 2]),
            BufFactory::buf_from_slice(&[3, 4]),
            BufFactory::buf_from_slice(&[5, 6, 7]),
            BufFactory::buf_from_slice(&[8, 9]),
        ];
        input_tx.send((dest, batch)).await.unwrap();

        let mut buf = vec![0u8; 64];
        for expected in [&[1u8, 2] as &[u8], &[3, 4], &[5, 6, 7], &[8, 9]] {
            let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], expected);
        }

        tx_handle.abort();
    }

    #[tokio::test]
    async fn udp_rx_exits_when_output_closed() {
        let std_socket = bind_std();
        let addr = std_socket.local_addr().unwrap();
        let (rx, _tx) = make_udp(std_socket, 1500, false).unwrap();

        let (output_tx, output_rx) = mpsc::channel(1);
        let handle = spawn_udp_rx(rx, output_tx, CancellationToken::new());

        // Drop receiver so output channel is closed.
        drop(output_rx);

        // Send a packet to trigger the actor to notice the closed channel.
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(&[1], addr).await.unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_millis(200), handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "udp_rx should exit gracefully when output closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn udp_tx_exits_when_input_closed() {
        let (_rx, tx) = make_udp(bind_std(), 1500, false).unwrap();

        let (input_tx, tx_handle) = spawn_udp_tx(tx, 4);

        // Drop sender to close input channel.
        drop(input_tx);

        let result = tokio::time::timeout(std::time::Duration::from_millis(200), tx_handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "udp_tx should exit gracefully when input closed, got {result:?}"
        );
    }
}
