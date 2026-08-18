//! Protocol-agnostic UDP I/O actors with shared `Arc<UdpSocket>`.
//!
//! Provides GRO-aware receive and GSO-aware send loops that both `BareUDP`
//! and H3v2 transports share. The actors communicate via
//! `(SocketAddr, Vec<PooledBuf>)` channels, tagging each batch with
//! the remote address.

use crate::actor::{ActorContext, ActorRef, ActorRuntime, SupervisionPolicy};
use crate::bind::UdpError;
use crate::helpers::alloc_packet_buf;
use crate::helpers::retry_on_transient;
use anyhow::Context;
use buffer_pool::PooledBuf;
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use std::io;
use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
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
/// Pure I/O actor: no filtering or metrics.
/// Protocol-specific logic belongs in the consuming actor.
pub fn spawn_udp_rx(
    rx: UdpRx,
    output: mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    ctx: &ActorContext,
    policy: SupervisionPolicy,
) -> ActorRef {
    let UdpRx {
        socket,
        state,
        max_udp_payload,
    } = rx;
    let local_addr = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();

    ctx.spawn(
        format!("udp-rx[{local_addr}]"),
        ActorRuntime::Udp,
        policy,
        |mut ctx| async move {
        info!(addr = %local_addr, "UDP RX actor started");
        let gro_segments = state.gro_segments();
        let mut buf = vec![0u8; max_udp_payload * gro_segments];
        let mut meta = RecvMeta::default();

        while let Some(result) = ctx.run_until_stopped(socket.readable()).await {
            result.context("wait for UDP socket readability")?;
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
                        return Err(e).context("receive UDP datagrams");
                    }
                }
            }
        }
        info!(addr = %local_addr, "UDP RX: stopping");
        Ok(())
        },
    )
}

/// Spawns a UDP send loop with GSO support for destination-tagged batches.
///
/// Pure I/O actor: no metrics, no protocol awareness.
/// Returns the input sender. Lifecycle monitoring remains internal to
/// `ActorBus`.
///
/// Exits when the input channel closes, draining all remaining batches
/// first. This guarantees that final packets (e.g. QUIC `CONNECTION_CLOSE`)
/// are sent before the actor stops. No `CancellationToken` is needed —
/// the caller controls shutdown by dropping the returned sender.
pub fn spawn_udp_tx(
    tx: UdpTx,
    queue_depth: usize,
    ctx: &ActorContext,
    policy: SupervisionPolicy,
) -> (mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>, ActorRef) {
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

    let actor_ref = ctx.spawn(
        format!("udp-tx[{local_addr}]"),
        ActorRuntime::Udp,
        policy,
        |mut ctx| async move {
            info!(addr = %local_addr, "UDP TX actor started");
            let mut gso_buf = Vec::with_capacity(u16::MAX as usize);

            loop {
                let next = tokio::select! {
                    biased;
                    () = ctx.wait_for_stop() => {
                        // Reject new batches, then drain those already buffered.
                        input_rx.close();
                        input_rx.recv().await
                    }
                    batch = input_rx.recv() => batch,
                };
                let Some((dest, packets)) = next else {
                    break;
                };

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
                    // Quinn disables GSO after certain driver errors, so this
                    // value must be refreshed instead of cached for the actor's
                    // full lifetime.
                    let max_segs = if enable_offload {
                        state.max_gso_segments()
                    } else {
                        1
                    };
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

                    let send_result = retry_on_transient!(
                        {
                            socket
                                .writable()
                                .await
                                .context("wait for UDP socket writability")?;
                            socket.try_io(Interest::WRITABLE, || {
                                state.try_send(UdpSockRef::from(&*socket), &transmit)
                            })
                        },
                        |_dur| {
                            // No metrics at this layer; protocol actor tracks congestion.
                        }
                    );

                    if let Err(err) = send_result {
                        let used_gso = gso_buf.len() > segment_size;
                        if is_non_fatal_send_error(&err, used_gso) {
                            // Drop known non-fatal send failures without stopping
                            // the shared TX actor. Unclassified failures propagate
                            // because they may indicate an unusable transport.
                            // TODO: Record UDP actor send-drop metrics and rate-limit
                            // this warning when ActorBus provides metrics handles.
                            warn!(
                                addr = %local_addr,
                                %dest,
                                error = %err,
                                "UDP TX: destination send failed; dropping batch"
                            );
                            break;
                        }
                        return Err(err).context("send UDP datagrams");
                    }
                }
            }
            info!(addr = %local_addr, "UDP TX: stopping");
            Ok(())
        },
    );

    (input_tx, actor_ref)
}

fn is_non_fatal_send_error(error: &io::Error, used_gso: bool) -> bool {
    let non_fatal_kind = matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::TimedOut
    );

    #[cfg(unix)]
    {
        let raw_error = error.raw_os_error();
        non_fatal_kind
            || matches!(raw_error, Some(libc::EMSGSIZE | libc::ENOBUFS))
            || (used_gso && raw_error == Some(libc::EIO))
    }

    #[cfg(not(unix))]
    {
        let _ = used_gso;
        non_fatal_kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Event;

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
        let actor_bus = crate::actor::ActorBus::on_current_runtime();
        let supervisor = actor_bus.mailbox("test-supervisor");
        let std_socket = bind_std();
        let addr = std_socket.local_addr().unwrap();
        let (rx, _tx) = make_udp(std_socket, 1500, false).unwrap();

        let (output_tx, mut output_rx) = mpsc::channel(4);
        let _udp_rx = spawn_udp_rx(rx, output_tx, &supervisor, SupervisionPolicy::Detached);

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
    }

    #[tokio::test]
    async fn udp_tx_sends_to_destination() {
        let actor_bus = crate::actor::ActorBus::on_current_runtime();
        let supervisor = actor_bus.mailbox("test-supervisor");
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let (_rx, tx) = make_udp(bind_std(), 1500, false).unwrap();

        let (input_tx, _udp_tx) = spawn_udp_tx(tx, 4, &supervisor, SupervisionPolicy::Detached);

        input_tx
            .send((dest, vec![alloc_packet_buf(&[9, 8, 7])]))
            .await
            .unwrap();

        let mut buf = vec![0u8; 64];
        let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], &[9, 8, 7]);
    }

    #[tokio::test]
    async fn udp_tx_gso_batch() {
        let actor_bus = crate::actor::ActorBus::on_current_runtime();
        let supervisor = actor_bus.mailbox("test-supervisor");
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let (_rx, tx) = make_udp(bind_std(), 1500, false).unwrap();

        let (input_tx, _udp_tx) = spawn_udp_tx(tx, 4, &supervisor, SupervisionPolicy::Detached);

        // Send a batch of 3 packets.
        let batch = vec![
            alloc_packet_buf(&[1, 2]),
            alloc_packet_buf(&[3, 4]),
            alloc_packet_buf(&[5, 6]),
        ];
        input_tx.send((dest, batch)).await.unwrap();

        // With GSO disabled (max_segs=1), each packet is sent individually.
        let mut buf = vec![0u8; 64];
        for expected in [[1u8, 2], [3, 4], [5, 6]] {
            let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], &expected);
        }
    }

    #[tokio::test]
    async fn udp_tx_mixed_size_batch() {
        let actor_bus = crate::actor::ActorBus::on_current_runtime();
        let supervisor = actor_bus.mailbox("test-supervisor");
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let (_rx, tx) = make_udp(bind_std(), 1500, false).unwrap();

        let (input_tx, _udp_tx) = spawn_udp_tx(tx, 4, &supervisor, SupervisionPolicy::Detached);

        // Mixed sizes: run of 2-byte, then 3-byte, then back to 2-byte.
        let batch = vec![
            alloc_packet_buf(&[1, 2]),
            alloc_packet_buf(&[3, 4]),
            alloc_packet_buf(&[5, 6, 7]),
            alloc_packet_buf(&[8, 9]),
        ];
        input_tx.send((dest, batch)).await.unwrap();

        let mut buf = vec![0u8; 64];
        for expected in [&[1u8, 2] as &[u8], &[3, 4], &[5, 6, 7], &[8, 9]] {
            let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], expected);
        }
    }

    #[tokio::test]
    async fn udp_rx_exits_when_output_closed() {
        let mut actor_bus = crate::actor::ActorBus::on_current_runtime();
        let mut supervisor = actor_bus.mailbox("test-supervisor");
        let std_socket = bind_std();
        let addr = std_socket.local_addr().unwrap();
        let (rx, _tx) = make_udp(std_socket, 1500, false).unwrap();

        let (output_tx, output_rx) = mpsc::channel(1);
        let _udp_rx = spawn_udp_rx(rx, output_tx, &supervisor, SupervisionPolicy::Detached);

        // Drop receiver so output channel is closed.
        drop(output_rx);

        // Send a packet to trigger the actor to notice the closed channel.
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(&[1], addr).await.unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            crate::actor::next_actor_exit(&mut actor_bus, &mut supervisor),
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
            "udp_rx should exit gracefully when output closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn udp_tx_exits_when_input_closed() {
        let mut actor_bus = crate::actor::ActorBus::on_current_runtime();
        let mut supervisor = actor_bus.mailbox("test-supervisor");
        let (_rx, tx) = make_udp(bind_std(), 1500, false).unwrap();

        let (input_tx, _udp_tx) = spawn_udp_tx(tx, 4, &supervisor, SupervisionPolicy::Detached);

        // Drop sender to close input channel.
        drop(input_tx);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            crate::actor::next_actor_exit(&mut actor_bus, &mut supervisor),
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
            "udp_tx should exit gracefully when input closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn udp_tx_drains_buffered_batch_when_stopped() {
        let mut actor_bus = crate::actor::ActorBus::on_current_runtime();
        let mut supervisor = actor_bus.mailbox("test-supervisor");
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();
        let (_rx, tx) = make_udp(bind_std(), 1500, false).unwrap();

        let (input_tx, udp_tx) = spawn_udp_tx(tx, 4, &supervisor, SupervisionPolicy::Detached);
        input_tx
            .send((dest, vec![alloc_packet_buf(&[9, 8, 7])]))
            .await
            .unwrap();
        supervisor.send(&udp_tx, Event::Stop).unwrap();

        let mut buf = [0; 64];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("buffered batch should be sent before shutdown")
        .unwrap();
        assert_eq!(&buf[..len], &[9, 8, 7]);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            crate::actor::next_actor_exit(&mut actor_bus, &mut supervisor),
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
            "udp_tx should exit after draining, got {result:?}"
        );
    }

    #[test]
    fn destination_errors_are_non_fatal() {
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::NetworkDown,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::TimedOut,
        ] {
            assert!(is_non_fatal_send_error(&io::Error::from(kind), false));
        }
        assert!(!is_non_fatal_send_error(
            &io::Error::from(io::ErrorKind::PermissionDenied),
            false,
        ));
        assert!(!is_non_fatal_send_error(
            &io::Error::from(io::ErrorKind::BrokenPipe),
            false,
        ));
    }

    #[cfg(unix)]
    #[test]
    fn raw_datagram_and_gso_errors_are_non_fatal() {
        assert!(is_non_fatal_send_error(
            &io::Error::from_raw_os_error(libc::EMSGSIZE),
            false,
        ));
        assert!(is_non_fatal_send_error(
            &io::Error::from_raw_os_error(libc::ENOBUFS),
            false,
        ));
        assert!(is_non_fatal_send_error(
            &io::Error::from_raw_os_error(libc::EIO),
            true,
        ));
        assert!(!is_non_fatal_send_error(
            &io::Error::from_raw_os_error(libc::EIO),
            false,
        ));
    }
}
