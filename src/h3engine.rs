//! Unified H3 engine actor: QUIC connection management, packet I/O, and
//! backpressure for both client and server CONNECT-IP connections.
//!
//! The [`H3Engine`] struct owns the QUIC connection and all I/O channels.
//! Client connections use [`establish`](H3Engine::establish) (in
//! [`crate::h3dialer`]) for handshake; server connections use
//! [`accept`](H3Engine::accept) (in [`crate::h3listener`]). Both then call
//! [`run`](H3Engine::run) for steady-state datagram forwarding.

use crate::actor::{ActorError, ActorExitResult};
use crate::config::H3Tuning;
use crate::events::Event;
use crate::h3session::{
    ConnectIpDatagramCodec, ConnectProgress, H3Session, HeaderAction, MAX_TIMEOUT,
};
use crate::helpers::alloc_uninit_packet_buf;
use crate::metrics::{Counters, Direction, DropReason, Source};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time;
use tokio_quiche::buf_factory::PooledBuf;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

// ========== Configuration Helpers ==========

/// Applies shared QUIC transport parameters to a quiche configuration.
///
/// Shared between client and server: payload sizes, flow control windows,
/// stream limits, DATAGRAM support, idle timeout, congestion control, pacing.
pub(crate) fn apply_transport_config(
    config: &mut quiche::Config,
    h3_tuning: &H3Tuning,
    max_udp_payload: usize,
) -> Result<(), quiche::Error> {
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    config.set_max_recv_udp_payload_size(max_udp_payload);
    config.set_max_send_udp_payload_size(max_udp_payload);
    // 10 MB connection-level flow control window (sufficient for tunneled traffic bursts).
    config.set_initial_max_data(10_000_000);
    // 1 MB per-stream window for the CONNECT-IP control stream.
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    // Allow up to 100 concurrent bidirectional/unidirectional streams.
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    // Enable QUIC DATAGRAM with a queue of 1024 send and 1024 recv slots.
    config.enable_dgram(true, 1024, 1024);
    // Saturate to u64::MAX (~584 million years) for absurdly large durations.
    let idle_ms = u64::try_from(h3_tuning.h3_max_idle_timeout.as_millis()).unwrap_or(u64::MAX);
    config.set_max_idle_timeout(idle_ms);
    config.set_cc_algorithm_name(&h3_tuning.h3_cc_algorithm)?;
    config.enable_pacing(h3_tuning.h3_enable_pacing);
    Ok(())
}

// ========== Packet I/O Helpers ==========

/// Decrypts a batch of received UDP packets by feeding them into quiche.
///
/// Takes ownership of the batch to pass each buffer mutably to `conn.recv()`,
/// avoiding an intermediate copy through a shared receive buffer.
pub(crate) fn handle_udp_recv(
    conn: &mut quiche::Connection,
    batch: Vec<PooledBuf>,
    info: quiche::RecvInfo,
    mut rx_counters: Option<&mut Counters>,
) {
    for mut pkt in batch {
        // quiche silently evicts the oldest datagram when the recv queue is
        // full (pop-oldest-then-push). This heuristic may over-count: not
        // every recv() adds a datagram (ACKs, stream data, etc.).
        if conn.is_dgram_recv_queue_full() {
            if let Some(c) = rx_counters.as_deref_mut() {
                c.record_drop(DropReason::QueueFull, 1, 0);
            }
        }
        match conn.recv(&mut pkt, info) {
            Ok(_) | Err(quiche::Error::Done) => {}
            Err(e) => {
                debug!(error = ?e, "quiche recv (non-fatal)");
                if let Some(c) = rx_counters.as_deref_mut() {
                    c.record_drop(DropReason::QuicError, 1, pkt.len() as u64);
                }
            }
        }
    }
}

/// Collects inbound QUIC DATAGRAMs with QSI validation and strips framing.
///
/// Records Rx success counters at decode time (Rx = decoded from QUIC, not
/// downstream delivery). Returns the batch for the caller to send via
/// `try_send` / pending pattern.
pub(crate) fn collect_router_ingress(
    conn: &mut quiche::Connection,
    max_udp_payload: usize,
    counters: &mut Counters,
    codec: &ConnectIpDatagramCodec,
) -> Vec<PooledBuf> {
    let mut batch = Vec::new();
    let mut ok_pkts: u64 = 0;
    let mut ok_bytes: u64 = 0;

    loop {
        let mut buf = alloc_uninit_packet_buf(max_udp_payload);
        match conn.dgram_recv(&mut buf) {
            Ok(len) => {
                buf.truncate(len);

                if !codec.strip(&mut buf) {
                    counters.record_drop(DropReason::InvalidFraming, 1, len as u64);
                    continue;
                }
                ok_pkts += 1;
                ok_bytes += buf.len() as u64;
                batch.push(buf);
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                warn!(error = ?e, "dgram_recv error");
                break;
            }
        }
    }

    if ok_pkts > 0 {
        counters.record_success(ok_pkts, ok_bytes);
    }
    batch
}

// ========== Backpressure ==========

/// Packet batch waiting for downstream channel capacity.
///
/// Used by both client and server engines for zero-drop backpressure.
/// Tracks when the batch first became pending (for congestion duration metrics).
pub(crate) struct PendingBatch {
    /// The buffered packet batch.
    pub(crate) batch: Vec<PooledBuf>,
    /// When the batch first became pending (for congestion duration tracking).
    pub(crate) since: Instant,
}

impl PendingBatch {
    pub(crate) fn new(batch: Vec<PooledBuf>) -> Self {
        Self {
            batch,
            since: Instant::now(),
        }
    }
}

// ========== QUIC Send Helpers ==========

/// Collects pending QUIC output packets into a batch.
///
/// Returns `None` when there is nothing to send, or `Some((dest, batch))`
/// where `dest` comes from the last [`quiche::SendInfo`] (the peer address
/// quiche wants the packets delivered to — tracks NAT rebinding).
fn collect_udp_send(
    conn: &mut quiche::Connection,
    max_udp_payload: usize,
) -> Option<(SocketAddr, Vec<PooledBuf>)> {
    let mut batch = Vec::new();
    let mut dest = None;
    loop {
        let mut buf = alloc_uninit_packet_buf(max_udp_payload);
        match conn.send(&mut buf) {
            Ok((len, send_info)) => {
                buf.truncate(len);
                batch.push(buf);
                // Safety: quiche builds packets on-the-fly from the current active
                // path — it never queues pre-formed UDP packets.  Path migration
                // only occurs inside `conn.recv()`, so `send_info.to` cannot
                // change within a single send loop.
                debug_assert!(
                    dest.is_none_or(|d| d == send_info.to),
                    "quiche returned mixed destinations in one send loop"
                );
                dest = Some(send_info.to);
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                warn!(error = ?e, "quiche send error");
                break;
            }
        }
    }
    dest.map(|d| (d, batch))
}

// ========== Router Egress ==========

/// Encodes egress IP packets as QUIC DATAGRAMs with QSI varint + Context ID prefix.
///
/// Drops packets when the dgram queue is full (counted via `DropReason::QueueFull`).
/// With cc=none the queue rarely fills; accepting the drop avoids retry complexity.
pub(crate) fn handle_router_egress(
    conn: &mut quiche::Connection,
    packets: Vec<PooledBuf>,
    codec: &ConnectIpDatagramCodec,
    counters: &mut Counters,
) {
    let mut ok_pkts: u64 = 0;
    let mut ok_bytes: u64 = 0;

    for mut pkt in packets {
        let pkt_len = pkt.len() as u64;
        if !codec.prepend(&mut pkt) {
            counters.record_drop(DropReason::NoHeadroom, 1, pkt_len);
            continue;
        }
        match conn.dgram_send(&pkt) {
            Ok(()) => {
                ok_pkts += 1;
                ok_bytes += pkt_len;
            }
            Err(quiche::Error::Done) => {
                counters.record_drop(DropReason::QueueFull, 1, pkt_len);
            }
            Err(e) => {
                warn!(error = ?e, "dgram_send failed; dropping packet");
                counters.record_drop(DropReason::QuicError, 1, pkt_len);
            }
        }
    }

    if ok_pkts > 0 {
        counters.record_success(ok_pkts, ok_bytes);
    }
}

/// Resets the pinned timer to the next quiche timeout deadline.
///
/// Uses `MAX_TIMEOUT` as sentinel when quiche returns `None` (no pending timers).
pub(crate) fn reset_timer(timer: std::pin::Pin<&mut time::Sleep>, conn: &quiche::Connection) {
    timer.reset(time::Instant::now() + conn.timeout().unwrap_or(MAX_TIMEOUT));
}

// ========== H3 Engine (unified client/server) ==========

/// Channels owned by the engine actor.
pub(crate) struct EngineIo {
    pub(crate) udp_recv_rx: mpsc::Receiver<(SocketAddr, Vec<PooledBuf>)>,
    pub(crate) udp_send_tx: mpsc::Sender<(SocketAddr, Vec<PooledBuf>)>,
    pub(crate) egress_rx: mpsc::Receiver<Vec<PooledBuf>>,
    pub(crate) ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    pub(crate) events_tx: mpsc::UnboundedSender<Event>,
}

/// Connection metadata shared across startup and established phases.
pub(crate) struct EngineMeta {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) peer_id: String,
    pub(crate) max_udp_payload: usize,
}

impl EngineMeta {
    /// Builds a [`quiche::RecvInfo`] for a packet received from `remote`.
    pub(crate) fn recv_info(&self, remote: SocketAddr) -> quiche::RecvInfo {
        quiche::RecvInfo {
            from: remote,
            to: self.local_addr,
        }
    }
}

/// Established-phase mutable state that does not own transport resources.
pub(crate) struct RunState {
    pub(crate) rx_counters: Counters,
    pub(crate) tx_counters: Counters,
    pub(crate) pending_ingress: Option<PendingBatch>,
    pub(crate) pending_send: Option<(SocketAddr, PendingBatch)>,
}

impl RunState {
    pub(crate) fn new() -> Self {
        Self {
            rx_counters: Counters::new(Source::Http3, Direction::Rx),
            tx_counters: Counters::new(Source::Http3, Direction::Tx),
            pending_ingress: None,
            pending_send: None,
        }
    }

    fn emit_metrics(&self, meta: &EngineMeta, events_tx: &mpsc::UnboundedSender<Event>) {
        let rx = self
            .rx_counters
            .snapshot(Some(&meta.peer_id), Some(meta.remote_addr));
        let tx = self
            .tx_counters
            .snapshot(Some(&meta.peer_id), Some(meta.remote_addr));
        let _ = events_tx.send(Event::Metrics(Box::new(rx)));
        let _ = events_tx.send(Event::Metrics(Box::new(tx)));
    }
}

/// Unified H3 engine actor for both client and server connections.
///
/// Owns the QUIC connection and all I/O channels. Client connections use
/// [`establish`](Self::establish) (in `h3dialer`) for handshake; server
/// connections use [`accept`](Self::accept) (in `h3listener`). Both then call
/// [`run`](Self::run) for steady-state datagram forwarding.
pub(crate) struct H3Engine {
    pub(crate) conn: quiche::Connection,
    pub(crate) session: Option<H3Session>,

    pub(crate) io: EngineIo,
    pub(crate) meta: EngineMeta,
    pub(crate) run_state: RunState,

    pub(crate) metrics_interval: Duration,
    pub(crate) keepalive_interval: Duration,

    /// Cancels associated UDP actors when the engine finishes.
    ///
    /// `None` for server-side engines where UDP actors are shared
    /// across all connections by the dispatcher.
    pub(crate) udp_cancel: Option<CancellationToken>,
}

impl H3Engine {
    /// Best-effort flush of QUIC output to the UDP send channel.
    ///
    /// Used during handshake where pending-send tracking is unnecessary.
    /// Drops on channel backpressure — acceptable because quiche retransmits.
    pub(crate) fn flush_send(&mut self) {
        if let Some(send) = collect_udp_send(&mut self.conn, self.meta.max_udp_payload) {
            let _ = self.io.udp_send_tx.try_send(send);
        }
    }

    /// Established phase: steady-state datagram forwarding.
    ///
    /// Uses two pending slots for backpressure:
    /// - `pending_ingress`: IP packets from `dgram_recv` waiting for `ingress_tx` capacity.
    /// - `pending_send`: encrypted QUIC packets waiting for `udp_send_tx` capacity.
    pub(crate) async fn run(self) -> ActorExitResult {
        let H3Engine {
            mut conn,
            session,
            io:
                EngineIo {
                    mut udp_recv_rx,
                    udp_send_tx,
                    mut egress_rx,
                    ingress_tx,
                    events_tx,
                },
            meta,
            mut run_state,
            metrics_interval,
            keepalive_interval,
            udp_cancel,
        } = self;
        let mut session = session.expect("session present after establish/accept");

        let mut ticker = time::interval(metrics_interval);
        let mut keepalive = time::interval(keepalive_interval);
        keepalive.tick().await;

        let timer = time::sleep(conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        let exit: Result<(), String> = loop {
            let ingress_pending = run_state.pending_ingress.is_some();
            let send_pending = run_state.pending_send.is_some();

            tokio::select! {
                maybe_batch = udp_recv_rx.recv(),
                    if !ingress_pending =>
                {
                    let Some((remote, packets)) = maybe_batch else {
                        break Ok(());
                    };

                    handle_udp_recv(&mut conn, packets, meta.recv_info(remote), Some(&mut run_state.rx_counters));

                    // Drain H3 control events. Post-establishment, this detects
                    // stream close/reset/goaway and rejects extra streams.
                    match session.poll_h3_events(
                        &mut conn,
                        &meta.peer_id,
                        &mut |_, _, _, _| Ok(HeaderAction::Ignore),
                    ) {
                        Ok(ConnectProgress::Pending | ConnectProgress::Ready) => {}
                        Err(err) => break Err(err.into_actor_reason()),
                    }

                    let batch = collect_router_ingress(
                        &mut conn,
                        meta.max_udp_payload,
                        &mut run_state.rx_counters,
                        &session.datagram_codec,
                    );
                    if !batch.is_empty() {
                        run_state.pending_ingress = match ingress_tx.try_send(batch) {
                            Ok(()) => None,
                            Err(mpsc::error::TrySendError::Full(b)) => Some(PendingBatch::new(b)),
                            Err(mpsc::error::TrySendError::Closed(_)) => break Ok(()),
                        };
                    }
                }

                permit_res = ingress_tx.reserve(),
                    if ingress_pending =>
                {
                    match permit_res {
                        Ok(permit) => {
                            let pending = run_state.pending_ingress.take().expect("pending ingress present");
                            run_state.rx_counters.record_queue_full(pending.since.elapsed());
                            permit.send(pending.batch);
                        }
                        Err(_) => break Ok(()),
                    }
                }

                maybe_batch = egress_rx.recv() => {
                    let Some(packets) = maybe_batch else {
                        break Ok(());
                    };

                    handle_router_egress(
                        &mut conn,
                        packets,
                        &session.datagram_codec,
                        &mut run_state.tx_counters,
                    );
                }

                permit_res = udp_send_tx.reserve(),
                    if send_pending =>
                {
                    match permit_res {
                        Ok(permit) => {
                            let (dest, pending) = run_state.pending_send.take()
                                .expect("pending send present");
                            run_state.tx_counters.record_queue_full(pending.since.elapsed());
                            permit.send((dest, pending.batch));
                        }
                        Err(_) => break Ok(()),
                    }
                }

                () = &mut timer => {
                    conn.on_timeout();
                }

                _ = keepalive.tick() => {
                    conn.send_ack_eliciting().ok();
                }

                _ = ticker.tick() => {
                    run_state.emit_metrics(&meta, &events_tx);
                }
            }

            if run_state.pending_send.is_none() {
                if let Some((dest, batch)) = collect_udp_send(&mut conn, meta.max_udp_payload) {
                    match udp_send_tx.try_send((dest, batch)) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full((_, b))) => {
                            run_state.pending_send = Some((dest, PendingBatch::new(b)));
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            break Err("UDP TX channel closed".into())
                        }
                    }
                }
            }
            reset_timer(timer.as_mut(), &conn);

            if conn.is_closed() {
                break Err("QUIC connection closed".into());
            }
        };

        // Single cleanup point: close QUIC and flush remaining packets.
        // Empty reason phrase avoids leaking implementation details in
        // the CONNECTION_CLOSE frame visible to the peer.
        conn.close(true, 0, b"").ok();
        if let Some(send) = collect_udp_send(&mut conn, meta.max_udp_payload) {
            let _ = udp_send_tx.send(send).await;
        }
        // Cancel the RX actor, which blocks on socket.readable().
        // TX actor exits naturally when udp_send_tx is dropped at
        // function return, draining any remaining batches first.
        if let Some(token) = udp_cancel {
            token.cancel();
        }
        exit.map_err(|reason| ActorError::H3Engine {
            peer_id: meta.peer_id.clone(),
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apply_transport_config_valid() {
        let h3_tuning = H3Tuning::default();
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        assert!(apply_transport_config(&mut config, &h3_tuning, 1350).is_ok());
    }

    #[test]
    fn apply_transport_config_rejects_bad_cc() {
        let h3_tuning = H3Tuning {
            h3_cc_algorithm: "invalid_algo".to_string(),
            ..H3Tuning::default()
        };
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        assert!(apply_transport_config(&mut config, &h3_tuning, 1350).is_err());
    }

    // ========== Engine Type Tests ==========

    fn test_meta() -> EngineMeta {
        EngineMeta {
            local_addr: "127.0.0.1:5000".parse().unwrap(),
            remote_addr: "10.0.0.1:443".parse().unwrap(),
            peer_id: "peer-x".into(),
            max_udp_payload: 1400,
        }
    }

    #[test]
    fn engine_meta_recv_info() {
        let meta = test_meta();
        let remote: SocketAddr = "10.0.0.2:9999".parse().unwrap();
        let info = meta.recv_info(remote);
        assert_eq!(info.from, remote);
        assert_eq!(info.to, meta.local_addr);
    }

    #[test]
    fn run_state_new_has_no_pending() {
        let state = RunState::new();
        assert!(state.pending_ingress.is_none());
        assert!(state.pending_send.is_none());
    }
}
