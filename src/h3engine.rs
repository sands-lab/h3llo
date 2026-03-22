//! Unified H3 engine actor: QUIC connection management, packet I/O, and
//! backpressure for both client and server CONNECT-IP connections.
//!
//! The [`H3Engine`] struct owns the QUIC connection and all I/O channels.
//! Client connections use [`establish`](H3Engine::establish) (in
//! [`crate::h3dialer`]) for handshake; server connections use
//! [`accept`](H3Engine::accept) (in [`crate::h3listener`]). Both then call
//! [`run`](H3Engine::run) for steady-state datagram forwarding.

use crate::actor::{ActorError, ActorExitResult};
use crate::config::Tuning;
use crate::events::Event;
use crate::h3session::{
    ConnectIpDatagramCodec, ConnectProgress, H3Session, HeaderAction, MAX_TIMEOUT,
};
use crate::metrics::{Counters, Direction, DropReason, Source};
use crate::tun::alloc_uninit_packet_buf;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time;
use tokio_quiche::buf_factory::PooledBuf;
use tracing::{debug, warn};

// ========== Configuration Helpers ==========

/// Applies shared QUIC transport parameters to a quiche configuration.
///
/// Shared between client and server: payload sizes, flow control windows,
/// stream limits, DATAGRAM support, idle timeout, congestion control, pacing.
pub(crate) fn apply_transport_config(
    config: &mut quiche::Config,
    tuning: &Tuning,
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
    config.set_max_idle_timeout(tuning.h3_max_idle_timeout.as_millis() as u64);
    config.set_cc_algorithm_name(&tuning.h3_cc_algorithm)?;
    config.enable_pacing(tuning.h3_enable_pacing);
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
        // quiche silently drops the oldest datagram when the recv queue is
        // full (pop-oldest-then-push). Record so metrics can surface it.
        if conn.is_dgram_recv_queue_full() {
            if let Some(c) = rx_counters.as_deref_mut() {
                c.record_drop(DropReason::QueueFull, 1, 0);
            }
        }
        match conn.recv(&mut pkt, info) {
            Ok(_) | Err(quiche::Error::Done) => {}
            Err(e) => debug!(error = ?e, "quiche recv (non-fatal)"),
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
                debug!(error = ?e, "dgram_recv error");
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
/// Called by [`flush_udp_send`] to gather all queued QUIC output before
/// sending via the tagged UDP TX channel.
fn collect_udp_send(conn: &mut quiche::Connection, max_udp_payload: usize) -> Vec<PooledBuf> {
    let mut batch = Vec::new();
    loop {
        let mut buf = alloc_uninit_packet_buf(max_udp_payload);
        match conn.send(&mut buf) {
            Ok((len, _send_info)) => {
                buf.truncate(len);
                batch.push(buf);
            }
            Err(quiche::Error::Done) => break,
            Err(e) => {
                warn!(error = ?e, "quiche send error");
                break;
            }
        }
    }
    batch
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
                debug!(error = ?e, "dgram_send failed; dropping packet");
                counters.record_drop(DropReason::SendError, 1, pkt_len);
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

/// Discriminates client vs. server engine for error reporting.
#[derive(Debug, Clone, Copy)]
pub(crate) enum EngineRole {
    Client,
    Server,
}

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
    // TODO: For QUIC path migration / NAT rebinding, recv_info should be
    // constructed per-batch from the actual source address instead of using
    // a fixed remote_addr. Currently all callers (establish, accept, run)
    // ignore the per-batch remote and use this fixed value.
    pub(crate) fn recv_info(&self) -> quiche::RecvInfo {
        quiche::RecvInfo {
            from: self.remote_addr,
            to: self.local_addr,
        }
    }

    pub(crate) fn actor_error(&self, role: EngineRole, reason: impl Into<String>) -> ActorError {
        let peer_id = self.peer_id.clone();
        let reason = reason.into();
        match role {
            EngineRole::Client => ActorError::H3Client { peer_id, reason },
            EngineRole::Server => ActorError::H3Server { peer_id, reason },
        }
    }
}

/// Exit reason for the established-phase event loop.
///
/// Carried out of the loop via `break` so that QUIC close + UDP flush
/// happen exactly once, after the loop.
pub(crate) enum LoopExit {
    Ok(&'static [u8]),
    Err {
        close_reason: &'static [u8],
        reason: String,
    },
}

impl LoopExit {
    pub(crate) fn close_reason(&self) -> &'static [u8] {
        match self {
            Self::Ok(r) => r,
            Self::Err { close_reason, .. } => close_reason,
        }
    }

    pub(crate) fn into_result(self, meta: &EngineMeta, role: EngineRole) -> ActorExitResult {
        match self {
            Self::Ok(_) => Ok(()),
            Self::Err { reason, .. } => Err(meta.actor_error(role, reason)),
        }
    }
}

/// Established-phase mutable state that does not own transport resources.
pub(crate) struct RunState {
    pub(crate) rx_counters: Counters,
    pub(crate) tx_counters: Counters,
    pub(crate) pending_ingress: Option<PendingBatch>,
    pub(crate) pending_send: Option<PendingBatch>,
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
        let _ = events_tx.send(Event::Metrics(rx));
        let _ = events_tx.send(Event::Metrics(tx));
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
    pub(crate) role: EngineRole,
}

impl H3Engine {
    /// Best-effort flush of QUIC output to the UDP send channel.
    ///
    /// Used during handshake where pending-send tracking is unnecessary.
    /// Drops on channel backpressure — acceptable because quiche retransmits.
    pub(crate) fn flush_send(&mut self) {
        let batch = collect_udp_send(&mut self.conn, self.meta.max_udp_payload);
        if !batch.is_empty() {
            let _ = self.io.udp_send_tx.try_send((self.meta.remote_addr, batch));
        }
    }

    /// Established phase: steady-state datagram forwarding.
    ///
    /// Uses two pending slots for backpressure:
    /// - `pending_ingress`: IP packets from dgram_recv waiting for `ingress_tx` capacity.
    /// - `pending_send`: encrypted QUIC packets waiting for `udp_send_tx` capacity.
    pub(crate) async fn run(self) -> ActorExitResult {
        let recv_info = self.meta.recv_info();

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
            role,
        } = self;
        let mut session = session.expect("session present after establish/accept");

        let mut ticker = time::interval(metrics_interval);
        let mut keepalive = time::interval(keepalive_interval);
        keepalive.tick().await;

        let timer = time::sleep(conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        let exit: LoopExit = loop {
            let ingress_pending = run_state.pending_ingress.is_some();
            let send_pending = run_state.pending_send.is_some();

            tokio::select! {
                maybe_batch = udp_recv_rx.recv(),
                    if !ingress_pending =>
                {
                    let Some((_remote, packets)) = maybe_batch else {
                        break LoopExit::Ok(b"udp rx closed");
                    };

                    handle_udp_recv(&mut conn, packets, recv_info, Some(&mut run_state.rx_counters));

                    // Drain H3 control events. Post-establishment, this detects
                    // stream close/reset/goaway. The header-parsing branch is
                    // unreachable after establishment (server never sees :status;
                    // client's connect_ready() is already true).
                    match session.poll_h3_events(
                        &mut conn,
                        &meta.peer_id,
                        &mut |_, _, _, _| Ok(HeaderAction::Ignore),
                    ) {
                        Ok(ConnectProgress::Pending | ConnectProgress::Ready) => {}
                        Err(err) => break LoopExit::Err {
                            close_reason: err.close_reason(),
                            reason: err.into_actor_reason(),
                        },
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
                            Err(mpsc::error::TrySendError::Closed(_)) => break LoopExit::Ok(b"shutdown"),
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
                        Err(_) => break LoopExit::Ok(b"shutdown"),
                    }
                }

                maybe_batch = egress_rx.recv() => {
                    let Some(packets) = maybe_batch else {
                        break LoopExit::Ok(b"shutdown");
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
                            let pending = run_state.pending_send.take()
                                .expect("pending send present");
                            run_state.tx_counters.record_queue_full(pending.since.elapsed());
                            permit.send((meta.remote_addr, pending.batch));
                        }
                        Err(_) => break LoopExit::Ok(b"udp tx closed"),
                    }
                }

                _ = &mut timer => {
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
                let batch = collect_udp_send(&mut conn, meta.max_udp_payload);
                if !batch.is_empty() {
                    match udp_send_tx.try_send((meta.remote_addr, batch)) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full((_, b))) => {
                            run_state.pending_send = Some(PendingBatch::new(b));
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            break LoopExit::Err {
                                close_reason: b"udp tx closed",
                                reason: "UDP TX channel closed".into(),
                            }
                        }
                    }
                }
            }
            reset_timer(timer.as_mut(), &conn);

            if conn.is_closed() {
                break LoopExit::Err {
                    close_reason: b"conn closed",
                    reason: "QUIC connection closed".into(),
                };
            }
        };

        // Single cleanup point: close QUIC and flush remaining packets.
        conn.close(true, 0, exit.close_reason()).ok();
        let batch = collect_udp_send(&mut conn, meta.max_udp_payload);
        if !batch.is_empty() {
            let _ = udp_send_tx.send((meta.remote_addr, batch)).await;
        }
        exit.into_result(&meta, role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::ActorKind;

    #[test]
    fn apply_transport_config_valid() {
        let tuning = Tuning::default();
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        assert!(apply_transport_config(&mut config, &tuning, 1350).is_ok());
    }

    #[test]
    fn apply_transport_config_rejects_bad_cc() {
        let tuning = Tuning {
            h3_cc_algorithm: "invalid_algo".to_string(),
            ..Tuning::default()
        };
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        assert!(apply_transport_config(&mut config, &tuning, 1350).is_err());
    }

    // ========== Engine Type Tests ==========

    #[test]
    fn loop_exit_close_reason() {
        let ok = LoopExit::Ok(b"shutdown");
        assert_eq!(ok.close_reason(), b"shutdown");

        let err = LoopExit::Err {
            close_reason: b"conn closed",
            reason: "QUIC closed".into(),
        };
        assert_eq!(err.close_reason(), b"conn closed");
    }

    fn test_meta() -> EngineMeta {
        EngineMeta {
            local_addr: "127.0.0.1:5000".parse().unwrap(),
            remote_addr: "10.0.0.1:443".parse().unwrap(),
            peer_id: "peer-x".into(),
            max_udp_payload: 1400,
        }
    }

    #[test]
    fn loop_exit_into_result_ok() {
        let exit = LoopExit::Ok(b"graceful");
        assert!(exit.into_result(&test_meta(), EngineRole::Client).is_ok());
    }

    #[test]
    fn loop_exit_into_result_err_client() {
        let exit = LoopExit::Err {
            close_reason: b"conn closed",
            reason: "QUIC connection closed".into(),
        };
        let err = exit
            .into_result(&test_meta(), EngineRole::Client)
            .unwrap_err();
        assert!(matches!(&err, ActorError::H3Client { peer_id, reason }
            if peer_id == "peer-x" && reason == "QUIC connection closed"
        ));
        assert_eq!(err.kind(), ActorKind::Restartable);
    }

    #[test]
    fn loop_exit_into_result_err_server() {
        let exit = LoopExit::Err {
            close_reason: b"conn closed",
            reason: "auth failed".into(),
        };
        let err = exit
            .into_result(&test_meta(), EngineRole::Server)
            .unwrap_err();
        assert!(matches!(&err, ActorError::H3Server { peer_id, reason }
            if peer_id == "peer-x" && reason == "auth failed"
        ));
        assert_eq!(err.kind(), ActorKind::Restartable);
    }

    #[test]
    fn engine_meta_recv_info() {
        let meta = test_meta();
        let info = meta.recv_info();
        assert_eq!(info.from, meta.remote_addr);
        assert_eq!(info.to, meta.local_addr);
    }

    #[test]
    fn engine_meta_actor_error_client() {
        let meta = test_meta();
        let err = meta.actor_error(EngineRole::Client, "connection reset");
        assert!(matches!(&err, ActorError::H3Client { peer_id, reason }
            if peer_id == "peer-x" && reason == "connection reset"
        ));
        assert_eq!(err.kind(), ActorKind::Restartable);
    }

    #[test]
    fn engine_meta_actor_error_server() {
        let meta = test_meta();
        let err = meta.actor_error(EngineRole::Server, "auth failed");
        assert!(matches!(&err, ActorError::H3Server { peer_id, reason }
            if peer_id == "peer-x" && reason == "auth failed"
        ));
        assert_eq!(err.kind(), ActorKind::Restartable);
    }

    #[test]
    fn run_state_new_has_no_pending() {
        let state = RunState::new();
        assert!(state.pending_ingress.is_none());
        assert!(state.pending_send.is_none());
    }
}
