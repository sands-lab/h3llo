//! H3 CONNECT-IP client: dial, handshake, and steady-state datagram forwarding.
//!
//! Uses a hand-rolled quiche event loop with separated UDP I/O actors.
//! See [`dial_h3_client`] for the public entry point.

use crate::actor::ActorExitResult;
use crate::auth::generate_bearer_auth;
use crate::bind::{make_unbound_udp_socket, RouteProbe};
use crate::config::{PeerH3, Tuning};
use crate::events::Event;
use crate::h3engine::{
    apply_transport_config, handle_udp_recv, reset_timer, EngineIo, EngineMeta, EngineRole,
    H3Engine, RunState,
};
use crate::h3session::CONNECT_IP_OVERHEAD;
use crate::h3session::{ConnectFailure, ConnectProgress, H3Session, HeaderAction, MAX_TIMEOUT};
use crate::udp;
use quiche::h3::NameValue;
use rand::Rng;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_quiche::buf_factory::PooledBuf;
use tracing::{debug, info};

// ========== Connection Handle ==========

/// Established H3 client CONNECT-IP connection.
///
/// Returned by [`dial_h3_client`]. The `tx` sender feeds IP packets into the
/// H3 client actor for encryption and transmission. Join handles are for
/// orchestrator supervision.
pub struct H3ClientConn {
    /// Authenticated peer identifier.
    pub peer_id: String,
    /// Remote socket address.
    pub remote_addr: SocketAddr,
    /// Channel for sending IP packets (TUN → encrypt → UDP).
    pub tx: mpsc::Sender<Vec<PooledBuf>>,
    /// H3 client actor join handle.
    pub engine_handle: JoinHandle<ActorExitResult>,
    /// UDP Rx actor join handle.
    pub udp_rx_handle: JoinHandle<ActorExitResult>,
    /// UDP Tx actor join handle.
    pub udp_tx_handle: JoinHandle<ActorExitResult>,
}

impl std::fmt::Debug for H3ClientConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3ClientConn")
            .field("peer_id", &self.peer_id)
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}

// ========== Dial Error ==========

/// Dial error for H3 client connection establishment.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// Socket setup failed.
    #[error("socket: {0}")]
    Socket(String),
    /// QUIC/TLS handshake or H3 negotiation failed.
    #[error("handshake: {0}")]
    Handshake(String),
    /// CONNECT-IP rejected by peer.
    #[error("rejected: status {0}")]
    Rejected(String),
    /// Handshake timed out.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
}

impl From<ConnectFailure> for DialError {
    fn from(failure: ConnectFailure) -> Self {
        match failure {
            ConnectFailure::Rejected(status) => DialError::Rejected(status),
            ConnectFailure::Closed(reason) | ConnectFailure::Poll(reason) => {
                DialError::Handshake(reason)
            }
        }
    }
}

// ========== Client-Specific H3Engine Methods ==========

impl H3Engine {
    /// Startup phase: wait for QUIC establishment + H3 CONNECT-IP acceptance.
    async fn establish(
        mut self,
        authority: String,
        connect_path: String,
        auth_header: String,
    ) -> Result<Self, DialError> {
        let recv_info = self.meta.recv_info();

        // Send initial QUIC packets (e.g. ClientHello).
        self.flush_send();

        let timer = time::sleep(self.conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                maybe_batch = self.io.udp_recv_rx.recv() => {
                    let Some((_remote, packets)) = maybe_batch else {
                        return Err(DialError::Handshake("UDP Rx closed during startup".into()));
                    };

                    handle_udp_recv(&mut self.conn, packets, recv_info, None);

                    if self.session.is_none() && self.conn.is_established() {
                        debug!(%self.meta.peer_id, "QUIC established; starting H3 CONNECT-IP");
                        // Two-phase H3 startup: send SETTINGS in a separate
                        // QUIC packet before the CONNECT-IP request so the
                        // server's H3 driver processes SETTINGS first, avoiding
                        // a ControllerWentAway race in tokio-quiche.
                        Self::start_h3_session(&mut self.conn, &mut self.session)?;
                        self.flush_send();
                        Self::send_connect_request(
                            &mut self.conn,
                            self.session.as_mut().unwrap(),
                            &authority, &connect_path, &auth_header,
                        )?;
                    }

                    if let Some(session) = &mut self.session {
                        // Guaranteed set by send_connect_request → bind_connect_stream
                        // above. Note: stream ID 0 is valid (first client bidi stream).
                        let connect_sid = session.connect_stream_id;
                        match session.poll_h3_events(
                            &mut self.conn,
                            &self.meta.peer_id,
                            &mut |_h3, _conn, sid, headers| {
                                if sid != connect_sid {
                                    return Ok(HeaderAction::Ignore);
                                }
                                let status = headers
                                    .iter()
                                    .find(|h| h.name() == b":status")
                                    .map(|h| String::from_utf8_lossy(h.value()).to_string());
                                match status.as_deref() {
                                    Some("200") => Ok(HeaderAction::Accept {
                                        stream_id: sid,
                                        peer_id: None,
                                    }),
                                    Some(code) => {
                                        Err(ConnectFailure::Rejected(code.to_string()))
                                    }
                                    None => Err(ConnectFailure::Closed(
                                        "missing :status on CONNECT-IP response".into(),
                                    )),
                                }
                            },
                        ) {
                            Ok(ConnectProgress::Pending) => {}
                            Ok(ConnectProgress::Ready) => return Ok(self),
                            Err(err) => return Err(DialError::from(err)),
                        }
                    }
                }

                _ = &mut timer => {
                    self.conn.on_timeout();
                }
            }

            self.flush_send();
            reset_timer(timer.as_mut(), &self.conn);

            if self.conn.is_closed() {
                return Err(DialError::Handshake(
                    "QUIC connection closed during startup".into(),
                ));
            }
        }
    }

    /// Creates the H3 connection, queuing SETTINGS on the control stream.
    ///
    /// The caller should flush after this and before [`Self::send_connect_request`]
    /// so that the server processes SETTINGS before the CONNECT-IP request.
    fn start_h3_session(
        conn: &mut quiche::Connection,
        session: &mut Option<H3Session>,
    ) -> Result<(), DialError> {
        *session = Some(H3Session::with_transport(conn).map_err(DialError::Handshake)?);

        Ok(())
    }

    /// Sends the CONNECT-IP request on the session's H3 connection.
    fn send_connect_request(
        conn: &mut quiche::Connection,
        session: &mut H3Session,
        authority: &str,
        connect_path: &str,
        auth_header: &str,
    ) -> Result<(), DialError> {
        let connect_headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", authority.as_bytes()),
            quiche::h3::Header::new(b":path", connect_path.as_bytes()),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            quiche::h3::Header::new(b"authorization", auth_header.as_bytes()),
        ];

        let connect_stream_id = session
            .h3_conn
            .send_request(conn, &connect_headers, false)
            .map_err(|e| DialError::Handshake(format!("send CONNECT: {e}")))?;

        session.bind_connect_stream(connect_stream_id);

        Ok(())
    }
}

// ========== Configuration Helpers ==========

/// Creates a quiche QUIC client configuration.
fn make_client_quiche_config(
    tuning: &Tuning,
    max_udp_payload: usize,
) -> Result<quiche::Config, DialError> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| DialError::Handshake(format!("quiche config: {e}")))?;
    apply_transport_config(&mut config, tuning, max_udp_payload)
        .map_err(|e| DialError::Handshake(format!("transport config: {e}")))?;
    if tuning.h3_insecure_skip_verify {
        config.verify_peer(false);
    }
    // TODO: Load system CA certs when verify_peer is true.
    Ok(config)
}

// ========== Public Dial Function ==========

/// Establishes an outbound H3 client CONNECT-IP connection.
///
/// Creates a UDP socket and spawns UDP I/O actors on `udp_rt`, builds the
/// H3 client engine, and drives QUIC+H3 handshake on `crypto_rt` before
/// entering steady-state forwarding.
///
/// # Arguments
///
/// * `peer_h3` - Peer HTTP/3 configuration including endpoint, token, and TLS options.
/// * `remote_addr` - Resolved remote server socket address.
/// * `peer_id` - Authenticated peer identifier for logging and metrics.
/// * `tun_if` - Optional TUN interface to exclude from routing.
/// * `tun_mtu` - TUN MTU in bytes, used for QUIC payload sizing.
/// * `probe` - Route probe for interface selection.
/// * `tuning` - Tuning parameters (timeouts, buffers, congestion control).
/// * `udp_rt` - Runtime handle for UDP I/O actors (socket + Rx/Tx).
/// * `crypto_rt` - Runtime handle for the H3 engine (handshake + forwarding).
/// * `ingress_tx` - Channel to forward decrypted IP packets toward the TUN.
/// * `events_tx` - Channel for emitting metrics events.
///
/// # Errors
///
/// Returns `DialError` on socket, handshake, or timeout failure.
#[allow(clippy::too_many_arguments)]
pub async fn dial_h3_client<P: RouteProbe>(
    peer_h3: &PeerH3,
    remote_addr: SocketAddr,
    peer_id: &str,
    tun_if: Option<&str>,
    tun_mtu: u16,
    probe: &P,
    tuning: &Tuning,
    udp_rt: &RuntimeHandle,
    crypto_rt: &RuntimeHandle,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    events_tx: mpsc::UnboundedSender<Event>,
) -> Result<H3ClientConn, DialError> {
    let endpoint = peer_h3
        .endpoint
        .as_ref()
        .ok_or_else(|| DialError::Socket("peer_h3.endpoint is None".into()))?;

    let server_name = peer_h3.sni.as_deref().unwrap_or(&endpoint.host);

    let authority = if endpoint.port == 443 {
        endpoint.host.clone()
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };

    let connect_path = endpoint.path.clone();
    let auth_header = generate_bearer_auth(&peer_h3.token);

    // Create unconnected UDP socket, then register and spawn actors on udp_rt.
    let std_socket = make_unbound_udp_socket(
        remote_addr,
        tun_if,
        peer_h3.bindif.as_deref(),
        probe,
        tuning.socket_buffer_bytes(),
    )
    .await
    .map_err(|e| DialError::Socket(e.to_string()))?;

    let (local_addr, max_udp_payload, udp_recv_rx, udp_rx_handle, udp_send_tx, udp_tx_handle) = {
        let _guard = udp_rt.enter();
        let socket = UdpSocket::from_std(std_socket)
            .map_err(|e| DialError::Socket(format!("from_std: {e}")))?;
        let local_addr = socket
            .local_addr()
            .map_err(|e| DialError::Socket(format!("local_addr: {e}")))?;
        let max_udp_payload = tun_mtu as usize + CONNECT_IP_OVERHEAD;
        let (udp_rx, udp_tx) = udp::make_udp(socket, max_udp_payload, tuning.udp_enable_offload)
            .map_err(|e| DialError::Socket(format!("make_udp: {e}")))?;
        let (udp_recv_tx, udp_recv_rx) =
            mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(tuning.packet_queue_depth);
        let udp_rx_handle = udp::spawn_udp_rx(udp_rx, udp_recv_tx);
        let (udp_send_tx, udp_tx_handle) = udp::spawn_udp_tx(udp_tx, tuning.packet_queue_depth);
        (
            local_addr,
            max_udp_payload,
            udp_recv_rx,
            udp_rx_handle,
            udp_send_tx,
            udp_tx_handle,
        )
    };

    // Create quiche config and connection.
    let mut config = make_client_quiche_config(tuning, max_udp_payload)?;
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::rng().fill_bytes(&mut scid_bytes);
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let conn = quiche::connect(
        Some(server_name),
        &scid,
        local_addr,
        remote_addr,
        &mut config,
    )
    .map_err(|e| DialError::Handshake(format!("quiche connect: {e}")))?;

    let (egress_tx, egress_rx) = mpsc::channel::<Vec<PooledBuf>>(tuning.packet_queue_depth);

    let engine = H3Engine {
        conn,
        session: None,

        io: EngineIo {
            udp_recv_rx,
            udp_send_tx: udp_send_tx.clone(),
            egress_rx,
            ingress_tx,
            events_tx: events_tx.clone(),
        },
        meta: EngineMeta {
            local_addr,
            remote_addr,
            peer_id: peer_id.to_string(),
            max_udp_payload,
        },
        run_state: RunState::new(),

        metrics_interval: tuning.metrics_push_interval,
        keepalive_interval: tuning.h3_keepalive_interval,
        role: EngineRole::Client,
    };

    let startup_handle = crypto_rt.spawn(engine.establish(authority, connect_path, auth_header));
    tokio::pin!(startup_handle);

    let result = match time::timeout(tuning.h3_handshake_timeout, &mut startup_handle).await {
        Ok(Ok(result)) => result,
        Ok(Err(join_err)) => Err(DialError::Handshake(format!(
            "startup task join error: {join_err}"
        ))),
        Err(_) => {
            // Abort the detached establish task — dropping JoinHandle only
            // detaches in Tokio, it does not cancel the spawned task.
            startup_handle.abort();
            Err(DialError::Timeout(tuning.h3_handshake_timeout))
        }
    };

    let engine = match result {
        Ok(engine) => engine,
        Err(err) => {
            udp_rx_handle.abort();
            udp_tx_handle.abort();
            return Err(err);
        }
    };

    let engine_handle = crypto_rt.spawn(engine.run());

    info!(%peer_id, %remote_addr, "h3 client connection established");
    Ok(H3ClientConn {
        peer_id: peer_id.to_string(),
        remote_addr,
        tx: egress_tx,
        engine_handle,
        udp_rx_handle,
        udp_tx_handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::test_support::FakeRouteProbe;
    use crate::config::default_mtu;
    use crate::events::{ConnectionDirection, Event};
    use crate::h3::{make_h3_listener, spawn_h3_listener, spawn_h3_rx, spawn_h3_tx};
    use crate::h3session::test_support::{insecure_tuning, test_peer_h3, TestCertBundle};
    use crate::h3session::ConnectFailure;
    use crate::tun::alloc_packet_buf;
    use std::collections::HashMap;

    #[test]
    fn dial_error_display() {
        let err = DialError::Timeout(Duration::from_secs(5));
        assert!(err.to_string().contains("5s"));
        let err = DialError::Socket("bind failed".into());
        assert!(err.to_string().contains("socket"));
        let err = DialError::Handshake("TLS error".into());
        assert!(err.to_string().contains("handshake"));
        let err = DialError::Rejected("403".into());
        assert!(err.to_string().contains("rejected"));
    }

    #[tokio::test]
    async fn h3_client_connection_debug_omits_handles() {
        let (tx, _rx) = mpsc::channel::<Vec<PooledBuf>>(1);
        let conn = H3ClientConn {
            peer_id: "peer-1".into(),
            remote_addr: "1.2.3.4:443".parse().unwrap(),
            tx,
            engine_handle: tokio::spawn(async { Ok(()) }),
            udp_rx_handle: tokio::spawn(async { Ok(()) }),
            udp_tx_handle: tokio::spawn(async { Ok(()) }),
        };
        let dbg = format!("{conn:?}");
        assert!(dbg.contains("peer-1"));
        assert!(dbg.contains("1.2.3.4:443"));
        // Join handles are excluded by finish_non_exhaustive
        assert!(!dbg.contains("engine_handle"));
    }

    // ========== ConnectFailure → DialError Tests ==========

    #[test]
    fn connect_failure_into_dial_error() {
        let err: DialError = ConnectFailure::Rejected("403".into()).into();
        assert!(matches!(err, DialError::Rejected(s) if s == "403"));

        let err: DialError = ConnectFailure::Closed("stream closed".into()).into();
        assert!(matches!(err, DialError::Handshake(s) if s == "stream closed"));

        let err: DialError = ConnectFailure::Poll("poll failed".into()).into();
        assert!(matches!(err, DialError::Handshake(s) if s == "poll failed"));
    }

    // ========== Integration Test Helpers ==========

    use crate::h3::test_support::await_server_connection;

    /// Test server wrapping h3.rs listener with cert and handle lifecycle management.
    struct TestServer {
        cmd_tx: mpsc::UnboundedSender<crate::h3::H3ListenerCommand>,
        events_rx: mpsc::UnboundedReceiver<Event>,
        bound_addr: SocketAddr,
        _certs: TestCertBundle,
        _handle: JoinHandle<crate::actor::ActorExitResult>,
    }

    impl TestServer {
        async fn start(peer_tokens: HashMap<String, String>) -> Self {
            let certs = TestCertBundle::generate();
            let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

            let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
                .expect("make_h3_listener");

            let (events_tx, events_rx) = mpsc::unbounded_channel();
            let (cmd_tx, handle, bound_addr) = spawn_h3_listener(
                listener,
                peer_tokens,
                default_mtu(),
                events_tx,
                &Tuning::default(),
            );

            // Give listener time to start accepting.
            tokio::time::sleep(Duration::from_millis(50)).await;

            Self {
                cmd_tx,
                events_rx,
                bound_addr,
                _certs: certs,
                _handle: handle,
            }
        }
    }

    /// Dials the h3v2 client against a test server, returning the connection,
    /// the ingress receiver (server-to-client datagram path), and the events
    /// receiver (must be kept alive to prevent actor shutdown).
    async fn dial_test_client(
        bound_addr: SocketAddr,
        token: &str,
        peer_id: &str,
    ) -> (
        H3ClientConn,
        mpsc::Receiver<Vec<PooledBuf>>,
        mpsc::UnboundedReceiver<Event>,
    ) {
        let peer_h3 = test_peer_h3(bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let tuning = insecure_tuning();

        let (ingress_tx, ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        let conn = dial_h3_client(
            &peer_h3,
            bound_addr,
            peer_id,
            None,
            default_mtu(),
            &probe,
            &tuning,
            &tokio::runtime::Handle::current(),
            &tokio::runtime::Handle::current(),
            ingress_tx,
            events_tx,
        )
        .await
        .expect("dial_h3_client failed");

        (conn, ingress_rx, events_rx)
    }

    // ========== h3v2 Client-Server Integration Tests ==========

    #[tokio::test]
    async fn h3v2_handshake_success() {
        let peer_id = "h3v2-test-client";
        let token = "h3v2-test-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;

        let (conn, _ingress_rx, _cli_events_rx) =
            dial_test_client(server.bound_addr, token, peer_id).await;

        assert_eq!(conn.peer_id, peer_id);
        assert_eq!(conn.remote_addr, server.bound_addr);

        // Server should emit H3Connected with correct peer_id.
        let server_event = await_server_connection(&mut server.events_rx).await;
        assert_eq!(server_event.connection.peer_id, peer_id);
        assert_eq!(server_event.direction, ConnectionDirection::Inbound);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_handshake_rejected_wrong_token() {
        let peer_id = "h3v2-reject-peer";
        let correct_token = "correct-token-12";
        let wrong_token = "wrong-token-12ch";
        let peer_tokens = HashMap::from([(peer_id.to_string(), correct_token.to_string())]);

        let server = TestServer::start(peer_tokens).await;

        let peer_h3 = test_peer_h3(server.bound_addr, wrong_token);
        let probe = FakeRouteProbe::noop();
        let tuning = insecure_tuning();

        let (ingress_tx, _ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        let result = dial_h3_client(
            &peer_h3,
            server.bound_addr,
            peer_id,
            None,
            default_mtu(),
            &probe,
            &tuning,
            &tokio::runtime::Handle::current(),
            &tokio::runtime::Handle::current(),
            ingress_tx,
            events_tx,
        )
        .await;

        assert!(
            matches!(result, Err(DialError::Rejected(_))),
            "expected Rejected, got {:?}",
            result,
        );

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_datagram_client_to_server() {
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let peer_id = "h3v2-c2s-client";
        let token = "h3v2-c2s-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;
        let (conn, _ingress_rx, _cli_events_rx) =
            dial_test_client(server.bound_addr, token, peer_id).await;

        // Obtain server-side connection and set up RX actor.
        let server_event = await_server_connection(&mut server.events_rx).await;
        let (server_rx, _server_tx) = server_event.connection.into_actors();
        let (server_router_tx, mut server_router_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (srv_events_tx, _srv_events_rx) = mpsc::unbounded_channel();
        let _server_rx_handle = spawn_h3_rx(
            server_rx,
            server_router_tx,
            srv_events_tx,
            Duration::from_secs(60),
        );

        // Send test packet via h3v2 client.
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        let pkt = alloc_packet_buf(&test_packet);
        conn.tx.send(vec![pkt]).await.expect("send failed");

        // Verify server received the packet.
        let batch = tokio::time::timeout(Duration::from_secs(5), server_router_rx.recv())
            .await
            .expect("timeout waiting for datagram")
            .expect("channel closed");

        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &test_packet[..]);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_datagram_server_to_client() {
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let peer_id = "h3v2-s2c-client";
        let token = "h3v2-s2c-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;
        let (_conn, mut ingress_rx, _cli_events_rx) =
            dial_test_client(server.bound_addr, token, peer_id).await;

        // Obtain server-side connection and set up TX actor.
        let server_event = await_server_connection(&mut server.events_rx).await;
        let (_server_rx, server_tx) = server_event.connection.into_actors();
        let (srv_events_tx, _srv_events_rx) = mpsc::unbounded_channel();
        let (server_send_tx, _server_tx_handle) = spawn_h3_tx(
            server_tx,
            srv_events_tx,
            Duration::from_secs(60),
            256,
            Duration::from_secs(20),
        );

        // Send test packet from server.
        let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2));
        let pkt = alloc_packet_buf(&test_packet);
        server_send_tx.send(vec![pkt]).await.expect("send failed");

        // Verify client received the packet via ingress_rx.
        let batch = tokio::time::timeout(Duration::from_secs(5), ingress_rx.recv())
            .await
            .expect("timeout waiting for datagram")
            .expect("channel closed");

        assert_eq!(batch.len(), 1);
        assert_eq!(&batch[0][..], &test_packet[..]);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_datagram_bidirectional() {
        use crate::helpers::test_packets::make_ipv4_packet;
        use std::net::Ipv4Addr;

        let peer_id = "h3v2-bidir-client";
        let token = "h3v2-bidir-tok-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;
        let (conn, mut ingress_rx, _cli_events_rx) =
            dial_test_client(server.bound_addr, token, peer_id).await;

        // Set up server RX and TX actors.
        let server_event = await_server_connection(&mut server.events_rx).await;
        let (server_rx, server_tx) = server_event.connection.into_actors();
        let (srv_events_tx, _srv_events_rx) = mpsc::unbounded_channel();

        let (c2s_router_tx, mut c2s_router_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let _server_rx_handle = spawn_h3_rx(
            server_rx,
            c2s_router_tx,
            srv_events_tx.clone(),
            Duration::from_secs(60),
        );

        let (server_send_tx, _server_tx_handle) = spawn_h3_tx(
            server_tx,
            srv_events_tx,
            Duration::from_secs(60),
            256,
            Duration::from_secs(20),
        );

        // Client -> Server
        let packet_c2s = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
        conn.tx
            .send(vec![alloc_packet_buf(&packet_c2s)])
            .await
            .expect("c2s send failed");
        let batch_c2s = tokio::time::timeout(Duration::from_secs(5), c2s_router_rx.recv())
            .await
            .expect("timeout c2s")
            .expect("channel closed");
        assert_eq!(&batch_c2s[0][..], &packet_c2s[..]);

        // Server -> Client
        let packet_s2c = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2));
        server_send_tx
            .send(vec![alloc_packet_buf(&packet_s2c)])
            .await
            .expect("s2c send failed");
        let batch_s2c = tokio::time::timeout(Duration::from_secs(5), ingress_rx.recv())
            .await
            .expect("timeout s2c")
            .expect("channel closed");
        assert_eq!(&batch_s2c[0][..], &packet_s2c[..]);

        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_connection_shutdown() {
        let peer_id = "h3v2-shutdown-peer";
        let token = "h3v2-shutdown-tk12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;
        let (conn, _ingress_rx, _cli_events_rx) =
            dial_test_client(server.bound_addr, token, peer_id).await;

        // Verify server accepted the connection.
        let _server_event = await_server_connection(&mut server.events_rx).await;

        // Drop the egress sender to trigger client shutdown.
        let H3ClientConn {
            engine_handle,
            udp_rx_handle,
            udp_tx_handle,
            tx,
            ..
        } = conn;
        drop(tx);

        // Engine handle should terminate cleanly within a reasonable timeout.
        let engine_result = tokio::time::timeout(Duration::from_secs(5), engine_handle)
            .await
            .expect("engine_handle did not terminate in time")
            .expect("engine task panicked");
        assert!(
            engine_result.is_ok(),
            "engine exited with error: {:?}",
            engine_result
        );

        // UDP actors may be aborted by the engine or complete on their own.
        // Best-effort check: they should not hang indefinitely.
        let _ = tokio::time::timeout(Duration::from_secs(2), udp_rx_handle).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), udp_tx_handle).await;

        drop(server.cmd_tx);
    }
}
