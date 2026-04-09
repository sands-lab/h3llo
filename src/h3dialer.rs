//! H3 CONNECT-IP client: dial, handshake, and steady-state datagram forwarding.
//!
//! Uses a hand-rolled quiche event loop with separated UDP I/O actors.
//! See [`dial_h3_client`] for the public entry point.

use crate::auth::generate_bearer_auth;
use crate::bind::{make_unbound_udp_socket, RouteProbe};
use crate::config::{PeerH3, Tuning};
use crate::events::{ConnOrigin, ConnectedEvent, DialContext, Endpoint};
use crate::h3engine::{
    apply_transport_config, handle_udp_recv, reset_timer, EngineIo, EngineMeta, H3Engine, RunState,
};
use crate::h3session::CONNECT_IP_OVERHEAD;
use crate::h3session::{ConnectFailure, ConnectProgress, H3Session, HeaderAction, MAX_TIMEOUT};
use crate::udp;
use quiche::h3::NameValue;
use rand::Rng;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;
use tokio_quiche::buf_factory::PooledBuf;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

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
        timeout: Duration,
    ) -> Result<Self, DialError> {
        // Send initial QUIC packets (e.g. ClientHello).
        self.flush_send();

        let deadline = time::sleep(timeout);
        tokio::pin!(deadline);
        let timer = time::sleep(self.conn.timeout().unwrap_or(MAX_TIMEOUT));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                maybe_batch = self.io.udp_recv_rx.recv() => {
                    let Some((remote, packets)) = maybe_batch else {
                        warn!(%self.meta.peer_id, "establish: UDP RX closed during startup");
                        return Err(DialError::Handshake("UDP Rx closed during startup".into()));
                    };

                    handle_udp_recv(&mut self.conn, packets, self.meta.recv_info(remote), None);

                    if self.session.is_none() && self.conn.is_established() {
                        debug!(%self.meta.peer_id, "QUIC established; starting H3 CONNECT-IP");
                        // Two-phase H3 startup: send SETTINGS in a separate
                        // QUIC packet before the CONNECT-IP request so the
                        // server's H3 driver processes SETTINGS first, avoiding
                        // a ControllerWentAway race in tokio-quiche.
                        self.session = Some(
                            H3Session::with_transport(&mut self.conn)
                                .map_err(DialError::Handshake)?,
                        );
                        self.flush_send();
                        Self::send_connect_request(
                            &mut self.conn,
                            self.session.as_mut().unwrap(),
                            &authority, &connect_path, &auth_header,
                        )?;
                    }

                    if let Some(session) = &mut self.session {
                        let connect_sid = session.connect_stream_id;
                        match session.poll_h3_events(
                            &mut self.conn,
                            &self.meta.peer_id,
                            &mut |_h3, _conn, sid, headers| {
                                if connect_sid != Some(sid) {
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

                _ = &mut deadline => {
                    warn!(%self.meta.peer_id, ?timeout, "establish: handshake timeout");
                    self.conn.close(true, 0, b"handshake timeout").ok();
                    self.flush_send();
                    return Err(DialError::Timeout(timeout));
                }
            }

            self.flush_send();
            reset_timer(timer.as_mut(), &self.conn);

            if self.conn.is_closed() {
                warn!(%self.meta.peer_id, "establish: QUIC connection closed during startup");
                return Err(DialError::Handshake(
                    "QUIC connection closed during startup".into(),
                ));
            }
        }
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
    apply_transport_config(&mut config, &tuning.h3, max_udp_payload)
        .map_err(|e| DialError::Handshake(format!("transport config: {e}")))?;
    if !tuning.h3.h3_insecure_skip_verify {
        // Enable TLS peer verification. System CA certificates are already
        // loaded by quiche::Config::new() via BoringSSL's
        // SSL_CTX_set_default_verify_paths().
        config.verify_peer(true);
        if let Some(ca_path) = &tuning.h3.h3_trusted_ca {
            config
                .load_verify_locations_from_file(ca_path)
                .map_err(|e| DialError::Handshake(format!("trusted CA `{ca_path}`: {e}")))?;
        }
    } else {
        config.verify_peer(false);
    }
    Ok(config)
}

// ========== Public Dial Function ==========

/// Establishes an outbound H3 client CONNECT-IP connection.
///
/// On success, returns [`ConnectedEvent`] with origin `Client`.
/// The caller is responsible for sending the event and handling errors.
pub(crate) async fn dial_h3_client<P: RouteProbe>(
    peer_h3: &PeerH3,
    remote_addr: SocketAddr,
    ctx: &DialContext,
    probe: &P,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
) -> Result<ConnectedEvent, DialError> {
    let DialContext {
        peer_id,
        tun_if,
        tun_mtu,
        tuning,
        udp_rt,
        crypto_rt,
        events_tx,
    } = ctx;
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
        Some(tun_if.as_str()),
        peer_h3.bindif.as_deref(),
        probe,
        tuning.io.socket_buffer_bytes(),
    )
    .await
    .map_err(|e| DialError::Socket(e.to_string()))?;

    let udp_cancel = CancellationToken::new();
    let cancel_guard = udp_cancel.clone().drop_guard();

    let (local_addr, max_udp_payload, udp_recv_rx, udp_rx_handle, udp_send_tx, udp_tx_handle) = {
        let _guard = udp_rt.enter();
        let local_addr = std_socket
            .local_addr()
            .map_err(|e| DialError::Socket(format!("local_addr: {e}")))?;
        let max_udp_payload = *tun_mtu + CONNECT_IP_OVERHEAD;
        let (udp_rx, udp_tx) =
            udp::make_udp(std_socket, max_udp_payload, tuning.io.udp_enable_offload)
                .map_err(|e| DialError::Socket(format!("make_udp: {e}")))?;
        let (udp_recv_tx, udp_recv_rx) =
            mpsc::channel::<(SocketAddr, Vec<PooledBuf>)>(tuning.io.packet_queue_depth);
        let udp_rx_handle = udp::spawn_udp_rx(udp_rx, udp_recv_tx, udp_cancel.clone());
        let (udp_send_tx, udp_tx_handle) = udp::spawn_udp_tx(udp_tx, tuning.io.packet_queue_depth);
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
    // Note: early `?` returns below are safe — `cancel_guard` cancels
    // the token on drop, causing both UDP actors to exit.
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

    let (egress_tx, egress_rx) = mpsc::channel::<Vec<PooledBuf>>(tuning.io.packet_queue_depth);

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

        metrics_interval: tuning.io.metrics_push_interval,
        keepalive_interval: tuning.h3.h3_keepalive_interval,
        origin: ConnOrigin::Client,
        udp_cancel: Some(udp_cancel),
    };

    let engine = crypto_rt
        .spawn(engine.establish(
            authority,
            connect_path,
            auth_header,
            tuning.h3.h3_handshake_timeout,
        ))
        .await
        .map_err(|join_err| {
            DialError::Handshake(format!("startup task join error: {join_err}"))
        })??;

    // Engine now owns the token — disarm the caller-side guard.
    cancel_guard.disarm();

    let engine_handle = crypto_rt.spawn(engine.run());

    Ok(ConnectedEvent {
        peer_id: peer_id.to_string(),
        remote_addr,
        tx: egress_tx,
        endpoint: peer_h3.endpoint.as_ref().map(|ep| Endpoint::H3(ep.clone())),
        main_handle: Some(engine_handle),
        udp_tx_handle: Some(udp_tx_handle),
        udp_rx_handle: Some(udp_rx_handle),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::ActorExitResult;
    use crate::bind::test_support::FakeRouteProbe;
    use crate::config::{default_mtu, H3Tuning};
    use crate::events::{ConnOrigin, ConnectedEvent, Event};
    use crate::h3::test_support::await_server_connection;
    use crate::h3::{
        make_h3_listener, spawn_h3_listener, spawn_h3_rx, spawn_h3_tx, H3ListenerCommand,
    };
    use crate::h3session::test_support::{insecure_tuning, test_peer_h3, TestCertBundle};
    use crate::h3session::ConnectFailure;
    use crate::helpers::alloc_packet_buf;
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

    // ========== make_client_quiche_config Unit Tests ==========

    #[test]
    fn make_client_config_bad_ca_path_errors() {
        let tuning = Tuning {
            h3: H3Tuning {
                h3_trusted_ca: Some("/nonexistent/ca.pem".to_string()),
                ..H3Tuning::default()
            },
            ..Tuning::default()
        };
        let err = make_client_quiche_config(&tuning, 1350)
            .err()
            .expect("should fail");
        assert!(
            matches!(err, DialError::Handshake(ref msg) if msg.contains("trusted CA")),
            "expected Handshake with trusted CA context, got: {err}",
        );
    }

    #[test]
    fn make_client_config_insecure_ignores_ca() {
        let tuning = Tuning {
            h3: H3Tuning {
                h3_insecure_skip_verify: true,
                h3_trusted_ca: Some("/nonexistent/ca.pem".to_string()),
                ..H3Tuning::default()
            },
            ..Tuning::default()
        };
        // Should succeed because insecure mode skips CA loading entirely.
        let result = make_client_quiche_config(&tuning, 1350);
        assert!(result.is_ok());
    }

    #[test]
    fn make_client_config_default_enables_verify_peer() {
        let tuning = Tuning::default();
        // Default tuning: verify_peer=true, no custom CA.
        // Should succeed — system CA certs are loaded automatically by quiche.
        make_client_quiche_config(&tuning, 1350)
            .map_err(|e| format!("default tuning should produce valid config: {e}"))
            .unwrap();
    }

    // ========== Integration Test Helpers ==========

    /// Test server wrapping h3.rs listener with cert and handle lifecycle management.
    struct TestServer {
        cmd_tx: mpsc::UnboundedSender<H3ListenerCommand>,
        events_rx: mpsc::UnboundedReceiver<Event>,
        bound_addr: SocketAddr,
        _certs: TestCertBundle,
        _handle: tokio::task::JoinHandle<ActorExitResult>,
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

    /// Dials the h3v2 client against a test server, returning the connected
    /// event and the ingress receiver (server-to-client datagram path).
    async fn dial_test_client(
        bound_addr: SocketAddr,
        token: &str,
        peer_id: &str,
    ) -> (ConnectedEvent, mpsc::Receiver<Vec<PooledBuf>>) {
        let peer_h3 = test_peer_h3(bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let tuning = insecure_tuning();

        let (ingress_tx, ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let ctx = DialContext::test(peer_id, tuning, events_tx);

        let event = dial_h3_client(&peer_h3, bound_addr, &ctx, &probe, ingress_tx)
            .await
            .expect("dial_h3_client failed");

        (event, ingress_rx)
    }

    // ========== h3v2 Client-Server Integration Tests ==========

    #[tokio::test]
    async fn h3v2_handshake_success() {
        let peer_id = "h3v2-test-client";
        let token = "h3v2-test-token-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let mut server = TestServer::start(peer_tokens).await;

        let (event, _ingress_rx) = dial_test_client(server.bound_addr, token, peer_id).await;

        assert_eq!(event.peer_id, peer_id);
        assert_eq!(event.remote_addr, server.bound_addr);

        // Server should emit H3Connected with correct peer_id.
        let server_event = await_server_connection(&mut server.events_rx).await;
        assert_eq!(server_event.connection.peer_id, peer_id);
        assert_eq!(server_event.origin, ConnOrigin::Server);

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

        let ctx = DialContext::test(peer_id, tuning, events_tx);

        let result = dial_h3_client(&peer_h3, server.bound_addr, &ctx, &probe, ingress_tx).await;

        assert!(
            matches!(result, Err(DialError::Rejected(_))),
            "expected Rejected, got {result:?}",
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
        let (event, _ingress_rx) = dial_test_client(server.bound_addr, token, peer_id).await;

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
        event.tx.send(vec![pkt]).await.expect("send failed");

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
        let (_event, mut ingress_rx) = dial_test_client(server.bound_addr, token, peer_id).await;

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
        let (event, mut ingress_rx) = dial_test_client(server.bound_addr, token, peer_id).await;

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
        event
            .tx
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
        let (event, _ingress_rx) = dial_test_client(server.bound_addr, token, peer_id).await;

        // Verify server accepted the connection.
        let _server_event = await_server_connection(&mut server.events_rx).await;

        // Drop the egress sender to trigger client shutdown.
        let ConnectedEvent {
            tx,
            main_handle,
            udp_rx_handle,
            udp_tx_handle,
            ..
        } = event;
        drop(tx);
        let engine_handle = main_handle.expect("client main_handle present");
        let udp_rx_handle = udp_rx_handle.expect("client udp_rx_handle present");
        let udp_tx_handle = udp_tx_handle.expect("client udp_tx_handle present");

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

    // ========== TLS Verification Integration Tests ==========

    #[tokio::test]
    async fn h3v2_handshake_with_trusted_ca() {
        let peer_id = "h3v2-ca-client";
        let token = "h3v2-ca-token-12ch";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let server = TestServer::start(peer_tokens).await;

        // Use the server's self-signed cert as the trusted CA.
        let ca_path = server
            ._certs
            .cert_path()
            .to_str()
            .expect("cert path is valid UTF-8")
            .to_string();

        let peer_h3 = test_peer_h3(server.bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let tuning = Tuning {
            h3: H3Tuning {
                h3_trusted_ca: Some(ca_path),
                ..H3Tuning::default()
            },
            ..Tuning::default()
        };

        let (ingress_tx, _ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let ctx = DialContext::test(peer_id, tuning, events_tx);

        let event = dial_h3_client(&peer_h3, server.bound_addr, &ctx, &probe, ingress_tx)
            .await
            .expect("dial with trusted CA should succeed");

        assert_eq!(event.peer_id, peer_id);
        drop(server.cmd_tx);
    }

    #[tokio::test]
    async fn h3v2_handshake_fails_without_trusted_ca() {
        let peer_id = "h3v2-notrust-client";
        let token = "h3v2-notrust-tok-12";
        let peer_tokens = HashMap::from([(peer_id.to_string(), token.to_string())]);

        let server = TestServer::start(peer_tokens).await;

        // Default tuning: verify_peer=true, no custom CA.
        // The server uses a self-signed cert not in the system trust store,
        // so the handshake should fail with a TLS verification error.
        let peer_h3 = test_peer_h3(server.bound_addr, token);
        let probe = FakeRouteProbe::noop();
        let tuning = Tuning::default();

        let (ingress_tx, _ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(16);
        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let ctx = DialContext::test(peer_id, tuning, events_tx);

        let result = dial_h3_client(&peer_h3, server.bound_addr, &ctx, &probe, ingress_tx).await;

        let err =
            result.expect_err("handshake with self-signed cert and no trusted CA should fail");
        assert!(
            matches!(err, DialError::Handshake(_)),
            "expected TLS Handshake error, got: {err}",
        );

        drop(server.cmd_tx);
    }
}
