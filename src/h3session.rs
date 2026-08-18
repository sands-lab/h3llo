//! H3 CONNECT-IP session state and DATAGRAM framing codec.
//!
//! Provides the H3 session (CONNECT-IP request/response binding), the
//! DATAGRAM framing codec (QSI + Context ID), and the control-plane
//! progress/failure types shared by [`crate::h3dialer`] and
//! [`crate::h3listener`].

use buffer_pool::PooledBuf;
use octets::{varint_len, varint_parse_len, Octets, OctetsMut};
use std::time::Duration;
use tracing::debug;

/// Context ID for IP payloads per RFC 9484 (always 0 for CONNECT-IP).
pub(crate) const CONTEXT_ID_IP: u8 = 0x00;

/// Conservative CONNECT-IP encapsulation overhead in bytes per
/// [RFC 9484 Section 7.2](https://datatracker.ietf.org/doc/html/rfc9484#section-7.2).
///
/// 51B base (QUIC v1 worst-case) + 8B optional DATAGRAM Length = 59B.
/// QUIC `max_send/recv_udp_payload_size` = `TUN_MTU + CONNECT_IP_OVERHEAD`.
pub(crate) const CONNECT_IP_OVERHEAD: usize = 59;

/// Duration used as "infinite" timeout when quiche returns None.
pub(crate) const MAX_TIMEOUT: Duration = Duration::from_secs(86400);

// ========== Header Action ==========

/// Action returned by the header handler callback in [`H3Session::poll_h3_events`].
pub(crate) enum HeaderAction {
    /// Accept the CONNECT-IP stream: bind stream + mark accepted.
    /// `peer_id` carries the authenticated identity for server-side
    /// acceptance (`None` for client).
    Accept {
        stream_id: u64,
        peer_id: Option<String>,
    },
    /// Ignore this header event (non-CONNECT stream or post-establishment).
    Ignore,
}

// ========== H3 Session ==========

/// H3 control/session state bound to the CONNECT-IP request.
pub(crate) struct H3Session {
    /// H3 connection for polling events and sending datagrams.
    ///
    /// Boxed because `quiche::h3::Connection` is ~544 B.
    pub(crate) h3_conn: Box<quiche::h3::Connection>,
    /// Stream ID of the CONNECT-IP request (`None` until bound).
    pub(crate) connect_stream_id: Option<u64>,
    /// CONNECT-IP DATAGRAM framing codec for this request stream.
    pub(crate) datagram_codec: ConnectIpDatagramCodec,
    /// Whether the CONNECT-IP request has been accepted (200 OK received).
    pub(crate) connect_accepted: bool,
    /// Authenticated peer ID set during server-side CONNECT-IP acceptance.
    ///
    /// `None` for client sessions. Consumed by the caller via `.take()`
    /// after `poll_h3_events` returns [`ConnectProgress::Ready`].
    pub(crate) accepted_peer_id: Option<String>,
}

impl H3Session {
    /// Creates a new H3 session bound to `conn`, before CONNECT-IP stream setup.
    pub(crate) fn with_transport(conn: &mut quiche::Connection) -> Result<Self, String> {
        let mut h3_config = quiche::h3::Config::new().map_err(|e| format!("h3 config: {e}"))?;
        h3_config.enable_extended_connect(true);
        let h3_conn = quiche::h3::Connection::with_transport(conn, &h3_config)
            .map_err(|e| format!("h3 connection: {e}"))?;

        Ok(Self {
            h3_conn: Box::new(h3_conn),
            connect_stream_id: None,
            datagram_codec: ConnectIpDatagramCodec::new(0),
            connect_accepted: false,
            accepted_peer_id: None,
        })
    }

    /// Binds the CONNECT-IP stream ID and updates the DATAGRAM codec.
    pub(crate) fn bind_connect_stream(&mut self, stream_id: u64) {
        self.connect_stream_id = Some(stream_id);
        self.datagram_codec = ConnectIpDatagramCodec::new(stream_id);
    }

    /// Returns `true` when the CONNECT-IP session is fully ready for datagram forwarding.
    ///
    /// Only checks `connect_accepted` (CONNECT-IP 200 OK exchanged) and
    /// `dgram_enabled_by_peer` (QUIC DATAGRAM transport parameter). The
    /// `extended_connect_enabled_by_peer()` check is intentionally omitted:
    /// per RFC 9220 only *servers* advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`,
    /// so the peer check fails on the server side where the client never sends it.
    /// Post-acceptance the check is also redundant — a successful CONNECT-IP
    /// exchange already proves extended CONNECT works.
    pub(crate) fn connect_ready(&self, conn: &quiche::Connection) -> bool {
        self.connect_accepted && self.h3_conn.dgram_enabled_by_peer(conn)
    }

    /// Polls H3 events with a caller-supplied header handler.
    ///
    /// The generic `on_headers` callback processes role-specific header logic:
    /// - **Client**: checks `:status=200`, returns `Accept` or error.
    /// - **Server**: validates CONNECT-IP + auth, sends 200 OK,
    ///   returns `Accept { peer_id: Some(...) }` or error.
    /// - **Post-establishment**: extra streams are rejected with 400 + FIN
    ///   (headers on the CONNECT-IP stream itself are still forwarded to
    ///   the handler). The caller typically passes an ignore-all handler.
    pub(crate) fn poll_h3_events<F>(
        &mut self,
        conn: &mut quiche::Connection,
        peer_id: &str,
        on_headers: &mut F,
    ) -> Result<ConnectProgress, ConnectFailure>
    where
        F: FnMut(
            &mut quiche::h3::Connection,
            &mut quiche::Connection,
            u64,
            &[quiche::h3::Header],
        ) -> Result<HeaderAction, ConnectFailure>,
    {
        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    // Ignore extra streams post-establishment without
                    // tearing down the connection. Shutdown the read side
                    // so the peer stops sending body data and quiche frees
                    // the stream's receive buffer.
                    if self.connect_accepted {
                        debug!(%peer_id, stream_id, "ignoring headers post-establishment");
                        conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                            .ok();
                        continue;
                    }
                    if let HeaderAction::Accept {
                        stream_id: sid,
                        peer_id: pid,
                    } = on_headers(&mut self.h3_conn, conn, stream_id, &list)?
                    {
                        self.bind_connect_stream(sid);
                        self.connect_accepted = true;
                        self.accepted_peer_id = pid;
                    }
                }

                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    if self.connect_stream_id == Some(stream_id) {
                        return Err(ConnectFailure::Closed("CONNECT-IP stream finished".into()));
                    }
                }

                Ok((stream_id, quiche::h3::Event::Reset(code))) => {
                    if self.connect_stream_id == Some(stream_id) {
                        return Err(ConnectFailure::Closed(format!(
                            "CONNECT-IP stream reset: {code}"
                        )));
                    }
                }

                Ok((_sid, quiche::h3::Event::GoAway)) => {
                    tracing::info!(%peer_id, "received H3 GOAWAY");
                    return Err(ConnectFailure::Closed("received GOAWAY".into()));
                }

                Ok((_sid, quiche::h3::Event::PriorityUpdate)) => {}

                Ok((_sid, ev)) => {
                    debug!(%peer_id, event = ?ev, "ignoring unrelated H3 event");
                }

                Err(quiche::h3::Error::Done) => {
                    return Ok(if self.connect_ready(conn) {
                        ConnectProgress::Ready
                    } else {
                        ConnectProgress::Pending
                    });
                }

                Err(e) => {
                    return Err(ConnectFailure::Poll(format!("H3 poll: {e}")));
                }
            }
        }
    }
}

// ========== CONNECT-IP Progress / Failure ==========

/// Result of advancing CONNECT-IP control-plane state.
#[derive(Debug)]
pub(crate) enum ConnectProgress {
    /// CONNECT-IP is not ready for datagram forwarding yet.
    Pending,
    /// CONNECT-IP is fully established and ready for datagrams.
    Ready,
}

/// Error raised while advancing CONNECT-IP control-plane state.
#[derive(Debug)]
pub(crate) enum ConnectFailure {
    /// CONNECT-IP rejected with the given status code.
    Rejected(String),
    /// CONNECT-IP stream closed unexpectedly.
    Closed(String),
    /// H3 control-plane polling itself failed.
    Poll(String),
}

impl ConnectFailure {
    pub(crate) fn into_actor_reason(self) -> String {
        match self {
            Self::Rejected(status) => format!("CONNECT-IP rejected after establish: {status}"),
            Self::Closed(reason) | Self::Poll(reason) => reason,
        }
    }
}

// ========== CONNECT-IP DATAGRAM Codec ==========

/// CONNECT-IP DATAGRAM framing codec bound to one CONNECT request stream.
pub(crate) struct ConnectIpDatagramCodec {
    expected_qsi: u64,
    qsi_buf: [u8; 8],
    qsi_len: usize,
}

impl ConnectIpDatagramCodec {
    pub(crate) fn new(connect_stream_id: u64) -> Self {
        let expected_qsi = connect_stream_id / 4;
        let (qsi_buf, qsi_len) = encode_qsi(expected_qsi);
        Self {
            expected_qsi,
            qsi_buf,
            qsi_len,
        }
    }

    fn qsi_bytes(&self) -> &[u8] {
        &self.qsi_buf[..self.qsi_len]
    }

    pub(crate) fn prepend(&self, packet: &mut PooledBuf) -> bool {
        packet.add_prefix(&[CONTEXT_ID_IP]) && packet.add_prefix(self.qsi_bytes())
    }

    pub(crate) fn strip(&self, packet: &mut PooledBuf) -> bool {
        let Some((qsi, qsi_len)) = decode_qsi(packet) else {
            return false;
        };
        if qsi != self.expected_qsi || qsi_len != self.qsi_len {
            return false;
        }

        let prefix_len = qsi_len + 1;
        if packet.len() < prefix_len || packet[qsi_len] != CONTEXT_ID_IP {
            return false;
        }
        if packet.len() == prefix_len {
            return false;
        }

        packet.pop_front(prefix_len);
        true
    }
}

// ========== QSI Helpers ==========

/// Encodes a Quarter Stream ID as a QUIC varint byte sequence.
fn encode_qsi(qsi: u64) -> ([u8; 8], usize) {
    let len = varint_len(qsi);
    let mut buf = [0u8; 8];
    OctetsMut::with_slice(&mut buf)
        .put_varint(qsi)
        .expect("qsi fits varint");
    (buf, len)
}

/// Decodes a Quarter Stream ID varint from the start of a buffer.
///
/// Returns `(qsi_value, qsi_byte_length)` on success.
fn decode_qsi(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let qsi_len = varint_parse_len(first);
    if buf.len() < qsi_len {
        return None;
    }

    let mut octets = Octets::with_slice(buf);
    let qsi = octets.get_varint().ok()?;
    Some((qsi, qsi_len))
}

/// Shared test utilities for H3 integration tests across modules.
///
/// Provides certificate generation, insecure TLS config, and peer config
/// builders used by h3dialer and h3listener integration tests.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::config::{H3Endpoint, H3Tuning, PeerH3, Tuning};
    use std::net::SocketAddr;

    /// Test certificate bundle with temporary files.
    pub struct TestCertBundle {
        _directory: tempfile::TempDir,
        cert_path: std::path::PathBuf,
        key_path: std::path::PathBuf,
    }

    impl TestCertBundle {
        /// Generates a self-signed certificate for localhost using rcgen.
        pub fn generate() -> Self {
            use rcgen::{generate_simple_self_signed, CertifiedKey};
            let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(subject_alt_names).expect("cert generation");

            let directory = tempfile::tempdir().expect("create certificate temp directory");
            let cert_path = directory.path().join("cert.pem");
            let key_path = directory.path().join("key.pem");
            std::fs::write(&cert_path, cert.pem()).expect("write cert");
            std::fs::write(&key_path, signing_key.serialize_pem()).expect("write key");

            Self {
                _directory: directory,
                cert_path,
                key_path,
            }
        }

        /// Returns the path to the certificate PEM file.
        pub fn cert_path(&self) -> &std::path::Path {
            &self.cert_path
        }

        /// Returns the path to the private key PEM file.
        pub fn key_path(&self) -> &std::path::Path {
            &self.key_path
        }
    }

    /// Returns `Tuning` with `h3_insecure_skip_verify: true` for tests.
    pub fn insecure_tuning() -> Tuning {
        Tuning {
            h3: H3Tuning {
                h3_insecure_skip_verify: true,
                ..H3Tuning::default()
            },
            ..Tuning::default()
        }
    }

    /// Creates a test `PeerH3` config pointing at the given server address.
    pub fn test_peer_h3(bound_addr: SocketAddr, token: &str) -> PeerH3 {
        PeerH3 {
            endpoint: Some(H3Endpoint {
                host: "localhost".to_string(),
                port: bound_addr.port(),
                path: "/.well-known/masque/udp/*/*/".to_string(),
            }),
            token: token.to_string(),
            bindif: None,
            sni: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::H3Tuning;
    use crate::h3engine::apply_transport_config;
    use crate::helpers::alloc_packet_buf;

    #[test]
    fn datagram_framing_encode_decode() {
        let ip_payload = b"test ip packet";
        let (qsi_buf, qsi_len) = encode_qsi(0);

        let mut buf = alloc_packet_buf(ip_payload);
        assert!(buf.add_prefix(&[CONTEXT_ID_IP]));
        assert!(buf.add_prefix(&qsi_buf[..qsi_len]));

        let data = &buf[..];
        let (qsi, qsi_len) = decode_qsi(data).expect("valid QSI");
        assert_eq!(qsi, 0);
        assert_eq!(data[qsi_len], CONTEXT_ID_IP);
        assert_eq!(&data[qsi_len + 1..], ip_payload);
    }

    #[test]
    fn constants_match_protocol() {
        assert_eq!(CONTEXT_ID_IP, 0x00);
        assert_eq!(CONNECT_IP_OVERHEAD, 59);
    }

    #[test]
    fn encode_qsi_roundtrip() {
        assert_eq!(encode_qsi(0), ([0x00, 0, 0, 0, 0, 0, 0, 0], 1));
        assert_eq!(encode_qsi(1), ([0x01, 0, 0, 0, 0, 0, 0, 0], 1));
        assert_eq!(encode_qsi(63).1, 1);
        let (buf, len) = encode_qsi(64);
        assert_eq!(len, 2);
        let parsed = Octets::with_slice(&buf[..len]).get_varint().unwrap();
        assert_eq!(parsed, 64);
    }

    #[test]
    fn decode_qsi_roundtrip() {
        // Single-byte varints.
        assert_eq!(decode_qsi(&[0x00]), Some((0, 1)));
        assert_eq!(decode_qsi(&[0x01]), Some((1, 1)));
        assert_eq!(decode_qsi(&[0x3f]), Some((63, 1)));

        // Two-byte varint via QSI roundtrip.
        let (buf, len) = encode_qsi(64);
        assert_eq!(decode_qsi(&buf[..len]), Some((64, 2)));

        // Empty buffer.
        assert_eq!(decode_qsi(&[]), None);

        // Truncated 2-byte varint (first byte indicates 2-byte encoding).
        assert_eq!(decode_qsi(&[0x40]), None);
    }

    // ========== ConnectIpDatagramCodec Tests ==========

    #[test]
    fn codec_new_qsi_and_prefix_len() {
        for (stream_id, expect_qsi, expect_prefix) in
            [(0, 0, 2), (4, 1, 2), (256, 64, 3), (1024, 256, 3)]
        {
            let codec = ConnectIpDatagramCodec::new(stream_id);
            assert_eq!(codec.expected_qsi, expect_qsi, "sid={stream_id}");
            let (expect_buf, expect_len) = encode_qsi(expect_qsi);
            assert_eq!(
                codec.qsi_bytes(),
                &expect_buf[..expect_len],
                "sid={stream_id}"
            );
            assert_eq!(codec.qsi_len + 1, expect_prefix, "sid={stream_id}");
        }
    }

    #[test]
    fn codec_prepend_adds_qsi_then_context_id() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = alloc_packet_buf(b"payload");
        assert!(codec.prepend(&mut buf));
        assert_eq!(buf[0], 0x00); // QSI
        assert_eq!(buf[1], CONTEXT_ID_IP); // Context ID
        assert_eq!(&buf[2..], b"payload");
    }

    #[test]
    fn codec_strip_happy_path() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut framed = vec![0x00, CONTEXT_ID_IP];
        framed.extend_from_slice(b"ip packet");
        let mut buf = alloc_packet_buf(&framed);
        assert!(codec.strip(&mut buf));
        assert_eq!(&buf[..], b"ip packet");
    }

    #[test]
    fn codec_strip_rejects_wrong_qsi() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = alloc_packet_buf(&[0x01, CONTEXT_ID_IP, 0xFF]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_non_canonical_qsi() {
        // QSI=0 encoded as 2-byte varint 0x4000 instead of canonical 1-byte 0x00.
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = alloc_packet_buf(&[0x40, 0x00, CONTEXT_ID_IP, 0xFF]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_wrong_context_id() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = alloc_packet_buf(&[0x00, 0x01, 0xFF]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_empty_payload() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = alloc_packet_buf(&[0x00, CONTEXT_ID_IP]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_too_short() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = alloc_packet_buf(&[0x00]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_empty_buffer() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = alloc_packet_buf(&[]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_roundtrip_prepend_strip() {
        for stream_id in [0u64, 4, 252, 256, 1024] {
            let codec = ConnectIpDatagramCodec::new(stream_id);
            let payload = b"roundtrip test payload";
            let mut buf = alloc_packet_buf(payload);
            assert!(
                codec.prepend(&mut buf),
                "prepend failed for sid={stream_id}"
            );
            let framed_data = buf[..].to_vec();
            let mut recv_buf = alloc_packet_buf(&framed_data);
            assert!(
                codec.strip(&mut recv_buf),
                "strip failed for sid={stream_id}"
            );
            assert_eq!(&recv_buf[..], payload);
        }
    }

    // ========== poll_h3_events Loopback Tests ==========

    /// In-memory quiche client-server pair with H3 sessions for testing
    /// `poll_h3_events` without network I/O.
    struct H3LoopbackPair {
        client_conn: quiche::Connection,
        server_conn: quiche::Connection,
        client_h3: H3Session,
        server_h3: H3Session,
        client_addr: std::net::SocketAddr,
        server_addr: std::net::SocketAddr,
        buf: Vec<u8>,
    }

    impl H3LoopbackPair {
        fn new() -> Self {
            use crate::h3session::test_support::TestCertBundle;

            let certs = TestCertBundle::generate();

            let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
            apply_transport_config(&mut client_config, &H3Tuning::default(), 1350).unwrap();
            client_config.verify_peer(false);

            let mut server_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
            apply_transport_config(&mut server_config, &H3Tuning::default(), 1350).unwrap();
            server_config
                .load_cert_chain_from_pem_file(certs.cert_path().to_str().unwrap())
                .unwrap();
            server_config
                .load_priv_key_from_pem_file(certs.key_path().to_str().unwrap())
                .unwrap();

            let client_addr: std::net::SocketAddr = "127.0.0.1:5000".parse().unwrap();
            let server_addr: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();

            let scid = quiche::ConnectionId::from_ref(&[0xaa; quiche::MAX_CONN_ID_LEN]);
            let dcid = quiche::ConnectionId::from_ref(&[0xbb; quiche::MAX_CONN_ID_LEN]);

            let mut client_conn = quiche::connect(
                Some("localhost"),
                &scid,
                client_addr,
                server_addr,
                &mut client_config,
            )
            .unwrap();

            let mut server_conn =
                quiche::accept(&dcid, None, server_addr, client_addr, &mut server_config).unwrap();

            // Drive QUIC handshake to completion.
            let mut buf = vec![0u8; 65535];
            loop {
                pump(
                    &mut client_conn,
                    &mut server_conn,
                    client_addr,
                    server_addr,
                    &mut buf,
                );
                pump(
                    &mut server_conn,
                    &mut client_conn,
                    server_addr,
                    client_addr,
                    &mut buf,
                );
                if client_conn.is_established() && server_conn.is_established() {
                    break;
                }
            }

            // Create H3 sessions on both sides.
            let client_h3 = H3Session::with_transport(&mut client_conn).unwrap();
            let server_h3 = H3Session::with_transport(&mut server_conn).unwrap();

            // Exchange H3 SETTINGS frames.
            pump(
                &mut client_conn,
                &mut server_conn,
                client_addr,
                server_addr,
                &mut buf,
            );
            pump(
                &mut server_conn,
                &mut client_conn,
                server_addr,
                client_addr,
                &mut buf,
            );

            Self {
                client_conn,
                server_conn,
                client_h3,
                server_h3,
                client_addr,
                server_addr,
                buf,
            }
        }

        /// Flush pending packets from client to server.
        fn flush_c2s(&mut self) {
            pump(
                &mut self.client_conn,
                &mut self.server_conn,
                self.client_addr,
                self.server_addr,
                &mut self.buf,
            );
        }

        /// Flush pending packets from server to client.
        fn flush_s2c(&mut self) {
            pump(
                &mut self.server_conn,
                &mut self.client_conn,
                self.server_addr,
                self.client_addr,
                &mut self.buf,
            );
        }

        /// Complete CONNECT-IP handshake: client sends CONNECT, server accepts.
        fn establish_connect_ip(&mut self) {
            let connect_headers = vec![
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":protocol", b"connect-ip"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"localhost"),
                quiche::h3::Header::new(b":path", b"/tunnel"),
                quiche::h3::Header::new(b"capsule-protocol", b"?1"),
            ];
            let stream_id = self
                .client_h3
                .h3_conn
                .send_request(&mut self.client_conn, &connect_headers, false)
                .unwrap();
            self.client_h3.bind_connect_stream(stream_id);

            self.flush_c2s();

            // Server polls: sees headers, accepts.
            let result = self.server_h3.poll_h3_events(
                &mut self.server_conn,
                "test-peer",
                &mut |h3, conn, sid, _headers| {
                    h3.send_response(
                        conn,
                        sid,
                        &[
                            quiche::h3::Header::new(b":status", b"200"),
                            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
                        ],
                        false,
                    )
                    .unwrap();
                    Ok(HeaderAction::Accept {
                        stream_id: sid,
                        peer_id: Some("test-peer".into()),
                    })
                },
            );
            assert!(matches!(
                result,
                Ok(ConnectProgress::Pending | ConnectProgress::Ready)
            ));
            assert!(self.server_h3.connect_accepted);

            self.flush_s2c();

            // Client polls: sees 200 OK.
            let connect_sid = self.client_h3.connect_stream_id;
            let result = self.client_h3.poll_h3_events(
                &mut self.client_conn,
                "client",
                &mut |_h3, _conn, sid, _headers| {
                    if connect_sid == Some(sid) {
                        Ok(HeaderAction::Accept {
                            stream_id: sid,
                            peer_id: None,
                        })
                    } else {
                        Ok(HeaderAction::Ignore)
                    }
                },
            );
            assert!(matches!(result, Ok(ConnectProgress::Ready)));
        }
    }

    /// Pump all pending packets from sender to receiver.
    fn pump(
        sender: &mut quiche::Connection,
        receiver: &mut quiche::Connection,
        from: std::net::SocketAddr,
        to: std::net::SocketAddr,
        buf: &mut [u8],
    ) {
        loop {
            let (len, _) = match sender.send(buf) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => panic!("send error: {e}"),
            };
            match receiver.recv(&mut buf[..len], quiche::RecvInfo { from, to }) {
                Ok(_) | Err(quiche::Error::Done) => {}
                Err(e) => panic!("recv error: {e}"),
            }
        }
    }

    #[test]
    fn poll_h3_events_rejects_extra_stream_post_establishment() {
        let mut pair = H3LoopbackPair::new();
        pair.establish_connect_ip();

        // Client opens an extra stream (e.g. a GET request).
        let extra_headers = vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/"),
        ];
        let extra_sid = pair
            .client_h3
            .h3_conn
            .send_request(&mut pair.client_conn, &extra_headers, true)
            .unwrap();
        assert_ne!(Some(extra_sid), pair.server_h3.connect_stream_id);

        pair.flush_c2s();

        // Server polls with ignore-all handler (post-establishment).
        let result =
            pair.server_h3
                .poll_h3_events(&mut pair.server_conn, "test-peer", &mut |_, _, _, _| {
                    Ok(HeaderAction::Ignore)
                });

        // Should NOT return error — connection stays alive.
        assert!(
            matches!(result, Ok(ConnectProgress::Ready)),
            "expected Ready, got {result:?}",
        );
    }

    #[test]
    fn poll_h3_events_finished_on_unbound_stream_0_ignored() {
        let mut pair = H3LoopbackPair::new();

        // Before any CONNECT-IP handshake, connect_stream_id is None.
        // Client opens a request on stream 0 and finishes it.
        assert!(!pair.server_h3.connect_accepted);
        assert!(pair.server_h3.connect_stream_id.is_none());

        let headers = vec![
            quiche::h3::Header::new(b":method", b"GET"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/probe"),
        ];
        let sid = pair
            .client_h3
            .h3_conn
            .send_request(&mut pair.client_conn, &headers, true)
            .unwrap();
        // First client bidi stream is stream ID 0.
        assert_eq!(sid, 0);

        pair.flush_c2s();

        // Server polls: sees Headers for stream 0 (handler ignores).
        // Then sees Finished for stream 0. Because connect_accepted is
        // false, this should NOT trigger ConnectFailure::Closed.
        let result = pair.server_h3.poll_h3_events(
            &mut pair.server_conn,
            "test-peer",
            &mut |h3, conn, stream_id, _headers| {
                let _ = h3.send_response(
                    conn,
                    stream_id,
                    &[quiche::h3::Header::new(b":status", b"400")],
                    true,
                );
                Ok(HeaderAction::Ignore)
            },
        );

        // Connection should stay alive (Pending, waiting for real CONNECT-IP).
        assert!(
            matches!(result, Ok(ConnectProgress::Pending)),
            "expected Pending, got {result:?}",
        );
    }

    #[test]
    fn poll_h3_events_reset_on_bound_stream_before_accept_detected() {
        let mut pair = H3LoopbackPair::new();

        // Client sends CONNECT-IP request (binds stream, but not yet accepted).
        let connect_headers = vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"localhost"),
            quiche::h3::Header::new(b":path", b"/tunnel"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ];
        let stream_id = pair
            .client_h3
            .h3_conn
            .send_request(&mut pair.client_conn, &connect_headers, false)
            .unwrap();
        pair.client_h3.bind_connect_stream(stream_id);
        assert!(!pair.client_h3.connect_accepted);
        assert_eq!(pair.client_h3.connect_stream_id, Some(stream_id));

        pair.flush_c2s();

        // Server receives headers, but instead of sending 200 OK, resets
        // the stream (simulating an abrupt rejection).
        let _ = pair.server_h3.poll_h3_events(
            &mut pair.server_conn,
            "test-peer",
            &mut |_h3, conn, sid, _headers| {
                conn.stream_shutdown(sid, quiche::Shutdown::Write, 0x0100)
                    .ok();
                Ok(HeaderAction::Ignore)
            },
        );
        pair.flush_s2c();

        // Client polls: should detect the Reset on the bound CONNECT stream
        // even though connect_accepted is still false.
        let result =
            pair.client_h3
                .poll_h3_events(&mut pair.client_conn, "client", &mut |_, _, _, _| {
                    Ok(HeaderAction::Ignore)
                });

        assert!(
            matches!(result, Err(ConnectFailure::Closed(_))),
            "expected Closed error on pre-accept reset, got {result:?}",
        );
    }

    // ========== ConnectFailure Tests ==========

    #[test]
    fn connect_failure_into_actor_reason() {
        let reason = ConnectFailure::Rejected("403".into()).into_actor_reason();
        assert!(reason.contains("CONNECT-IP rejected"));
        assert!(reason.contains("403"));

        let reason = ConnectFailure::Closed("fin".into()).into_actor_reason();
        assert_eq!(reason, "fin");

        let reason = ConnectFailure::Poll("poll err".into()).into_actor_reason();
        assert_eq!(reason, "poll err");
    }
}
