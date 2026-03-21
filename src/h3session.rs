//! H3 CONNECT-IP session state and DATAGRAM framing codec.
//!
//! Provides the H3 session (CONNECT-IP request/response binding), the
//! DATAGRAM framing codec (QSI + Context ID), and the control-plane
//! progress/failure types shared by [`crate::h3dialer`] and
//! [`crate::h3listener`].

use crate::h3::CONTEXT_ID_IP;
use octets::{varint_len, varint_parse_len, Octets, OctetsMut};
use std::time::Duration;
use tokio_quiche::buf_factory::PooledBuf;
use tracing::debug;

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
    /// Stream ID of the CONNECT-IP request.
    pub(crate) connect_stream_id: u64,
    /// CONNECT-IP DATAGRAM framing codec for this request stream.
    pub(crate) datagram_codec: ConnectIpDatagramCodec,
    /// Whether the CONNECT-IP request has been accepted (200 OK received).
    pub(crate) connect_accepted: bool,
}

impl H3Session {
    /// Creates a new H3 session bound to `conn`, before CONNECT-IP stream setup.
    pub(crate) fn with_transport(conn: &mut quiche::Connection) -> Result<Self, String> {
        let h3_config = quiche::h3::Config::new().map_err(|e| format!("h3 config: {e}"))?;
        let h3_conn = quiche::h3::Connection::with_transport(conn, &h3_config)
            .map_err(|e| format!("h3 connection: {e}"))?;

        Ok(Self {
            h3_conn: Box::new(h3_conn),
            connect_stream_id: 0,
            datagram_codec: ConnectIpDatagramCodec::new(0),
            connect_accepted: false,
        })
    }

    /// Binds the CONNECT-IP stream ID and updates the DATAGRAM codec.
    pub(crate) fn bind_connect_stream(&mut self, connect_stream_id: u64) {
        self.connect_stream_id = connect_stream_id;
        self.datagram_codec = ConnectIpDatagramCodec::new(connect_stream_id);
    }

    /// Marks the CONNECT-IP request as accepted.
    pub(crate) fn mark_connect_accepted(&mut self) {
        self.connect_accepted = true;
    }

    /// Returns `true` when the CONNECT-IP session is fully ready for datagram forwarding.
    pub(crate) fn connect_ready(&self, conn: &quiche::Connection) -> bool {
        self.connect_accepted
            && self.h3_conn.dgram_enabled_by_peer(conn)
            && self.h3_conn.extended_connect_enabled_by_peer()
    }

    /// Polls H3 events with a caller-supplied header handler.
    ///
    /// The generic `on_headers` callback processes role-specific header logic:
    /// - **Client**: checks `:status=200`, returns `Accept` or error.
    /// - **Server**: validates CONNECT-IP + auth, sends 200 OK,
    ///   returns `Accept { peer_id: Some(...) }` or error.
    /// - **Post-establishment**: use an ignore-all handler.
    ///
    /// After `connect_accepted` is true, headers are silently ignored
    /// regardless of the handler.
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
        let mut accepted_peer_id: Option<String> = None;

        loop {
            match self.h3_conn.poll(conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    // Post-acceptance headers (including duplicate CONNECT-IP
                    // requests) are silently ignored rather than hard-rejected,
                    // avoiding unnecessary connection teardown.
                    if self.connect_accepted {
                        debug!(%peer_id, stream_id, "ignoring headers post-establishment");
                        continue;
                    }
                    match on_headers(&mut self.h3_conn, conn, stream_id, &list)? {
                        HeaderAction::Accept {
                            stream_id: sid,
                            peer_id: pid,
                        } => {
                            self.bind_connect_stream(sid);
                            self.mark_connect_accepted();
                            accepted_peer_id = pid;
                        }
                        HeaderAction::Ignore => {}
                    }
                }

                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    if stream_id == self.connect_stream_id {
                        return Err(ConnectFailure::Closed("CONNECT-IP stream finished".into()));
                    }
                }

                Ok((stream_id, quiche::h3::Event::Reset(code))) => {
                    if stream_id == self.connect_stream_id {
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
                        ConnectProgress::Ready(accepted_peer_id.take())
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
pub(crate) enum ConnectProgress {
    /// CONNECT-IP is not ready for datagram forwarding yet.
    Pending,
    /// CONNECT-IP is fully established and ready for datagrams.
    ///
    /// Carries the authenticated peer ID for server-side acceptance
    /// (`Some(peer_id)`), or `None` for client / steady-state.
    Ready(Option<String>),
}

/// Error raised while advancing CONNECT-IP control-plane state.
pub(crate) enum ConnectFailure {
    /// CONNECT-IP rejected with the given status code.
    Rejected(String),
    /// CONNECT-IP stream closed unexpectedly.
    Closed(String),
    /// H3 control-plane polling itself failed.
    Poll(String),
}

impl ConnectFailure {
    pub(crate) fn close_reason(&self) -> &'static [u8] {
        match self {
            Self::Rejected(_) => b"connect-ip rejected",
            Self::Closed(_) => b"connect-ip control closed",
            Self::Poll(_) => b"h3 poll error",
        }
    }

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
    qsi_bytes: Vec<u8>,
}

impl ConnectIpDatagramCodec {
    pub(crate) fn new(connect_stream_id: u64) -> Self {
        let expected_qsi = connect_stream_id / 4;
        let qsi_bytes = encode_qsi(expected_qsi);
        Self {
            expected_qsi,
            qsi_bytes,
        }
    }

    fn prefix_len(&self) -> usize {
        self.qsi_bytes.len() + 1
    }

    pub(crate) fn prepend(&self, packet: &mut PooledBuf) -> bool {
        packet.add_prefix(&[CONTEXT_ID_IP]) && packet.add_prefix(&self.qsi_bytes)
    }

    pub(crate) fn strip(&self, packet: &mut PooledBuf) -> bool {
        let Some((qsi, qsi_len)) = decode_qsi(packet) else {
            return false;
        };
        if qsi != self.expected_qsi || qsi_len != self.qsi_bytes.len() {
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

    pub(crate) fn undo_prefix(&self, packet: &mut PooledBuf) {
        packet.pop_front(self.prefix_len());
    }
}

// ========== QSI Helpers ==========

/// Encodes a Quarter Stream ID as a QUIC varint byte sequence.
fn encode_qsi(qsi: u64) -> Vec<u8> {
    let len = varint_len(qsi);
    let mut buf = [0u8; 8];
    OctetsMut::with_slice(&mut buf)
        .put_varint(qsi)
        .expect("qsi fits varint");
    buf[..len].to_vec()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3::{CONNECT_IP_OVERHEAD, CONTEXT_ID_IP};
    use crate::tun::alloc_packet_buf;
    use tokio_quiche::buf_factory::BufFactory;

    #[test]
    fn datagram_framing_encode_decode() {
        let ip_payload = b"test ip packet";
        let qsi_bytes = encode_qsi(0);

        let mut buf = alloc_packet_buf(ip_payload);
        assert!(buf.add_prefix(&[CONTEXT_ID_IP]));
        assert!(buf.add_prefix(&qsi_bytes));

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
        assert_eq!(encode_qsi(0), vec![0x00]);
        assert_eq!(encode_qsi(1), vec![0x01]);
        assert_eq!(encode_qsi(63).len(), 1);
        let encoded = encode_qsi(64);
        assert_eq!(encoded.len(), 2);
        let parsed = Octets::with_slice(&encoded).get_varint().unwrap();
        assert_eq!(parsed, 64);
    }

    #[test]
    fn decode_qsi_roundtrip() {
        // Single-byte varints.
        assert_eq!(decode_qsi(&[0x00]), Some((0, 1)));
        assert_eq!(decode_qsi(&[0x01]), Some((1, 1)));
        assert_eq!(decode_qsi(&[0x3f]), Some((63, 1)));

        // Two-byte varint via QSI roundtrip.
        let encoded = encode_qsi(64);
        assert_eq!(decode_qsi(&encoded), Some((64, 2)));

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
            assert_eq!(codec.qsi_bytes, encode_qsi(expect_qsi), "sid={stream_id}");
            assert_eq!(codec.prefix_len(), expect_prefix, "sid={stream_id}");
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
        let mut buf = BufFactory::dgram_from_vec(framed);
        assert!(codec.strip(&mut buf));
        assert_eq!(&buf[..], b"ip packet");
    }

    #[test]
    fn codec_strip_rejects_wrong_qsi() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![0x01, CONTEXT_ID_IP, 0xFF]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_non_canonical_qsi() {
        // QSI=0 encoded as 2-byte varint 0x4000 instead of canonical 1-byte 0x00.
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![0x40, 0x00, CONTEXT_ID_IP, 0xFF]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_wrong_context_id() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![0x00, 0x01, 0xFF]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_empty_payload() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![0x00, CONTEXT_ID_IP]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_too_short() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![0x00]);
        assert!(!codec.strip(&mut buf));
    }

    #[test]
    fn codec_strip_rejects_empty_buffer() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = BufFactory::dgram_from_vec(vec![]);
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
            let mut recv_buf = BufFactory::dgram_from_vec(framed_data);
            assert!(
                codec.strip(&mut recv_buf),
                "strip failed for sid={stream_id}"
            );
            assert_eq!(&recv_buf[..], payload);
        }
    }

    #[test]
    fn codec_undo_prefix_restores_payload() {
        let codec = ConnectIpDatagramCodec::new(0);
        let mut buf = alloc_packet_buf(b"undo test");
        assert!(codec.prepend(&mut buf));
        codec.undo_prefix(&mut buf);
        assert_eq!(&buf[..], b"undo test");
    }

    // ========== ConnectFailure Tests ==========

    #[test]
    fn connect_failure_close_reason() {
        assert_eq!(
            ConnectFailure::Rejected("403".into()).close_reason(),
            b"connect-ip rejected"
        );
        assert_eq!(
            ConnectFailure::Closed("stream fin".into()).close_reason(),
            b"connect-ip control closed"
        );
        assert_eq!(
            ConnectFailure::Poll("h3 error".into()).close_reason(),
            b"h3 poll error"
        );
    }

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
