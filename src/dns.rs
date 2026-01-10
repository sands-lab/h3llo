//! DNS resolver coroutine: consumes resolve commands, processes UDP responses, retries on timeout, and emits events.

use crate::bind::{BindWarning, RouteProbe};
use crate::config::{parse_dns_server_uri, LocalDns};
use crate::events::{
    DnsAnswer, DnsAnswerRecord, DnsAnswerWarning, DnsEvent, DnsEventDetail, DnsRecordType,
    DnsTimeout, DnsUnexpected, DnsUnexpectedKind, Event,
};
use crate::udp::bind_socket;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use rand::Rng;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;

const DNS_BUFFER_SIZE: usize = 1500;
const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Commands accepted by the DNS resolver coroutine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsCommand {
    /// Resolve the provided hostname by sending A and AAAA queries.
    Resolve { host: String },
}

/// Describes resolver initialization failures.
#[derive(Debug, Error)]
pub enum ResolveInitError {
    /// DNS server URI could not be parsed.
    #[error("invalid dns server: {0}")]
    InvalidServer(String),
    /// DNS socket could not be prepared.
    #[error("dns resolver failed to initialize: {0}")]
    Socket(String),
}

/// Configures and spawns the DNS resolver coroutine.
#[derive(Debug, Clone)]
pub struct DnsResolver {
    server: SocketAddr,
    bind_interface: Option<String>,
    tun_if: Option<String>,
    timeout: Duration,
}

impl DnsResolver {
    /// Creates a resolver targeting `server`, binding to `bind_interface`, and using `timeout`.
    pub fn new(
        server: SocketAddr,
        bind_interface: Option<String>,
        tun_if: Option<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            server,
            bind_interface,
            tun_if,
            timeout,
        }
    }

    /// Builds a resolver from configuration.
    ///
    /// # Errors
    ///
    /// Returns `ResolveInitError::InvalidServer` when `local_dns.server` is malformed.
    pub fn from_config(
        local_dns: &LocalDns,
        tun_if: Option<String>,
        timeout: Duration,
    ) -> Result<Self, ResolveInitError> {
        let server =
            parse_dns_server_uri(&local_dns.server).map_err(ResolveInitError::InvalidServer)?;
        Ok(Self::new(server, local_dns.bindif.clone(), tun_if, timeout))
    }

    /// Spawns the DNS resolver coroutine, returning its join handle.
    ///
    /// # Errors
    ///
    /// Returns `ResolveInitError::Socket` when socket creation, binding, or connection fails.
    pub async fn spawn<P: RouteProbe + Send + Sync + 'static>(
        self,
        probe: P,
        command_rx: mpsc::Receiver<DnsCommand>,
        events_tx: mpsc::Sender<Event>,
    ) -> Result<JoinHandle<()>, ResolveInitError> {
        let (socket, bind_warnings) = self.prepare_socket(&probe).await?;
        let mut task = ResolverTask::new(self.server, self.timeout, command_rx, events_tx, socket);

        let handle = tokio::spawn(async move {
            task.emit_bind_warnings(bind_warnings).await;
            task.run().await;
        });

        Ok(handle)
    }

    /// Prepares and connects a UDP socket to the DNS server.
    ///
    /// # Errors
    ///
    /// Returns `ResolveInitError::Socket` when binding or connecting fails.
    async fn prepare_socket<P: RouteProbe>(
        &self,
        probe: &P,
    ) -> Result<(UdpSocket, Vec<BindWarning>), ResolveInitError> {
        let bind_addr: SocketAddr = match self.server {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
        };

        let (socket, warnings) = bind_socket(
            bind_addr,
            self.bind_interface.as_deref(),
            self.server.ip(),
            self.tun_if.as_deref(),
            probe,
        )
        .await
        .map_err(|e| ResolveInitError::Socket(e.to_string()))?;

        socket
            .connect(self.server)
            .await
            .map_err(|e| ResolveInitError::Socket(e.to_string()))?;

        Ok((socket, warnings))
    }
}

/// Tracks outstanding DNS queries by transaction ID.
#[derive(Debug, Clone)]
struct PendingRequest {
    host: String,
    record_type: DnsRecordType,
    last_sent: Instant,
}

/// Drives the DNS resolver coroutine.
struct ResolverTask {
    server: SocketAddr,
    socket: UdpSocket,
    timeout: Duration,
    command_rx: mpsc::Receiver<DnsCommand>,
    events_tx: mpsc::Sender<Event>,
    pending: HashMap<u16, PendingRequest>,
    command_rx_closed: bool,
}

impl ResolverTask {
    /// Constructs a resolver task with the provided socket and channels.
    fn new(
        server: SocketAddr,
        timeout: Duration,
        command_rx: mpsc::Receiver<DnsCommand>,
        events_tx: mpsc::Sender<Event>,
        socket: UdpSocket,
    ) -> Self {
        Self {
            server,
            socket,
            timeout,
            command_rx,
            events_tx,
            pending: HashMap::new(),
            command_rx_closed: false,
        }
    }

    /// Emits binding warnings as DNS events.
    async fn emit_bind_warnings(&mut self, warnings: Vec<BindWarning>) {
        for warning in warnings {
            let event = Event::Dns(DnsEvent {
                server: self.server,
                detail: DnsEventDetail::BindWarning(warning),
            });
            if self.events_tx.send(event).await.is_err() {
                break;
            }
        }
    }

    /// Runs the resolver loop with select over commands, UDP socket, and timer ticks.
    async fn run(&mut self) {
        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let mut ticker = time::interval(TICK_INTERVAL);

        loop {
            tokio::select! {
                maybe_cmd = self.command_rx.recv() => self.handle_command(maybe_cmd).await,
                result = self.socket.recv(&mut buf) => self.handle_recv(result, &buf).await,
                _ = ticker.tick() => self.handle_tick().await,
            }

            if self.command_rx_closed && self.pending.is_empty() {
                break;
            }
        }
    }

    /// Handles commands from the orchestrator queue.
    async fn handle_command(&mut self, command: Option<DnsCommand>) {
        match command {
            Some(DnsCommand::Resolve { host }) => {
                self.issue_query(host.clone(), DnsRecordType::A).await;
                self.issue_query(host, DnsRecordType::Aaaa).await;
            }
            None => {
                self.command_rx_closed = true;
            }
        }
    }

    /// Issues a query for `host` and `record_type`, emitting a send-failure event on error.
    async fn issue_query(&mut self, host: String, record_type: DnsRecordType) {
        if let Err(err) = self.send_query(host.clone(), record_type).await {
            self.emit_unexpected(
                None,
                Some(host),
                Some(record_type),
                DnsUnexpectedKind::SendFailed(err),
            )
            .await;
        }
    }

    /// Sends a DNS query packet and records it as pending.
    ///
    /// # Errors
    ///
    /// Returns an error string when query construction or send fails.
    async fn send_query(&mut self, host: String, record_type: DnsRecordType) -> Result<(), String> {
        let name = Name::from_ascii(&host).map_err(|e| e.to_string())?;

        let mut message = Message::new();
        let id = self.allocate_id();
        message.set_id(id);
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(record_type_query(name, record_type));

        let outbound = message.to_vec().map_err(|e| e.to_string())?;
        self.socket
            .send(&outbound)
            .await
            .map_err(|e| e.to_string())?;

        self.pending.insert(
            id,
            PendingRequest {
                host,
                record_type,
                last_sent: Instant::now(),
            },
        );

        Ok(())
    }

    /// Allocates a transaction ID unique among current pending requests.
    fn allocate_id(&self) -> u16 {
        loop {
            let candidate = rand::rng().random::<u16>();
            if !self.pending.contains_key(&candidate) {
                return candidate;
            }
        }
    }

    /// Handles UDP socket reads and dispatches decoded packets.
    async fn handle_recv(&mut self, result: io::Result<usize>, buf: &[u8]) {
        let len = match result {
            Ok(len) if len > 0 => len,
            Ok(_) => return,
            Err(_) => return,
        };

        let data = &buf[..len];
        self.handle_packet(data).await;
    }

    /// Parses a DNS packet and emits the corresponding event.
    async fn handle_packet(&mut self, data: &[u8]) {
        let message = match Message::from_vec(data) {
            Ok(msg) => msg,
            Err(err) => {
                self.emit_unexpected(
                    None,
                    None,
                    None,
                    DnsUnexpectedKind::DecodeFailed(err.to_string()),
                )
                .await;
                return;
            }
        };

        let id = message.id();
        if let Some(request) = self.pending.remove(&id) {
            self.handle_decoded_packet(message, request).await;
        } else {
            let record_type = message
                .queries()
                .first()
                .map(|q| DnsRecordType::from(q.query_type()));
            self.emit_unexpected(
                Some(id),
                None,
                record_type,
                DnsUnexpectedKind::UnknownTransaction,
            )
            .await;
        }
    }

    /// Handles a parsed DNS packet that matches a pending request.
    async fn handle_decoded_packet(&mut self, message: Message, request: PendingRequest) {
        let warnings = response_warnings(&message);
        let records = extract_records(&message, request.record_type);

        if message.response_code() == ResponseCode::NoError && records.is_empty() {
            if let Some(unexpected_type) = first_nonmatching_answer(&message, request.record_type) {
                self.emit_unexpected(
                    Some(message.id()),
                    Some(request.host),
                    Some(request.record_type),
                    DnsUnexpectedKind::UnexpectedRecordType(unexpected_type),
                )
                .await;
                return;
            }
        }

        let event = Event::Dns(DnsEvent {
            server: self.server,
            detail: DnsEventDetail::Answer(DnsAnswer {
                host: request.host,
                record_type: request.record_type,
                records,
                warnings,
            }),
        });

        let _ = self.events_tx.send(event).await;
    }

    /// Handles timer ticks by retrying timed-out pending queries.
    async fn handle_tick(&mut self) {
        let now = Instant::now();
        let mut expired = Vec::new();

        for (id, req) in &self.pending {
            if now.duration_since(req.last_sent) >= self.timeout {
                expired.push((*id, req.clone()));
            }
        }

        for (id, request) in expired {
            self.pending.remove(&id);
            self.emit_timeout(&request).await;
            if let Err(err) = self
                .send_query(request.host.clone(), request.record_type)
                .await
            {
                self.emit_unexpected(
                    None,
                    Some(request.host),
                    Some(request.record_type),
                    DnsUnexpectedKind::SendFailed(err),
                )
                .await;
            }
        }
    }

    /// Emits an unexpected event.
    async fn emit_unexpected(
        &mut self,
        id: Option<u16>,
        host: Option<String>,
        record_type: Option<DnsRecordType>,
        warning: DnsUnexpectedKind,
    ) {
        let event = Event::Dns(DnsEvent {
            server: self.server,
            detail: DnsEventDetail::Unexpected(DnsUnexpected {
                id,
                host,
                record_type,
                warning,
            }),
        });
        let _ = self.events_tx.send(event).await;
    }

    /// Emits a timeout event.
    async fn emit_timeout(&mut self, request: &PendingRequest) {
        let event = Event::Dns(DnsEvent {
            server: self.server,
            detail: DnsEventDetail::Timeout(DnsTimeout {
                host: request.host.clone(),
                record_type: request.record_type,
            }),
        });
        let _ = self.events_tx.send(event).await;
    }
}

/// Builds a query for `name` and `record_type`.
fn record_type_query(name: Name, record_type: DnsRecordType) -> Query {
    let mut query = Query::new();
    query.set_name(name);
    if let Some(rt) = to_record_type(record_type) {
        query.set_query_type(rt);
    }
    query
}

/// Converts a `DnsRecordType` into Hickory's `RecordType`.
fn to_record_type(record_type: DnsRecordType) -> Option<RecordType> {
    match record_type {
        DnsRecordType::A => Some(RecordType::A),
        DnsRecordType::Aaaa => Some(RecordType::AAAA),
        DnsRecordType::Other(_) => None,
    }
}

/// Extracts answers matching `expected`, deduplicating by IP and keeping an arbitrary TTL (order not guaranteed).
fn extract_records(message: &Message, expected: DnsRecordType) -> Vec<DnsAnswerRecord> {
    let mut records: HashMap<IpAddr, DnsAnswerRecord> = HashMap::new();

    for answer in message.answers() {
        let (ip, ttl) = match answer.data() {
            RData::A(addr) if expected == DnsRecordType::A => {
                (Some(IpAddr::V4(ipv4_from_rdata(addr))), answer.ttl())
            }
            RData::AAAA(addr) if expected == DnsRecordType::Aaaa => {
                (Some(IpAddr::V6(ipv6_from_rdata(addr))), answer.ttl())
            }
            _ => (None, 0u32),
        };

        if let Some(ip) = ip {
            records
                .entry(ip)
                .or_insert_with(|| DnsAnswerRecord { address: ip, ttl });
        }
    }

    records.into_values().collect()
}

/// Finds the first answer whose record type does not match `expected`.
fn first_nonmatching_answer(message: &Message, expected: DnsRecordType) -> Option<DnsRecordType> {
    for answer in message.answers() {
        let record_type = DnsRecordType::from(answer.record_type());
        if record_type != expected {
            return Some(record_type);
        }
    }
    None
}

/// Collects warnings from the DNS response code and flags.
fn response_warnings(message: &Message) -> Vec<DnsAnswerWarning> {
    let mut warnings = Vec::new();
    match message.response_code() {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => warnings.push(DnsAnswerWarning::NxDomain),
        ResponseCode::Refused => warnings.push(DnsAnswerWarning::Refused),
        other => warnings.push(DnsAnswerWarning::ResponseCode(format!("{other:?}"))),
    }

    if message.truncated() {
        warnings.push(DnsAnswerWarning::Truncated);
    }

    if !message.recursion_available() {
        warnings.push(DnsAnswerWarning::RecursionUnavailable);
    }

    warnings
}

/// Converts Hickory's IPv4 RDATA to `Ipv4Addr`.
fn ipv4_from_rdata(data: &hickory_proto::rr::rdata::A) -> std::net::Ipv4Addr {
    data.0
}

/// Converts Hickory's IPv6 RDATA to `Ipv6Addr`.
fn ipv6_from_rdata(data: &hickory_proto::rr::rdata::AAAA) -> std::net::Ipv6Addr {
    data.0
}

impl From<RecordType> for DnsRecordType {
    /// Converts Hickory's `RecordType` into the resolver-specific representation.
    fn from(value: RecordType) -> Self {
        match value {
            RecordType::A => DnsRecordType::A,
            RecordType::AAAA => DnsRecordType::Aaaa,
            other => DnsRecordType::Other(u16::from(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::RouteProbeError;
    use hickory_proto::rr::rdata::{A, AAAA, TXT};
    use hickory_proto::rr::Record;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    /// Route probe stub for DNS tests.
    #[derive(Clone)]
    struct FakeRouteProbe {
        result: Result<Vec<String>, RouteProbeError>,
    }

    impl RouteProbe for FakeRouteProbe {
        /// Returns the configured probe result.
        async fn probe_interfaces(
            &self,
            _target: &str,
            _tun_if: Option<&str>,
        ) -> Result<Vec<String>, RouteProbeError> {
            self.result.clone()
        }
    }

    /// Starts a resolver coroutine wired to the provided server socket.
    async fn start_resolver(
        server: SocketAddr,
        bindif: Option<String>,
    ) -> (
        mpsc::Sender<DnsCommand>,
        mpsc::Receiver<Event>,
        JoinHandle<()>,
    ) {
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let (event_tx, event_rx) = mpsc::channel(8);
        let resolver = DnsResolver::new(server, bindif, None, Duration::from_millis(50));
        let probe = FakeRouteProbe {
            result: Ok(Vec::new()),
        };
        let handle = resolver
            .spawn(probe, cmd_rx, event_tx)
            .await
            .expect("resolver spawn");

        (cmd_tx, event_rx, handle)
    }

    /// Builds a DNS response message for the provided transaction ID.
    fn build_response(
        id: u16,
        query: Query,
        response_code: ResponseCode,
        answers: Vec<Record>,
    ) -> Vec<u8> {
        let mut response = Message::new();
        response.set_id(id);
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_response_code(response_code);
        response.set_recursion_available(true);
        response.add_query(query);
        for answer in answers {
            response.add_answer(answer);
        }
        response.to_vec().unwrap()
    }

    /// Receives the next DNS event detail, skipping bind warnings.
    async fn next_relevant_detail(events_rx: &mut mpsc::Receiver<Event>) -> DnsEventDetail {
        loop {
            let event = events_rx.recv().await.expect("dns event");
            if let Event::Dns(dns) = event {
                match dns.detail {
                    DnsEventDetail::BindWarning(_) => continue,
                    detail => return detail,
                }
            }
        }
    }

    #[tokio::test]
    async fn emits_answers_with_warnings() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        cmd_tx
            .send(DnsCommand::Resolve {
                host: "example.com".to_string(),
            })
            .await
            .unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        let request = Message::from_vec(&buf[..len]).unwrap();
        let query = request.queries().first().cloned().unwrap();
        let response = build_response(
            request.id(),
            query.clone(),
            ResponseCode::NXDomain,
            vec![Record::from_rdata(
                query.name().clone().into(),
                60,
                RData::A(A(Ipv4Addr::new(1, 1, 1, 1))),
            )],
        );
        socket.send_to(&response, peer).await.unwrap();

        let (len2, peer2) = socket.recv_from(&mut buf).await.unwrap();
        let request2 = Message::from_vec(&buf[..len2]).unwrap();
        let query2 = request2.queries().first().cloned().unwrap();
        let response2 = build_response(
            request2.id(),
            query2.clone(),
            ResponseCode::NoError,
            vec![Record::from_rdata(
                query2.name().clone().into(),
                60,
                RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
            )],
        );
        socket.send_to(&response2, peer2).await.unwrap();

        let detail = next_relevant_detail(&mut events_rx).await;
        match detail {
            DnsEventDetail::Answer(answer) => {
                assert_eq!(answer.host, "example.com");
                assert_eq!(answer.record_type, DnsRecordType::A);
                assert!(answer.warnings.contains(&DnsAnswerWarning::NxDomain));
                assert_eq!(answer.records.len(), 1);
                assert_eq!(
                    answer.records[0].address,
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
                );
                assert_eq!(answer.records[0].ttl, 60);
            }
            _ => panic!("unexpected event"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn flags_unknown_transaction() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        cmd_tx
            .send(DnsCommand::Resolve {
                host: "unknown.test".to_string(),
            })
            .await
            .unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let (_len, peer) = socket.recv_from(&mut buf).await.unwrap();

        let mut message = Message::new();
        message.set_id(55);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);
        message.add_query(record_type_query(
            Name::from_ascii("example.com").unwrap(),
            DnsRecordType::A,
        ));

        let outbound = message.to_vec().unwrap();
        socket.send_to(&outbound, peer).await.unwrap();

        let detail = next_relevant_detail(&mut events_rx).await;
        match detail {
            DnsEventDetail::Unexpected(DnsUnexpected {
                warning: DnsUnexpectedKind::UnknownTransaction,
                ..
            }) => {}
            _ => panic!("unexpected event"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn deduplicates_answers_and_keeps_some_ttl() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        cmd_tx
            .send(DnsCommand::Resolve {
                host: "ttl.test".to_string(),
            })
            .await
            .unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        let request = Message::from_vec(&buf[..len]).unwrap();
        let query = request.queries().first().cloned().unwrap();
        let response = build_response(
            request.id(),
            query,
            ResponseCode::NoError,
            vec![
                Record::from_rdata(
                    Name::from_ascii("ttl.test").unwrap().into(),
                    120,
                    RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
                ),
                Record::from_rdata(
                    Name::from_ascii("ttl.test").unwrap().into(),
                    30,
                    RData::A(A(Ipv4Addr::new(10, 0, 0, 2))),
                ),
                Record::from_rdata(
                    Name::from_ascii("ttl.test").unwrap().into(),
                    90,
                    RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
                ),
            ],
        );
        socket.send_to(&response, peer).await.unwrap();

        let detail = next_relevant_detail(&mut events_rx).await;
        match detail {
            DnsEventDetail::Answer(answer) => {
                assert_eq!(answer.host, "ttl.test");
                assert_eq!(answer.record_type, DnsRecordType::A);
                let mut map = HashMap::new();
                for rec in answer.records {
                    map.insert(rec.address, rec.ttl);
                }
                assert_eq!(map.len(), 2);
                assert!(
                    matches!(
                        map.get(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                        Some(120) | Some(90)
                    ),
                    "ttl should be taken from one of the duplicated records"
                );
                assert_eq!(map.get(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))), Some(&30));
            }
            _ => panic!("unexpected event"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn flags_decode_failures() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        cmd_tx
            .send(DnsCommand::Resolve {
                host: "decode.test".to_string(),
            })
            .await
            .unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let (_len, peer) = socket.recv_from(&mut buf).await.unwrap();

        socket.send_to(b"not-dns", peer).await.unwrap();

        let detail = next_relevant_detail(&mut events_rx).await;
        match detail {
            DnsEventDetail::Unexpected(DnsUnexpected {
                warning: DnsUnexpectedKind::DecodeFailed(_),
                ..
            }) => {}
            _ => panic!("unexpected event"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn flags_unexpected_record_type() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        cmd_tx
            .send(DnsCommand::Resolve {
                host: "txt.example".to_string(),
            })
            .await
            .unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        let request = Message::from_vec(&buf[..len]).unwrap();
        let query = request.queries().first().cloned().unwrap();
        let response = build_response(
            request.id(),
            query,
            ResponseCode::NoError,
            vec![Record::from_rdata(
                Name::from_ascii("txt.example").unwrap().into(),
                60,
                RData::TXT(TXT::new(vec!["hello".to_string()])),
            )],
        );
        socket.send_to(&response, peer).await.unwrap();

        let (len2, peer2) = socket.recv_from(&mut buf).await.unwrap();
        let request2 = Message::from_vec(&buf[..len2]).unwrap();
        let query2 = request2.queries().first().cloned().unwrap();
        let response2 = build_response(
            request2.id(),
            query2.clone(),
            ResponseCode::NoError,
            vec![Record::from_rdata(
                query2.name().clone().into(),
                60,
                RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
            )],
        );
        socket.send_to(&response2, peer2).await.unwrap();

        let detail = next_relevant_detail(&mut events_rx).await;
        match detail {
            DnsEventDetail::Unexpected(DnsUnexpected {
                warning: DnsUnexpectedKind::UnexpectedRecordType(DnsRecordType::Other(16)),
                host,
                record_type,
                ..
            }) => {
                assert_eq!(host.as_deref(), Some("txt.example"));
                assert_eq!(record_type, Some(DnsRecordType::A));
            }
            _ => panic!("unexpected event"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn retries_with_new_id_on_timeout() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        cmd_tx
            .send(DnsCommand::Resolve {
                host: "timeout.example".to_string(),
            })
            .await
            .unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let mut first_ids: HashMap<DnsRecordType, u16> = HashMap::new();
        for _ in 0..2 {
            let (len, _peer) = socket.recv_from(&mut buf).await.unwrap();
            let message = Message::from_vec(&buf[..len]).unwrap();
            let query = message.queries().first().cloned().unwrap();
            first_ids.insert(DnsRecordType::from(query.query_type()), message.id());
        }

        let detail1 = next_relevant_detail(&mut events_rx).await;
        match detail1 {
            DnsEventDetail::Timeout(timeout) => {
                assert_eq!(timeout.host, "timeout.example");
            }
            _ => panic!("expected timeout event"),
        }

        let detail2 = next_relevant_detail(&mut events_rx).await;
        match detail2 {
            DnsEventDetail::Timeout(timeout) => {
                assert_eq!(timeout.host, "timeout.example");
            }
            _ => panic!("expected timeout event"),
        }

        let mut retry_ids: HashMap<DnsRecordType, u16> = HashMap::new();
        for _ in 0..2 {
            let (len, _peer) = socket.recv_from(&mut buf).await.unwrap();
            let message = Message::from_vec(&buf[..len]).unwrap();
            let query = message.queries().first().cloned().unwrap();
            retry_ids.insert(DnsRecordType::from(query.query_type()), message.id());
        }

        assert_ne!(
            first_ids.get(&DnsRecordType::A),
            retry_ids.get(&DnsRecordType::A)
        );
        assert_ne!(
            first_ids.get(&DnsRecordType::Aaaa),
            retry_ids.get(&DnsRecordType::Aaaa)
        );

        handle.abort();
    }
}
