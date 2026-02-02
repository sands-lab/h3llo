//! DNS resolver coroutine: consumes SetHostnames commands, manages IP lifecycle with TTL-based expiration,
//! and emits IpResolved/IpExpired events.

use crate::actor::{ActorError, ActorExitResult};
use crate::bind::{make_client_udp_socket, RouteProbe};
use crate::config::{parse_dns_server_uri, LocalDns};
use crate::events::{DnsEvent, DnsEventDetail, DnsIpExpired, DnsIpResolved, Event};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::warn;

const DNS_BUFFER_SIZE: usize = 1500;
const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Minimum TTL floor to prevent excessive refresh (60 seconds).
const MIN_TTL_SECS: u32 = 60;

/// Commands accepted by the DNS resolver coroutine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsCommand {
    /// Register/update the set of hostnames to monitor.
    ///
    /// Replaces the previous registration set entirely. The DNS module will:
    /// - Start tracking new hostnames (issue queries, emit IpResolved)
    /// - Continue tracking existing hostnames (refresh before TTL expiry)
    /// - Stop tracking removed hostnames (emit IpExpired for active IPs)
    SetHostnames { hosts: HashSet<String> },
}

/// Cached DNS resolution result with expiration tracking.
#[derive(Debug, Clone)]
struct CachedRecord {
    /// Absolute expiration time.
    expires_at: Instant,
}

impl CachedRecord {
    /// Creates a new cached record with TTL floored to MIN_TTL_SECS.
    fn new(ttl: u32) -> Self {
        let ttl_secs = ttl.max(MIN_TTL_SECS);
        let expires_at = Instant::now() + Duration::from_secs(ttl_secs as u64);
        Self { expires_at }
    }

    /// Returns true if this record has expired.
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Refreshes the TTL, resetting the expiration time.
    fn refresh(&mut self, ttl: u32) {
        let ttl_secs = ttl.max(MIN_TTL_SECS);
        self.expires_at = Instant::now() + Duration::from_secs(ttl_secs as u64);
    }
}

/// Represents DNS record types supported by the resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    /// IPv4 A record.
    A,
    /// IPv6 AAAA record.
    Aaaa,
    /// Non-A/AAAA record type.
    Other(u16),
}

/// Internal representation of a DNS answer record with its TTL.
/// Used during response processing before caching.
#[derive(Debug, Clone)]
struct DnsAnswerRecord {
    /// Resolved IP address.
    address: IpAddr,
    /// Time-to-live in seconds for the record.
    ttl: u32,
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
    refresh_interval: Duration,
}

impl DnsResolver {
    /// Creates a resolver targeting `server`, binding to `bind_interface`, and using `timeout`.
    pub fn new(
        server: SocketAddr,
        bind_interface: Option<String>,
        tun_if: Option<String>,
        timeout: Duration,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            server,
            bind_interface,
            tun_if,
            timeout,
            refresh_interval,
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
        let refresh_interval = Duration::from_secs(local_dns.refresh);
        Ok(Self::new(
            server,
            local_dns.bindif.clone(),
            tun_if,
            timeout,
            refresh_interval,
        ))
    }

    /// Spawns the DNS resolver coroutine.
    ///
    /// Creates an unbounded command channel internally (actor owns the receiver).
    /// Returns the command sender and join handle. The actor exits when all
    /// senders are dropped, closing the channel naturally.
    ///
    /// # Errors
    ///
    /// Returns `ResolveInitError::Socket` when socket creation, binding, or connection fails.
    pub async fn spawn<P: RouteProbe + Send + Sync + 'static>(
        self,
        probe: P,
        events_tx: mpsc::UnboundedSender<Event>,
    ) -> Result<
        (
            mpsc::UnboundedSender<DnsCommand>,
            JoinHandle<ActorExitResult>,
        ),
        ResolveInitError,
    > {
        // Actor creates and owns its command channel receiver
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

        let socket = self.prepare_socket(&probe).await?;
        let server_str = self.server.to_string();
        let mut task = ResolverTask::new(
            self.server,
            self.timeout,
            cmd_rx,
            events_tx,
            socket,
            self.refresh_interval,
        );

        let handle = tokio::spawn(async move { task.run(server_str).await });

        Ok((cmd_tx, handle))
    }

    /// Prepares and connects a UDP socket to the DNS server.
    ///
    /// # Errors
    ///
    /// Returns `ResolveInitError::Socket` when binding or connecting fails.
    async fn prepare_socket<P: RouteProbe>(
        &self,
        probe: &P,
    ) -> Result<UdpSocket, ResolveInitError> {
        make_client_udp_socket(
            self.server,
            self.tun_if.as_deref(),
            self.bind_interface.as_deref(),
            probe,
        )
        .await
        .map_err(|e| ResolveInitError::Socket(e.to_string()))
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
    cmd_rx: mpsc::UnboundedReceiver<DnsCommand>,
    events_tx: mpsc::UnboundedSender<Event>,
    pending: HashMap<u16, PendingRequest>,
    cmd_rx_closed: bool,
    /// Registered hostnames for lifecycle tracking.
    registered_hosts: HashSet<String>,
    /// IP cache: (hostname, IP) -> cached record.
    cache: HashMap<(String, IpAddr), CachedRecord>,
    /// Refresh interval from config.
    refresh_interval: Duration,
}

impl ResolverTask {
    /// Constructs a resolver task with the provided socket and channels.
    fn new(
        server: SocketAddr,
        timeout: Duration,
        cmd_rx: mpsc::UnboundedReceiver<DnsCommand>,
        events_tx: mpsc::UnboundedSender<Event>,
        socket: UdpSocket,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            server,
            socket,
            timeout,
            cmd_rx,
            events_tx,
            pending: HashMap::new(),
            cmd_rx_closed: false,
            registered_hosts: HashSet::new(),
            cache: HashMap::new(),
            refresh_interval,
        }
    }

    /// Runs the resolver loop with select over commands, UDP socket, and timer ticks.
    async fn run(&mut self, server_str: String) -> ActorExitResult {
        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let mut ticker = time::interval(TICK_INTERVAL);

        // Refresh ticker for periodic DNS refresh
        let refresh_duration = if self.refresh_interval.is_zero() {
            Duration::from_secs(3600) // placeholder; branch disabled below
        } else {
            self.refresh_interval
        };
        let mut refresh_ticker = time::interval(refresh_duration);
        refresh_ticker.tick().await; // consume immediate first tick

        loop {
            tokio::select! {
                maybe_cmd = self.cmd_rx.recv() => self.handle_command(maybe_cmd).await,
                result = self.socket.recv(&mut buf) => {
                    match result {
                        Ok(len) if len > 0 => {
                            self.handle_packet(&buf[..len]).await;
                        }
                        Ok(_) => {}
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(err) => {
                            return Err(ActorError::DnsRecv { server: server_str, source: err });
                        }
                    }
                }
                _ = ticker.tick() => self.handle_tick().await,
                _ = refresh_ticker.tick(), if !self.refresh_interval.is_zero() => {
                    self.trigger_refresh().await;
                }
            }

            // Check for expired IPs on every iteration
            self.check_expirations().await;

            if self.cmd_rx_closed && self.pending.is_empty() && self.cache.is_empty() {
                return Ok(());
            }
        }
    }

    /// Handles commands from the orchestrator queue.
    async fn handle_command(&mut self, command: Option<DnsCommand>) {
        match command {
            Some(DnsCommand::SetHostnames { hosts }) => {
                self.handle_set_hostnames(hosts).await;
            }
            None => {
                self.cmd_rx_closed = true;
            }
        }
    }

    /// Handles the SetHostnames command: diff against current state.
    async fn handle_set_hostnames(&mut self, new_hosts: HashSet<String>) {
        // Find removed hostnames
        let removed: Vec<String> = self
            .registered_hosts
            .difference(&new_hosts)
            .cloned()
            .collect();

        // Find added hostnames
        let added: Vec<String> = new_hosts
            .difference(&self.registered_hosts)
            .cloned()
            .collect();

        // Update registered set
        self.registered_hosts = new_hosts;

        // Emit IpExpired for all IPs of removed hostnames
        for host in removed {
            self.expire_hostname(&host).await;
        }

        // Issue queries for added hostnames
        for host in added {
            self.resolve_hostname(&host).await;
        }
    }

    /// Issues DNS queries for a hostname (handling IP literals).
    async fn resolve_hostname(&mut self, host: &str) {
        // Fast path: IP literal detection
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.handle_ip_literal(host.to_string(), ip).await;
        } else {
            self.issue_query(host.to_string(), DnsRecordType::A).await;
            self.issue_query(host.to_string(), DnsRecordType::Aaaa)
                .await;
        }
    }

    /// Handles IP literal: emit IpResolved immediately, cache with max TTL.
    async fn handle_ip_literal(&mut self, host: String, ip: IpAddr) {
        let key = (host.clone(), ip);
        if self.cache.contains_key(&key) {
            return; // Already cached
        }

        // IP literals use max TTL (effectively never expire)
        self.cache.insert(key, CachedRecord::new(u32::MAX));
        self.emit_ip_resolved(&host, ip).await;
    }

    /// Expires all IPs for a hostname and emits IpExpired events.
    async fn expire_hostname(&mut self, host: &str) {
        let keys_to_remove: Vec<(String, IpAddr)> = self
            .cache
            .keys()
            .filter(|(h, _)| h == host)
            .cloned()
            .collect();

        for (h, ip) in keys_to_remove {
            self.cache.remove(&(h.clone(), ip));
            self.emit_ip_expired(&h, ip).await;
        }
    }

    /// Triggers refresh for all registered hostnames.
    async fn trigger_refresh(&mut self) {
        for host in self.registered_hosts.clone() {
            // Skip IP literals (never need refresh)
            if host.parse::<IpAddr>().is_err() {
                self.issue_query(host.clone(), DnsRecordType::A).await;
                self.issue_query(host, DnsRecordType::Aaaa).await;
            }
        }
    }

    /// Checks for expired cache entries and emits IpExpired events.
    async fn check_expirations(&mut self) {
        let expired: Vec<(String, IpAddr)> = self
            .cache
            .iter()
            .filter(|(_, record)| record.is_expired())
            .map(|((host, ip), _)| (host.clone(), *ip))
            .collect();

        for (host, ip) in expired {
            self.cache.remove(&(host.clone(), ip));
            self.emit_ip_expired(&host, ip).await;
        }
    }

    /// Issues a query for `host` and `record_type`, logging on error.
    async fn issue_query(&mut self, host: String, record_type: DnsRecordType) {
        if let Err(err) = self.send_query(host.clone(), record_type).await {
            warn!(host = %host, record_type = ?record_type, error = %err, "dns: query send failed");
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

    /// Parses a DNS packet and emits the corresponding event.
    async fn handle_packet(&mut self, data: &[u8]) {
        let message = match Message::from_vec(data) {
            Ok(msg) => msg,
            Err(err) => {
                warn!(error = %err, "dns: packet decode failed");
                return;
            }
        };

        let id = message.id();
        if let Some(request) = self.pending.remove(&id) {
            self.handle_decoded_packet(message, request).await;
        } else {
            warn!(id = id, "dns: unknown transaction ID");
        }
    }

    /// Handles a parsed DNS packet that matches a pending request.
    async fn handle_decoded_packet(&mut self, message: Message, request: PendingRequest) {
        // Log warnings at origin instead of sending via events
        log_response_warnings(&message, &request.host);

        let records = extract_records(&message, request.record_type);

        if message.response_code() == ResponseCode::NoError && records.is_empty() {
            if let Some(unexpected_type) = first_nonmatching_answer(&message, request.record_type) {
                warn!(
                    host = %request.host,
                    expected = ?request.record_type,
                    got = ?unexpected_type,
                    "dns: unexpected record type in response"
                );
                return;
            }
        }

        // Process each record: cache and emit new IPs, refresh existing
        for record in records {
            let key = (request.host.clone(), record.address);
            if let Some(cached) = self.cache.get_mut(&key) {
                // Existing IP - refresh TTL (no event emitted)
                cached.refresh(record.ttl);
            } else {
                // New IP - cache and emit IpResolved
                self.cache.insert(key, CachedRecord::new(record.ttl));
                self.emit_ip_resolved(&request.host, record.address).await;
            }
        }
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
            warn!(host = %request.host, record_type = ?request.record_type, "dns: query timed out, retrying");
            if let Err(err) = self
                .send_query(request.host.clone(), request.record_type)
                .await
            {
                warn!(host = %request.host, error = %err, "dns: retry send failed");
            }
        }
    }

    /// Emits an IpResolved event.
    async fn emit_ip_resolved(&self, host: &str, address: IpAddr) {
        let event = Event::Dns(DnsEvent {
            server: self.server,
            detail: DnsEventDetail::IpResolved(DnsIpResolved {
                host: host.to_string(),
                address,
            }),
        });
        let _ = self.events_tx.send(event);
    }

    /// Emits an IpExpired event.
    async fn emit_ip_expired(&self, host: &str, address: IpAddr) {
        let event = Event::Dns(DnsEvent {
            server: self.server,
            detail: DnsEventDetail::IpExpired(DnsIpExpired {
                host: host.to_string(),
                address,
            }),
        });
        let _ = self.events_tx.send(event);
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

/// Logs DNS response warnings at origin (not sent as events).
fn log_response_warnings(message: &Message, host: &str) {
    match message.response_code() {
        ResponseCode::NoError => {}
        ResponseCode::NXDomain => {
            warn!(host = %host, "dns: NXDOMAIN response");
        }
        ResponseCode::Refused => {
            warn!(host = %host, "dns: query refused");
        }
        other => {
            warn!(host = %host, code = ?other, "dns: unexpected response code");
        }
    }

    if message.truncated() {
        warn!(host = %host, "dns: response truncated");
    }

    if !message.recursion_available() {
        warn!(host = %host, "dns: recursion unavailable");
    }
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
    use crate::bind::test_support::FakeRouteProbe;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::Record;
    use std::net::Ipv4Addr;

    /// Starts a resolver coroutine wired to the provided server socket.
    async fn start_resolver(
        server: SocketAddr,
        bindif: Option<String>,
    ) -> (
        mpsc::UnboundedSender<DnsCommand>,
        mpsc::UnboundedReceiver<Event>,
        JoinHandle<ActorExitResult>,
    ) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let resolver = DnsResolver::new(
            server,
            bindif,
            None,
            Duration::from_millis(50),
            Duration::ZERO,
        );
        let probe = FakeRouteProbe::noop();
        let (cmd_tx, handle) = resolver
            .spawn(probe, event_tx)
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

    /// Receives the next DNS event detail.
    async fn next_relevant_detail(
        events_rx: &mut mpsc::UnboundedReceiver<Event>,
    ) -> DnsEventDetail {
        loop {
            let event = events_rx.recv().await.expect("dns event");
            if let Event::Dns(dns) = event {
                return dns.detail;
            }
        }
    }

    // ========== IpResolved Tests ==========

    #[tokio::test]
    async fn emits_ip_resolved_for_new_ip() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        let mut hosts = HashSet::new();
        hosts.insert("example.com".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        let request = Message::from_vec(&buf[..len]).unwrap();
        let query = request.queries().first().cloned().unwrap();
        let response = build_response(
            request.id(),
            query.clone(),
            ResponseCode::NoError,
            vec![Record::from_rdata(
                query.name().clone(),
                300,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            )],
        );
        socket.send_to(&response, peer).await.unwrap();

        let detail = next_relevant_detail(&mut events_rx).await;
        match detail {
            DnsEventDetail::IpResolved(resolved) => {
                assert_eq!(resolved.host, "example.com");
                assert_eq!(resolved.address, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
            }
            _ => panic!("expected IpResolved event"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn does_not_emit_duplicate_ip_on_refresh() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        let mut hosts = HashSet::new();
        hosts.insert("example.com".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        // First resolution
        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        let request = Message::from_vec(&buf[..len]).unwrap();
        let query = request.queries().first().cloned().unwrap();
        let response = build_response(
            request.id(),
            query.clone(),
            ResponseCode::NoError,
            vec![Record::from_rdata(
                query.name().clone(),
                300,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            )],
        );
        socket.send_to(&response, peer).await.unwrap();

        // Wait for first IpResolved
        let _ = next_relevant_detail(&mut events_rx).await;

        // Consume AAAA query
        let (len2, peer2) = socket.recv_from(&mut buf).await.unwrap();
        let request2 = Message::from_vec(&buf[..len2]).unwrap();
        let response2 = build_response(
            request2.id(),
            request2.queries()[0].clone(),
            ResponseCode::NoError,
            vec![],
        );
        socket.send_to(&response2, peer2).await.unwrap();

        // Re-register same hosts (simulating refresh via new SetHostnames with same content)
        // This should not re-query since hosts haven't changed
        let mut hosts2 = HashSet::new();
        hosts2.insert("example.com".to_string());
        cmd_tx
            .send(DnsCommand::SetHostnames { hosts: hosts2 })
            .unwrap();

        // Should not receive another IpResolved (no new hostnames added)
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Expected - no event
            }
            event = events_rx.recv() => {
                // Only IpResolved events should not fire for same IP
                if let Some(Event::Dns(dns)) = event {
                    if matches!(dns.detail, DnsEventDetail::IpResolved(_)) {
                        panic!("should not emit duplicate IpResolved");
                    }
                }
            }
        }

        handle.abort();
    }

    #[tokio::test]
    async fn emits_ip_expired_on_hostname_removal() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        // Register and resolve
        let mut hosts = HashSet::new();
        hosts.insert("example.com".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        let request = Message::from_vec(&buf[..len]).unwrap();
        let query = request.queries().first().cloned().unwrap();
        let response = build_response(
            request.id(),
            query.clone(),
            ResponseCode::NoError,
            vec![Record::from_rdata(
                query.name().clone(),
                3600,
                RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
            )],
        );
        socket.send_to(&response, peer).await.unwrap();

        // Wait for IpResolved
        let _ = next_relevant_detail(&mut events_rx).await;

        // Consume AAAA query
        let (len2, peer2) = socket.recv_from(&mut buf).await.unwrap();
        let request2 = Message::from_vec(&buf[..len2]).unwrap();
        let response2 = build_response(
            request2.id(),
            request2.queries()[0].clone(),
            ResponseCode::NoError,
            vec![],
        );
        socket.send_to(&response2, peer2).await.unwrap();

        // Unregister by sending empty hosts
        cmd_tx
            .send(DnsCommand::SetHostnames {
                hosts: HashSet::new(),
            })
            .unwrap();

        // Should receive IpExpired
        let detail = next_relevant_detail(&mut events_rx).await;
        match detail {
            DnsEventDetail::IpExpired(expired) => {
                assert_eq!(expired.host, "example.com");
                assert_eq!(expired.address, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
            }
            _ => panic!("expected IpExpired event"),
        }

        handle.abort();
    }

    // ========== IP Literal Tests ==========

    #[tokio::test]
    async fn ip_literal_emits_immediate_ip_resolved() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        // Register IP literal
        let mut hosts = HashSet::new();
        hosts.insert("192.168.1.100".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        // Should receive immediate IpResolved (no network query)
        let detail = next_relevant_detail(&mut events_rx).await;
        match detail {
            DnsEventDetail::IpResolved(resolved) => {
                assert_eq!(resolved.host, "192.168.1.100");
                assert_eq!(resolved.address.to_string(), "192.168.1.100");
            }
            _ => panic!("expected IpResolved event"),
        }

        handle.abort();
    }

    #[tokio::test]
    async fn ipv6_literal_emits_immediate_ip_resolved() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        // Register IPv6 literal
        let mut hosts = HashSet::new();
        hosts.insert("2001:db8::1".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        // Should receive immediate IpResolved
        let detail = next_relevant_detail(&mut events_rx).await;
        match detail {
            DnsEventDetail::IpResolved(resolved) => {
                assert_eq!(resolved.host, "2001:db8::1");
                assert!(resolved.address.is_ipv6());
            }
            _ => panic!("expected IpResolved event"),
        }

        handle.abort();
    }

    // ========== Deduplication Tests ==========

    #[tokio::test]
    async fn emits_multiple_ips_for_same_hostname() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        let mut hosts = HashSet::new();
        hosts.insert("multi.example.com".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        let request = Message::from_vec(&buf[..len]).unwrap();
        let query = request.queries().first().cloned().unwrap();
        let response = build_response(
            request.id(),
            query.clone(),
            ResponseCode::NoError,
            vec![
                Record::from_rdata(
                    query.name().clone(),
                    120,
                    RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
                ),
                Record::from_rdata(
                    query.name().clone(),
                    120,
                    RData::A(A(Ipv4Addr::new(10, 0, 0, 2))),
                ),
            ],
        );
        socket.send_to(&response, peer).await.unwrap();

        // Should receive two IpResolved events
        let detail1 = next_relevant_detail(&mut events_rx).await;
        let detail2 = next_relevant_detail(&mut events_rx).await;

        let mut ips = HashSet::new();
        if let DnsEventDetail::IpResolved(r) = detail1 {
            ips.insert(r.address);
        }
        if let DnsEventDetail::IpResolved(r) = detail2 {
            ips.insert(r.address);
        }

        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

        handle.abort();
    }

    // ========== Actor Lifecycle Tests ==========

    #[tokio::test]
    async fn spawn_returns_working_cmd_tx() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();

        let resolver = DnsResolver::new(
            server_addr,
            None,
            None,
            Duration::from_millis(50),
            Duration::ZERO,
        );
        let probe = FakeRouteProbe::noop();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, _handle) = resolver
            .spawn(probe, event_tx)
            .await
            .expect("resolver spawn");

        // Verify cmd_tx is functional
        let mut hosts = HashSet::new();
        hosts.insert("test.example".to_string());
        assert!(cmd_tx.send(DnsCommand::SetHostnames { hosts }).is_ok());
    }

    #[tokio::test]
    async fn actor_exits_when_sender_dropped() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();

        let resolver = DnsResolver::new(
            server_addr,
            None,
            None,
            Duration::from_millis(50),
            Duration::ZERO,
        );
        let probe = FakeRouteProbe::noop();
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, join_handle) = resolver
            .spawn(probe, event_tx)
            .await
            .expect("resolver spawn");

        // Drop sender to signal shutdown
        drop(cmd_tx);

        // Actor should exit gracefully (check both timeout and join result)
        let result = tokio::time::timeout(Duration::from_millis(200), join_handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "actor should shut down cleanly after sender dropped, got {:?}",
            result
        );
    }

    // ========== Timeout Retry Tests ==========

    #[tokio::test]
    async fn retries_with_new_id_on_timeout() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, _events_rx, handle) = start_resolver(server_addr, None).await;

        let mut hosts = HashSet::new();
        hosts.insert("timeout.example".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let mut first_ids: HashMap<DnsRecordType, u16> = HashMap::new();
        for _ in 0..2 {
            let (len, _peer) = socket.recv_from(&mut buf).await.unwrap();
            let message = Message::from_vec(&buf[..len]).unwrap();
            let query = message.queries().first().cloned().unwrap();
            first_ids.insert(DnsRecordType::from(query.query_type()), message.id());
        }

        // Wait for timeout and retry
        tokio::time::sleep(Duration::from_millis(100)).await;

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
