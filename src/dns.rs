//! DNS resolver coroutine: consumes SetHostnames commands, manages IP lifecycle with TTL-based expiration,
//! and emits IpResolved/IpExpired events.

use crate::actor::{ActorError, ActorExitResult};
use crate::bind::{make_client_udp_socket, RouteProbe};
use crate::config::LocalDns;
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
    // Note: InvalidServer variant removed - parsing now happens during config deserialization.
    /// DNS socket could not be prepared.
    #[error("dns resolver failed to initialize: {0}")]
    Socket(String),
}

/// DNS resolver actor state.
///
/// Created by `make_dns()`, consumed by `spawn_dns()`.
#[derive(Debug)]
pub struct DnsActor {
    server: SocketAddr,
    socket: UdpSocket,
    timeout: Duration,
    refresh_interval: Duration,
}

/// Creates a DNS resolver actor state from configuration.
///
/// Performs fallible I/O (socket binding and connection) during construction.
/// The returned state is consumed by `spawn_dns()` to start the actor.
///
/// # Arguments
///
/// * `local_dns` - DNS configuration from config file.
/// * `tun_if` - Optional TUN interface name to exclude from routing.
/// * `timeout` - Query timeout duration.
/// * `probe` - Route probe for interface selection.
///
/// # Errors
///
/// Returns `ResolveInitError::InvalidServer` when the DNS server URI is malformed.
/// Returns `ResolveInitError::Socket` when socket creation, binding, or connect fails.
pub async fn make_dns<P: RouteProbe>(
    local_dns: &LocalDns,
    tun_if: Option<&str>,
    timeout: Duration,
    probe: &P,
) -> Result<DnsActor, ResolveInitError> {
    // server is pre-parsed as SocketAddr during config deserialization
    let server = local_dns.server;
    let refresh_interval = Duration::from_secs(local_dns.refresh);

    let socket = make_client_udp_socket(server, tun_if, local_dns.bindif.as_deref(), probe)
        .await
        .map_err(|e| ResolveInitError::Socket(e.to_string()))?;

    Ok(DnsActor {
        server,
        socket,
        timeout,
        refresh_interval,
    })
}

/// Spawns the DNS resolver actor task.
///
/// Creates an unbounded command channel internally (actor owns the receiver).
/// Returns the command sender and join handle. The actor exits gracefully when
/// all senders are dropped, closing the channel naturally.
///
/// # Arguments
///
/// * `actor` - Actor state created by `make_dns()`.
/// * `events_tx` - Unbounded channel for emitting DNS events.
pub fn spawn_dns(
    actor: DnsActor,
    events_tx: mpsc::UnboundedSender<Event>,
) -> (
    mpsc::UnboundedSender<DnsCommand>,
    JoinHandle<ActorExitResult>,
) {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

    let DnsActor {
        server,
        socket,
        timeout,
        refresh_interval,
    } = actor;

    let server_str = server.to_string();

    let handle = tokio::spawn(async move {
        let mut pending: HashMap<u16, PendingRequest> = HashMap::new();
        let mut cmd_rx_closed = false;
        let mut registered_hosts: HashSet<String> = HashSet::new();
        let mut cache: HashMap<(String, IpAddr), CachedRecord> = HashMap::new();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let mut ticker = time::interval(TICK_INTERVAL);

        let refresh_duration = if refresh_interval.is_zero() {
            Duration::from_secs(3600) // placeholder; branch disabled below
        } else {
            refresh_interval
        };
        let mut refresh_ticker = time::interval(refresh_duration);
        refresh_ticker.tick().await; // consume immediate first tick

        loop {
            tokio::select! {
                maybe_cmd = cmd_rx.recv() => {
                    handle_command(
                        maybe_cmd,
                        &mut cmd_rx_closed,
                        &mut registered_hosts,
                        &mut cache,
                        &mut pending,
                        &socket,
                        server,
                        &events_tx,
                    ).await;
                }
                result = socket.recv(&mut buf) => {
                    match result {
                        Ok(len) if len > 0 => {
                            handle_packet(
                                &buf[..len],
                                &mut pending,
                                &mut cache,
                                server,
                                &events_tx,
                            ).await;
                        }
                        Ok(_) => {}
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(err) => {
                            return Err(ActorError::DnsRecv { server: server_str, source: err });
                        }
                    }
                }
                _ = ticker.tick() => {
                    handle_tick(&mut pending, &socket, timeout).await;
                }
                _ = refresh_ticker.tick(), if !refresh_interval.is_zero() => {
                    trigger_refresh(&registered_hosts, &mut pending, &socket).await;
                }
            }

            // Check for expired IPs on every iteration
            check_expirations(&mut cache, server, &events_tx);

            if cmd_rx_closed && pending.is_empty() && cache.is_empty() {
                return Ok(());
            }
        }
    });

    (cmd_tx, handle)
}

/// Tracks outstanding DNS queries by transaction ID.
#[derive(Debug, Clone)]
struct PendingRequest {
    host: String,
    record_type: DnsRecordType,
    last_sent: Instant,
}

/// Handles commands from the orchestrator queue.
#[allow(clippy::too_many_arguments)]
async fn handle_command(
    command: Option<DnsCommand>,
    cmd_rx_closed: &mut bool,
    registered_hosts: &mut HashSet<String>,
    cache: &mut HashMap<(String, IpAddr), CachedRecord>,
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
    server: SocketAddr,
    events_tx: &mpsc::UnboundedSender<Event>,
) {
    match command {
        Some(DnsCommand::SetHostnames { hosts }) => {
            handle_set_hostnames(
                hosts,
                registered_hosts,
                cache,
                pending,
                socket,
                server,
                events_tx,
            )
            .await;
        }
        None => {
            *cmd_rx_closed = true;
        }
    }
}

/// Handles the SetHostnames command: diff against current state.
#[allow(clippy::too_many_arguments)]
async fn handle_set_hostnames(
    new_hosts: HashSet<String>,
    registered_hosts: &mut HashSet<String>,
    cache: &mut HashMap<(String, IpAddr), CachedRecord>,
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
    server: SocketAddr,
    events_tx: &mpsc::UnboundedSender<Event>,
) {
    // Find removed hostnames
    let removed: Vec<String> = registered_hosts.difference(&new_hosts).cloned().collect();

    // Find added hostnames
    let added: Vec<String> = new_hosts.difference(registered_hosts).cloned().collect();

    // Update registered set
    *registered_hosts = new_hosts;

    // Emit IpExpired for all IPs of removed hostnames
    for host in removed {
        expire_hostname(&host, cache, server, events_tx);
    }

    // Issue queries for added hostnames
    for host in added {
        resolve_hostname(&host, cache, pending, socket, server, events_tx).await;
    }
}

/// Issues DNS queries for a hostname (handling IP literals).
async fn resolve_hostname(
    host: &str,
    cache: &mut HashMap<(String, IpAddr), CachedRecord>,
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
    server: SocketAddr,
    events_tx: &mpsc::UnboundedSender<Event>,
) {
    // Fast path: IP literal detection
    if let Ok(ip) = host.parse::<IpAddr>() {
        handle_ip_literal(host.to_string(), ip, cache, server, events_tx);
    } else {
        issue_query(host.to_string(), DnsRecordType::A, pending, socket).await;
        issue_query(host.to_string(), DnsRecordType::Aaaa, pending, socket).await;
    }
}

/// Handles IP literal: emit IpResolved immediately, cache with max TTL.
fn handle_ip_literal(
    host: String,
    ip: IpAddr,
    cache: &mut HashMap<(String, IpAddr), CachedRecord>,
    server: SocketAddr,
    events_tx: &mpsc::UnboundedSender<Event>,
) {
    let key = (host.clone(), ip);
    if cache.contains_key(&key) {
        return; // Already cached
    }

    // IP literals use max TTL (effectively never expire)
    cache.insert(key, CachedRecord::new(u32::MAX));
    emit_ip_resolved(&host, ip, server, events_tx);
}

/// Expires all IPs for a hostname and emits IpExpired events.
fn expire_hostname(
    host: &str,
    cache: &mut HashMap<(String, IpAddr), CachedRecord>,
    server: SocketAddr,
    events_tx: &mpsc::UnboundedSender<Event>,
) {
    let keys_to_remove: Vec<(String, IpAddr)> =
        cache.keys().filter(|(h, _)| h == host).cloned().collect();

    for (h, ip) in keys_to_remove {
        cache.remove(&(h.clone(), ip));
        emit_ip_expired(&h, ip, server, events_tx);
    }
}

/// Triggers refresh for all registered hostnames.
async fn trigger_refresh(
    registered_hosts: &HashSet<String>,
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
) {
    for host in registered_hosts.iter() {
        // Skip IP literals (never need refresh)
        if host.parse::<IpAddr>().is_err() {
            issue_query(host.clone(), DnsRecordType::A, pending, socket).await;
            issue_query(host.clone(), DnsRecordType::Aaaa, pending, socket).await;
        }
    }
}

/// Checks for expired cache entries and emits IpExpired events.
fn check_expirations(
    cache: &mut HashMap<(String, IpAddr), CachedRecord>,
    server: SocketAddr,
    events_tx: &mpsc::UnboundedSender<Event>,
) {
    let expired: Vec<(String, IpAddr)> = cache
        .iter()
        .filter(|(_, record)| record.is_expired())
        .map(|((host, ip), _)| (host.clone(), *ip))
        .collect();

    for (host, ip) in expired {
        cache.remove(&(host.clone(), ip));
        emit_ip_expired(&host, ip, server, events_tx);
    }
}

/// Issues a query for `host` and `record_type`, logging on error.
async fn issue_query(
    host: String,
    record_type: DnsRecordType,
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
) {
    if let Err(err) = send_query(host.clone(), record_type, pending, socket).await {
        warn!(host = %host, record_type = ?record_type, error = %err, "dns: query send failed");
    }
}

/// Sends a DNS query packet and records it as pending.
async fn send_query(
    host: String,
    record_type: DnsRecordType,
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
) -> Result<(), String> {
    let name = Name::from_ascii(&host).map_err(|e| e.to_string())?;

    let mut message = Message::new();
    let id = allocate_id(pending);
    message.set_id(id);
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);
    message.add_query(record_type_query(name, record_type));

    let outbound = message.to_vec().map_err(|e| e.to_string())?;
    socket.send(&outbound).await.map_err(|e| e.to_string())?;

    pending.insert(
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
fn allocate_id(pending: &HashMap<u16, PendingRequest>) -> u16 {
    loop {
        let candidate = rand::rng().random::<u16>();
        if !pending.contains_key(&candidate) {
            return candidate;
        }
    }
}

/// Parses a DNS packet and emits the corresponding event.
async fn handle_packet(
    data: &[u8],
    pending: &mut HashMap<u16, PendingRequest>,
    cache: &mut HashMap<(String, IpAddr), CachedRecord>,
    server: SocketAddr,
    events_tx: &mpsc::UnboundedSender<Event>,
) {
    let message = match Message::from_vec(data) {
        Ok(msg) => msg,
        Err(err) => {
            warn!(error = %err, "dns: packet decode failed");
            return;
        }
    };

    let id = message.id();
    if let Some(request) = pending.remove(&id) {
        handle_decoded_packet(message, request, cache, server, events_tx);
    } else {
        warn!(id = id, "dns: unknown transaction ID");
    }
}

/// Handles a parsed DNS packet that matches a pending request.
fn handle_decoded_packet(
    message: Message,
    request: PendingRequest,
    cache: &mut HashMap<(String, IpAddr), CachedRecord>,
    server: SocketAddr,
    events_tx: &mpsc::UnboundedSender<Event>,
) {
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
        if let Some(cached) = cache.get_mut(&key) {
            // Existing IP - refresh TTL (no event emitted)
            cached.refresh(record.ttl);
        } else {
            // New IP - cache and emit IpResolved
            cache.insert(key, CachedRecord::new(record.ttl));
            emit_ip_resolved(&request.host, record.address, server, events_tx);
        }
    }
}

/// Handles timer ticks by retrying timed-out pending queries.
async fn handle_tick(
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
    timeout: Duration,
) {
    let now = Instant::now();
    let mut expired = Vec::new();

    for (id, req) in pending.iter() {
        if now.duration_since(req.last_sent) >= timeout {
            expired.push((*id, req.clone()));
        }
    }

    for (id, request) in expired {
        pending.remove(&id);
        warn!(host = %request.host, record_type = ?request.record_type, "dns: query timed out, retrying");
        if let Err(err) =
            send_query(request.host.clone(), request.record_type, pending, socket).await
        {
            warn!(host = %request.host, error = %err, "dns: retry send failed");
        }
    }
}

/// Emits an IpResolved event.
fn emit_ip_resolved(
    host: &str,
    address: IpAddr,
    server: SocketAddr,
    events_tx: &mpsc::UnboundedSender<Event>,
) {
    let event = Event::Dns(DnsEvent {
        server,
        detail: DnsEventDetail::IpResolved(DnsIpResolved {
            host: host.to_string(),
            address,
        }),
    });
    let _ = events_tx.send(event);
}

/// Emits an IpExpired event.
fn emit_ip_expired(
    host: &str,
    address: IpAddr,
    server: SocketAddr,
    events_tx: &mpsc::UnboundedSender<Event>,
) {
    let event = Event::Dns(DnsEvent {
        server,
        detail: DnsEventDetail::IpExpired(DnsIpExpired {
            host: host.to_string(),
            address,
        }),
    });
    let _ = events_tx.send(event);
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
        _bindif: Option<String>,
    ) -> (
        mpsc::UnboundedSender<DnsCommand>,
        mpsc::UnboundedReceiver<Event>,
        JoinHandle<ActorExitResult>,
    ) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Build LocalDns config for make_dns (server is now pre-parsed SocketAddr)
        let local_dns = LocalDns {
            server,
            bindif: None,
            refresh: 0, // ZERO disables automatic refresh
        };

        let probe = FakeRouteProbe::noop();
        let dns_actor = make_dns(&local_dns, None, Duration::from_millis(50), &probe)
            .await
            .expect("make_dns failed");

        let (cmd_tx, handle) = spawn_dns(dns_actor, event_tx);
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
    async fn spawn_dns_returns_working_cmd_tx() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();

        let local_dns = LocalDns {
            server: server_addr,
            bindif: None,
            refresh: 0,
        };

        let probe = FakeRouteProbe::noop();
        let dns_actor = make_dns(&local_dns, None, Duration::from_millis(50), &probe)
            .await
            .expect("make_dns");

        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, _handle) = spawn_dns(dns_actor, event_tx);

        // Verify cmd_tx is functional
        let mut hosts = HashSet::new();
        hosts.insert("test.example".to_string());
        assert!(cmd_tx.send(DnsCommand::SetHostnames { hosts }).is_ok());
    }

    #[tokio::test]
    async fn dns_actor_exits_when_sender_dropped() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();

        let local_dns = LocalDns {
            server: server_addr,
            bindif: None,
            refresh: 0,
        };

        let probe = FakeRouteProbe::noop();
        let dns_actor = make_dns(&local_dns, None, Duration::from_millis(50), &probe)
            .await
            .expect("make_dns");

        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, join_handle) = spawn_dns(dns_actor, event_tx);

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
