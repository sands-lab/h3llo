//! DNS resolver coroutine: consumes SetHostnames commands, manages IP lifecycle with TTL-based expiration,
//! and emits state snapshot events on resolution changes.

use crate::actor::{ActorError, ActorExitResult};
use crate::bind::{make_client_udp_socket, RouteProbe};
use crate::config::{LocalDns, Tuning};
use crate::events::{DnsEvent, Event};
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

/// Commands accepted by the DNS resolver coroutine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsCommand {
    /// Register/update the set of hostnames to monitor.
    ///
    /// Replaces the previous registration set entirely. The DNS module will:
    /// - Start tracking new hostnames (issue queries)
    /// - Continue tracking existing hostnames (refresh before TTL expiry)
    /// - Stop tracking removed hostnames (remove from state, mark dirty)
    SetHostnames { hosts: HashSet<String> },
}

/// Unified DNS resolution state.
///
/// Consolidates hostname registration and IP cache into a single structure.
/// Emits state snapshots on change rather than per-IP events.
#[derive(Debug, Clone)]
struct DnsState {
    /// Active resolutions: hostname -> (IP -> expiration time).
    entries: HashMap<String, HashMap<IpAddr, Instant>>,
    /// True if state changed since last snapshot emission.
    dirty: bool,
    /// Minimum TTL floor in seconds to prevent excessive refresh.
    min_ttl_secs: u32,
}

impl DnsState {
    /// Updates the set of registered hostnames.
    ///
    /// Removes unregistered hostnames and their IPs; adds new hostnames with
    /// empty IP maps. Returns true if registration changed.
    fn set_hostnames(&mut self, hosts: &HashSet<String>) -> bool {
        let mut changed = false;

        // Remove unregistered hostnames
        self.entries.retain(|h, _| {
            let keep = hosts.contains(h);
            if !keep {
                changed = true;
            }
            keep
        });

        // Add new hostnames (empty IP map)
        for host in hosts {
            self.entries.entry(host.clone()).or_insert_with(|| {
                changed = true;
                HashMap::new()
            });
        }

        if changed {
            self.dirty = true;
        }
        changed
    }

    /// Records a resolved IP for a hostname. Returns true if the IP is new.
    fn record_ip(&mut self, host: &str, ip: IpAddr, ttl: u32) -> bool {
        let Some(ips) = self.entries.get_mut(host) else {
            return false;
        };

        let ttl_secs = ttl.max(self.min_ttl_secs);
        let expires_at = Instant::now() + Duration::from_secs(ttl_secs as u64);
        let mut is_new = false;
        ips.entry(ip)
            .and_modify(|exp| *exp = expires_at)
            .or_insert_with(|| {
                is_new = true;
                expires_at
            });
        if is_new {
            self.dirty = true;
        }
        is_new
    }

    /// Removes expired IPs. Returns true if any were removed.
    fn expire_stale(&mut self) -> bool {
        let now = Instant::now();
        let mut removed = false;

        for ips in self.entries.values_mut() {
            ips.retain(|_, expires_at| {
                let keep = *expires_at > now;
                if !keep {
                    removed = true;
                }
                keep
            });
        }

        if removed {
            self.dirty = true;
        }
        removed
    }

    /// Emits a snapshot to the orchestrator if dirty, clearing the dirty flag.
    fn emit_snapshot(&mut self, events_tx: &mpsc::UnboundedSender<Event>) {
        if !self.dirty {
            return;
        }
        self.dirty = false;

        let state = self
            .entries
            .iter()
            .map(|(host, ips)| (host.clone(), ips.keys().copied().collect()))
            .collect();
        let _ = events_tx.send(Event::Dns(DnsEvent { state }));
    }

    /// Checks if a hostname is registered.
    fn is_registered(&self, host: &str) -> bool {
        self.entries.contains_key(host)
    }

    /// Returns an iterator over registered hostnames.
    fn hostnames(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }

    /// Returns true if all entries have empty IP maps and no pending work.
    fn is_idle(&self) -> bool {
        self.entries.values().all(|ips| ips.is_empty())
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
    snapshot_delay: Duration,
    min_ttl_secs: u32,
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
/// * `tuning` - Tuning parameters (timeouts, intervals, TTL floor, etc.).
/// * `probe` - Route probe for interface selection.
///
/// # Errors
///
/// Returns `ResolveInitError::Socket` when socket creation, binding, or connect fails.
pub async fn make_dns<P: RouteProbe>(
    local_dns: &LocalDns,
    tun_if: Option<&str>,
    tuning: &Tuning,
    probe: &P,
) -> Result<DnsActor, ResolveInitError> {
    let server = local_dns.server;

    let socket = make_client_udp_socket(
        server,
        tun_if,
        local_dns.bindif.as_deref(),
        probe,
        tuning.socket_buffer_bytes(),
    )
    .await
    .map_err(|e| ResolveInitError::Socket(e.to_string()))?;

    Ok(DnsActor {
        server,
        socket,
        timeout: tuning.dns_query_timeout,
        refresh_interval: tuning.dns_refresh_interval,
        snapshot_delay: tuning.dns_snapshot_delay,
        min_ttl_secs: tuning.dns_min_ttl,
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
        snapshot_delay,
        min_ttl_secs,
    } = actor;

    let server_str = server.to_string();

    let handle = tokio::spawn(async move {
        let mut pending: HashMap<u16, PendingRequest> = HashMap::new();
        let mut cmd_rx_closed = false;
        let mut state = DnsState {
            entries: HashMap::new(),
            dirty: false,
            min_ttl_secs,
        };

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let mut ticker = time::interval(timeout / 2);

        // Debounce timer: armed when state becomes dirty, fires after snapshot_delay.
        let snapshot_timer = time::sleep(snapshot_delay);
        tokio::pin!(snapshot_timer);
        let mut snapshot_armed = false;

        let refresh_duration = if refresh_interval.is_zero() {
            Duration::from_secs(3600) // placeholder; branch disabled below
        } else {
            refresh_interval
        };
        let mut refresh_ticker = time::interval(refresh_duration);
        refresh_ticker.tick().await; // consume immediate first tick

        // Arms the debounce timer if dirty and not already armed.
        macro_rules! arm_snapshot_timer {
            () => {
                if state.dirty && !snapshot_armed {
                    snapshot_timer
                        .as_mut()
                        .reset(time::Instant::now() + snapshot_delay);
                    snapshot_armed = true;
                }
            };
        }

        loop {
            tokio::select! {
                maybe_cmd = cmd_rx.recv() => {
                    handle_command(
                        maybe_cmd,
                        &mut cmd_rx_closed,
                        &mut state,
                        &mut pending,
                        &socket,
                    ).await;
                    state.emit_snapshot(&events_tx);
                }
                result = socket.recv(&mut buf) => {
                    match result {
                        Ok(len) if len > 0 => {
                            handle_packet(
                                &buf[..len],
                                &mut pending,
                                &mut state,
                            ).await;
                            arm_snapshot_timer!();
                        }
                        Ok(_) => {}
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(err) => {
                            return Err(ActorError::DnsRecv { server: server_str, source: err });
                        }
                    }
                }
                () = &mut snapshot_timer, if snapshot_armed => {
                    snapshot_armed = false;
                    state.emit_snapshot(&events_tx);
                }
                _ = ticker.tick() => {
                    handle_tick(&mut pending, &socket, timeout).await;
                    state.expire_stale();
                    arm_snapshot_timer!();
                }
                _ = refresh_ticker.tick(), if !refresh_interval.is_zero() => {
                    trigger_refresh(&state, &mut pending, &socket).await;
                }
            }

            if cmd_rx_closed && pending.is_empty() && state.is_idle() {
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
async fn handle_command(
    command: Option<DnsCommand>,
    cmd_rx_closed: &mut bool,
    state: &mut DnsState,
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
) {
    match command {
        Some(DnsCommand::SetHostnames { hosts }) => {
            handle_set_hostnames(hosts, state, pending, socket).await;
        }
        None => {
            *cmd_rx_closed = true;
        }
    }
}

/// Handles the SetHostnames command: diff against current state.
async fn handle_set_hostnames(
    new_hosts: HashSet<String>,
    state: &mut DnsState,
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
) {
    // Find added hostnames
    let added: Vec<String> = new_hosts
        .iter()
        .filter(|h| !state.is_registered(h))
        .cloned()
        .collect();

    // Update state (handles adds + removes + dirty flag)
    state.set_hostnames(&new_hosts);

    // Issue queries for added hostnames
    for host in added {
        resolve_hostname(&host, state, pending, socket).await;
    }
}

/// Issues DNS queries for a hostname (handling IP literals).
async fn resolve_hostname(
    host: &str,
    state: &mut DnsState,
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
) {
    // Fast path: IP literal detection
    if let Ok(ip) = host.parse::<IpAddr>() {
        // IP literals use max TTL (effectively never expire)
        state.record_ip(host, ip, u32::MAX);
    } else {
        issue_query(host.to_string(), DnsRecordType::A, pending, socket).await;
        issue_query(host.to_string(), DnsRecordType::Aaaa, pending, socket).await;
    }
}

/// Triggers refresh for all registered hostnames.
async fn trigger_refresh(
    state: &DnsState,
    pending: &mut HashMap<u16, PendingRequest>,
    socket: &UdpSocket,
) {
    for host in state.hostnames() {
        // Skip IP literals (never need refresh)
        if host.parse::<IpAddr>().is_err() {
            issue_query(host.clone(), DnsRecordType::A, pending, socket).await;
            issue_query(host.clone(), DnsRecordType::Aaaa, pending, socket).await;
        }
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

/// Parses a DNS packet and updates state accordingly.
async fn handle_packet(
    data: &[u8],
    pending: &mut HashMap<u16, PendingRequest>,
    state: &mut DnsState,
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
        handle_decoded_packet(message, request, state);
    } else {
        warn!(id = id, "dns: unknown transaction ID");
    }
}

/// Handles a parsed DNS packet that matches a pending request.
fn handle_decoded_packet(message: Message, request: PendingRequest, state: &mut DnsState) {
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

    // Process each record: record new IPs, refresh existing TTLs
    for record in records {
        state.record_ip(&request.host, record.address, record.ttl);
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
        };

        let probe = FakeRouteProbe::noop();
        let tuning = Tuning::default();
        let dns_actor = make_dns(&local_dns, None, &tuning, &probe)
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

    /// Receives the next DNS snapshot event.
    async fn next_dns_snapshot(
        events_rx: &mut mpsc::UnboundedReceiver<Event>,
    ) -> HashMap<String, HashSet<IpAddr>> {
        loop {
            let event = events_rx.recv().await.expect("dns event");
            if let Event::Dns(dns) = event {
                return dns.state;
            }
        }
    }

    /// Waits for a DNS snapshot where the specified hostname has at least one IP.
    ///
    /// Skips snapshots where the hostname is missing or has empty IPs.
    async fn next_dns_snapshot_with_ips(
        events_rx: &mut mpsc::UnboundedReceiver<Event>,
        hostname: &str,
    ) -> HashMap<String, HashSet<IpAddr>> {
        loop {
            let snapshot = next_dns_snapshot(events_rx).await;
            if let Some(ips) = snapshot.get(hostname) {
                if !ips.is_empty() {
                    return snapshot;
                }
            }
        }
    }

    // ========== Snapshot Tests ==========

    #[tokio::test]
    async fn emits_snapshot_for_new_ip() {
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

        // Wait for snapshot with resolved IPs (may skip initial empty snapshot)
        let snapshot = next_dns_snapshot_with_ips(&mut events_rx, "example.com").await;
        let ips = snapshot.get("example.com").expect("missing example.com");
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));

        handle.abort();
    }

    #[tokio::test]
    async fn does_not_emit_duplicate_snapshot_on_refresh() {
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

        // Wait for snapshot with resolved IPs (skips the immediate empty snapshot)
        let _ = next_dns_snapshot_with_ips(&mut events_rx, "example.com").await;

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

        // Drain any pending debounce snapshot before the duplicate check
        tokio::time::sleep(Duration::from_millis(200)).await;
        while events_rx.try_recv().is_ok() {}

        // Re-register same hosts (simulating refresh via new SetHostnames with same content)
        // This should not re-query since hosts haven't changed
        let mut hosts2 = HashSet::new();
        hosts2.insert("example.com".to_string());
        cmd_tx
            .send(DnsCommand::SetHostnames { hosts: hosts2 })
            .unwrap();

        // Should not receive another snapshot (no new hostnames added, no state change)
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Expected - no event
            }
            event = events_rx.recv() => {
                if let Some(Event::Dns(_)) = event {
                    panic!("should not emit duplicate snapshot when state unchanged");
                }
            }
        }

        handle.abort();
    }

    #[tokio::test]
    async fn emits_snapshot_on_hostname_removal() {
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

        // Wait for snapshot with IPs (may skip initial empty snapshot)
        let snapshot = next_dns_snapshot_with_ips(&mut events_rx, "example.com").await;
        assert!(snapshot
            .get("example.com")
            .unwrap()
            .contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));

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

        // Should receive snapshot with example.com removed
        let snapshot = next_dns_snapshot(&mut events_rx).await;
        assert!(
            !snapshot.contains_key("example.com"),
            "example.com should be removed"
        );

        handle.abort();
    }

    // ========== IP Literal Tests ==========

    #[tokio::test]
    async fn ip_literal_emits_snapshot() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        // Register IP literal
        let mut hosts = HashSet::new();
        hosts.insert("192.168.1.100".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        // Snapshot emitted on next tick (not immediately anymore)
        let snapshot = next_dns_snapshot(&mut events_rx).await;
        let ips = snapshot.get("192.168.1.100").expect("missing IP literal");
        assert!(ips.contains(&"192.168.1.100".parse::<IpAddr>().unwrap()));

        handle.abort();
    }

    #[tokio::test]
    async fn ipv6_literal_emits_snapshot() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        // Register IPv6 literal
        let mut hosts = HashSet::new();
        hosts.insert("2001:db8::1".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        // Snapshot emitted on next tick
        let snapshot = next_dns_snapshot(&mut events_rx).await;
        let ips = snapshot.get("2001:db8::1").expect("missing IPv6 literal");
        assert!(ips.iter().any(|ip| ip.is_ipv6()));

        handle.abort();
    }

    // ========== Multi-IP Tests ==========

    #[tokio::test]
    async fn snapshot_contains_multiple_ips_for_same_hostname() {
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

        // Single snapshot contains both IPs (may skip initial empty snapshot)
        let snapshot = next_dns_snapshot_with_ips(&mut events_rx, "multi.example.com").await;
        let ips = snapshot.get("multi.example.com").expect("missing host");
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
        };

        let probe = FakeRouteProbe::noop();
        let tuning = Tuning::default();
        let dns_actor = make_dns(&local_dns, None, &tuning, &probe)
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
        };

        let probe = FakeRouteProbe::noop();
        let tuning = Tuning::default();
        let dns_actor = make_dns(&local_dns, None, &tuning, &probe)
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
