//! DNS resolver coroutine: consumes `SetHostnames` commands, manages IP lifecycle with TTL-based expiration,
//! and emits state snapshot events on resolution changes.

use crate::actor::{ActorError, ActorExitResult};
use crate::bind::{make_client_udp_socket, RouteProbe, UdpError};
use crate::config::{DnsTuning, LocalDns, Tuning};
use crate::events::{DnsEvent, Event};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rand::RngExt;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{debug, info, warn};

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

/// Normalizes a DNS wire-format name to a hostname string.
///
/// Wire-decoded names are always marked as FQDN, so `to_ascii()` includes a
/// trailing dot (e.g., `"example.com."`). This function strips it to match
/// the hostname format used as `HashMap` keys throughout the DNS module.
fn normalize_dns_name(name: &Name) -> String {
    let s = name.to_ascii();
    s.strip_suffix('.').unwrap_or(&s).to_ascii_lowercase()
}

/// Per-hostname DNS resolution and query tracking state.
///
/// Co-locates resolved IPs, in-flight queries, and refresh scheduling into a
/// single struct to eliminate map synchronization overhead. The `pending` map
/// is keyed by `RecordType` (A or AAAA), allowing at most one pending query
/// per record type per hostname.
#[derive(Debug)]
struct HostnameState {
    /// Resolved IPs with TTL-based expiration times.
    ips: HashMap<IpAddr, Instant>,
    /// Pending queries keyed by record type: (`transaction_id`, `last_sent_time`).
    pending: HashMap<RecordType, (u16, Instant)>,
    /// Earliest time at which `trigger_refresh` should re-query this hostname.
    next_refresh_at: Instant,
}

impl Default for HostnameState {
    fn default() -> Self {
        Self {
            ips: HashMap::new(),
            pending: HashMap::new(),
            next_refresh_at: Instant::now(),
        }
    }
}

/// DNS resolver actor state.
///
/// Created by `make_dns()`, consumed by `spawn_dns()`.
#[derive(Debug)]
pub struct DnsActor {
    server: SocketAddr,
    socket: UdpSocket,
    dns_tuning: DnsTuning,
    /// Per-hostname resolution state: resolved IPs, pending queries, and refresh scheduling.
    hostnames: HashMap<String, HostnameState>,
    /// True if state changed since the last snapshot emission.
    dirty: bool,
}

impl DnsActor {
    /// Updates the set of registered hostnames.
    ///
    /// Removes unregistered hostnames (including their IPs and pending queries);
    /// adds new hostnames with default state.
    fn set_hostnames(&mut self, hosts: &HashSet<String>) {
        let removed: Vec<String> = self
            .hostnames
            .extract_if(|host, _| !hosts.contains(host))
            .map(|(host, _)| host)
            .collect();
        if !removed.is_empty() {
            self.dirty = true;
            info!(hostnames = ?removed, "dns: hostnames unregistered");
        }
        for host in hosts {
            if !self.hostnames.contains_key(host) {
                self.dirty = true;
                info!(hostname = %host, "dns: hostname registered");
                self.hostnames
                    .insert(host.clone(), HostnameState::default());
            }
        }
    }

    /// Records a resolved IP for a hostname.
    fn record_ip(&mut self, host: &str, ip: IpAddr, ttl: u32) {
        let Some(entry) = self.hostnames.get_mut(host) else {
            return;
        };
        let record_ttl = Duration::from_secs(u64::from(ttl));
        let effective_ttl = record_ttl.max(self.dns_tuning.dns_min_ttl);
        let expires_at = Instant::now() + effective_ttl;
        if entry.ips.insert(ip, expires_at).is_none() {
            self.dirty = true;
            info!(host = %host, ip = %ip, ttl = ?effective_ttl, "dns: new IP resolved");
        }
    }

    /// Removes expired IPs.
    fn expire_stale(&mut self) {
        let now = Instant::now();
        for (host, entry) in &mut self.hostnames {
            let expired: Vec<IpAddr> = entry
                .ips
                .extract_if(|_, expires_at| *expires_at <= now)
                .map(|(ip, _)| ip)
                .collect();
            if !expired.is_empty() {
                self.dirty = true;
                info!(host = %host, ips = ?expired, "dns: IPs expired");
            }
        }
    }

    /// Emits a snapshot to the orchestrator if dirty, clearing the dirty flag.
    fn emit_snapshot(&mut self, events_tx: &mpsc::UnboundedSender<Event>) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let state = self
            .hostnames
            .iter()
            .map(|(host, entry)| (host.clone(), entry.ips.keys().copied().collect()))
            .collect();
        if events_tx.send(Event::Dns(DnsEvent { state })).is_err() {
            warn!("DNS: events channel closed, snapshot dropped");
        }
    }

    /// Validates and clears a pending query matching (hostname, `record_type`, txid).
    ///
    /// Returns `true` only when the hostname, record type, and transaction ID
    /// all match an in-flight query.
    fn take_pending(&mut self, hostname: &str, record_type: RecordType, id: u16) -> bool {
        let Some(entry) = self.hostnames.get_mut(hostname) else {
            warn!(hostname = %hostname, "dns: response for unregistered hostname");
            return false;
        };
        let Some(&(expected_id, _)) = entry.pending.get(&record_type) else {
            debug!(
                hostname = %hostname,
                record_type = ?record_type,
                "dns: response without pending query"
            );
            return false;
        };
        if expected_id != id {
            warn!(
                hostname = %hostname,
                expected = expected_id,
                got = id,
                "dns: transaction ID mismatch"
            );
            return false;
        }
        entry.pending.remove(&record_type);
        true
    }

    /// Runs the DNS resolver actor until its command channel closes or socket I/O fails.
    async fn run(
        mut self,
        mut cmd_rx: mpsc::UnboundedReceiver<DnsCommand>,
        events_tx: mpsc::UnboundedSender<Event>,
    ) -> ActorExitResult {
        let server_str = self.server.to_string();
        let query_timeout = self.dns_tuning.dns_query_timeout;
        let refresh_interval = self.dns_tuning.dns_refresh_interval;
        let snapshot_delay = self.dns_tuning.dns_snapshot_delay;

        info!(
            server = %self.server,
            refresh_interval = ?refresh_interval,
            min_ttl = ?self.dns_tuning.dns_min_ttl,
            "dns: resolver started"
        );

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let mut ticker = time::interval(query_timeout / 2);

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
                if self.dirty && !snapshot_armed {
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
                    match maybe_cmd {
                        Some(DnsCommand::SetHostnames { hosts }) => {
                            self.handle_set_hostnames(hosts, &events_tx).await;
                        }
                        None => return Ok(()),
                    }
                }
                result = self.socket.recv(&mut buf) => {
                    match result {
                        Ok(len) if len > 0 => {
                            self.handle_packet(&buf[..len]);
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
                    self.emit_snapshot(&events_tx);
                }
                _ = ticker.tick() => {
                    self.handle_tick().await;
                    self.expire_stale();
                    arm_snapshot_timer!();
                }
                _ = refresh_ticker.tick(), if !refresh_interval.is_zero() => {
                    self.trigger_refresh().await;
                }
            }
        }
    }

    /// Applies a complete hostname registration update and triggers resolution.
    async fn handle_set_hostnames(
        &mut self,
        new_hosts: HashSet<String>,
        events_tx: &mpsc::UnboundedSender<Event>,
    ) {
        self.set_hostnames(&new_hosts);

        // Record IP literals immediately (trigger_refresh skips them).
        for host in &new_hosts {
            if let Ok(ip) = host.parse::<IpAddr>() {
                self.record_ip(host, ip, u32::MAX);
            }
        }

        // Always emit a snapshot so the orchestrator rebuilds routing after config
        // changes. Without this, config updates that only change allowed_ips (same
        // hostnames, same resolved IPs) would never trigger a routing table rebuild.
        self.dirty = true;
        self.emit_snapshot(events_tx);

        self.trigger_refresh().await;
    }

    /// Sends A+AAAA queries for hostnames whose refresh deadline has passed.
    ///
    /// Skips IP literals and recently refreshed hostnames, then advances each
    /// selected hostname's refresh deadline.
    async fn trigger_refresh(&mut self) {
        let now = Instant::now();
        let refresh_interval = self.dns_tuning.dns_refresh_interval;
        let query_interval = self.dns_tuning.dns_query_interval;
        let hosts: Vec<String> = self
            .hostnames
            .iter()
            .filter(|(host, _)| host.parse::<IpAddr>().is_err())
            .filter(|(_, entry)| now >= entry.next_refresh_at)
            .map(|(host, _)| host.clone())
            .collect();

        for host in hosts {
            if let Some(entry) = self.hostnames.get_mut(&host) {
                entry.next_refresh_at = now + refresh_interval;
            }
            time::sleep(query_interval).await;
            self.send_query(host.clone(), RecordType::A).await;
            time::sleep(query_interval).await;
            self.send_query(host, RecordType::AAAA).await;
        }
    }

    /// Sends a DNS query and records it as pending.
    ///
    /// Skips the send when the same hostname and record type are already pending.
    async fn send_query(&mut self, host: String, record_type: RecordType) {
        if self
            .hostnames
            .get(&host)
            .is_some_and(|entry| entry.pending.contains_key(&record_type))
        {
            return;
        }

        let result: Result<(), String> = async {
            let name = Name::from_ascii(&host).map_err(|err| err.to_string())?;

            let mut message = Message::new();
            let id = rand::rng().random::<u16>();
            message.set_id(id);
            message.set_message_type(MessageType::Query);
            message.set_op_code(OpCode::Query);
            message.set_recursion_desired(true);
            message.add_query(record_type_query(name, record_type));

            let outbound = message.to_vec().map_err(|err| err.to_string())?;
            self.socket
                .send(&outbound)
                .await
                .map_err(|err| err.to_string())?;

            if let Some(entry) = self.hostnames.get_mut(&host) {
                entry.pending.insert(record_type, (id, Instant::now()));
            }

            Ok(())
        }
        .await;

        if let Err(err) = result {
            warn!(host = %host, record_type = ?record_type, server = %self.server, error = %err, "dns: query send failed");
        }
    }

    /// Parses a DNS response and updates the matching hostname state.
    ///
    /// Uses the response question for direct hostname lookup, then validates
    /// both the record type and transaction ID before applying records.
    fn handle_packet(&mut self, data: &[u8]) {
        let message = match Message::from_vec(data) {
            Ok(message) => message,
            Err(err) => {
                warn!(error = %err, "dns: packet decode failed");
                return;
            }
        };

        let Some(query) = message.queries().first() else {
            warn!("dns: response with empty question section");
            return;
        };

        let hostname = normalize_dns_name(query.name());
        let record_type = query.query_type();
        let id = message.id();

        // Treat truncated responses as packet loss: leave the pending entry
        // untouched so the timeout handler retries it.
        if message.truncated() {
            if self.hostnames.contains_key(&hostname) {
                warn!(host = %hostname, "dns: response truncated, will retry");
            } else {
                debug!(host = %hostname, "dns: truncated response for unregistered hostname");
            }
            return;
        }

        if !self.take_pending(&hostname, record_type, id) {
            return;
        }

        self.handle_decoded_packet(&message, &hostname, record_type);
    }

    /// Applies records from a decoded response that matches a pending query.
    fn handle_decoded_packet(&mut self, message: &Message, host: &str, record_type: RecordType) {
        log_response_warnings(message, host);

        let records = extract_records(message, record_type);

        if message.response_code() == ResponseCode::NoError && records.is_empty() {
            if let Some(got) = message
                .answers()
                .iter()
                .map(Record::record_type)
                .find(|&got| got != record_type)
            {
                warn!(
                    host = %host,
                    expected = ?record_type,
                    got = ?got,
                    "dns: unexpected record type in response"
                );
                return;
            }
        }

        for (address, ttl) in records {
            self.record_ip(host, address, ttl);
        }
    }

    /// Retries timed-out pending queries with new transaction IDs.
    async fn handle_tick(&mut self) {
        let now = Instant::now();
        let timeout = self.dns_tuning.dns_query_timeout;
        let query_interval = self.dns_tuning.dns_query_interval;
        let mut expired = Vec::new();
        for (host, entry) in &self.hostnames {
            for (&record_type, &(_, last_sent)) in &entry.pending {
                if now.duration_since(last_sent) >= timeout {
                    expired.push((host.clone(), record_type));
                }
            }
        }

        for (host, record_type) in expired {
            if let Some(entry) = self.hostnames.get_mut(&host) {
                entry.pending.remove(&record_type);
            }
            time::sleep(query_interval).await;
            warn!(host = %host, record_type = ?record_type, "dns: query timed out, retrying");
            self.send_query(host, record_type).await;
        }
    }
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
/// Returns [`UdpError`] when socket creation, binding, or connect fails.
pub async fn make_dns<P: RouteProbe>(
    local_dns: &LocalDns,
    tun_if: Option<&str>,
    tuning: &Tuning,
    probe: &P,
) -> Result<DnsActor, UdpError> {
    let server = local_dns.server;

    let socket = make_client_udp_socket(
        server,
        tun_if,
        local_dns.bindif.as_deref(),
        probe,
        tuning.io.socket_buffer_bytes(),
    )
    .await?;
    let socket = UdpSocket::from_std(socket).map_err(|e| UdpError::Socket(e.to_string()))?;

    Ok(DnsActor {
        server,
        socket,
        dns_tuning: tuning.dns.clone(),
        hostnames: HashMap::new(),
        dirty: false,
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
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let handle = tokio::spawn(actor.run(cmd_rx, events_tx));

    (cmd_tx, handle)
}

/// Builds a query for `name` and `record_type`.
fn record_type_query(name: Name, record_type: RecordType) -> Query {
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(record_type);
    query
}

/// Extracts answers matching `expected`, deduplicating by IP and keeping an arbitrary TTL (order not guaranteed).
fn extract_records(message: &Message, expected: RecordType) -> Vec<(IpAddr, u32)> {
    let mut records: HashMap<IpAddr, u32> = HashMap::new();

    for answer in message.answers() {
        let (ip, ttl) = match answer.data() {
            RData::A(addr) if expected == RecordType::A => (IpAddr::V4(addr.0), answer.ttl()),
            RData::AAAA(addr) if expected == RecordType::AAAA => (IpAddr::V6(addr.0), answer.ttl()),
            _ => continue,
        };

        records.entry(ip).or_insert(ttl);
    }

    records.into_iter().collect()
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

    if !message.recursion_available() {
        warn!(host = %host, "dns: recursion unavailable");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::test_support::FakeRouteProbe;
    use hickory_proto::rr::rdata::A;
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

    /// Creates an actor for tests that exercise synchronous state transitions.
    async fn test_dns_actor() -> DnsActor {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        DnsActor {
            server: socket.local_addr().unwrap(),
            socket,
            dns_tuning: DnsTuning::default(),
            hostnames: HashMap::new(),
            dirty: false,
        }
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

    /// Builds a truncated DNS response (TC bit set, no answers).
    fn build_truncated_response(id: u16, query: Query) -> Vec<u8> {
        let mut response = Message::new();
        response.set_id(id);
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_response_code(ResponseCode::NoError);
        response.set_recursion_available(true);
        response.set_truncated(true);
        response.add_query(query);
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
    async fn emits_snapshot_on_repeated_set_hostnames() {
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

        // Drain any pending debounce snapshot before the re-register check
        tokio::time::sleep(Duration::from_millis(200)).await;
        while events_rx.try_recv().is_ok() {}

        // Re-register same hosts (simulating config push with changed allowed_ips)
        // SetHostnames always marks dirty so the orchestrator can rebuild routing.
        let mut hosts2 = HashSet::new();
        hosts2.insert("example.com".to_string());
        cmd_tx
            .send(DnsCommand::SetHostnames { hosts: hosts2 })
            .unwrap();

        // Should receive a snapshot (SetHostnames unconditionally marks dirty)
        let snapshot = next_dns_snapshot(&mut events_rx).await;
        let ips = snapshot.get("example.com").expect("missing example.com");
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));

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

    // ========== Truncation Tests ==========

    #[tokio::test]
    async fn retries_on_truncated_response() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, _events_rx, handle) = start_resolver(server_addr, None).await;

        let mut hosts = HashSet::new();
        hosts.insert("truncated.example".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        // Collect the two initial queries (A + AAAA).
        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let mut original_ids: HashMap<RecordType, u16> = HashMap::new();
        for _ in 0..2 {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..len]).unwrap();
            let query = request.queries().first().cloned().unwrap();
            original_ids.insert(query.query_type(), request.id());

            let data = build_truncated_response(request.id(), query);
            socket.send_to(&data, peer).await.unwrap();
        }

        // Wait briefly, then collect the retry queries (driven by handle_tick).
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut retry_ids: HashMap<RecordType, u16> = HashMap::new();
        for _ in 0..2 {
            let (len, _peer) = socket.recv_from(&mut buf).await.unwrap();
            let message = Message::from_vec(&buf[..len]).unwrap();
            let query = message.queries().first().cloned().unwrap();
            retry_ids.insert(query.query_type(), message.id());
        }

        // Retry must use new transaction IDs.
        let orig_a = *original_ids
            .get(&RecordType::A)
            .expect("missing original A query");
        let orig_aaaa = *original_ids
            .get(&RecordType::AAAA)
            .expect("missing original AAAA query");
        let retry_a = *retry_ids
            .get(&RecordType::A)
            .expect("missing retry A query");
        let retry_aaaa = *retry_ids
            .get(&RecordType::AAAA)
            .expect("missing retry AAAA query");
        assert_ne!(orig_a, retry_a);
        assert_ne!(orig_aaaa, retry_aaaa);

        handle.abort();
    }

    #[tokio::test]
    async fn truncated_response_does_not_emit_snapshot() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        let mut hosts = HashSet::new();
        hosts.insert("truncated.example".to_string());
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        // Consume the initial empty snapshot from SetHostnames.
        let snapshot = next_dns_snapshot(&mut events_rx).await;
        assert!(
            snapshot
                .get("truncated.example")
                .is_none_or(|ips| ips.is_empty()),
            "initial snapshot should have no IPs"
        );

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];

        // Receive and reply with truncated for both A and AAAA.
        for _ in 0..2 {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..len]).unwrap();
            let query = request.queries().first().cloned().unwrap();

            let data = build_truncated_response(request.id(), query);
            socket.send_to(&data, peer).await.unwrap();
        }

        // Wait briefly and verify no snapshot is emitted.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            events_rx.try_recv().unwrap_err(),
            tokio::sync::mpsc::error::TryRecvError::Empty,
            "truncated response should not trigger a snapshot"
        );

        handle.abort();
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
        let mut first_ids: HashMap<RecordType, u16> = HashMap::new();
        for _ in 0..2 {
            let (len, _peer) = socket.recv_from(&mut buf).await.unwrap();
            let message = Message::from_vec(&buf[..len]).unwrap();
            let query = message.queries().first().cloned().unwrap();
            first_ids.insert(query.query_type(), message.id());
        }

        // Wait for timeout and retry
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut retry_ids: HashMap<RecordType, u16> = HashMap::new();
        for _ in 0..2 {
            let (len, _peer) = socket.recv_from(&mut buf).await.unwrap();
            let message = Message::from_vec(&buf[..len]).unwrap();
            let query = message.queries().first().cloned().unwrap();
            retry_ids.insert(query.query_type(), message.id());
        }

        assert_ne!(first_ids.get(&RecordType::A), retry_ids.get(&RecordType::A));
        assert_ne!(
            first_ids.get(&RecordType::AAAA),
            retry_ids.get(&RecordType::AAAA)
        );

        handle.abort();
    }

    // ========== Actor State Unit Tests ==========

    #[test]
    fn normalize_dns_name_strips_trailing_dot() {
        let fqdn = Name::from_ascii("example.com.").unwrap();
        assert_eq!(normalize_dns_name(&fqdn), "example.com");

        let non_fqdn = Name::from_ascii("example.com").unwrap();
        assert_eq!(normalize_dns_name(&non_fqdn), "example.com");

        let root = Name::root();
        assert_eq!(normalize_dns_name(&root), "");
    }

    #[tokio::test]
    async fn set_hostnames_cleans_all_state() {
        let mut actor = test_dns_actor().await;
        let mut hosts = HashSet::new();
        hosts.insert("example.com".to_string());
        actor.set_hostnames(&hosts);

        let entry = actor.hostnames.get_mut("example.com").unwrap();
        entry.pending.insert(RecordType::A, (42, Instant::now()));
        entry.pending.insert(RecordType::AAAA, (43, Instant::now()));
        entry
            .ips
            .insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), Instant::now());

        actor.set_hostnames(&HashSet::new());
        assert!(actor.hostnames.is_empty());
    }

    #[tokio::test]
    async fn take_pending_validates_txid() {
        let mut actor = test_dns_actor().await;
        let mut entry = HostnameState::default();
        entry.pending.insert(RecordType::A, (42, Instant::now()));
        actor.hostnames.insert("example.com".into(), entry);

        // Unregistered hostname → rejected
        assert!(!actor.take_pending("unknown.com", RecordType::A, 42));

        // Wrong txid → rejected, pending preserved
        assert!(!actor.take_pending("example.com", RecordType::A, 99));
        assert!(actor.hostnames["example.com"]
            .pending
            .contains_key(&RecordType::A));

        // Wrong record type → rejected
        assert!(!actor.take_pending("example.com", RecordType::AAAA, 42));

        // Correct txid → accepted and cleared
        assert!(actor.take_pending("example.com", RecordType::A, 42));
        assert!(!actor.hostnames["example.com"]
            .pending
            .contains_key(&RecordType::A));
    }

    #[tokio::test]
    async fn repeated_set_hostnames_skips_recent_refresh() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, handle) = start_resolver(server_addr, None).await;

        let mut hosts = HashSet::new();
        hosts.insert("example.com".to_string());
        cmd_tx
            .send(DnsCommand::SetHostnames {
                hosts: hosts.clone(),
            })
            .unwrap();

        // Consume initial queries (A + AAAA)
        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        for _ in 0..2 {
            let _ = socket.recv_from(&mut buf).await.unwrap();
        }

        // Consume initial snapshot
        let _ = next_dns_snapshot(&mut events_rx).await;

        // Re-register same hostnames immediately (within refresh_interval)
        cmd_tx.send(DnsCommand::SetHostnames { hosts }).unwrap();

        // Consume snapshot from second SetHostnames (always emitted)
        let _ = next_dns_snapshot(&mut events_rx).await;

        // Verify no new queries are sent (trigger_refresh should skip)
        let result =
            tokio::time::timeout(Duration::from_millis(200), socket.recv_from(&mut buf)).await;
        assert!(
            result.is_err(),
            "no additional queries expected after recent refresh"
        );

        handle.abort();
    }
}
