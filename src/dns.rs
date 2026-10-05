//! DNS resolver coroutine: consumes `SetHostnames` events, manages IP lifecycle with TTL-based expiration,
//! and emits state snapshot events on resolution changes.

use crate::actor::{ActorContext, ActorExitResult, ActorRef, ActorRuntime, SupervisionPolicy};
use crate::bind::{make_client_udp_socket, RouteProbe};
use crate::config::{DnsTuning, LocalDns};
use crate::events::{DnsEvent, Event};
use crate::helpers::make_interval;
use anyhow::{anyhow, Context};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rand::RngExt;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time;
use tracing::{debug, info, warn};

const DNS_BUFFER_SIZE: usize = 1500;

/// Normalizes a DNS wire-format name to a hostname string.
///
/// Wire-decoded names are always marked as FQDN, so `to_ascii()` includes a
/// trailing dot (e.g., `"example.com."`). This function strips it to match
/// the hostname format used as `HashMap` keys throughout the DNS module.
fn normalize_dns_name(name: &Name) -> String {
    let s = name.to_ascii();
    s.strip_suffix('.').unwrap_or(&s).to_ascii_lowercase()
}

/// Per-hostname DNS resolution and refresh state.
#[derive(Debug)]
struct HostnameState {
    /// Resolved IPs with TTL-based expiration times.
    ips: HashMap<IpAddr, Instant>,
    /// Earliest time at which `trigger_refresh` should re-query this hostname.
    next_refresh_at: Instant,
}

/// A DNS query waiting for the global query pacing timer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsQuery {
    hostname: String,
    record_type: RecordType,
}

/// Result of one query task, tagged with the query it answers.
type QueryOutcome = (DnsQuery, anyhow::Result<Message>);

impl Default for HostnameState {
    fn default() -> Self {
        Self {
            ips: HashMap::new(),
            next_refresh_at: Instant::now(),
        }
    }
}

/// DNS resolver actor state.
///
/// The actor owns only resolution state; every query runs as a task in
/// `tasks` with its own freshly bound socket, so socket errors stay scoped to
/// one query and each query gets a new ephemeral source port (RFC 5452).
#[derive(Debug)]
struct DnsActor<P> {
    server: SocketAddr,
    tun_if: Option<String>,
    bindif: Option<String>,
    probe: P,
    dns_tuning: DnsTuning,
    /// Per-hostname resolution and refresh state.
    hostnames: HashMap<String, HostnameState>,
    /// Queries waiting to be sent, deduplicated by hostname and record type.
    /// A query is never both queued here and present in `pending_queries`.
    queued_queries: HashSet<DnsQuery>,
    /// In-flight query tasks. Dropping the actor aborts all of them.
    tasks: JoinSet<QueryOutcome>,
    /// Queries with an in-flight task; each has exactly one task, whose result
    /// alone removes the entry.
    pending_queries: HashSet<DnsQuery>,
    /// True if state changed since the last snapshot emission.
    dirty: bool,
}

impl<P: RouteProbe + Clone + Send + Sync + 'static> DnsActor<P> {
    /// Creates an idle actor; performs no I/O.
    fn new(local_dns: &LocalDns, tun_if: Option<&str>, dns_tuning: &DnsTuning, probe: P) -> Self {
        Self {
            server: local_dns.server,
            tun_if: tun_if.map(str::to_owned),
            bindif: local_dns.bindif.clone(),
            probe,
            dns_tuning: dns_tuning.clone(),
            hostnames: HashMap::new(),
            queued_queries: HashSet::new(),
            tasks: JoinSet::new(),
            pending_queries: HashSet::new(),
            dirty: false,
        }
    }

    /// Updates the set of registered hostnames.
    ///
    /// Removes unregistered hostnames (including their IPs and queued queries);
    /// adds new hostnames with default state. In-flight tasks are left to finish
    /// and their results are discarded if the hostname is still unregistered.
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
        self.queued_queries
            .retain(|query| hosts.contains(&query.hostname));
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

    /// Emits a snapshot to the actor owner if dirty, clearing the dirty flag.
    fn emit_snapshot(&mut self, ctx: &ActorContext) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let state = self
            .hostnames
            .iter()
            .map(|(host, entry)| (host.clone(), entry.ips.keys().copied().collect()))
            .collect();
        if ctx.notify_owner(Event::Dns(DnsEvent { state })).is_err() {
            warn!("DNS: orchestrator inbox closed, snapshot dropped");
        }
    }

    /// Runs the DNS resolver actor until stopped or a query task panics.
    async fn run(mut self, mut ctx: ActorContext) -> ActorExitResult {
        let refresh_interval = self.dns_tuning.dns_refresh_interval;
        let query_interval = self.dns_tuning.dns_query_interval;

        info!(
            server = %self.server,
            refresh_interval = ?refresh_interval,
            min_ttl = ?self.dns_tuning.dns_min_ttl,
            "dns: resolver started"
        );

        let mut query_ticker = make_interval(query_interval);

        let mut refresh_ticker = make_interval(refresh_interval);
        refresh_ticker.tick().await; // consume immediate first tick

        loop {
            tokio::select! {
                message = ctx.recv() => {
                    match message {
                        Some(Event::SetHostnames { hosts }) => {
                            self.handle_set_hostnames(hosts);
                        }
                        Some(Event::Stop) => return Ok(()),
                        Some(message) => debug!(?message, "DNS: ignoring unexpected message"),
                        None => return Ok(()),
                    }
                }
                Some(joined) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    let (query, result) = joined.context("DNS query task panicked")?;
                    self.handle_query_result(query, result);
                }
                _ = refresh_ticker.tick() => {
                    self.trigger_refresh();
                    self.expire_stale();
                }
                _ = query_ticker.tick(), if !self.queued_queries.is_empty() => {
                    // A partially consumed ExtractIf retains every unvisited query.
                    let query = self.queued_queries.extract_if(|_| true).next();
                    if let Some(query) = query {
                        self.spawn_query(query);
                    }
                }
            }

            self.emit_snapshot(&ctx);
        }
    }

    /// Applies a complete hostname registration update and triggers resolution.
    fn handle_set_hostnames(&mut self, new_hosts: HashSet<String>) {
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

        self.trigger_refresh();
    }

    /// Queues A+AAAA queries for hostnames whose refresh deadline has passed.
    ///
    /// Skips IP literals and recently refreshed hostnames, then advances each
    /// selected hostname's refresh deadline.
    fn trigger_refresh(&mut self) {
        let now = Instant::now();
        let refresh_interval = self.dns_tuning.dns_refresh_interval;
        let queued_queries = &mut self.queued_queries;
        let pending_queries = &self.pending_queries;

        for (hostname, entry) in &mut self.hostnames {
            if hostname.parse::<IpAddr>().is_ok() || now < entry.next_refresh_at {
                continue;
            }

            entry.next_refresh_at = now + refresh_interval;
            for record_type in [RecordType::A, RecordType::AAAA] {
                let query = DnsQuery {
                    hostname: hostname.clone(),
                    record_type,
                };
                if !pending_queries.contains(&query) {
                    queued_queries.insert(query);
                }
            }
        }
    }

    /// Spawns a task resolving `query` and records it as pending.
    fn spawn_query(&mut self, query: DnsQuery) {
        let resolve = resolve(
            self.server,
            self.tun_if.clone(),
            self.bindif.clone(),
            self.probe.clone(),
            query.clone(),
            self.dns_tuning.dns_query_timeout,
        );
        let task_query = query.clone();
        self.tasks.spawn(async move { (task_query, resolve.await) });
        self.pending_queries.insert(query);
    }

    /// Applies a finished query task's result, or requeues the query on failure.
    fn handle_query_result(&mut self, query: DnsQuery, result: anyhow::Result<Message>) {
        self.pending_queries.remove(&query);
        if !self.hostnames.contains_key(&query.hostname) {
            debug!(host = %query.hostname, "dns: dropping result for unregistered hostname");
            return;
        }

        match result {
            Ok(message) => self.handle_response(&message, &query.hostname, query.record_type),
            Err(err) => {
                warn!(host = %query.hostname, record_type = ?query.record_type, server = %self.server, error = %format!("{err:#}"), "dns: query failed, scheduling retry");
                self.queued_queries.insert(query);
            }
        }
    }

    /// Applies records from a response that answers a pending query.
    fn handle_response(&mut self, message: &Message, host: &str, record_type: RecordType) {
        log_response_warnings(message, host);

        let records = extract_records(message, record_type);

        if message.metadata.response_code == ResponseCode::NoError && records.is_empty() {
            if let Some(got) = message
                .answers
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
}

/// Resolves `query` once over a fresh socket, failing no earlier than `timeout`.
///
/// Every failure (socket setup, ICMP-induced `ECONNREFUSED`, truncation,
/// timeout) is reported only after the full timeout elapses, so a dead server
/// is retried once per `timeout` rather than once per pacing tick.
async fn resolve<P: RouteProbe>(
    server: SocketAddr,
    tun_if: Option<String>,
    bindif: Option<String>,
    probe: P,
    query: DnsQuery,
    timeout: Duration,
) -> anyhow::Result<Message> {
    let deadline = time::Instant::now() + timeout;
    let exchange = exchange(server, tun_if.as_deref(), bindif.as_deref(), &probe, &query);
    let err = match time::timeout_at(deadline, exchange).await {
        Ok(Ok(message)) => return Ok(message),
        Ok(Err(err)) => err,
        Err(_) => anyhow!("query timed out after {timeout:?}"),
    };
    time::sleep_until(deadline).await;
    Err(err)
}

/// Sends `query` from a new interface-bound socket and waits for its answer.
///
/// Skips packets whose transaction ID or question does not match, and treats
/// truncated responses as packet loss.
async fn exchange<P: RouteProbe>(
    server: SocketAddr,
    tun_if: Option<&str>,
    bindif: Option<&str>,
    probe: &P,
    query: &DnsQuery,
) -> anyhow::Result<Message> {
    // Buffer size 0 keeps OS defaults: the configured size targets data-plane
    // sockets and would log a warning per query when it exceeds `rmem_max`.
    let socket = make_client_udp_socket(server, tun_if, bindif, probe, 0).await?;
    let socket = UdpSocket::from_std(socket).context("register DNS socket")?;

    let id = rand::rng().random::<u16>();
    let mut request = Message::new(id, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(record_type_query(
        Name::from_ascii(&query.hostname)?,
        query.record_type,
    ));
    socket
        .send(&request.to_vec()?)
        .await
        .context("send DNS query")?;

    let mut buf = [0u8; DNS_BUFFER_SIZE];
    loop {
        let len = socket
            .recv(&mut buf)
            .await
            .context("receive DNS response")?;
        let response = match Message::from_vec(&buf[..len]) {
            Ok(response) => response,
            Err(err) => {
                warn!(error = %err, "dns: packet decode failed");
                continue;
            }
        };
        let answers_query = response.metadata.id == id
            && response.queries.first().is_some_and(|question| {
                question.query_type() == query.record_type
                    && normalize_dns_name(question.name()) == query.hostname
            });
        if !answers_query {
            warn!(host = %query.hostname, record_type = ?query.record_type, "dns: ignoring mismatched response");
            continue;
        }
        if response.metadata.truncation {
            warn!(host = %query.hostname, "dns: response truncated, will retry");
            continue;
        }
        return Ok(response);
    }
}

/// Spawns the DNS resolver actor task.
///
/// Construction performs no I/O: each query binds its own socket when sent.
///
/// # Arguments
///
/// * `local_dns` - DNS configuration from config file.
/// * `tun_if` - Optional TUN interface name to exclude from routing.
/// * `dns_tuning` - DNS timeouts, intervals, and TTL floor.
/// * `probe` - Route probe for per-query interface selection.
/// * `ctx` - Parent actor context used to spawn the actor.
pub fn spawn_dns<P: RouteProbe + Clone + Send + Sync + 'static>(
    local_dns: &LocalDns,
    tun_if: Option<&str>,
    dns_tuning: &DnsTuning,
    probe: P,
    ctx: &ActorContext,
) -> ActorRef {
    let actor = DnsActor::new(local_dns, tun_if, dns_tuning, probe);
    ctx.spawn(
        format!("dns-resolver[{}]", actor.server),
        ActorRuntime::Main,
        SupervisionPolicy::Critical,
        |ctx| actor.run(ctx),
    )
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

    for answer in &message.answers {
        let (ip, ttl) = match &answer.data {
            RData::A(addr) if expected == RecordType::A => (IpAddr::V4(addr.0), answer.ttl),
            RData::AAAA(addr) if expected == RecordType::AAAA => (IpAddr::V6(addr.0), answer.ttl),
            _ => continue,
        };

        records.entry(ip).or_insert(ttl);
    }

    records.into_iter().collect()
}

/// Logs DNS response warnings at origin (not sent as events).
fn log_response_warnings(message: &Message, host: &str) {
    match message.metadata.response_code {
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

    if !message.metadata.recursion_available {
        warn!(host = %host, "dns: recursion unavailable");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bind::test_support::FakeRouteProbe;
    use hickory_proto::rr::rdata::A;
    use std::net::Ipv4Addr;
    use tokio::sync::mpsc;
    use tokio::time;

    struct TestDnsHandle {
        ctx: ActorContext,
        actor: ActorRef,
    }

    impl TestDnsHandle {
        fn send(&self, message: Event) -> Result<(), mpsc::error::SendError<Event>> {
            self.ctx.send(&self.actor, message)
        }
    }

    /// Starts a resolver coroutine wired to the provided server socket.
    fn start_resolver(
        server: SocketAddr,
        dns_tuning: &DnsTuning,
    ) -> (TestDnsHandle, ActorContext, crate::actor::ActorBus) {
        let local_dns = LocalDns {
            server,
            bindif: None,
        };
        let actor_bus = crate::actor::ActorBus::on_current_runtime();
        let orchestrator = actor_bus.mailbox("test-orchestrator");
        let controller = actor_bus.mailbox("test-controller");
        let actor = spawn_dns(
            &local_dns,
            None,
            dns_tuning,
            FakeRouteProbe::noop(),
            &orchestrator,
        );
        (
            TestDnsHandle {
                ctx: controller,
                actor,
            },
            orchestrator,
            actor_bus,
        )
    }

    /// Creates an actor for tests that exercise synchronous state transitions.
    ///
    /// Spawned query tasks never run unless the test yields to the runtime.
    fn test_dns_actor() -> DnsActor<FakeRouteProbe> {
        let local_dns = LocalDns {
            server: "127.0.0.1:53".parse().unwrap(),
            bindif: None,
        };
        DnsActor::new(
            &local_dns,
            None,
            &DnsTuning::default(),
            FakeRouteProbe::noop(),
        )
    }

    /// Builds a DNS response message for the provided transaction ID.
    fn build_response(
        id: u16,
        query: Query,
        response_code: ResponseCode,
        answers: Vec<Record>,
    ) -> Vec<u8> {
        let mut response = Message::response(id, OpCode::Query);
        response.metadata.response_code = response_code;
        response.metadata.recursion_available = true;
        response.add_query(query);
        for answer in answers {
            response.add_answer(answer);
        }
        response.to_vec().unwrap()
    }

    /// Builds a truncated DNS response (TC bit set, no answers).
    fn build_truncated_response(id: u16, query: Query) -> Vec<u8> {
        let mut response = Message::response(id, OpCode::Query);
        response.metadata.response_code = ResponseCode::NoError;
        response.metadata.recursion_available = true;
        response.metadata.truncation = true;
        response.add_query(query);
        response.to_vec().unwrap()
    }

    /// Answers one A and one AAAA query in any order, returning IPv4 records for A.
    async fn answer_initial_queries_with_ipv4(
        socket: &UdpSocket,
        addresses: &[Ipv4Addr],
        ttl: u32,
    ) {
        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        for _ in 0..2 {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..len]).unwrap();
            let query = request.queries.first().cloned().unwrap();
            let answers = if query.query_type() == RecordType::A {
                addresses
                    .iter()
                    .map(|&address| {
                        Record::from_rdata(query.name().clone(), ttl, RData::A(A(address)))
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let response =
                build_response(request.metadata.id, query, ResponseCode::NoError, answers);
            socket.send_to(&response, peer).await.unwrap();
        }
    }

    /// Receives the next DNS snapshot event.
    async fn next_dns_snapshot(events_rx: &mut ActorContext) -> HashMap<String, HashSet<IpAddr>> {
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
        events_rx: &mut ActorContext,
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
        let (cmd_tx, mut events_rx, _actor_bus) =
            start_resolver(server_addr, &DnsTuning::default());

        let mut hosts = HashSet::new();
        hosts.insert("example.com".to_string());
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        answer_initial_queries_with_ipv4(&socket, &[Ipv4Addr::new(1, 2, 3, 4)], 300).await;

        // Wait for snapshot with resolved IPs (may skip initial empty snapshot)
        let snapshot = next_dns_snapshot_with_ips(&mut events_rx, "example.com").await;
        let ips = snapshot.get("example.com").expect("missing example.com");
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[tokio::test]
    async fn emits_snapshot_on_repeated_set_hostnames() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, _actor_bus) =
            start_resolver(server_addr, &DnsTuning::default());

        let mut hosts = HashSet::new();
        hosts.insert("example.com".to_string());
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        // First resolution
        answer_initial_queries_with_ipv4(&socket, &[Ipv4Addr::new(1, 2, 3, 4)], 300).await;

        // Wait for snapshot with resolved IPs (skips the immediate empty snapshot)
        let _ = next_dns_snapshot_with_ips(&mut events_rx, "example.com").await;

        // Drain snapshots queued before the re-register check.
        while events_rx.try_recv().is_ok() {}

        // Re-register same hosts (simulating config push with changed allowed_ips)
        // SetHostnames always marks dirty so the orchestrator can rebuild routing.
        let mut hosts2 = HashSet::new();
        hosts2.insert("example.com".to_string());
        cmd_tx.send(Event::SetHostnames { hosts: hosts2 }).unwrap();

        // Should receive a snapshot (SetHostnames unconditionally marks dirty)
        let snapshot = next_dns_snapshot(&mut events_rx).await;
        let ips = snapshot.get("example.com").expect("missing example.com");
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[tokio::test]
    async fn emits_snapshot_on_hostname_removal() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, _actor_bus) =
            start_resolver(server_addr, &DnsTuning::default());

        // Register and resolve
        let mut hosts = HashSet::new();
        hosts.insert("example.com".to_string());
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        answer_initial_queries_with_ipv4(&socket, &[Ipv4Addr::new(1, 2, 3, 4)], 3600).await;

        // Wait for snapshot with IPs (may skip initial empty snapshot)
        let snapshot = next_dns_snapshot_with_ips(&mut events_rx, "example.com").await;
        assert!(snapshot
            .get("example.com")
            .unwrap()
            .contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));

        // Unregister by sending empty hosts
        cmd_tx
            .send(Event::SetHostnames {
                hosts: HashSet::new(),
            })
            .unwrap();

        // Should receive snapshot with example.com removed
        let snapshot = next_dns_snapshot(&mut events_rx).await;
        assert!(
            !snapshot.contains_key("example.com"),
            "example.com should be removed"
        );
    }

    // ========== IP Literal Tests ==========

    #[tokio::test]
    async fn ip_literal_emits_snapshot() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, _actor_bus) =
            start_resolver(server_addr, &DnsTuning::default());

        // Register IP literal
        let mut hosts = HashSet::new();
        hosts.insert("192.168.1.100".to_string());
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        // SetHostnames emits the snapshot immediately.
        let snapshot = next_dns_snapshot(&mut events_rx).await;
        let ips = snapshot.get("192.168.1.100").expect("missing IP literal");
        assert!(ips.contains(&"192.168.1.100".parse::<IpAddr>().unwrap()));
    }

    #[tokio::test]
    async fn ipv6_literal_emits_snapshot() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, _actor_bus) =
            start_resolver(server_addr, &DnsTuning::default());

        // Register IPv6 literal
        let mut hosts = HashSet::new();
        hosts.insert("2001:db8::1".to_string());
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        // SetHostnames emits the snapshot immediately.
        let snapshot = next_dns_snapshot(&mut events_rx).await;
        let ips = snapshot.get("2001:db8::1").expect("missing IPv6 literal");
        assert!(ips.iter().any(|ip| ip.is_ipv6()));
    }

    // ========== Multi-IP Tests ==========

    #[tokio::test]
    async fn snapshot_contains_multiple_ips_for_same_hostname() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, _actor_bus) =
            start_resolver(server_addr, &DnsTuning::default());

        let mut hosts = HashSet::new();
        hosts.insert("multi.example.com".to_string());
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        answer_initial_queries_with_ipv4(
            &socket,
            &[Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
            120,
        )
        .await;

        // Single snapshot contains both IPs (may skip initial empty snapshot)
        let snapshot = next_dns_snapshot_with_ips(&mut events_rx, "multi.example.com").await;
        let ips = snapshot.get("multi.example.com").expect("missing host");
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    // ========== Actor Lifecycle Tests ==========

    #[tokio::test]
    async fn dns_actor_exits_when_stopped() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (cmd_tx, mut orchestrator, mut actor_bus) =
            start_resolver(socket.local_addr().unwrap(), &DnsTuning::default());
        cmd_tx.send(Event::Stop).unwrap();

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            crate::actor::next_actor_exit(&mut actor_bus, &mut orchestrator),
        )
        .await;
        assert!(
            matches!(
                result,
                Ok(crate::actor::ActorExit {
                    result: Ok(Ok(())),
                    ..
                })
            ),
            "actor should shut down cleanly after sender dropped, got {:?}",
            result
        );
    }

    // ========== Retry Tests ==========

    /// Tuning with a short query timeout so retries happen quickly.
    fn fast_retry_tuning() -> DnsTuning {
        DnsTuning {
            dns_query_timeout: Duration::from_millis(200),
            ..DnsTuning::default()
        }
    }

    /// Receives one A and one AAAA query, keyed by record type with (txid, source).
    ///
    /// Replies with a truncated response when `reply_truncated` is set.
    async fn recv_query_pair(
        socket: &UdpSocket,
        reply_truncated: bool,
    ) -> HashMap<RecordType, (u16, SocketAddr)> {
        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        let mut queries = HashMap::new();
        for _ in 0..2 {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..len]).unwrap();
            let query = request.queries.first().cloned().unwrap();
            queries.insert(query.query_type(), (request.metadata.id, peer));
            if reply_truncated {
                let data = build_truncated_response(request.metadata.id, query);
                socket.send_to(&data, peer).await.unwrap();
            }
        }
        queries
    }

    /// Asserts every retry uses a new transaction ID and a new socket.
    fn assert_fresh_retries(
        first: &HashMap<RecordType, (u16, SocketAddr)>,
        retry: &HashMap<RecordType, (u16, SocketAddr)>,
    ) {
        for record_type in [RecordType::A, RecordType::AAAA] {
            let (first_id, first_source) = first[&record_type];
            let (retry_id, retry_source) = retry[&record_type];
            assert_ne!(first_id, retry_id, "{record_type:?} retry reused txid");
            assert_ne!(
                first_source, retry_source,
                "{record_type:?} retry reused source port"
            );
        }
    }

    #[tokio::test]
    async fn retries_on_truncated_response() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (cmd_tx, _events_rx, _actor_bus) =
            start_resolver(socket.local_addr().unwrap(), &fast_retry_tuning());

        let hosts = HashSet::from(["truncated.example".to_string()]);
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        let first = recv_query_pair(&socket, true).await;
        let retry = recv_query_pair(&socket, false).await;
        assert_fresh_retries(&first, &retry);
    }

    #[tokio::test]
    async fn truncated_response_does_not_emit_snapshot() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (cmd_tx, mut events_rx, _actor_bus) =
            start_resolver(socket.local_addr().unwrap(), &DnsTuning::default());

        let hosts = HashSet::from(["truncated.example".to_string()]);
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        // Consume the initial empty snapshot from SetHostnames.
        let snapshot = next_dns_snapshot(&mut events_rx).await;
        assert!(
            snapshot
                .get("truncated.example")
                .is_none_or(|ips| ips.is_empty()),
            "initial snapshot should have no IPs"
        );

        recv_query_pair(&socket, true).await;

        // Wait briefly and verify no snapshot is emitted.
        time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            events_rx.try_recv().unwrap_err(),
            mpsc::error::TryRecvError::Empty,
            "truncated response should not trigger a snapshot"
        );
    }

    #[tokio::test]
    async fn retries_with_new_socket_on_timeout() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (cmd_tx, _events_rx, _actor_bus) =
            start_resolver(socket.local_addr().unwrap(), &fast_retry_tuning());

        let hosts = HashSet::from(["timeout.example".to_string()]);
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        let first = recv_query_pair(&socket, false).await;
        let retry = recv_query_pair(&socket, false).await;
        assert_fresh_retries(&first, &retry);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn survives_connection_refused_and_retries() {
        // Reserve a port, then close it so queries trigger ICMP port unreachable.
        let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = closed.local_addr().unwrap();
        drop(closed);

        let (cmd_tx, mut events_rx, _actor_bus) = start_resolver(server_addr, &fast_retry_tuning());
        let hosts = HashSet::from(["example.com".to_string()]);
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        // Let both initial queries hit the closed port, then bring the server up.
        time::sleep(Duration::from_millis(300)).await;
        let socket = UdpSocket::bind(server_addr).await.unwrap();
        answer_initial_queries_with_ipv4(&socket, &[Ipv4Addr::new(1, 2, 3, 4)], 300).await;

        let snapshot = time::timeout(
            Duration::from_secs(2),
            next_dns_snapshot_with_ips(&mut events_rx, "example.com"),
        )
        .await
        .expect("resolver should recover after ECONNREFUSED");
        assert!(logs_contain("receive DNS response"));
        assert!(snapshot["example.com"].contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[tokio::test]
    async fn ignores_response_with_mismatched_txid() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (cmd_tx, mut events_rx, _actor_bus) =
            start_resolver(socket.local_addr().unwrap(), &DnsTuning::default());
        let hosts = HashSet::from(["example.com".to_string()]);
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        for _ in 0..2 {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..len]).unwrap();
            let query = request.queries.first().cloned().unwrap();
            let id = request.metadata.id;
            for (reply_id, address) in [
                (id.wrapping_add(1), Ipv4Addr::new(6, 6, 6, 6)),
                (id, Ipv4Addr::new(1, 2, 3, 4)),
            ] {
                let answers = if query.query_type() == RecordType::A {
                    vec![Record::from_rdata(
                        query.name().clone(),
                        300,
                        RData::A(A(address)),
                    )]
                } else {
                    Vec::new()
                };
                let response =
                    build_response(reply_id, query.clone(), ResponseCode::NoError, answers);
                socket.send_to(&response, peer).await.unwrap();
            }
        }

        let snapshot = next_dns_snapshot_with_ips(&mut events_rx, "example.com").await;
        assert_eq!(
            snapshot["example.com"],
            HashSet::from([IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))])
        );
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

    fn query(hostname: &str, record_type: RecordType) -> DnsQuery {
        DnsQuery {
            hostname: hostname.to_string(),
            record_type,
        }
    }

    #[tokio::test]
    async fn set_hostnames_cleans_state_but_keeps_in_flight_queries() {
        let mut actor = test_dns_actor();
        actor.set_hostnames(&HashSet::from(["example.com".to_string()]));

        actor.spawn_query(query("example.com", RecordType::A));
        actor.spawn_query(query("example.com", RecordType::AAAA));
        actor
            .hostnames
            .get_mut("example.com")
            .unwrap()
            .ips
            .insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), Instant::now());
        actor
            .queued_queries
            .insert(query("example.com", RecordType::A));

        actor.set_hostnames(&HashSet::new());
        assert!(actor.hostnames.is_empty());
        assert!(actor.queued_queries.is_empty());
        assert_eq!(actor.pending_queries.len(), 2);

        // Re-registering within the timeout reuses the in-flight queries.
        actor.set_hostnames(&HashSet::from(["example.com".to_string()]));
        actor.trigger_refresh();
        assert!(actor.queued_queries.is_empty());
    }

    #[tokio::test]
    async fn trigger_refresh_deduplicates_queued_queries() {
        let mut actor = test_dns_actor();
        actor.set_hostnames(&HashSet::from(["example.com".to_string()]));
        actor.trigger_refresh();
        actor
            .hostnames
            .get_mut("example.com")
            .unwrap()
            .next_refresh_at = Instant::now();
        actor.trigger_refresh();

        assert_eq!(
            actor.queued_queries,
            HashSet::from([
                query("example.com", RecordType::A),
                query("example.com", RecordType::AAAA),
            ])
        );
    }

    #[tokio::test]
    async fn trigger_refresh_skips_pending_queries() {
        let mut actor = test_dns_actor();
        actor.set_hostnames(&HashSet::from(["example.com".to_string()]));
        actor.spawn_query(query("example.com", RecordType::A));
        actor.trigger_refresh();

        assert_eq!(
            actor.queued_queries,
            HashSet::from([query("example.com", RecordType::AAAA)])
        );
    }

    #[tokio::test]
    async fn failed_query_is_requeued() {
        let mut actor = test_dns_actor();
        actor.set_hostnames(&HashSet::from(["example.com".to_string()]));
        let failed = query("example.com", RecordType::A);
        actor.spawn_query(failed.clone());

        actor.handle_query_result(failed.clone(), Err(anyhow!("refused")));

        assert!(actor.pending_queries.is_empty());
        assert_eq!(actor.queued_queries, HashSet::from([failed]));
    }

    #[tokio::test]
    async fn result_for_unregistered_hostname_is_dropped() {
        let mut actor = test_dns_actor();
        actor.set_hostnames(&HashSet::from(["example.com".to_string()]));
        let removed = query("example.com", RecordType::A);
        actor.spawn_query(removed.clone());
        actor.set_hostnames(&HashSet::new());

        actor.handle_query_result(removed, Err(anyhow!("refused")));

        assert!(actor.pending_queries.is_empty());
        assert!(actor.queued_queries.is_empty());
    }

    #[tokio::test]
    async fn queued_queries_are_paced() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tuning = DnsTuning {
            dns_query_interval: Duration::from_millis(200),
            ..DnsTuning::default()
        };
        let (cmd_tx, _events_rx, _actor_bus) =
            start_resolver(socket.local_addr().unwrap(), &tuning);

        cmd_tx
            .send(Event::SetHostnames {
                hosts: HashSet::from(["example.com".to_string()]),
            })
            .unwrap();

        let mut buf = vec![0u8; DNS_BUFFER_SIZE];
        time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf))
            .await
            .expect("first query should be sent")
            .unwrap();
        assert!(
            time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf))
                .await
                .is_err(),
            "only one DNS query should be sent per pacing interval"
        );
        time::timeout(Duration::from_millis(200), socket.recv_from(&mut buf))
            .await
            .expect("second query should be sent after the pacing interval")
            .unwrap();
    }

    #[tokio::test]
    async fn queued_queries_do_not_block_events() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tuning = DnsTuning {
            dns_query_interval: Duration::from_secs(10),
            ..DnsTuning::default()
        };
        let (cmd_tx, mut events_rx, _actor_bus) =
            start_resolver(socket.local_addr().unwrap(), &tuning);

        cmd_tx
            .send(Event::SetHostnames {
                hosts: HashSet::from(["example.com".to_string()]),
            })
            .unwrap();
        let _ = next_dns_snapshot(&mut events_rx).await;

        cmd_tx
            .send(Event::SetHostnames {
                hosts: HashSet::new(),
            })
            .unwrap();
        let snapshot = time::timeout(
            Duration::from_millis(200),
            next_dns_snapshot(&mut events_rx),
        )
        .await
        .expect("SetHostnames should not wait for the query queue to drain");
        assert!(!snapshot.contains_key("example.com"));
    }

    #[tokio::test]
    async fn repeated_set_hostnames_skips_recent_refresh() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = socket.local_addr().unwrap();
        let (cmd_tx, mut events_rx, _actor_bus) =
            start_resolver(server_addr, &DnsTuning::default());

        let mut hosts = HashSet::new();
        hosts.insert("example.com".to_string());
        cmd_tx
            .send(Event::SetHostnames {
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
        cmd_tx.send(Event::SetHostnames { hosts }).unwrap();

        // Consume snapshot from second SetHostnames (always emitted)
        let _ = next_dns_snapshot(&mut events_rx).await;

        // Verify no new queries are sent (trigger_refresh should skip)
        let result =
            tokio::time::timeout(Duration::from_millis(200), socket.recv_from(&mut buf)).await;
        assert!(
            result.is_err(),
            "no additional queries expected after recent refresh"
        );
    }
}
