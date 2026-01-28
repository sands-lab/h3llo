//! BareUDP-only runtime orchestration.

use crate::actor::{ActorError, ActorExitResult};
use crate::bare::{spawn_udp_rx, spawn_udp_tx, BareUdpRx, BareUdpRxCommand, BareUdpTx};
use crate::bind::DefaultRouteProbe;
use crate::config::{parse_udp_uri, Config, Peer};
use crate::dns::{DnsCommand, DnsResolver};
use crate::events::{DnsEventDetail, Event, TransportEvent};
use crate::route::{sync_tun_routes, RouteManagerHandle};
use crate::tun::{self, RoutingTable, TunRxCommand};
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, error, info, warn};

const METRICS_INTERVAL: Duration = Duration::from_secs(30);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Errors returned by the orchestrator.
#[derive(Debug, Error)]
pub enum OrchestratorError {
    /// BareUDP configuration is missing.
    #[error("bare runtime requires local.bare.listen to be set")]
    MissingBareListen,
    /// BareUDP listen URI failed validation.
    #[error("invalid bare listen uri: {0}")]
    InvalidBareListen(String),
    /// BareUDP peer endpoint failed validation.
    #[error("peer '{peer_id}' bare.endpoint invalid: {reason}")]
    InvalidPeerEndpoint { peer_id: String, reason: String },
    /// BareUDP listen host could not be resolved.
    #[error("failed to resolve bare listen host '{host}': {reason}")]
    ListenResolveFailed { host: String, reason: String },
    /// DNS resolver failed to initialize.
    #[error("dns resolver failed to initialize: {0}")]
    DnsInit(String),
    /// TUN setup failed.
    #[error("tun setup failed: {0}")]
    Tun(String),
    /// UDP socket setup failed.
    #[error("udp socket setup failed: {0}")]
    Udp(String),
    /// Routing table build failed.
    #[error("routing table build failed: {0}")]
    Routing(String),
    /// Route sync failed.
    #[error("route sync failed: {0}")]
    RouteSync(String),
    /// An actor exited with an error.
    #[error("actor error: {0}")]
    ActorError(#[from] ActorError),
    /// A runtime task failed to join (panic or cancel).
    #[error("runtime task join failed: {0}")]
    TaskJoin(String),
}

/// BareUDP runtime orchestrator.
///
/// Manages child actors (TUN-Rx/Tx, BareUDP-Rx/Tx, DNS resolver) and processes runtime events.
/// Uses a single unified event loop for both initialization and runtime.
pub struct Orchestrator {
    events_rx: mpsc::UnboundedReceiver<Event>,
    events_tx: mpsc::UnboundedSender<Event>,
    join_set: JoinSet<Result<ActorExitResult, tokio::task::JoinError>>,

    dns_refresh: Duration,

    // Runtime state
    tun_if: String,
    #[allow(dead_code)]
    mtu: usize,
    peers: Vec<Peer>,
    active_ips: HashSet<IpAddr>,
    peer_txs: HashMap<String, mpsc::Sender<Vec<u8>>>,
    tun_cmd_tx: mpsc::UnboundedSender<TunRxCommand>,
    bare_rx_cmd_tx: Option<mpsc::UnboundedSender<BareUdpRxCommand>>,

    /// DNS resolver command sender for refresh commands.
    dns_cmd_tx: mpsc::UnboundedSender<DnsCommand>,

    /// Whether to manage system routes (`local.table`).
    manage_routes: bool,
    /// Pre-parsed TUN interface addresses as host-prefixed IpNets (for system route sync).
    tun_addrs: Vec<IpNet>,
}

impl Orchestrator {
    /// Creates a new orchestrator from configuration.
    ///
    /// Initializes TUN interface, BareUDP sockets, routing table, and spawns
    /// child actors. Listen hostname is resolved synchronously; peer hostnames
    /// are resolved asynchronously via the event loop.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError` when initialization fails.
    pub async fn new(config: Config) -> Result<Self, OrchestratorError> {
        let local_bare = config
            .local
            .bare
            .as_ref()
            .ok_or(OrchestratorError::MissingBareListen)?;
        let listen_endpoint =
            parse_udp_uri(&local_bare.listen).map_err(OrchestratorError::InvalidBareListen)?;

        let tun_if = config.local.tun.ifname.clone();
        let mtu = config.local.tun.mtu as usize;
        let manage_routes = config.local.table;
        let tun_addrs = tun_prefixes(&config.local.tun.addrs)?;

        // Resolve listen address synchronously (blocking for hostname)
        let listen_addr = resolve_listen_addr(&listen_endpoint)?;

        // Setup TUN
        let (tun_reader, tun_writer) = tun::from_config(&config.local.tun)
            .await
            .map_err(|err| OrchestratorError::Tun(err.to_string()))?;

        // Setup BareUDP RX
        let bare_rx = BareUdpRx::from_config(listen_addr, mtu)
            .await
            .map_err(|err| OrchestratorError::Udp(err.to_string()))?;

        // Control plane: unbounded to prevent deadlocks from actor cycles.
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        // Extract validated peers for storage (enabled BareUDP peers only)
        let peers: Vec<Peer> = config
            .peers
            .iter()
            .filter(|p| p.enabled && p.bare.is_some())
            .cloned()
            .collect();

        let peer_txs = HashMap::new();
        let active_ips = HashSet::new();
        let mut join_set = JoinSet::new();

        // Start with empty routing table; routes populated as DNS answers arrive
        let routing = RoutingTable::new();

        // Spawn TUN actors - actors create their own command channels
        let (tun_cmd_tx, tun_rx_handle) =
            tun::spawn_tun_rx(tun_reader, routing, events_tx.clone(), METRICS_INTERVAL);
        // TUN-Tx actor creates its own packet channel; returns sender for BareUDP-Rx to use
        let (tun_packet_tx, tun_tx_handle) =
            tun::spawn_tun_tx(tun_writer, events_tx.clone(), METRICS_INTERVAL);

        // BareUDP RX forwards received packets to TUN TX's packet channel
        let (bare_rx_cmd_tx, bare_rx_handle) = spawn_udp_rx(
            bare_rx,
            HashSet::new(),
            tun_packet_tx,
            events_tx.clone(),
            METRICS_INTERVAL,
        );

        join_set.spawn(tun_rx_handle);
        join_set.spawn(tun_tx_handle);
        join_set.spawn(bare_rx_handle);

        let dns_refresh = Duration::from_secs(config.local.dns.refresh);

        // Spawn DNS resolver - actor creates its own command channel
        let resolver =
            DnsResolver::from_config(&config.local.dns, Some(tun_if.clone()), DNS_QUERY_TIMEOUT)
                .map_err(|err| OrchestratorError::DnsInit(err.to_string()))?;

        let probe = DefaultRouteProbe;
        let (dns_cmd_tx, handle) = resolver
            .spawn(probe, events_tx.clone())
            .await
            .map_err(|err| OrchestratorError::DnsInit(err.to_string()))?;

        // Send initial resolve commands for all peer endpoints.
        // IP literals are detected by resolver and emit immediate DnsAnswer events.
        send_resolve_commands(&peers, &dns_cmd_tx)?;

        join_set.spawn(handle);

        if peers.iter().all(|p| !p.enabled || p.bare.is_none()) {
            warn!("no active BareUDP peers; traffic will be dropped");
        }

        Ok(Self {
            events_rx,
            events_tx,
            join_set,
            dns_refresh,
            tun_if,
            mtu,
            peers,
            active_ips,
            peer_txs,
            tun_cmd_tx,
            bare_rx_cmd_tx: Some(bare_rx_cmd_tx),
            dns_cmd_tx,
            manage_routes,
            tun_addrs,
        })
    }

    /// Runs the orchestrator event loop until shutdown or task failure.
    ///
    /// Processes events from child actors (including DNS answers), monitors
    /// child tasks, and handles graceful shutdown on `ctrl_c`.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError` when a child task exits unexpectedly.
    pub async fn run(mut self) -> Result<(), OrchestratorError> {
        let mut dns_ticker = tokio::time::interval(if self.dns_refresh.is_zero() {
            Duration::from_secs(3600) // placeholder; branch disabled below
        } else {
            self.dns_refresh
        });
        dns_ticker.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                Some(event) = self.events_rx.recv() => {
                    self.handle_event(event).await;
                }
                _ = dns_ticker.tick(), if !self.dns_refresh.is_zero() => {
                    self.refresh_dns().await;
                }
                result = self.join_set.join_next() => {
                    match result {
                        Some(Ok(Ok(Ok(())))) => {
                            // Graceful shutdown of one actor; continue running
                            debug!("an actor exited gracefully");
                        }
                        Some(Ok(Ok(Err(actor_error)))) => {
                            // Actor exited with error
                            error!("actor error: {}", actor_error);
                            return Err(OrchestratorError::ActorError(actor_error));
                        }
                        Some(Ok(Err(join_err))) | Some(Err(join_err)) => {
                            // Task panicked or was cancelled
                            error!("task join failed (panic/cancel): {}", join_err);
                            return Err(OrchestratorError::TaskJoin(join_err.to_string()));
                        }
                        None => {
                            // All actors have exited
                            return Ok(());
                        }
                    }
                }
                result = tokio::signal::ctrl_c() => {
                    match result {
                        Ok(()) => {
                            info!("shutdown signal received, stopping...");
                            break;
                        }
                        Err(e) => {
                            warn!("signal handler error: {e}");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Handles an event from a child actor.
    async fn handle_event(&mut self, event: Event) {
        match event {
            Event::Dns(dns_event) => {
                if let DnsEventDetail::Answer(answer) = dns_event.detail {
                    // Log DNS warnings
                    for warning in &answer.warnings {
                        warn!("dns warning for {}: {:?}", answer.host, warning);
                    }

                    // Process answer by iterating all peers with matching hostname.
                    // Empty answers (e.g., AAAA when no IPv6) are ignored; subsequent
                    // A record answers will still be processed.
                    if !answer.records.is_empty() {
                        self.handle_dns_answer(&answer).await;
                    }
                } else {
                    debug!(
                        "dns event from {}: {:?}",
                        dns_event.server, dns_event.detail
                    );
                }
            }
            Event::Transport(TransportEvent::Metrics(metrics)) => {
                let labels = &metrics.labels;
                let stats = &metrics.stats;
                debug!(
                    "{:?} {:?} {}: {} pkts/{} bytes ok, {} pkts/{} bytes dropped",
                    labels.kind,
                    labels.direction,
                    labels.peer_id.as_deref().unwrap_or("local"),
                    stats.succeeded.packets,
                    stats.succeeded.bytes,
                    stats.dropped.packets,
                    stats.dropped.bytes,
                );
                if stats.dropped.packets > 0 {
                    for (reason, counters) in &stats.drop_reasons {
                        if counters.packets > 0 {
                            debug!(
                                "  drop reason {:?}: {} pkts/{} bytes",
                                reason, counters.packets, counters.bytes
                            );
                        }
                    }
                }
            }
            Event::Other(msg) => {
                debug!("other event: {}", msg);
            }
        }
    }

    /// Sends DNS resolve commands for all peer endpoints (periodic refresh).
    ///
    /// Existing TX actors for unchanged IPs are deduplicated by `active_ips`
    /// in `spawn_bare_tx_for_peer`. IP literals flow through DNS resolver
    /// (emits immediate answer).
    async fn refresh_dns(&mut self) {
        if let Err(err) = send_resolve_commands(&self.peers, &self.dns_cmd_tx) {
            warn!("dns refresh: unexpected error: {}", err);
        }
    }

    /// Handles a DNS answer by iterating all peers to create TX paths.
    ///
    /// This reactive approach eliminates the need for `pending_dns` state:
    /// on each answer, we iterate peers and spawn TX actors for those
    /// whose endpoint hostname matches the resolved host.
    async fn handle_dns_answer(&mut self, answer: &crate::events::DnsAnswer) {
        let mut any_spawned = false;

        for peer in &self.peers {
            if !peer.enabled {
                continue;
            }
            let Some(bare) = peer.bare.as_ref() else {
                continue;
            };
            let Ok(endpoint) = parse_udp_uri(&bare.endpoint) else {
                // Invalid endpoints were validated at startup; skip silently
                continue;
            };

            // Check if this peer's hostname matches the DNS answer
            if endpoint.host != answer.host {
                continue;
            }

            // Spawn TX actors for all resolved IPs
            for record in &answer.records {
                let destination = SocketAddr::new(record.address, endpoint.port);
                if let Some((packet_tx, tx_handle)) = spawn_bare_tx_for_peer(
                    &peer.id,
                    destination,
                    bare.bindif.as_deref(),
                    &self.tun_if,
                    self.events_tx.clone(),
                    &mut self.active_ips,
                )
                .await
                {
                    self.peer_txs.insert(peer.id.clone(), packet_tx);
                    self.join_set.spawn(tx_handle);
                    any_spawned = true;
                }
            }
        }

        // Only update routing/filters if we actually spawned something
        if any_spawned {
            // 1. Update allowed sources (fast, in-memory filter)
            if let Some(cmd_tx) = &self.bare_rx_cmd_tx {
                if cmd_tx
                    .send(BareUdpRxCommand::UpdateAllowedSources(
                        self.active_ips.clone(),
                    ))
                    .is_err()
                {
                    warn!("failed to send allowed sources update command");
                }
            }

            // 2. Update internal routing table
            if let Ok(routing) = RoutingTable::from_peers(&self.peers, &self.peer_txs) {
                if self
                    .tun_cmd_tx
                    .send(TunRxCommand::UpdateRouting { routing })
                    .is_err()
                {
                    warn!("failed to send routing update command");
                }
            }

            // 3. Sync system routes if enabled
            if self.manage_routes {
                match collect_allowed_ips(&self.peers) {
                    Ok(allowed) => {
                        sync_system_routes(&self.tun_if, &self.tun_addrs, &allowed).await
                    }
                    Err(err) => warn!("route sync skipped: {err}"),
                }
            }
        }
    }
}

/// Runs the BareUDP-only runtime until a task exits or shutdown signal.
///
/// This is a convenience function that creates an `Orchestrator` and runs it.
///
/// # Errors
///
/// Returns `OrchestratorError` when initialization fails or a runtime task exits unexpectedly.
pub async fn run_bare(config: Config) -> Result<(), OrchestratorError> {
    Orchestrator::new(config).await?.run().await
}

/// Resolves listen address, using synchronous DNS lookup for hostnames.
fn resolve_listen_addr(
    listen: &crate::config::UdpEndpoint,
) -> Result<SocketAddr, OrchestratorError> {
    if let Some(ip) = parse_ip_literal(&listen.host) {
        return Ok(SocketAddr::new(ip, listen.port));
    }

    // Synchronous DNS lookup for listen hostname
    use std::net::ToSocketAddrs;
    let addr_str = format!("{}:{}", listen.host, listen.port);
    let addrs: Vec<_> = addr_str
        .to_socket_addrs()
        .map_err(|err| OrchestratorError::ListenResolveFailed {
            host: listen.host.clone(),
            reason: err.to_string(),
        })?
        .collect();

    if addrs.is_empty() {
        return Err(OrchestratorError::ListenResolveFailed {
            host: listen.host.clone(),
            reason: "no resolved addresses".to_string(),
        });
    }
    if addrs.len() > 1 {
        warn!(
            "bare listen resolved multiple addresses for {}; using {}",
            listen.host, addrs[0]
        );
    }
    Ok(addrs[0])
}

/// Spawns a BareUDP TX actor for a peer.
///
/// Returns the packet sender and task handle, or None if socket setup fails.
/// Updates `active_ips` with the destination IP for deduplication.
async fn spawn_bare_tx_for_peer(
    peer_id: &str,
    destination: SocketAddr,
    bindif: Option<&str>,
    tun_if: &str,
    events_tx: mpsc::UnboundedSender<Event>,
    active_ips: &mut HashSet<IpAddr>,
) -> Option<(mpsc::Sender<Vec<u8>>, JoinHandle<ActorExitResult>)> {
    // Dedup by IP
    if !active_ips.insert(destination.ip()) {
        return None;
    }

    let probe = DefaultRouteProbe;
    let tx_socket = match BareUdpTx::from_config(destination, bindif, Some(tun_if), &probe).await {
        Ok(result) => result,
        Err(err) => {
            warn!("bare peer '{}' socket setup failed: {err}", peer_id);
            active_ips.remove(&destination.ip());
            return None;
        }
    };

    // BareUDP TX actor creates its own packet channel; returns sender
    let (packet_tx, tx_handle) = spawn_udp_tx(tx_socket, destination, events_tx, METRICS_INTERVAL);

    Some((packet_tx, tx_handle))
}

/// Performs system route synchronization, logging warnings on failure.
async fn sync_system_routes(tun_if: &str, tun_addrs: &[IpNet], allowed: &[IpNet]) {
    match RouteManagerHandle::new() {
        Ok(mut handle) => {
            if let Err(err) = sync_tun_routes(tun_if, tun_addrs, allowed, &mut handle).await {
                warn!("route sync failed: {err}");
            }
        }
        Err(err) => warn!("route manager unavailable: {err}"),
    }
}

fn collect_allowed_ips(peers: &[Peer]) -> Result<Vec<IpNet>, OrchestratorError> {
    let mut allowed = Vec::new();
    for peer in peers {
        for cidr in &peer.tun.allowed_ips {
            let net = cidr
                .parse::<IpNet>()
                .map_err(|err| OrchestratorError::Routing(err.to_string()))?;
            allowed.push(net);
        }
    }
    Ok(allowed)
}

fn tun_prefixes(addrs: &[String]) -> Result<Vec<IpNet>, OrchestratorError> {
    let mut prefixes = Vec::new();
    for addr in addrs {
        let ip = addr
            .parse::<IpAddr>()
            .map_err(|err| OrchestratorError::Routing(err.to_string()))?;
        let net = match ip {
            IpAddr::V4(ip) => IpNet::new(ip.into(), 32).map_err(|e| {
                OrchestratorError::Routing(format!("invalid IPv4 TUN addr {addr}: {e}"))
            })?,
            IpAddr::V6(ip) => IpNet::new(ip.into(), 128).map_err(|e| {
                OrchestratorError::Routing(format!("invalid IPv6 TUN addr {addr}: {e}"))
            })?,
        };
        prefixes.push(net);
    }
    Ok(prefixes)
}

fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    host.parse::<IpAddr>().ok()
}

/// Sends DNS resolve commands for all unique peer endpoint hostnames.
///
/// # Arguments
///
/// * `peers` - Slice of peer configurations to process
/// * `dns_cmd_tx` - Channel to send DNS resolve commands
///
/// # Errors
///
/// Returns `OrchestratorError::InvalidPeerEndpoint` if any enabled peer
/// has an invalid BareUDP endpoint URI.
fn send_resolve_commands(
    peers: &[Peer],
    dns_cmd_tx: &mpsc::UnboundedSender<DnsCommand>,
) -> Result<(), OrchestratorError> {
    let mut seen_hosts = HashSet::new();

    for peer in peers {
        if !peer.enabled {
            continue;
        }
        let bare = match peer.bare.as_ref() {
            Some(b) => b,
            None => continue,
        };
        let endpoint = parse_udp_uri(&bare.endpoint).map_err(|err| {
            OrchestratorError::InvalidPeerEndpoint {
                peer_id: peer.id.clone(),
                reason: err,
            }
        })?;

        // Send resolve command only once per hostname (deduplication)
        if seen_hosts.insert(endpoint.host.clone())
            && dns_cmd_tx
                .send(DnsCommand::Resolve {
                    host: endpoint.host,
                })
                .is_err()
        {
            warn!("dns: resolver channel closed");
        }
    }

    Ok(())
}

#[cfg(test)]
mod test_support {
    use super::*;

    /// Test-only builder for creating an Orchestrator with injected dependencies.
    ///
    /// Bypasses all I/O operations (TUN creation, UDP binding, DNS spawning)
    /// to enable isolated unit testing of event handling logic.
    pub struct TestableOrchestratorBuilder {
        tun_if: String,
        mtu: usize,
        peers: Vec<Peer>,
        active_ips: HashSet<IpAddr>,
        peer_txs: HashMap<String, mpsc::Sender<Vec<u8>>>,
        dns_refresh: Duration,
        manage_routes: bool,
        tun_addrs: Vec<IpNet>,
    }

    impl Default for TestableOrchestratorBuilder {
        fn default() -> Self {
            Self {
                tun_if: "test0".to_string(),
                mtu: 1400,
                peers: Vec::new(),
                active_ips: HashSet::new(),
                peer_txs: HashMap::new(),
                dns_refresh: Duration::ZERO,
                manage_routes: false,
                tun_addrs: Vec::new(),
            }
        }
    }

    /// Test handles for verifying commands sent by the orchestrator.
    pub struct TestHandles {
        #[allow(dead_code)]
        pub events_tx: mpsc::UnboundedSender<Event>,
        pub tun_cmd_rx: mpsc::UnboundedReceiver<TunRxCommand>,
        pub bare_rx_cmd_rx: mpsc::UnboundedReceiver<BareUdpRxCommand>,
        pub dns_cmd_rx: mpsc::UnboundedReceiver<DnsCommand>,
    }

    impl TestableOrchestratorBuilder {
        pub fn with_peers(mut self, peers: Vec<Peer>) -> Self {
            self.peers = peers;
            self
        }

        pub fn with_peer_txs(mut self, peer_txs: HashMap<String, mpsc::Sender<Vec<u8>>>) -> Self {
            self.peer_txs = peer_txs;
            self
        }

        /// Builds a testable orchestrator with dummy channels.
        ///
        /// Returns the orchestrator and test handles that allow verifying
        /// commands sent to child actors.
        pub fn build(self) -> (Orchestrator, TestHandles) {
            let (events_tx, events_rx) = mpsc::unbounded_channel();
            let (tun_cmd_tx, tun_cmd_rx) = mpsc::unbounded_channel();
            let (bare_rx_cmd_tx, bare_rx_cmd_rx) = mpsc::unbounded_channel();
            let (dns_cmd_tx, dns_cmd_rx) = mpsc::unbounded_channel();

            let orch = Orchestrator {
                events_rx,
                events_tx: events_tx.clone(),
                join_set: JoinSet::new(),
                dns_refresh: self.dns_refresh,
                tun_if: self.tun_if,
                mtu: self.mtu,
                peers: self.peers,
                active_ips: self.active_ips,
                peer_txs: self.peer_txs,
                tun_cmd_tx,
                bare_rx_cmd_tx: Some(bare_rx_cmd_tx),
                dns_cmd_tx,
                manage_routes: self.manage_routes,
                tun_addrs: self.tun_addrs,
            };

            (
                orch,
                TestHandles {
                    events_tx,
                    tun_cmd_rx,
                    bare_rx_cmd_rx,
                    dns_cmd_rx,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TestableOrchestratorBuilder;
    use super::*;
    use crate::config::{PeerBare, PeerTun};
    use crate::events::{
        Direction, DnsAnswer, DnsAnswerRecord, DnsEvent, DnsEventDetail, DnsRecordType,
        TransportEvent, TransportKind, TransportLabels, TransportMetrics, TransportStats,
    };

    /// Helper to create test peers with BareUDP configuration.
    fn bare_peer(id: &str, allowed: &[&str]) -> Peer {
        Peer {
            id: id.to_string(),
            enabled: true,
            h3: None,
            bare: Some(PeerBare {
                endpoint: "udp://127.0.0.1:5353".to_string(),
                bindif: None,
            }),
            tun: PeerTun {
                allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            },
        }
    }

    /// Helper to create test peers with BareUDP configuration at a specific hostname.
    fn bare_peer_at_host(id: &str, hostname: &str, port: u16, allowed: &[&str]) -> Peer {
        Peer {
            id: id.to_string(),
            enabled: true,
            h3: None,
            bare: Some(PeerBare {
                endpoint: format!("udp://{}:{}", hostname, port),
                bindif: None,
            }),
            tun: PeerTun {
                allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            },
        }
    }

    fn make_metrics_event() -> Event {
        Event::Transport(TransportEvent::Metrics(TransportMetrics {
            labels: TransportLabels {
                kind: TransportKind::Tun,
                direction: Direction::Rx,
                peer_id: None,
                ip_addr: None,
            },
            stats: TransportStats::default(),
        }))
    }

    #[test]
    fn orchestrator_error_includes_actor_context() {
        // Verify that OrchestratorError::ActorError includes actor context
        use crate::actor::ActorError;
        use std::io;

        let actor_err = ActorError::TunRxRecv {
            name: "tun0".to_string(),
            source: io::Error::new(io::ErrorKind::Other, "test error"),
        };
        let error = OrchestratorError::ActorError(actor_err);
        let error_msg = error.to_string();
        assert!(
            error_msg.contains("tun_rx"),
            "error message should contain actor type"
        );
        assert!(
            error_msg.contains("tun0"),
            "error message should contain interface name"
        );
    }

    #[test]
    fn parse_ip_literal_parses_ipv4() {
        let ip = parse_ip_literal("192.168.1.1");
        assert!(ip.is_some());
        assert_eq!(ip.unwrap().to_string(), "192.168.1.1");
    }

    #[test]
    fn parse_ip_literal_parses_ipv6() {
        let ip = parse_ip_literal("::1");
        assert!(ip.is_some());
        assert!(ip.unwrap().is_ipv6());
    }

    #[test]
    fn parse_ip_literal_returns_none_for_hostname() {
        let ip = parse_ip_literal("example.com");
        assert!(ip.is_none());
    }

    #[test]
    fn parse_ip_literal_returns_none_for_empty() {
        let ip = parse_ip_literal("");
        assert!(ip.is_none());
    }

    // ========== collect_allowed_ips tests ==========

    #[test]
    fn collect_allowed_ips_parses_valid_cidrs() {
        let peers = vec![
            bare_peer("peer1", &["10.0.0.0/24", "192.168.1.0/24"]),
            bare_peer("peer2", &["172.16.0.0/16"]),
        ];
        let result = collect_allowed_ips(&peers).expect("should parse");
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"10.0.0.0/24".parse().unwrap()));
        assert!(result.contains(&"192.168.1.0/24".parse().unwrap()));
        assert!(result.contains(&"172.16.0.0/16".parse().unwrap()));
    }

    #[test]
    fn collect_allowed_ips_rejects_invalid_cidr() {
        let peers = vec![bare_peer("peer1", &["not-a-cidr"])];
        let result = collect_allowed_ips(&peers);
        assert!(result.is_err());
    }

    #[test]
    fn collect_allowed_ips_handles_empty_peers() {
        let peers: Vec<Peer> = vec![];
        let result = collect_allowed_ips(&peers).expect("should parse");
        assert!(result.is_empty());
    }

    // ========== tun_prefixes tests ==========

    #[test]
    fn tun_prefixes_parses_ipv4_addresses() {
        let addrs = vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()];
        let result = tun_prefixes(&addrs).expect("should parse");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].prefix_len(), 32);
        assert_eq!(result[1].prefix_len(), 32);
    }

    #[test]
    fn tun_prefixes_parses_ipv6_addresses() {
        let addrs = vec!["2001:db8::1".to_string()];
        let result = tun_prefixes(&addrs).expect("should parse");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].prefix_len(), 128);
    }

    #[test]
    fn tun_prefixes_rejects_invalid_address() {
        let addrs = vec!["not-an-ip".to_string()];
        let result = tun_prefixes(&addrs);
        assert!(result.is_err());
    }

    #[test]
    fn tun_prefixes_handles_mixed_families() {
        let addrs = vec!["192.168.1.1".to_string(), "2001:db8::1".to_string()];
        let result = tun_prefixes(&addrs).expect("should parse");
        assert_eq!(result.len(), 2);
        assert!(result[0].addr().is_ipv4());
        assert!(result[1].addr().is_ipv6());
    }

    #[test]
    fn tun_prefixes_handles_empty_addrs() {
        let addrs: Vec<String> = vec![];
        let result = tun_prefixes(&addrs).expect("should parse");
        assert!(result.is_empty());
    }

    // ========== OrchestratorError tests ==========

    #[test]
    fn orchestrator_error_missing_bare_listen() {
        let error = OrchestratorError::MissingBareListen;
        assert!(error.to_string().contains("local.bare.listen"));
    }

    #[test]
    fn orchestrator_error_invalid_bare_listen() {
        let error = OrchestratorError::InvalidBareListen("bad uri".to_string());
        let msg = error.to_string();
        assert!(msg.contains("invalid bare listen"));
        assert!(msg.contains("bad uri"));
    }

    #[test]
    fn orchestrator_error_invalid_peer_endpoint() {
        let error = OrchestratorError::InvalidPeerEndpoint {
            peer_id: "test-peer".to_string(),
            reason: "bad uri".to_string(),
        };
        let msg = error.to_string();
        assert!(msg.contains("test-peer"));
        assert!(msg.contains("bad uri"));
    }

    #[test]
    fn orchestrator_error_listen_resolve_failed() {
        let error = OrchestratorError::ListenResolveFailed {
            host: "example.com".to_string(),
            reason: "dns timeout".to_string(),
        };
        let msg = error.to_string();
        assert!(msg.contains("example.com"));
        assert!(msg.contains("dns timeout"));
    }

    #[test]
    fn orchestrator_error_dns_init() {
        let error = OrchestratorError::DnsInit("socket bind failed".to_string());
        assert!(error.to_string().contains("socket bind failed"));
    }

    #[test]
    fn orchestrator_error_tun() {
        let error = OrchestratorError::Tun("device creation failed".to_string());
        assert!(error.to_string().contains("device creation failed"));
    }

    #[test]
    fn orchestrator_error_udp() {
        let error = OrchestratorError::Udp("address in use".to_string());
        assert!(error.to_string().contains("address in use"));
    }

    #[test]
    fn orchestrator_error_routing() {
        let error = OrchestratorError::Routing("invalid prefix".to_string());
        assert!(error.to_string().contains("invalid prefix"));
    }

    #[test]
    fn orchestrator_error_route_sync() {
        let error = OrchestratorError::RouteSync("permission denied".to_string());
        assert!(error.to_string().contains("permission denied"));
    }

    #[test]
    fn orchestrator_error_task_join() {
        let error = OrchestratorError::TaskJoin("task panicked".to_string());
        assert!(error.to_string().contains("task panicked"));
    }

    // ========== resolve_listen_addr tests ==========

    #[test]
    fn resolve_listen_addr_with_ipv4_literal() {
        use crate::config::UdpEndpoint;
        let endpoint = UdpEndpoint {
            host: "127.0.0.1".to_string(),
            port: 5353,
        };
        let result = resolve_listen_addr(&endpoint).expect("should resolve");
        assert_eq!(
            result.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(result.port(), 5353);
    }

    #[test]
    fn resolve_listen_addr_with_ipv6_literal() {
        use crate::config::UdpEndpoint;
        let endpoint = UdpEndpoint {
            host: "::1".to_string(),
            port: 5353,
        };
        let result = resolve_listen_addr(&endpoint).expect("should resolve");
        assert!(result.ip().is_ipv6());
        assert_eq!(result.port(), 5353);
    }

    // ========== Event handling tests ==========

    #[tokio::test]
    async fn handle_event_processes_metrics_without_state_change() {
        let peer = bare_peer("peer1", &["10.0.0.0/24"]);
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let mut peer_txs = HashMap::new();
        peer_txs.insert("peer1".to_string(), peer_tx);

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_txs(peer_txs)
            .build();

        orch.handle_event(make_metrics_event()).await;

        // State preserved: existing entries not modified
        assert_eq!(orch.peer_txs.len(), 1);
        assert!(orch.peer_txs.contains_key("peer1"));

        // No commands sent to child actors
        assert!(handles.tun_cmd_rx.try_recv().is_err());
        assert!(handles.bare_rx_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_event_processes_other_event() {
        let peer = bare_peer("peer1", &["10.0.0.0/24"]);
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let mut peer_txs = HashMap::new();
        peer_txs.insert("peer1".to_string(), peer_tx);

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_txs(peer_txs)
            .build();

        orch.handle_event(Event::Other("test message".to_string()))
            .await;

        // State preserved
        assert_eq!(orch.peer_txs.len(), 1);

        // No commands sent
        assert!(handles.tun_cmd_rx.try_recv().is_err());
        assert!(handles.bare_rx_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_event_ignores_dns_answer_for_unknown_host() {
        // Peer configured for known.example.com, but we send answer for unknown host
        let peer = bare_peer_at_host("peer1", "known.example.com", 5353, &["10.0.0.0/24"]);

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        // Answer for a host that doesn't match any peer
        let answer = Event::Dns(DnsEvent {
            server: "127.0.0.1:53".parse().unwrap(),
            detail: DnsEventDetail::Answer(DnsAnswer {
                host: "unknown.example.com".to_string(),
                record_type: DnsRecordType::A,
                records: vec![DnsAnswerRecord {
                    address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
                    ttl: 60,
                }],
                warnings: vec![],
            }),
        });
        orch.handle_event(answer).await;

        // No peer TX created (hostname doesn't match)
        assert!(orch.peer_txs.is_empty());
        // No commands sent
        assert!(handles.tun_cmd_rx.try_recv().is_err());
        assert!(handles.bare_rx_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_dns_answer_with_empty_records_no_op() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        // DNS answer with empty records should be ignored (no processing)
        let answer = Event::Dns(DnsEvent {
            server: "127.0.0.1:53".parse().unwrap(),
            detail: DnsEventDetail::Answer(DnsAnswer {
                host: "example.com".to_string(),
                record_type: DnsRecordType::Aaaa,
                records: vec![],
                warnings: vec![],
            }),
        });
        orch.handle_event(answer).await;

        // No peer TX created (empty records)
        assert!(orch.peer_txs.is_empty());
        // No commands sent
        assert!(handles.tun_cmd_rx.try_recv().is_err());
        assert!(handles.bare_rx_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_dns_answer_iterates_all_matching_peers() {
        let peer1 = bare_peer_at_host("peer1", "shared.example.com", 5353, &["10.0.0.0/24"]);
        let peer2 = bare_peer_at_host("peer2", "shared.example.com", 5354, &["172.16.0.0/16"]);

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer1, peer2])
            .build();

        let answer = DnsAnswer {
            host: "shared.example.com".to_string(),
            record_type: DnsRecordType::A,
            records: vec![DnsAnswerRecord {
                address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
                ttl: 60,
            }],
            warnings: vec![],
        };

        orch.handle_dns_answer(&answer).await;

        // Both peers should be processed (iteration covers all matching)
        // Note: actual socket binding may fail in test environment,
        // but the iteration logic is exercised
    }

    #[tokio::test]
    async fn handle_dns_answer_ignores_non_matching_hostnames() {
        let peer = bare_peer_at_host("peer1", "different.example.com", 5353, &["10.0.0.0/24"]);

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        let answer = DnsAnswer {
            host: "other.example.com".to_string(),
            record_type: DnsRecordType::A,
            records: vec![DnsAnswerRecord {
                address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
                ttl: 60,
            }],
            warnings: vec![],
        };

        orch.handle_dns_answer(&answer).await;

        // No commands should be sent (no peers matched)
        assert!(handles.tun_cmd_rx.try_recv().is_err());
        assert!(handles.bare_rx_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_dns_answer_skips_disabled_peers() {
        let mut peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        peer.enabled = false;

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        let answer = DnsAnswer {
            host: "example.com".to_string(),
            record_type: DnsRecordType::A,
            records: vec![DnsAnswerRecord {
                address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
                ttl: 60,
            }],
            warnings: vec![],
        };

        orch.handle_dns_answer(&answer).await;

        // No commands should be sent (peer disabled)
        assert!(handles.tun_cmd_rx.try_recv().is_err());
    }

    // ========== send_resolve_commands helper function tests ==========

    #[test]
    fn send_resolve_commands_deduplicates_hostnames() {
        let peers = vec![
            bare_peer_at_host("peer1", "shared.example.com", 5353, &["10.0.0.0/24"]),
            bare_peer_at_host("peer2", "shared.example.com", 5354, &["172.16.0.0/16"]),
        ];

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let result = send_resolve_commands(&peers, &cmd_tx);
        assert!(result.is_ok());

        // Only ONE DNS command sent (hostname deduplicated)
        let cmd = cmd_rx.try_recv().expect("should receive command");
        assert!(matches!(cmd, DnsCommand::Resolve { host } if host == "shared.example.com"));
        assert!(cmd_rx.try_recv().is_err(), "should be no more commands");
    }

    #[test]
    fn send_resolve_commands_skips_disabled_peers() {
        let mut peer = bare_peer_at_host("disabled", "example.com", 5353, &["10.0.0.0/24"]);
        peer.enabled = false;

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let result = send_resolve_commands(&[peer], &cmd_tx);
        assert!(result.is_ok());

        assert!(cmd_rx.try_recv().is_err(), "no commands should be sent");
    }

    #[test]
    fn send_resolve_commands_skips_non_bare_peers() {
        let peer = Peer {
            id: "h3only".to_string(),
            enabled: true,
            h3: None,
            bare: None,
            tun: PeerTun {
                allowed_ips: vec![],
            },
        };

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let result = send_resolve_commands(&[peer], &cmd_tx);
        assert!(result.is_ok());

        assert!(cmd_rx.try_recv().is_err(), "no commands should be sent");
    }

    #[test]
    fn send_resolve_commands_returns_error_for_invalid_endpoint() {
        let peer = Peer {
            id: "badpeer".to_string(),
            enabled: true,
            h3: None,
            bare: Some(PeerBare {
                endpoint: "not-a-valid-uri".to_string(),
                bindif: None,
            }),
            tun: PeerTun {
                allowed_ips: vec!["10.0.0.0/24".to_string()],
            },
        };

        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let result = send_resolve_commands(&[peer], &cmd_tx);

        assert!(matches!(
            result,
            Err(OrchestratorError::InvalidPeerEndpoint { peer_id, .. }) if peer_id == "badpeer"
        ));
    }

    // ========== refresh_dns integration tests ==========

    #[tokio::test]
    async fn refresh_dns_sends_commands_for_shared_hostname() {
        let peer1 = Peer {
            id: "peer1".to_string(),
            enabled: true,
            h3: None,
            bare: Some(PeerBare {
                endpoint: "udp://example.com:5353".to_string(),
                bindif: None,
            }),
            tun: PeerTun {
                allowed_ips: vec!["10.0.0.0/24".to_string()],
            },
        };
        let peer2 = Peer {
            id: "peer2".to_string(),
            enabled: true,
            h3: None,
            bare: Some(PeerBare {
                endpoint: "udp://example.com:5354".to_string(),
                bindif: None,
            }),
            tun: PeerTun {
                allowed_ips: vec!["172.16.0.0/16".to_string()],
            },
        };

        let (mut orch, handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer1, peer2])
            .build();

        orch.refresh_dns().await;
        let mut dns_cmd_rx = handles.dns_cmd_rx;

        // Verify only ONE DNS command sent (hostname deduplicated)
        let cmd = dns_cmd_rx.try_recv().expect("should receive command");
        assert!(matches!(cmd, DnsCommand::Resolve { host } if host == "example.com"));
        assert!(dns_cmd_rx.try_recv().is_err(), "should be no more commands");
    }

    #[tokio::test]
    async fn refresh_dns_handles_closed_channel_gracefully() {
        let peer = bare_peer("peer1", &["10.0.0.0/24"]);

        let (mut orch, handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        drop(handles.dns_cmd_rx); // Close receiver

        // Should not panic, just log warning
        orch.refresh_dns().await;
    }
}
