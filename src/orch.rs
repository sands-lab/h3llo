//! BareUDP-only runtime orchestration.

use crate::bare::{spawn_udp_rx, spawn_udp_tx, BareUdpRx, BareUdpRxCommand, BareUdpTx};
use crate::bind::{BindWarning, DefaultRouteProbe};
use crate::config::{parse_udp_uri, Config, Peer, UdpEndpoint};
use crate::dns::{DnsCommand, DnsResolver};
use crate::events::{DnsEventDetail, Event, TransportEvent};
use crate::route::{sync_tun_routes, RouteManagerHandle, RouteSyncWarning};
use crate::tun::{self, RoutingTable, TunRxCommand};
use ipnet::IpNet;
use log::warn;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};

const PACKET_QUEUE_DEPTH: usize = 256;
const EVENTS_QUEUE_DEPTH: usize = 64;
const METRICS_INTERVAL: Duration = Duration::from_secs(30);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Configuration for a BareUDP peer pending DNS resolution.
struct BarePeerConfig {
    peer_id: String,
    port: u16,
    bindif: Option<String>,
    #[allow(dead_code)]
    peer: Peer,
}

/// Pending DNS resolution context.
///
/// Tracks what operations are waiting for a hostname to be resolved.
/// Multiple peers may share the same hostname.
enum PendingDns {
    /// Waiting for BareUDP peer addresses.
    BarePeers { configs: Vec<BarePeerConfig> },
}

impl PendingDns {
    /// Adds a peer config to the pending DNS entry.
    fn push_config(&mut self, config: BarePeerConfig) {
        match self {
            PendingDns::BarePeers { configs } => configs.push(config),
        }
    }
}

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
    /// A runtime task exited unexpectedly.
    #[error("runtime task exited: {0}")]
    TaskExited(String),
    /// A runtime task failed to join.
    #[error("runtime task join failed: {0}")]
    TaskJoin(String),
}

/// BareUDP runtime orchestrator.
///
/// Manages child actors (TUN-Rx/Tx, BareUDP-Rx/Tx, DNS resolver) and processes runtime events.
/// Uses a single unified event loop for both initialization and runtime.
pub struct Orchestrator {
    events_rx: mpsc::Receiver<Event>,
    events_tx: mpsc::Sender<Event>,
    join_set: JoinSet<String>,

    // DNS state (minimal)
    pending_dns: HashMap<String, PendingDns>,
    dns_refresh: Duration,

    // Runtime state
    tun_if: String,
    #[allow(dead_code)]
    mtu: usize,
    peers: Vec<Peer>,
    active_ips: HashSet<IpAddr>,
    peer_txs: HashMap<String, mpsc::Sender<Vec<u8>>>,
    tun_cmd_tx: mpsc::Sender<TunRxCommand>,
    bare_rx_cmd_tx: Option<mpsc::Sender<BareUdpRxCommand>>,

    /// DNS resolver command sender for refresh commands.
    dns_cmd_tx: Option<mpsc::Sender<DnsCommand>>,

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

        let (events_tx, events_rx) = mpsc::channel(EVENTS_QUEUE_DEPTH);
        let (bare_packet_tx, bare_packet_rx) = mpsc::channel(PACKET_QUEUE_DEPTH);
        let (bare_rx_cmd_tx, bare_rx_cmd_rx) = mpsc::channel::<BareUdpRxCommand>(1);
        let (tun_cmd_tx, tun_cmd_rx) = mpsc::channel::<TunRxCommand>(1);

        // Collect peers and build pending DNS / immediate TX
        let mut peers = Vec::new();
        let mut pending_dns = HashMap::new();
        let mut peer_txs = HashMap::new();
        let mut active_ips = HashSet::new();
        let mut join_set = JoinSet::new();

        for peer in &config.peers {
            if !peer.enabled {
                continue;
            }
            let bare = match peer.bare.as_ref() {
                Some(bare) => bare,
                None => {
                    warn!(
                        "peer '{}' uses non-BareUDP transport; ignoring in bare runtime",
                        peer.id
                    );
                    continue;
                }
            };
            let endpoint = parse_udp_uri(&bare.endpoint).map_err(|err| {
                OrchestratorError::InvalidPeerEndpoint {
                    peer_id: peer.id.clone(),
                    reason: err,
                }
            })?;

            peers.push(peer.clone());

            if let Some(ip) = parse_ip_literal(&endpoint.host) {
                // IP literal: create TX immediately
                let destination = SocketAddr::new(ip, endpoint.port);
                if let Some((packet_tx, tx_handle)) = spawn_bare_tx_for_peer(
                    &peer.id,
                    destination,
                    bare.bindif.as_deref(),
                    &tun_if,
                    events_tx.clone(),
                    &mut active_ips,
                )
                .await
                {
                    peer_txs.insert(peer.id.clone(), packet_tx);
                    let label = format!("bare_tx:{}", peer.id);
                    join_set.spawn(wrap_task(label, tx_handle));
                }
            } else {
                // Hostname: add to pending DNS (accumulate if same hostname)
                let config = BarePeerConfig {
                    peer_id: peer.id.clone(),
                    port: endpoint.port,
                    bindif: bare.bindif.clone(),
                    peer: peer.clone(),
                };
                pending_dns
                    .entry(endpoint.host.clone())
                    .or_insert_with(|| PendingDns::BarePeers {
                        configs: Vec::new(),
                    })
                    .push_config(config);
            }
        }

        // Build initial routing table from IP literals
        let routing = RoutingTable::from_peers(&peers, &peer_txs)
            .map_err(|err| OrchestratorError::Routing(err.to_string()))?;

        // Sync system routes if enabled
        if manage_routes {
            let allowed = collect_allowed_ips(&peers)?;
            sync_system_routes(&tun_if, &tun_addrs, &allowed).await;
        }

        // Spawn TUN actors
        let tun_rx_handle = tun::spawn_tun_rx(
            tun_reader,
            routing,
            tun_cmd_rx,
            events_tx.clone(),
            METRICS_INTERVAL,
        );
        let tun_tx_handle = tun::spawn_tun_tx(
            tun_writer,
            bare_packet_rx,
            events_tx.clone(),
            METRICS_INTERVAL,
        );

        // Spawn BareUDP RX
        let bare_rx_handle = spawn_udp_rx(
            bare_rx,
            active_ips.clone(),
            bare_rx_cmd_rx,
            bare_packet_tx,
            events_tx.clone(),
            METRICS_INTERVAL,
        );

        join_set.spawn(wrap_task("tun_rx", tun_rx_handle));
        join_set.spawn(wrap_task("tun_tx", tun_tx_handle));
        join_set.spawn(wrap_task("bare_rx", bare_rx_handle));

        let dns_refresh = Duration::from_secs(config.local.dns.refresh);

        // Spawn DNS resolver if there are pending hostnames or refresh is enabled
        let dns_cmd_tx = if !pending_dns.is_empty() || !dns_refresh.is_zero() {
            let resolver = DnsResolver::from_config(
                &config.local.dns,
                Some(tun_if.clone()),
                DNS_QUERY_TIMEOUT,
            )
            .map_err(|err| OrchestratorError::DnsInit(err.to_string()))?;

            let (cmd_tx, cmd_rx) = mpsc::channel(16);
            let probe = DefaultRouteProbe;
            let handle = resolver
                .spawn(probe, cmd_rx, events_tx.clone())
                .await
                .map_err(|err| OrchestratorError::DnsInit(err.to_string()))?;

            // Send resolve commands for all pending hostnames
            for host in pending_dns.keys() {
                if cmd_tx
                    .send(DnsCommand::Resolve { host: host.clone() })
                    .await
                    .is_err()
                {
                    warn!("failed to send DNS resolve command for host");
                }
            }

            join_set.spawn(wrap_task("dns_resolver", handle));
            Some(cmd_tx)
        } else {
            None
        };

        if peer_txs.is_empty() && pending_dns.is_empty() {
            warn!("no active BareUDP peers; traffic will be dropped");
        }

        Ok(Self {
            events_rx,
            events_tx,
            join_set,
            pending_dns,
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
                _ = dns_ticker.tick(), if !self.dns_refresh.is_zero() && self.dns_cmd_tx.is_some() => {
                    self.refresh_dns().await;
                }
                result = self.join_set.join_next() => {
                    match result {
                        Some(Ok(label)) => {
                            log::error!("task '{}' exited unexpectedly", label);
                            return Err(OrchestratorError::TaskExited(label));
                        }
                        Some(Err(err)) => {
                            log::error!("task join failed: {}", err);
                            return Err(OrchestratorError::TaskJoin(err.to_string()));
                        }
                        None => return Ok(()),
                    }
                }
                result = tokio::signal::ctrl_c() => {
                    match result {
                        Ok(()) => {
                            log::info!("shutdown signal received, stopping...");
                            break;
                        }
                        Err(e) => {
                            log::warn!("signal handler error: {e}");
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

                    if let Some(pending) = self.pending_dns.remove(&answer.host) {
                        match pending {
                            PendingDns::BarePeers { configs } => {
                                for config in configs {
                                    self.handle_bare_peer_resolved(&answer, config).await;
                                }
                            }
                        }
                    }
                } else {
                    log::debug!(
                        "dns event from {}: {:?}",
                        dns_event.server,
                        dns_event.detail
                    );
                }
            }
            Event::Transport(TransportEvent::Metrics(metrics)) => {
                let labels = &metrics.labels;
                let stats = &metrics.stats;
                log::debug!(
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
                            log::debug!(
                                "  drop reason {:?}: {} pkts/{} bytes",
                                reason,
                                counters.packets,
                                counters.bytes
                            );
                        }
                    }
                }
            }
            Event::Other(msg) => {
                log::debug!("other event: {}", msg);
            }
        }
    }

    /// Sends DNS resolve commands for all hostname-based peer endpoints.
    ///
    /// Re-populates `pending_dns` so that incoming answers trigger the existing
    /// `handle_bare_peer_resolved` path. Existing TX actors for unchanged IPs are
    /// deduplicated by `active_ips` in `spawn_bare_tx_for_peer`.
    async fn refresh_dns(&mut self) {
        let cmd_tx = match &self.dns_cmd_tx {
            Some(tx) => tx,
            None => return,
        };

        // TODO: The `resolved_hosts` deduplication below skips config creation
        // and `push_config` for subsequent peers sharing the same hostname.
        // This differs from initialization (lines 203-217) which correctly
        // accumulates all peer configs per hostname. The deduplication should
        // only prevent sending duplicate DnsCommand::Resolve, not skip the
        // config/push_config logic.
        let mut resolved_hosts = HashSet::new();
        for peer in &self.peers {
            let bare = match peer.bare.as_ref() {
                Some(b) => b,
                None => continue,
            };
            let endpoint = match parse_udp_uri(&bare.endpoint) {
                Ok(ep) => ep,
                Err(_) => continue,
            };
            if parse_ip_literal(&endpoint.host).is_some() {
                continue;
            }
            if !resolved_hosts.insert(endpoint.host.clone()) {
                continue; // already enqueued this hostname
            }

            // Re-populate pending_dns so existing answer handler processes it.
            // TODO: Consider using `insert` instead of `or_insert_with` here to
            // replace stale in-flight entries rather than accumulating duplicates.
            let config = BarePeerConfig {
                peer_id: peer.id.clone(),
                port: endpoint.port,
                bindif: bare.bindif.clone(),
                peer: peer.clone(),
            };
            self.pending_dns
                .entry(endpoint.host.clone())
                .or_insert_with(|| PendingDns::BarePeers {
                    configs: Vec::new(),
                })
                .push_config(config);

            if cmd_tx
                .send(DnsCommand::Resolve {
                    host: endpoint.host,
                })
                .await
                .is_err()
            {
                warn!("dns refresh: resolver channel closed");
                break;
            }
        }
    }

    /// Handles a resolved BareUDP peer hostname.
    async fn handle_bare_peer_resolved(
        &mut self,
        answer: &crate::events::DnsAnswer,
        config: BarePeerConfig,
    ) {
        if answer.records.is_empty() {
            warn!(
                "dns resolved no addresses for peer '{}' hostname",
                config.peer_id
            );
            return;
        }

        for record in &answer.records {
            let destination = SocketAddr::new(record.address, config.port);
            if let Some((packet_tx, tx_handle)) = spawn_bare_tx_for_peer(
                &config.peer_id,
                destination,
                config.bindif.as_deref(),
                &self.tun_if,
                self.events_tx.clone(),
                &mut self.active_ips,
            )
            .await
            {
                // Latest resolution wins for routing (enables IP migration on refresh).
                // TODO: IP migration is broken. When insert() replaces the old
                // packet_tx, the old TX actor exits (bare.rs:166), triggering
                // OrchestratorError::TaskExited (line 352-356) and shutting down.
                // The old IP also remains in active_ips as stale state.
                // Fix requires: (1) gracefully stop old TX actor before replacing,
                // (2) remove old IP from active_ips, (3) distinguish expected TX
                // exits from unexpected ones in the join_set handler.
                self.peer_txs.insert(config.peer_id.clone(), packet_tx);

                let label = format!("bare_tx:{}", config.peer_id);
                self.join_set.spawn(wrap_task(label, tx_handle));
            }
        }

        // 1. Update allowed sources (fast, in-memory filter)
        if let Some(cmd_tx) = &self.bare_rx_cmd_tx {
            if cmd_tx
                .send(BareUdpRxCommand::UpdateAllowedSources(
                    self.active_ips.clone(),
                ))
                .await
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
                .await
                .is_err()
            {
                warn!("failed to send routing update command");
            }
        }

        // 3. Sync system routes if enabled
        if self.manage_routes {
            if let Ok(allowed) = collect_allowed_ips(&self.peers) {
                sync_system_routes(&self.tun_if, &self.tun_addrs, &allowed).await;
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
fn resolve_listen_addr(listen: &UdpEndpoint) -> Result<SocketAddr, OrchestratorError> {
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
    events_tx: mpsc::Sender<Event>,
    active_ips: &mut HashSet<IpAddr>,
) -> Option<(mpsc::Sender<Vec<u8>>, JoinHandle<()>)> {
    // Dedup by IP
    if !active_ips.insert(destination.ip()) {
        return None;
    }

    let probe = DefaultRouteProbe;
    let (tx_socket, warnings) =
        match BareUdpTx::from_config(destination, bindif, Some(tun_if), &probe).await {
            Ok(result) => result,
            Err(err) => {
                warn!("bare peer '{}' socket setup failed: {err}", peer_id);
                active_ips.remove(&destination.ip());
                return None;
            }
        };

    for warning in warnings {
        log_bind_warning(&format!("peer {}", peer_id), &warning);
    }

    let (packet_tx, packet_rx) = mpsc::channel(PACKET_QUEUE_DEPTH);
    let tx_handle = spawn_udp_tx(
        tx_socket,
        destination,
        packet_rx,
        events_tx,
        METRICS_INTERVAL,
    );

    Some((packet_tx, tx_handle))
}

/// Performs system route synchronization, logging warnings on failure.
async fn sync_system_routes(tun_if: &str, tun_addrs: &[IpNet], allowed: &[IpNet]) {
    match RouteManagerHandle::new() {
        Ok(mut handle) => match sync_tun_routes(tun_if, tun_addrs, allowed, &mut handle).await {
            Ok(warnings) => {
                for warning in warnings {
                    log_route_warning(&warning);
                }
            }
            Err(err) => warn!("route sync failed: {err}"),
        },
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

fn log_bind_warning(context: &str, warning: &BindWarning) {
    warn!("bind warning ({}): {:?}", context, warning);
}

fn log_route_warning(warning: &RouteSyncWarning) {
    match warning {
        RouteSyncWarning::AddFailed { prefix, error } => {
            warn!("route add failed for {}: {}", prefix, error);
        }
        RouteSyncWarning::DeleteFailed { prefix, error } => {
            warn!("route delete failed for {}: {}", prefix, error);
        }
        RouteSyncWarning::DefaultRouteSplit { prefix } => {
            warn!("default route {} split into two /1 prefixes", prefix);
        }
        RouteSyncWarning::Conflict {
            prefix,
            existing_ifindex,
        } => {
            warn!(
                "route conflict for {} (existing ifindex {})",
                prefix, existing_ifindex
            );
        }
        RouteSyncWarning::UnsupportedRoute { reason } => {
            warn!("unsupported route skipped: {}", reason);
        }
        RouteSyncWarning::MissingIfIndex { prefix } => {
            warn!("route missing ifindex skipped: {}", prefix);
        }
    }
}

async fn wrap_task(label: impl Into<String>, handle: JoinHandle<()>) -> String {
    let name = label.into();
    let _ = handle.await;
    name
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
        pending_dns: HashMap<String, PendingDns>,
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
                pending_dns: HashMap::new(),
                dns_refresh: Duration::ZERO,
                manage_routes: false,
                tun_addrs: Vec::new(),
            }
        }
    }

    impl TestableOrchestratorBuilder {
        pub fn with_peers(mut self, peers: Vec<Peer>) -> Self {
            self.peers = peers;
            self
        }

        pub fn with_pending_dns(mut self, host: &str, pending: PendingDns) -> Self {
            self.pending_dns.insert(host.to_string(), pending);
            self
        }

        /// Builds a testable orchestrator with dummy channels.
        pub fn build(self) -> (Orchestrator, mpsc::Sender<Event>) {
            let (events_tx, events_rx) = mpsc::channel(64);
            let (tun_cmd_tx, _tun_cmd_rx) = mpsc::channel(1);
            let (bare_rx_cmd_tx, _bare_rx_cmd_rx) = mpsc::channel(1);

            let orch = Orchestrator {
                events_rx,
                events_tx: events_tx.clone(),
                join_set: JoinSet::new(),
                pending_dns: self.pending_dns,
                dns_refresh: self.dns_refresh,
                tun_if: self.tun_if,
                mtu: self.mtu,
                peers: self.peers,
                active_ips: self.active_ips,
                peer_txs: self.peer_txs,
                tun_cmd_tx,
                bare_rx_cmd_tx: Some(bare_rx_cmd_tx),
                dns_cmd_tx: None,
                manage_routes: self.manage_routes,
                tun_addrs: self.tun_addrs,
            };

            (orch, events_tx)
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

    #[tokio::test]
    async fn orchestrator_error_includes_task_label() {
        // Verify that OrchestratorError::TaskExited includes the task label
        let error = OrchestratorError::TaskExited("tun_rx".to_string());
        let error_msg = error.to_string();
        assert!(
            error_msg.contains("tun_rx"),
            "error message should contain task label"
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

    // ========== PendingDns tests ==========

    #[test]
    fn pending_dns_accumulates_configs() {
        let mut pending = PendingDns::BarePeers {
            configs: Vec::new(),
        };

        pending.push_config(BarePeerConfig {
            peer_id: "peer1".to_string(),
            port: 5353,
            bindif: None,
            peer: bare_peer("peer1", &["10.0.0.0/24"]),
        });

        pending.push_config(BarePeerConfig {
            peer_id: "peer2".to_string(),
            port: 5354,
            bindif: Some("eth0".to_string()),
            peer: bare_peer("peer2", &["172.16.0.0/16"]),
        });

        match pending {
            PendingDns::BarePeers { configs } => {
                assert_eq!(configs.len(), 2);
                assert_eq!(configs[0].peer_id, "peer1");
                assert_eq!(configs[1].peer_id, "peer2");
                assert_eq!(configs[1].bindif, Some("eth0".to_string()));
            }
        }
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
        let (mut orch, events_tx) = TestableOrchestratorBuilder::default().build();

        let initial_peer_count = orch.peer_txs.len();
        let initial_pending_count = orch.pending_dns.len();

        orch.handle_event(make_metrics_event()).await;

        assert_eq!(orch.peer_txs.len(), initial_peer_count);
        assert_eq!(orch.pending_dns.len(), initial_pending_count);

        drop(events_tx);
    }

    #[tokio::test]
    async fn handle_event_processes_other_event() {
        let (mut orch, events_tx) = TestableOrchestratorBuilder::default().build();

        orch.handle_event(Event::Other("test message".to_string()))
            .await;

        assert!(orch.peer_txs.is_empty());
        assert!(orch.pending_dns.is_empty());

        drop(events_tx);
    }

    #[tokio::test]
    async fn handle_event_ignores_dns_answer_for_unknown_host() {
        let (mut orch, events_tx) = TestableOrchestratorBuilder::default().build();

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

        // No new peer TX should be created for unknown host
        assert!(orch.peer_txs.is_empty());

        drop(events_tx);
    }

    #[tokio::test]
    async fn handle_event_removes_pending_dns_on_answer() {
        let peer = bare_peer("peer1", &["10.0.0.0/24"]);
        let pending = PendingDns::BarePeers {
            configs: vec![BarePeerConfig {
                peer_id: "peer1".to_string(),
                port: 5353,
                bindif: None,
                peer: peer.clone(),
            }],
        };

        let (mut orch, events_tx) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_pending_dns("example.com", pending)
            .build();

        assert!(orch.pending_dns.contains_key("example.com"));

        // DNS answer with empty records (will trigger warning path but still remove pending)
        let answer = Event::Dns(DnsEvent {
            server: "127.0.0.1:53".parse().unwrap(),
            detail: DnsEventDetail::Answer(DnsAnswer {
                host: "example.com".to_string(),
                record_type: DnsRecordType::A,
                records: vec![],
                warnings: vec![],
            }),
        });
        orch.handle_event(answer).await;

        // Pending DNS entry should be removed after processing
        assert!(!orch.pending_dns.contains_key("example.com"));

        drop(events_tx);
    }

    #[tokio::test]
    async fn handle_bare_peer_resolved_with_empty_records_logs_warning() {
        let peer = bare_peer("peer1", &["10.0.0.0/24"]);
        let (mut orch, events_tx) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer.clone()])
            .build();

        let answer = DnsAnswer {
            host: "example.com".to_string(),
            record_type: DnsRecordType::A,
            records: vec![],
            warnings: vec![],
        };

        let config = BarePeerConfig {
            peer_id: "peer1".to_string(),
            port: 5353,
            bindif: None,
            peer,
        };

        // This should return early with a warning, not create any TX
        orch.handle_bare_peer_resolved(&answer, config).await;

        // No peer TX should be created
        assert!(!orch.peer_txs.contains_key("peer1"));

        drop(events_tx);
    }

    #[tokio::test]
    async fn handle_bare_peer_resolved_updates_routing_and_allowed_sources() {
        let peer = bare_peer("peer1", &["10.0.0.0/24"]);
        let (mut orch, events_tx) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer.clone()])
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

        let config = BarePeerConfig {
            peer_id: "peer1".to_string(),
            port: 5353,
            bindif: None,
            peer,
        };

        // Should not panic; exercises allowed sources → routing → (no system route sync)
        orch.handle_bare_peer_resolved(&answer, config).await;

        drop(events_tx);
    }

    #[tokio::test]
    async fn handle_bare_peer_resolved_skips_route_sync_when_disabled() {
        let peer = bare_peer("peer1", &["10.0.0.0/24"]);
        let (mut orch, events_tx) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer.clone()])
            .build();

        // manage_routes defaults to false in TestableOrchestratorBuilder
        assert!(!orch.manage_routes);

        let answer = DnsAnswer {
            host: "example.com".to_string(),
            record_type: DnsRecordType::A,
            records: vec![DnsAnswerRecord {
                address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
                ttl: 60,
            }],
            warnings: vec![],
        };

        let config = BarePeerConfig {
            peer_id: "peer1".to_string(),
            port: 5353,
            bindif: None,
            peer,
        };

        // Should complete without panic; no system route sync attempted
        orch.handle_bare_peer_resolved(&answer, config).await;

        drop(events_tx);
    }

    // TODO: Add tests for `refresh_dns`:
    // - Verify refresh_dns populates pending_dns for hostname-based peers
    // - Verify refresh_dns skips IP-literal peers
    // - Verify refresh_dns deduplicates hostnames shared by multiple peers
    // - Verify refresh_dns sends DnsCommand::Resolve for each unique hostname
    // - Verify refresh_dns handles closed resolver channel gracefully
    // - Verify dns_ticker branch is disabled when dns_refresh is zero
    // - Verify dns_ticker fires at configured interval when dns_refresh > 0
}
