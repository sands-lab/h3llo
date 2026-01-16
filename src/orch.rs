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

    // Runtime state
    tun_if: String,
    #[allow(dead_code)]
    mtu: usize,
    peers: Vec<Peer>,
    active_ips: HashSet<IpAddr>,
    peer_txs: HashMap<String, mpsc::Sender<Vec<u8>>>,
    tun_cmd_tx: mpsc::Sender<TunRxCommand>,
    bare_rx_cmd_tx: Option<mpsc::Sender<BareUdpRxCommand>>,

    /// DNS resolver command sender for future refresh commands.
    #[allow(dead_code)]
    dns_cmd_tx: Option<mpsc::Sender<DnsCommand>>,
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
        if config.local.table {
            let allowed = collect_allowed_ips(&peers)?;
            let tun_addrs = tun_prefixes(&config.local.tun.addrs)?;
            match RouteManagerHandle::new() {
                Ok(mut handle) => {
                    match sync_tun_routes(&tun_if, &tun_addrs, &allowed, &mut handle).await {
                        Ok(warnings) => {
                            for warning in warnings {
                                log_route_warning(&warning);
                            }
                        }
                        Err(err) => warn!("route sync failed: {err}"),
                    }
                }
                Err(err) => warn!("route manager unavailable: {err}"),
            }
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

        // Spawn DNS resolver if there are pending hostnames
        let dns_cmd_tx = if !pending_dns.is_empty() {
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
            tun_if,
            mtu,
            peers,
            active_ips,
            peer_txs,
            tun_cmd_tx,
            bare_rx_cmd_tx: Some(bare_rx_cmd_tx),
            dns_cmd_tx,
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
        loop {
            tokio::select! {
                Some(event) = self.events_rx.recv() => {
                    self.handle_event(event).await;
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
                // First IP wins for routing
                self.peer_txs
                    .entry(config.peer_id.clone())
                    .or_insert(packet_tx);

                let label = format!("bare_tx:{}", config.peer_id);
                self.join_set.spawn(wrap_task(label, tx_handle));
            }
        }

        // Update routing table
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

        // Update allowed sources
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
mod tests {
    use super::*;

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
}
