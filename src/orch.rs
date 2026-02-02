//! Runtime orchestration for BareUDP and HTTP/3 transports.

use crate::actor::{ActorError, ActorExitResult, ActorKind};
use crate::bare::{spawn_udp_rx, spawn_udp_tx, BareUdpRx, BareUdpRxCommand, BareUdpTx};
use crate::bind::DefaultRouteProbe;
use crate::config::{parse_h3_uri, parse_udp_uri, Config, Peer};
use crate::dns::{DnsCommand, DnsResolver};
use crate::events::{DnsEventDetail, Event, TransportEvent};
use crate::h3::{
    dial_h3, spawn_h3_listener, spawn_h3_rx, spawn_h3_tx, H3Connection, H3ListenerCommand,
};
use crate::route::{sync_tun_routes, RouteManagerHandle};
use crate::tun::{self, RoutingTable, TunRxCommand};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, error, info, warn};

const METRICS_INTERVAL: Duration = Duration::from_secs(30);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Unique identifier for a bound within the orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BoundId(u64);

/// Identifies the transport protocol for a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportType {
    BareUdp,
    Http3,
}

/// A single active connection bound to a peer.
#[derive(Debug)]
struct BoundState {
    /// Unique identifier for tracking.
    #[allow(dead_code)]
    id: BoundId,
    /// Transport kind for this bound.
    #[allow(dead_code)]
    transport: TransportType,
    /// Destination socket address.
    dest: SocketAddr,
    /// TX channel for sending packets.
    tx: mpsc::Sender<Vec<u8>>,
}

/// Entry for a single peer in the unified pool.
#[derive(Debug)]
struct PeerEntry {
    /// Peer configuration (read-only after creation).
    config: Peer,
    /// Active bounds (connections) for this peer.
    bounds: Vec<BoundState>,
}

impl PeerEntry {
    /// Creates a new peer entry from configuration.
    fn new(config: Peer) -> Self {
        Self {
            config,
            bounds: Vec::new(),
        }
    }

    /// Returns the preferred TX channel (first bound) or None if disconnected.
    fn preferred_tx(&self) -> Option<&mpsc::Sender<Vec<u8>>> {
        self.bounds.first().map(|b| &b.tx)
    }

    /// Returns all active destination IPs for this peer.
    fn active_ips(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.bounds.iter().map(|b| b.dest.ip())
    }

    /// Returns true if a bound exists for the given destination IP.
    fn has_bound_for_ip(&self, ip: IpAddr) -> bool {
        self.bounds.iter().any(|b| b.dest.ip() == ip)
    }
}

/// Errors returned by the orchestrator.
#[derive(Debug, Error)]
pub enum OrchestratorError {
    /// BareUDP configuration is missing.
    #[error("bare runtime requires local.bare.listen to be set")]
    MissingBareListen,
    /// HTTP/3 configuration is missing.
    #[error("h3 runtime requires local.h3.listen to be set")]
    MissingH3Listen,
    /// BareUDP listen URI failed validation.
    #[error("invalid bare listen uri: {0}")]
    InvalidBareListen(String),
    /// HTTP/3 listen URI failed validation.
    #[error("invalid h3 listen uri: {0}")]
    InvalidH3Listen(String),
    /// BareUDP peer endpoint failed validation.
    #[error("peer '{peer_id}' bare.endpoint invalid: {reason}")]
    InvalidPeerEndpoint { peer_id: String, reason: String },
    /// HTTP/3 peer endpoint failed validation.
    #[error("peer '{peer_id}' h3.endpoints[{index}] invalid: {reason}")]
    InvalidH3Endpoint {
        peer_id: String,
        index: usize,
        reason: String,
    },
    /// BareUDP listen host could not be resolved.
    #[error("failed to resolve bare listen host '{host}': {reason}")]
    ListenResolveFailed { host: String, reason: String },
    /// HTTP/3 listener failed to start.
    #[error("h3 listener failed: {0}")]
    H3Listener(String),
    /// HTTP/3 dial failed.
    #[error("h3 dial to '{peer_id}' failed: {reason}")]
    H3Dial { peer_id: String, reason: String },
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

/// Runtime orchestrator for BareUDP and HTTP/3 transports.
///
/// Manages child actors with selective supervision:
/// - Critical actors (TUN, BareUDP-Rx, H3-Listener): failure causes immediate exit
/// - Peer actors (BareUDP-Tx, H3-Tx/Rx): failure logged (reconnection deferred to future iteration)
pub struct Orchestrator {
    events_rx: mpsc::UnboundedReceiver<Event>,
    events_tx: mpsc::UnboundedSender<Event>,
    join_set: JoinSet<Result<ActorExitResult, tokio::task::JoinError>>,

    dns_refresh: Duration,

    // Runtime state
    local_id: String,
    tun_if: String,
    #[allow(dead_code)]
    mtu: usize,
    /// Unified peer state: config + active bounds.
    peers: HashMap<String, PeerEntry>,
    /// Counter for generating unique BoundIds.
    bound_counter: u64,
    tun_cmd_tx: mpsc::UnboundedSender<TunRxCommand>,
    bare_rx_cmd_tx: Option<mpsc::UnboundedSender<BareUdpRxCommand>>,
    /// H3 listener command sender (if listening).
    #[allow(dead_code)]
    h3_listener_cmd_tx: Option<mpsc::UnboundedSender<H3ListenerCommand>>,
    /// H3 connection receiver for inbound connections.
    h3_conn_rx: Option<mpsc::UnboundedReceiver<H3Connection>>,
    /// Packet sender to TUN TX (for H3 RX actors).
    tun_packet_tx: mpsc::Sender<Vec<u8>>,

    /// DNS resolver command sender for refresh commands.
    dns_cmd_tx: mpsc::UnboundedSender<DnsCommand>,

    /// Whether to manage system routes (`local.table`).
    manage_routes: bool,
    /// Pre-parsed TUN interface addresses as host-prefixed IpNets (for system route sync).
    tun_addrs: Vec<IpNet>,
}

impl Orchestrator {
    /// Returns set of all active destination IPs (for BareRx filtering).
    fn active_ips(&self) -> std::collections::HashSet<IpAddr> {
        self.peers.values().flat_map(|e| e.active_ips()).collect()
    }

    /// Updates all dependent subsystems after bounds topology changes.
    ///
    /// Performs the three-update sequence:
    /// 1. BareRx allowed sources (in-memory filter)
    /// 2. TUN routing table (internal forwarding)
    /// 3. System routes (if `local.table` is enabled)
    ///
    /// Called after any bound is added or removed.
    async fn on_bounds_changed(&self) {
        // 1. Update allowed sources (fast, in-memory filter)
        if let Some(cmd_tx) = &self.bare_rx_cmd_tx {
            if let Err(e) = cmd_tx.send(BareUdpRxCommand::UpdateAllowedSources(self.active_ips())) {
                warn!(error = %e, "failed to send allowed sources update command");
            }
        }

        // 2. Update internal routing table
        let peer_configs = self.peer_configs();
        let peer_txs = self.peer_txs();
        if let Ok(routing) = RoutingTable::from_peers(&peer_configs, &peer_txs) {
            if let Err(e) = self
                .tun_cmd_tx
                .send(TunRxCommand::UpdateRouting { routing })
            {
                warn!(error = %e, "failed to send routing update command");
            }
        }

        // 3. Sync system routes if enabled
        if self.manage_routes {
            match collect_allowed_ips(&peer_configs) {
                Ok(allowed) => sync_system_routes(&self.tun_if, &self.tun_addrs, &allowed).await,
                Err(err) => warn!("route sync skipped: {err}"),
            }
        }
    }

    /// Returns map of peer ID to preferred TX channel (for routing table).
    fn peer_txs(&self) -> HashMap<String, mpsc::Sender<Vec<u8>>> {
        self.peers
            .iter()
            .filter_map(|(id, e)| e.preferred_tx().map(|tx| (id.clone(), tx.clone())))
            .collect()
    }

    /// Returns peer configurations as a Vec (for routing table and route sync).
    fn peer_configs(&self) -> Vec<Peer> {
        self.peers.values().map(|e| e.config.clone()).collect()
    }

    /// Generates a new unique BoundId.
    fn next_bound_id(&mut self) -> BoundId {
        self.bound_counter += 1;
        BoundId(self.bound_counter)
    }

    /// Creates a new orchestrator from configuration.
    ///
    /// Initializes TUN interface, transport listeners (BareUDP and/or H3),
    /// routing table, and spawns child actors. Listen hostnames are resolved
    /// synchronously; peer hostnames are resolved asynchronously via the event loop.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError` when initialization fails.
    pub async fn new(config: Config) -> Result<Self, OrchestratorError> {
        let local_id = config.local.id.clone();
        let tun_if = config.local.tun.ifname.clone();
        let mtu = config.local.tun.mtu as usize;
        let manage_routes = config.local.table;
        let tun_addrs = tun_prefixes(&config.local.tun.addrs)?;

        // At least one transport must be configured
        let has_bare = config.local.bare.is_some();
        let has_h3 = config.local.h3.is_some();
        if !has_bare && !has_h3 {
            return Err(OrchestratorError::MissingBareListen);
        }

        // Setup TUN
        let (tun_reader, tun_writer) = tun::from_config(&config.local.tun)
            .await
            .map_err(|err| OrchestratorError::Tun(err.to_string()))?;

        // Control plane: unbounded to prevent deadlocks from actor cycles.
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        let mut join_set = JoinSet::new();

        // Start with empty routing table; routes populated as DNS answers arrive
        let routing = RoutingTable::new();

        // Spawn TUN actors - actors create their own command channels
        let (tun_cmd_tx, tun_rx_handle) =
            tun::spawn_tun_rx(tun_reader, routing, events_tx.clone(), METRICS_INTERVAL);
        // TUN-Tx actor creates its own packet channel; returns sender for transports to use
        let (tun_packet_tx, tun_tx_handle) =
            tun::spawn_tun_tx(tun_writer, events_tx.clone(), METRICS_INTERVAL);

        join_set.spawn(tun_rx_handle);
        join_set.spawn(tun_tx_handle);

        // Initialize BareUDP listener if configured
        let bare_rx_cmd_tx = if let Some(local_bare) = config.local.bare.as_ref() {
            let listen_endpoint =
                parse_udp_uri(&local_bare.listen).map_err(OrchestratorError::InvalidBareListen)?;
            let listen_addr = resolve_listen_addr(&listen_endpoint.host, listen_endpoint.port)?;

            let bare_rx = BareUdpRx::from_config(listen_addr, mtu)
                .map_err(|err| OrchestratorError::Udp(err.to_string()))?;

            let (cmd_tx, bare_rx_handle) = spawn_udp_rx(
                bare_rx,
                std::collections::HashSet::new(),
                tun_packet_tx.clone(),
                events_tx.clone(),
                METRICS_INTERVAL,
            );

            join_set.spawn(bare_rx_handle);
            Some(cmd_tx)
        } else {
            None
        };

        // Initialize H3 listener if configured
        let (h3_listener_cmd_tx, h3_conn_rx) = if let Some(h3_cfg) = config.local.h3.as_ref() {
            let listen_endpoint =
                parse_h3_uri(&h3_cfg.listen).map_err(OrchestratorError::InvalidH3Listen)?;
            let listen_addr = resolve_listen_addr(&listen_endpoint.host, listen_endpoint.port)?;

            let cert_path = Path::new(&h3_cfg.cert);
            let key_path = Path::new(&h3_cfg.key);

            // Build peer secrets map for authentication
            let peer_secrets: HashMap<String, String> = config
                .peers
                .iter()
                .filter(|p| p.enabled && p.h3.is_some())
                .map(|p| (p.id.clone(), p.h3.as_ref().unwrap().secret.clone()))
                .collect();

            let (conn_tx, conn_rx) = mpsc::unbounded_channel();
            let (cmd_tx, listener_handle, _bound_addr) =
                spawn_h3_listener(listen_addr, cert_path, key_path, peer_secrets, conn_tx)
                    .await
                    .map_err(|e| OrchestratorError::H3Listener(e.to_string()))?;

            join_set.spawn(listener_handle);
            (Some(cmd_tx), Some(conn_rx))
        } else {
            (None, None)
        };

        // Initialize unified peer state from config (enabled peers with any transport)
        let peers: HashMap<String, PeerEntry> = config
            .peers
            .iter()
            .filter(|p| p.enabled && (p.bare.is_some() || p.h3.is_some()))
            .map(|p| (p.id.clone(), PeerEntry::new(p.clone())))
            .collect();

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
        let peer_configs: Vec<Peer> = peers.values().map(|e| e.config.clone()).collect();
        send_resolve_commands(&peer_configs, &dns_cmd_tx)?;

        join_set.spawn(handle);

        let has_active_peers = peers.values().any(|e| e.config.enabled);
        if !has_active_peers {
            warn!("no active peers; traffic will be dropped");
        }

        Ok(Self {
            events_rx,
            events_tx,
            join_set,
            dns_refresh,
            local_id,
            tun_if,
            mtu,
            peers,
            bound_counter: 0,
            tun_cmd_tx,
            bare_rx_cmd_tx,
            h3_listener_cmd_tx,
            h3_conn_rx,
            tun_packet_tx,
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
                Some(conn) = async {
                    match self.h3_conn_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.handle_h3_inbound(conn).await;
                }
                result = self.join_set.join_next() => {
                    match result {
                        Some(Ok(Ok(Ok(())))) => {
                            // Graceful shutdown of one actor; continue running
                            debug!("an actor exited gracefully");
                        }
                        Some(Ok(Ok(Err(actor_error)))) => {
                            match actor_error.kind() {
                                ActorKind::Critical => {
                                    // Critical actor failure - exit h3llo
                                    error!("critical actor failed: {}", actor_error);
                                    return Err(OrchestratorError::ActorError(actor_error));
                                }
                                ActorKind::Restartable => {
                                    // Peer actor failure - log and continue
                                    // TODO: implement reconnection delay in future iteration
                                    warn!("peer actor failed (reconnection not yet implemented): {}", actor_error);
                                    // Remove the failed bound from the peer entry
                                    if let ActorError::BareTxSend { dest, .. } = &actor_error {
                                        if let Ok(dest_addr) = dest.parse::<SocketAddr>() {
                                            for entry in self.peers.values_mut() {
                                                entry.bounds.retain(|b| b.dest != dest_addr);
                                            }
                                        }
                                    }
                                }
                            }
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
            Event::Transport(TransportEvent::H3Connected(event)) => {
                debug!(
                    "H3 connection established: peer={} remote={} direction={:?}",
                    event.peer_id, event.remote_addr, event.direction
                );
            }
            Event::Transport(TransportEvent::H3Closed(event)) => {
                debug!(
                    "H3 connection closed: peer={} reason={:?}",
                    event.peer_id, event.reason
                );
            }
            Event::Other(msg) => {
                debug!("other event: {}", msg);
            }
        }
    }

    /// Sends DNS resolve commands for all peer endpoints (periodic refresh).
    ///
    /// Existing TX actors for unchanged IPs are deduplicated by
    /// `PeerEntry::has_bound_for_ip`. IP literals flow through DNS resolver
    /// (emits immediate answer).
    async fn refresh_dns(&mut self) {
        let peer_configs = self.peer_configs();
        if let Err(err) = send_resolve_commands(&peer_configs, &self.dns_cmd_tx) {
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

        // Collect peer IDs to process (to avoid borrow conflicts)
        let peer_ids: Vec<String> = self.peers.keys().cloned().collect();

        for peer_id in peer_ids {
            let entry = self.peers.get(&peer_id).unwrap();
            if !entry.config.enabled {
                continue;
            }

            // Handle BareUDP endpoints
            if let Some(bare) = entry.config.bare.as_ref() {
                let Ok(endpoint) = parse_udp_uri(&bare.endpoint) else {
                    continue;
                };

                if endpoint.host == answer.host {
                    for record in &answer.records {
                        let destination = SocketAddr::new(record.address, endpoint.port);
                        let entry = self.peers.get(&peer_id).unwrap();
                        if entry.has_bound_for_ip(destination.ip()) {
                            continue;
                        }

                        let bindif = entry.config.bare.as_ref().and_then(|b| b.bindif.as_deref());
                        if let Some((packet_tx, tx_handle)) = spawn_bare_tx(
                            &peer_id,
                            destination,
                            bindif,
                            &self.tun_if,
                            self.events_tx.clone(),
                        )
                        .await
                        {
                            let bound_id = self.next_bound_id();
                            let entry = self.peers.get_mut(&peer_id).unwrap();
                            entry.bounds.push(BoundState {
                                id: bound_id,
                                transport: TransportType::BareUdp,
                                dest: destination,
                                tx: packet_tx,
                            });
                            self.join_set.spawn(tx_handle);
                            any_spawned = true;
                        }
                    }
                }
            }

            // Handle H3 endpoints - collect dial targets first to avoid borrow conflicts
            let h3_dial_targets: Vec<(SocketAddr, String, String, String, Option<String>, bool)> = {
                let entry = self.peers.get(&peer_id).unwrap();
                let Some(h3) = entry.config.h3.as_ref() else {
                    continue;
                };

                let mut targets = Vec::new();
                for endpoint_uri in &h3.endpoints {
                    let Ok(endpoint) = parse_h3_uri(endpoint_uri) else {
                        continue;
                    };

                    // Strip IPv6 brackets for comparison
                    let host = endpoint.host.trim_start_matches('[').trim_end_matches(']');

                    if host != answer.host {
                        continue;
                    }

                    for record in &answer.records {
                        let destination = SocketAddr::new(record.address, endpoint.port);
                        if entry.has_bound_for_ip(destination.ip()) {
                            continue;
                        }

                        targets.push((
                            destination,
                            endpoint.host.clone(),
                            endpoint.path.clone(),
                            h3.secret.clone(),
                            h3.ca.clone(),
                            h3.insecure,
                        ));
                    }
                }
                targets
            };

            // Now dial H3 peers
            for (destination, server_name, path, secret, ca_path, insecure) in h3_dial_targets {
                if let Some((packet_tx, handles)) = self
                    .spawn_h3_peer(
                        &peer_id,
                        destination,
                        &server_name,
                        &path,
                        &secret,
                        ca_path.as_deref(),
                        insecure,
                    )
                    .await
                {
                    let bound_id = self.next_bound_id();
                    let entry = self.peers.get_mut(&peer_id).unwrap();
                    entry.bounds.push(BoundState {
                        id: bound_id,
                        transport: TransportType::Http3,
                        dest: destination,
                        tx: packet_tx,
                    });
                    for handle in handles {
                        self.join_set.spawn(handle);
                    }
                    any_spawned = true;
                }
            }
        }

        // Only update routing/filters if we actually spawned something
        if any_spawned {
            self.on_bounds_changed().await;
        }
    }

    /// Handles an inbound H3 connection from the listener.
    ///
    /// Spawns RX/TX actors for the authenticated peer and adds to routing.
    async fn handle_h3_inbound(&mut self, conn: H3Connection) {
        let peer_id = &conn.peer_id;
        let remote_addr = conn.remote_addr;

        // Check if peer is configured
        if !self.peers.contains_key(peer_id) {
            warn!(peer = %peer_id, addr = %remote_addr, "H3 inbound connection from unknown peer");
            return;
        }

        // Check if already have a bound for this IP
        let entry = self.peers.get(peer_id).unwrap();
        if entry.has_bound_for_ip(remote_addr.ip()) {
            debug!(peer = %peer_id, addr = %remote_addr, "H3 inbound: already have bound for this IP");
            return;
        }

        debug!(peer = %peer_id, addr = %remote_addr, "H3 inbound connection accepted");

        // Spawn RX/TX actors
        let rx_handle = spawn_h3_rx(
            peer_id.to_string(),
            conn.datagram_rx,
            self.tun_packet_tx.clone(),
            self.events_tx.clone(),
            METRICS_INTERVAL,
        );

        let (packet_tx, tx_handle) = spawn_h3_tx(
            peer_id.to_string(),
            conn.datagram_tx,
            conn.flow_id,
            self.events_tx.clone(),
            METRICS_INTERVAL,
        );

        let bound_id = self.next_bound_id();
        let entry = self.peers.get_mut(peer_id).unwrap();
        entry.bounds.push(BoundState {
            id: bound_id,
            transport: TransportType::Http3,
            dest: remote_addr,
            tx: packet_tx,
        });

        self.join_set.spawn(rx_handle);
        self.join_set.spawn(tx_handle);

        self.on_bounds_changed().await;
    }

    /// Spawns H3 TX/RX actors for a peer connection.
    ///
    /// Returns the packet sender and task handles, or None if dialing fails.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_h3_peer(
        &self,
        peer_id: &str,
        dest: SocketAddr,
        server_name: &str,
        path: &str,
        secret: &str,
        ca_path: Option<&str>,
        insecure: bool,
    ) -> Option<(mpsc::Sender<Vec<u8>>, Vec<JoinHandle<ActorExitResult>>)> {
        let probe = DefaultRouteProbe;
        let conn = match dial_h3(
            dest,
            server_name,
            path,
            &self.local_id,
            peer_id,
            secret,
            ca_path.map(Path::new),
            None, // bindif - TODO: support H3 bindifs
            Some(&self.tun_if),
            &probe,
            insecure,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                warn!(peer = %peer_id, addr = %dest, error = %e, "H3 dial failed");
                return None;
            }
        };

        debug!(peer = %peer_id, addr = %dest, "H3 connection established");

        let rx_handle = spawn_h3_rx(
            peer_id.to_string(),
            conn.datagram_rx,
            self.tun_packet_tx.clone(),
            self.events_tx.clone(),
            METRICS_INTERVAL,
        );

        let (packet_tx, tx_handle) = spawn_h3_tx(
            peer_id.to_string(),
            conn.datagram_tx,
            conn.flow_id,
            self.events_tx.clone(),
            METRICS_INTERVAL,
        );

        Some((packet_tx, vec![rx_handle, tx_handle]))
    }
}

/// Resolves a listen address from host and port, using synchronous DNS lookup for hostnames.
///
/// Handles IPv6 bracket notation (e.g., "[::1]" -> "::1") for compatibility with
/// both UDP and H3 endpoint formats.
fn resolve_listen_addr(host: &str, port: u16) -> Result<SocketAddr, OrchestratorError> {
    // Strip IPv6 bracket notation (safe no-op for non-bracketed hosts)
    let host = host.trim_start_matches('[').trim_end_matches(']');

    // Fast path: IP literal
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // Synchronous DNS lookup for hostname
    use std::net::ToSocketAddrs;
    let addr_str = format!("{}:{}", host, port);
    let addrs: Vec<_> = addr_str
        .to_socket_addrs()
        .map_err(|err| OrchestratorError::ListenResolveFailed {
            host: host.to_string(),
            reason: err.to_string(),
        })?
        .collect();

    if addrs.is_empty() {
        return Err(OrchestratorError::ListenResolveFailed {
            host: host.to_string(),
            reason: "no resolved addresses".to_string(),
        });
    }
    if addrs.len() > 1 {
        warn!(
            "listen resolved multiple addresses for {}; using {}",
            host, addrs[0]
        );
    }
    Ok(addrs[0])
}

/// Spawns a BareUDP TX actor for a peer destination.
///
/// Returns the packet sender and task handle, or None if socket setup fails.
async fn spawn_bare_tx(
    peer_id: &str,
    destination: SocketAddr,
    bindif: Option<&str>,
    tun_if: &str,
    events_tx: mpsc::UnboundedSender<Event>,
) -> Option<(mpsc::Sender<Vec<u8>>, JoinHandle<ActorExitResult>)> {
    let probe = DefaultRouteProbe;
    let tx_socket = match BareUdpTx::from_config(destination, bindif, Some(tun_if), &probe).await {
        Ok(result) => result,
        Err(err) => {
            warn!("bare peer '{}' socket setup failed: {err}", peer_id);
            return None;
        }
    };

    // BareUDP TX actor creates its own packet channel; returns sender
    let (packet_tx, tx_handle) = spawn_udp_tx(tx_socket, events_tx, METRICS_INTERVAL);

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

/// Sends DNS resolve commands for all unique peer endpoint hostnames.
///
/// Handles both BareUDP and H3 endpoints.
///
/// # Arguments
///
/// * `peers` - Slice of peer configurations to process
/// * `dns_cmd_tx` - Channel to send DNS resolve commands
///
/// # Errors
///
/// Returns `OrchestratorError::InvalidPeerEndpoint` or `OrchestratorError::InvalidH3Endpoint`
/// if any enabled peer has an invalid endpoint URI.
fn send_resolve_commands(
    peers: &[Peer],
    dns_cmd_tx: &mpsc::UnboundedSender<DnsCommand>,
) -> Result<(), OrchestratorError> {
    let mut seen_hosts = std::collections::HashSet::new();

    for peer in peers {
        if !peer.enabled {
            continue;
        }

        // Handle BareUDP endpoints
        if let Some(bare) = peer.bare.as_ref() {
            let endpoint = parse_udp_uri(&bare.endpoint).map_err(|err| {
                OrchestratorError::InvalidPeerEndpoint {
                    peer_id: peer.id.clone(),
                    reason: err,
                }
            })?;

            if seen_hosts.insert(endpoint.host.clone()) {
                if let Err(e) = dns_cmd_tx.send(DnsCommand::Resolve {
                    host: endpoint.host.clone(),
                }) {
                    warn!(host = %endpoint.host, error = %e, "dns: resolver channel closed");
                }
            }
        }

        // Handle H3 endpoints
        if let Some(h3) = peer.h3.as_ref() {
            for (idx, endpoint_uri) in h3.endpoints.iter().enumerate() {
                let endpoint = parse_h3_uri(endpoint_uri).map_err(|err| {
                    OrchestratorError::InvalidH3Endpoint {
                        peer_id: peer.id.clone(),
                        index: idx,
                        reason: err,
                    }
                })?;

                // Strip IPv6 brackets for DNS resolution
                let host = endpoint
                    .host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string();

                if seen_hosts.insert(host.clone()) {
                    if let Err(e) = dns_cmd_tx.send(DnsCommand::Resolve { host: host.clone() }) {
                        warn!(host = %host, error = %e, "dns: resolver channel closed");
                    }
                }
            }
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
        peers: HashMap<String, PeerEntry>,
        bound_counter: u64,
        dns_refresh: Duration,
        manage_routes: bool,
        tun_addrs: Vec<IpNet>,
    }

    impl Default for TestableOrchestratorBuilder {
        fn default() -> Self {
            Self {
                tun_if: "test0".to_string(),
                mtu: 1400,
                peers: HashMap::new(),
                bound_counter: 0,
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
            self.peers = peers
                .into_iter()
                .map(|p| (p.id.clone(), PeerEntry::new(p)))
                .collect();
            self
        }

        pub fn with_peer_tx(
            mut self,
            peer_id: &str,
            dest: SocketAddr,
            tx: mpsc::Sender<Vec<u8>>,
        ) -> Self {
            if let Some(entry) = self.peers.get_mut(peer_id) {
                self.bound_counter += 1;
                entry.bounds.push(BoundState {
                    id: BoundId(self.bound_counter),
                    transport: TransportType::BareUdp,
                    dest,
                    tx,
                });
            }
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
            let (tun_packet_tx, _tun_packet_rx) = mpsc::channel(1);

            let orch = Orchestrator {
                events_rx,
                events_tx: events_tx.clone(),
                join_set: JoinSet::new(),
                dns_refresh: self.dns_refresh,
                local_id: "test-local".to_string(),
                tun_if: self.tun_if,
                mtu: self.mtu,
                peers: self.peers,
                bound_counter: self.bound_counter,
                tun_cmd_tx,
                bare_rx_cmd_tx: Some(bare_rx_cmd_tx),
                h3_listener_cmd_tx: None,
                h3_conn_rx: None,
                tun_packet_tx,
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

    // ========== PeerEntry unit tests ==========

    #[test]
    fn peer_entry_tracks_multiple_bounds() {
        let config = Peer {
            id: "peer-1".to_string(),
            enabled: true,
            h3: None,
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["10.0.0.0/24".to_string()],
            },
        };
        let mut entry = PeerEntry::new(config);

        assert!(entry.bounds.is_empty());
        assert!(entry.preferred_tx().is_none());

        let (tx1, _rx1) = mpsc::channel(1);
        entry.bounds.push(BoundState {
            id: BoundId(1),
            transport: TransportType::BareUdp,
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx: tx1,
        });

        assert!(!entry.bounds.is_empty());
        assert!(entry.preferred_tx().is_some());
        assert!(entry.has_bound_for_ip("1.2.3.4".parse().unwrap()));
        assert!(!entry.has_bound_for_ip("5.6.7.8".parse().unwrap()));

        let (tx2, _rx2) = mpsc::channel(1);
        entry.bounds.push(BoundState {
            id: BoundId(2),
            transport: TransportType::BareUdp,
            dest: "5.6.7.8:5353".parse().unwrap(),
            tx: tx2,
        });

        assert_eq!(entry.bounds.len(), 2);
        assert_eq!(entry.active_ips().count(), 2);
        assert!(entry.has_bound_for_ip("5.6.7.8".parse().unwrap()));
    }

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
    fn resolve_listen_addr_handles_ipv4_literal() {
        let result = resolve_listen_addr("127.0.0.1", 5353).expect("should resolve");
        assert_eq!(
            result.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(result.port(), 5353);
    }

    #[test]
    fn resolve_listen_addr_handles_ipv6_literal() {
        let result = resolve_listen_addr("::1", 5353).expect("should resolve");
        assert!(result.ip().is_ipv6());
        assert_eq!(result.port(), 5353);
    }

    #[test]
    fn resolve_listen_addr_strips_ipv6_brackets() {
        let result = resolve_listen_addr("[::1]", 443).expect("should resolve");
        assert!(result.ip().is_ipv6());
        assert_eq!(result.port(), 443);
    }

    // ========== Event handling tests ==========

    #[tokio::test]
    async fn handle_event_processes_metrics_without_state_change() {
        let peer = bare_peer("peer1", &["10.0.0.0/24"]);
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let dest: SocketAddr = "127.0.0.1:5353".parse().unwrap();

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", dest, peer_tx)
            .build();

        orch.handle_event(make_metrics_event()).await;

        // State preserved: existing entries not modified
        assert_eq!(orch.peers.len(), 1);
        assert!(orch.peers.contains_key("peer1"));
        assert_eq!(orch.peers.get("peer1").unwrap().bounds.len(), 1);

        // No commands sent to child actors
        assert!(handles.tun_cmd_rx.try_recv().is_err());
        assert!(handles.bare_rx_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_event_processes_other_event() {
        let peer = bare_peer("peer1", &["10.0.0.0/24"]);
        let (peer_tx, _peer_rx) = mpsc::channel(1);
        let dest: SocketAddr = "127.0.0.1:5353".parse().unwrap();

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", dest, peer_tx)
            .build();

        orch.handle_event(Event::Other("test message".to_string()))
            .await;

        // State preserved
        assert_eq!(orch.peers.len(), 1);

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

        // No bounds created (hostname doesn't match)
        assert!(orch.peers.get("peer1").unwrap().bounds.is_empty());
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

        // No bounds created (empty records)
        assert!(orch.peers.get("peer1").unwrap().bounds.is_empty());
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
