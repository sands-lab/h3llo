//! Runtime orchestration for BareUDP and HTTP/3 transports.

use crate::actor::{ActorError, ActorExitResult, ActorKind};
use crate::api::MetricsStore;
use crate::bare::{make_bare_rx, make_bare_tx, spawn_udp_rx, spawn_udp_tx, BareUdpRxCommand};
use crate::bind::DefaultRouteProbe;
use crate::config::{validate_peers, Config, ConfigError, Local, Peer, Tuning};
use crate::dns::{make_dns, spawn_dns, DnsCommand};
use crate::events::ApiEvent;
use crate::events::{
    BareConnectedEvent, ConnectionDirection, DnsEvent, Endpoint, Event, H3ConnectedEvent,
    TransportEvent,
};
use crate::h3::{
    dial_h3, make_h3_listener, spawn_h3_listener, spawn_h3_rx, spawn_h3_tx, H3ListenerCommand,
};
use crate::route::{make_route, spawn_route, RouteCommand};
use crate::tun::{self, RoutingTable, TunRxCommand};
use ipnet::IpNet;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Instant;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_quiche::buf_factory::PooledBuf;
use tracing::{debug, error, info, warn};

/// A single active connection bound to a peer.
#[derive(Debug)]
struct BoundState {
    /// Unique identifier for detecting changes in preferred TX.
    id: u64,
    /// Configured endpoint that originated this connection.
    ///
    /// `None` for listener-originated (inbound) connections.
    endpoint: Option<Endpoint>,
    /// Destination socket address.
    dest: SocketAddr,
    /// TX channel for sending packet batches.
    tx: mpsc::Sender<Vec<PooledBuf>>,
}

/// Entry for a single peer in the unified pool.
#[derive(Debug)]
struct PeerEntry {
    /// Peer configuration (read-only after creation).
    config: Peer,
    /// Active connections for this peer, ordered by preference (first = preferred TX).
    bounds: Vec<BoundState>,
    /// Current DNS-resolved IPs for this peer's endpoint.
    resolved_ips: HashSet<IpAddr>,
    /// Last time `try_connect` actually spawned connections.
    last_try_connect: Option<Instant>,
    /// Monotonic counter for assigning unique bound IDs.
    next_bound_id: u64,
}

impl PeerEntry {
    /// Creates a new peer entry from configuration.
    fn new(config: Peer) -> Self {
        Self {
            config,
            bounds: Vec::new(),
            resolved_ips: HashSet::new(),
            last_try_connect: None,
            next_bound_id: 0,
        }
    }

    /// Returns the preferred TX channel (first bound) or `None` if no active connections.
    fn preferred_tx(&self) -> Option<&mpsc::Sender<Vec<PooledBuf>>> {
        self.bounds.first().map(|b| &b.tx)
    }

    /// Appends a new bound with an auto-assigned unique ID.
    fn push_bound(
        &mut self,
        endpoint: Option<Endpoint>,
        dest: SocketAddr,
        tx: mpsc::Sender<Vec<PooledBuf>>,
    ) {
        let id = self.next_bound_id;
        self.next_bound_id += 1;
        self.bounds.push(BoundState {
            id,
            endpoint,
            dest,
            tx,
        });
    }

    /// Returns the current config endpoint as an `Endpoint` enum, if configured.
    fn config_endpoint(&self) -> Option<Endpoint> {
        if let Some(bare) = &self.config.bare {
            Some(Endpoint::Udp(bare.endpoint.clone()))
        } else if let Some(h3) = &self.config.h3 {
            h3.endpoint.as_ref().map(|ep| Endpoint::H3(ep.clone()))
        } else {
            None
        }
    }

    /// Removes invalid bounds and returns whether the first (preferred) TX changed.
    ///
    /// A bound is invalid if:
    /// - Its TX channel is closed (actor exited).
    /// - Its endpoint is `Some` but differs from the current config endpoint (reconfig).
    /// - Its endpoint is `Some` and its dest IP is not in `resolved_ips` (DNS changed).
    fn prune(&mut self) -> bool {
        let old_first_id = self.bounds.first().map(|b| b.id);
        let config_ep = self.config_endpoint();

        self.bounds.retain(|bound| {
            // TX channel closed -> remove
            if bound.tx.is_closed() {
                debug!(dest = %bound.dest, "pruned: tx channel closed");
                return false;
            }
            // Only check endpoint-based invalidation for outbound connections
            if let Some(ref bound_ep) = bound.endpoint {
                // Endpoint changed (dynamic reconfig)
                if config_ep.as_ref() != Some(bound_ep) {
                    debug!(dest = %bound.dest, "pruned: endpoint changed");
                    return false;
                }
                // Dest IP no longer in resolved_ips (DNS changed)
                if !self.resolved_ips.contains(&bound.dest.ip()) {
                    debug!(dest = %bound.dest, "pruned: IP no longer in DNS");
                    return false;
                }
            }
            true
        });

        old_first_id != self.bounds.first().map(|b| b.id)
    }

    /// Spawns connections for resolved IPs not already covered by an existing bound.
    ///
    /// Rate-limited: only attempts if `tuning.reconnect_interval` has elapsed since last attempt.
    /// Does nothing if `resolved_ips` is empty. Only updates `last_try_connect` when at
    /// least one connection task is actually spawned.
    fn try_connect(
        &mut self,
        events_tx: &mpsc::UnboundedSender<Event>,
        tun_if: &str,
        mtu: usize,
        tuning: &Tuning,
    ) {
        // Rate limit
        if let Some(last) = self.last_try_connect {
            if last.elapsed() < tuning.reconnect_interval {
                return;
            }
        }

        if self.resolved_ips.is_empty() {
            return;
        }

        // Collect IPs already covered by existing bounds
        let covered_ips: HashSet<IpAddr> = self.bounds.iter().map(|b| b.dest.ip()).collect();

        // Determine which IPs need connections
        let uncovered: Vec<IpAddr> = self
            .resolved_ips
            .difference(&covered_ips)
            .copied()
            .collect();

        if uncovered.is_empty() {
            return;
        }

        self.last_try_connect = Some(Instant::now());

        if let Some(bare) = self.config.bare.as_ref() {
            let port = bare.endpoint.port;

            for ip in &uncovered {
                let destination = SocketAddr::new(*ip, port);
                let events_tx = events_tx.clone();
                let tun_if = tun_if.to_string();
                let peer_id = self.config.id.clone();
                let bindif = bare.bindif.clone();
                let endpoint = Endpoint::Udp(bare.endpoint.clone());
                let metrics_interval = tuning.metrics_push_interval;
                let packet_queue_depth = tuning.packet_queue_depth;
                let socket_buffer_bytes = tuning.socket_buffer_bytes();

                tokio::spawn(async move {
                    let probe = DefaultRouteProbe;
                    match make_bare_tx(
                        destination,
                        bindif.as_deref(),
                        Some(&tun_if),
                        &probe,
                        socket_buffer_bytes,
                    )
                    .await
                    {
                        Ok(tx_socket) => {
                            let (packet_tx, tx_handle) = spawn_udp_tx(
                                tx_socket,
                                events_tx.clone(),
                                metrics_interval,
                                packet_queue_depth,
                            );
                            let event = Event::Transport(TransportEvent::BareConnected(
                                BareConnectedEvent {
                                    peer_id,
                                    endpoint,
                                    dest: destination,
                                    tx: packet_tx,
                                    tx_handle,
                                },
                            ));
                            let _ = events_tx.send(event);
                        }
                        Err(err) => {
                            warn!(peer = %peer_id, error = %err, "bare tx socket setup failed");
                        }
                    }
                });
            }
        } else if let Some(h3) = self.config.h3.as_ref() {
            let Some(h3_endpoint) = h3.endpoint.as_ref() else {
                return;
            };
            let port = h3_endpoint.port;
            let tun_mtu = mtu as u16;

            for ip in &uncovered {
                let destination = SocketAddr::new(*ip, port);
                let events_tx = events_tx.clone();
                let tun_if = tun_if.to_string();
                let peer_id = self.config.id.clone();
                let peer_h3 = h3.clone();
                let tuning = tuning.clone();

                tokio::spawn(async move {
                    let probe = DefaultRouteProbe;
                    match dial_h3(
                        &peer_h3,
                        destination,
                        &peer_id,
                        Some(&tun_if),
                        tun_mtu,
                        &probe,
                        &tuning,
                    )
                    .await
                    {
                        Ok(conn) => {
                            debug!(peer = %peer_id, addr = %destination, "H3 connection established");
                            let event =
                                Event::Transport(TransportEvent::H3Connected(H3ConnectedEvent {
                                    connection: conn,
                                    direction: ConnectionDirection::Outbound,
                                }));
                            let _ = events_tx.send(event);
                        }
                        Err(e) => {
                            warn!(peer = %peer_id, addr = %destination, error = %e, "H3 dial failed");
                        }
                    }
                });
            }
        }
    }
}

/// Returns the DNS hostname for a peer's configured endpoint, if any.
///
/// Extracts the hostname from BareUDP or H3 endpoint configuration,
/// stripping IPv6 brackets from H3 hosts.
fn peer_dns_hostname(peer: &Peer) -> Option<&str> {
    if let Some(bare) = &peer.bare {
        Some(&bare.endpoint.host)
    } else if let Some(h3) = &peer.h3 {
        h3.endpoint.as_ref().map(|ep| strip_ipv6_brackets(&ep.host))
    } else {
        None
    }
}

/// Errors returned by the orchestrator.
#[derive(Debug, Error)]
pub enum OrchestratorError {
    /// BareUDP listen host could not be resolved.
    #[error("failed to resolve bare listen host '{host}': {reason}")]
    ListenResolveFailed { host: String, reason: String },
    /// HTTP/3 listener failed to start.
    #[error("h3 listener failed: {0}")]
    H3Listener(String),
    /// HTTP/3 dial failed.
    #[error("h3 dial to '{peer_id}' failed: {reason}")]
    H3Dial { peer_id: String, reason: String },
    /// Management API failed to initialize.
    #[error("api server failed to start: {0}")]
    ApiInit(String),
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
/// - Peer actors (BareUDP-Tx, H3-Tx/Rx): failure triggers maintenance cycle (prune + reconnect)
pub struct Orchestrator {
    events_rx: mpsc::UnboundedReceiver<Event>,
    events_tx: mpsc::UnboundedSender<Event>,
    join_set: JoinSet<Result<ActorExitResult, tokio::task::JoinError>>,

    // Runtime state
    tun_if: String,
    mtu: usize,
    /// Tuning parameters from config.
    tuning: Tuning,
    /// Unified peer state: config + active bound.
    peers: HashMap<String, PeerEntry>,
    tun_cmd_tx: mpsc::UnboundedSender<TunRxCommand>,
    bare_rx_cmd_tx: Option<mpsc::UnboundedSender<BareUdpRxCommand>>,
    /// H3 listener command sender (if listening).
    #[allow(dead_code)]
    h3_listener_cmd_tx: Option<mpsc::UnboundedSender<H3ListenerCommand>>,
    /// Packet sender to TUN TX (for H3 RX actors).
    tun_packet_tx: mpsc::Sender<Vec<PooledBuf>>,

    /// DNS resolver command sender for SetHostnames.
    dns_cmd_tx: mpsc::UnboundedSender<DnsCommand>,

    /// Route sync actor command sender (None when `local.table` is false or init failed).
    route_cmd_tx: Option<mpsc::UnboundedSender<RouteCommand>>,
    /// TUN interface addresses for route sync commands.
    tun_addrs: Vec<IpNet>,
    /// Stored local config for GET /config snapshot reconstruction.
    local: Local,

    /// Metrics store shared with the prometheus-client Collector.
    metrics_store: MetricsStore,
    /// Prometheus registry with registered collector for /metrics rendering.
    metrics_registry: Registry,
}

impl Orchestrator {
    /// Updates BareUDP RX accepted source filter.
    ///
    /// Sends the new set of accepted source IPs to the BareUDP RX actor.
    /// No-op when BareUDP is not configured (`bare_rx_cmd_tx` is `None`).
    fn update_accepted_sources(&self) {
        if let Some(cmd_tx) = &self.bare_rx_cmd_tx {
            let accepted_ips: HashSet<IpAddr> = self
                .peers
                .values()
                .filter(|e| e.config.bare.is_some())
                .flat_map(|e| e.resolved_ips.iter().copied())
                .collect();
            if let Err(e) = cmd_tx.send(BareUdpRxCommand::UpdateAcceptedSources(accepted_ips)) {
                warn!(error = %e, "failed to send accepted sources update command");
            }
        }
    }

    /// Updates internal routing table and system routes.
    ///
    /// Performs the routing update sequence:
    /// 1. TUN routing table (internal forwarding)
    /// 2. System routes via route actor (if available)
    fn update_routing(&self) {
        let peer_configs = self.peer_configs();
        let peer_txs: HashMap<String, mpsc::Sender<Vec<PooledBuf>>> = self
            .peers
            .iter()
            .filter_map(|(id, e)| e.preferred_tx().map(|tx| (id.clone(), tx.clone())))
            .collect();
        if let Ok(routing) = RoutingTable::from_peers(&peer_configs, &peer_txs) {
            if let Err(e) = self
                .tun_cmd_tx
                .send(TunRxCommand::UpdateRouting { routing })
            {
                warn!(error = %e, "failed to send routing update command");
            }
        }

        if let Some(route_cmd_tx) = &self.route_cmd_tx {
            let allowed = collect_allowed_ips(&peer_configs);
            if let Err(e) = route_cmd_tx.send(RouteCommand::SyncRoutes {
                tun_addrs: self.tun_addrs.clone(),
                allowed,
            }) {
                warn!(error = %e, "failed to send route sync command");
            }
        }
    }

    /// Returns peer configurations as a Vec (for routing table and route sync).
    fn peer_configs(&self) -> Vec<Peer> {
        self.peers.values().map(|e| e.config.clone()).collect()
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
        let tuning = &config.tuning;
        let tun_if = config.local.tun.ifname.clone();
        let mtu = config.local.tun.mtu as usize;
        let manage_routes = config.local.table;
        let tun_addrs = config.local.tun.addrs.clone();

        // Note: NoTransportConfigured validation moved to Config::validate()

        // Setup TUN
        let (tun_reader, tun_writer) = tun::make_tun(&config.local.tun)
            .await
            .map_err(|err| OrchestratorError::Tun(err.to_string()))?;

        // Control plane: unbounded to prevent deadlocks from actor cycles.
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        let mut join_set = JoinSet::new();

        // Start with empty routing table; routes populated as DNS answers arrive
        let routing = RoutingTable::new();

        // Spawn TUN actors - actors create their own command channels
        let (tun_cmd_tx, tun_rx_handle) = tun::spawn_tun_rx(
            tun_reader,
            routing,
            events_tx.clone(),
            tuning.metrics_push_interval,
        );
        // TUN-Tx actor creates its own packet channel; returns sender for transports to use
        let (tun_packet_tx, tun_tx_handle) = tun::spawn_tun_tx(
            tun_writer,
            events_tx.clone(),
            tuning.metrics_push_interval,
            tuning.packet_queue_depth,
        );

        join_set.spawn(tun_rx_handle);
        join_set.spawn(tun_tx_handle);

        // Initialize BareUDP listener if configured
        let bare_rx_cmd_tx = if let Some(ref local_bare) = config.local.bare {
            // Endpoint already parsed during config deserialization
            let listen_addr = resolve_listen_addr(&local_bare.listen.host, local_bare.listen.port)?;

            let bare_rx = make_bare_rx(listen_addr, mtu, tuning.socket_buffer_bytes())
                .map_err(|err| OrchestratorError::Udp(err.to_string()))?;

            let (cmd_tx, bare_rx_handle) = spawn_udp_rx(
                bare_rx,
                std::collections::HashSet::new(),
                tun_packet_tx.clone(),
                events_tx.clone(),
                tuning.metrics_push_interval,
            );

            join_set.spawn(bare_rx_handle);
            Some(cmd_tx)
        } else {
            None
        };

        // Initialize H3 listener if configured
        let h3_listener_cmd_tx = if let Some(ref h3_cfg) = config.local.h3 {
            let listen_addr = resolve_listen_addr(&h3_cfg.listen.host, h3_cfg.listen.port)?;
            let cert_path = Path::new(&h3_cfg.cert);
            let key_path = Path::new(&h3_cfg.key);

            // Build peer tokens map for authentication
            let peer_tokens: HashMap<String, String> = config
                .peers
                .iter()
                .filter_map(|p| p.h3.as_ref().map(|h3| (p.id.clone(), h3.token.clone())))
                .collect();

            // make: fallible I/O (socket bind, TLS config)
            let listener = make_h3_listener(
                listen_addr,
                cert_path,
                key_path,
                tuning.socket_buffer_bytes(),
            )
            .map_err(|e| OrchestratorError::H3Listener(e.to_string()))?;

            // spawn: infallible task creation; listener sends events through events_tx
            let (cmd_tx, listener_handle, _bound_addr) = spawn_h3_listener(
                listener,
                peer_tokens,
                config.local.tun.mtu,
                events_tx.clone(),
                tuning,
            );

            join_set.spawn(listener_handle);
            Some(cmd_tx)
        } else {
            None
        };

        // Initialize unified peer state from config
        let peers: HashMap<String, PeerEntry> = config
            .peers
            .iter()
            .map(|p| (p.id.clone(), PeerEntry::new(p.clone())))
            .collect();

        // Create DNS actor state (performs fallible socket binding)
        let probe = DefaultRouteProbe;
        let dns_actor = make_dns(&config.local.dns, Some(tun_if.as_str()), tuning, &probe)
            .await
            .map_err(|err| OrchestratorError::DnsInit(err.to_string()))?;

        // Spawn DNS actor task (infallible)
        let (dns_cmd_tx, handle) = spawn_dns(dns_actor, events_tx.clone());

        join_set.spawn(handle);

        // Initialize route sync actor if system route management is enabled.
        // Soft failure: if make_route() fails (e.g., no netlink on BSD), warn and continue.
        let route_cmd_tx = if manage_routes {
            match make_route() {
                Ok(route_actor) => {
                    let (cmd_tx, route_handle) = spawn_route(route_actor, tun_if.clone());
                    join_set.spawn(route_handle);
                    Some(cmd_tx)
                }
                Err(err) => {
                    warn!(error = %err, "route manager unavailable, system routes will not be managed");
                    None
                }
            }
        } else {
            None
        };

        if peers.is_empty() {
            warn!("no active peers; traffic will be dropped");
        }

        // Initialize management API if configured
        if let Some(ref local_api) = config.local.api {
            let api_listen_addr =
                resolve_listen_addr(&local_api.listen.host, local_api.listen.port)?;
            let api_listener = crate::api::make_api(api_listen_addr)
                .await
                .map_err(|e| OrchestratorError::ApiInit(e.to_string()))?;
            let api_handle = crate::api::spawn_api(
                api_listener,
                local_api.listen.path.clone(),
                events_tx.clone(),
            );
            join_set.spawn(api_handle);
        }

        let metrics_store = MetricsStore::new();
        let mut metrics_registry = Registry::default();
        metrics_registry.register_collector(Box::new(metrics_store.clone()));

        let mut orch = Self {
            events_rx,
            events_tx,
            join_set,
            tun_if,
            mtu,
            tuning: config.tuning,
            peers,
            tun_cmd_tx,
            bare_rx_cmd_tx,
            h3_listener_cmd_tx,
            tun_packet_tx,
            dns_cmd_tx,
            route_cmd_tx,
            tun_addrs,
            local: config.local,
            metrics_store,
            metrics_registry,
        };
        orch.sync_dns_hostnames();
        Ok(orch)
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
        // Run maintenance at half the connect interval so closed channels and
        // newly resolved IPs are detected promptly.
        let mut maintenance_ticker = tokio::time::interval(self.tuning.reconnect_interval / 2);
        loop {
            tokio::select! {
                Some(event) = self.events_rx.recv() => {
                    self.handle_event(event).await;
                }
                _ = maintenance_ticker.tick() => {
                    self.run_maintenance();
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
                                    warn!("peer actor failed: {}", actor_error);
                                    self.run_maintenance();
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

    /// Periodic maintenance: prune stale bounds and attempt reconnection.
    fn run_maintenance(&mut self) {
        let mut routing_changed = false;
        for entry in self.peers.values_mut() {
            if entry.prune() {
                routing_changed = true;
            }
            entry.try_connect(&self.events_tx, &self.tun_if, self.mtu, &self.tuning);
        }
        if routing_changed {
            self.update_routing();
        }
    }

    /// Handles management API events.
    fn handle_api_event(&mut self, event: ApiEvent) {
        match event {
            ApiEvent::GetConfig { reply_tx } => {
                let _ = reply_tx.send(self.config_snapshot());
            }
            ApiEvent::PostConfig { peers, reply_tx } => {
                let result = self
                    .handle_post_config(peers)
                    .map(|()| self.config_snapshot());
                let _ = reply_tx.send(result);
            }
            ApiEvent::DeleteConfig { peer_ids, reply_tx } => {
                self.handle_delete_config(&peer_ids);
                let _ = reply_tx.send(Ok(self.config_snapshot()));
            }
            ApiEvent::GetMetrics { reply_tx } => {
                let mut text = String::new();
                prometheus_client::encoding::text::encode(&mut text, &self.metrics_registry)
                    .expect("infallible: encoding to String cannot fail");
                let _ = reply_tx.send(text);
            }
        }
    }

    /// Builds a full Config snapshot from current orchestrator state.
    ///
    /// Reused by GET, POST, and DELETE API handlers for consistent responses.
    fn config_snapshot(&self) -> Config {
        Config {
            local: self.local.clone(),
            tuning: self.tuning.clone(),
            peers: self.peer_configs(),
        }
    }

    /// Sends updated hostname set to the DNS resolver after peer mutations.
    ///
    /// The DNS resolver will re-resolve and emit a snapshot, which triggers
    /// routing and accepted-source updates in [`handle_dns_snapshot`].
    fn sync_dns_hostnames(&mut self) {
        let peer_configs = self.peer_configs();
        let hostnames = collect_hostnames(&peer_configs);
        let _ = self
            .dns_cmd_tx
            .send(DnsCommand::SetHostnames { hosts: hostnames });
    }

    /// Handles POST /config — upsert peers with orchestrator-side validation.
    fn handle_post_config(&mut self, new_peers: Vec<Peer>) -> Result<(), String> {
        // Build merged peer map for validation (borrow-based, O(n+m)).
        let mut merged: HashMap<&str, &Peer> = self
            .peers
            .iter()
            .map(|(id, entry)| (id.as_str(), &entry.config))
            .collect();
        for peer in &new_peers {
            merged.insert(&peer.id, peer);
        }
        let merged_vec: Vec<Peer> = merged.into_values().cloned().collect();
        validate_peers(&merged_vec).map_err(|e| ConfigError::Validation(e).to_string())?;

        let count = new_peers.len();
        for peer in new_peers {
            let id = peer.id.clone();
            if let Some(existing) = self.peers.get_mut(&id) {
                existing.config = peer;
            } else {
                self.peers.insert(id, PeerEntry::new(peer));
            }
        }

        self.sync_dns_hostnames();
        info!(count = count, "API: peers upserted");
        Ok(())
    }

    /// Handles DELETE /config — remove peers by ID.
    fn handle_delete_config(&mut self, peer_ids: &[String]) {
        let mut changed = false;
        for id in peer_ids {
            if self.peers.remove(id).is_some() {
                changed = true;
                debug!(peer = %id, "API: peer removed");
            }
        }
        if changed {
            self.sync_dns_hostnames();
        }
    }

    /// Handles an event from a child actor.
    async fn handle_event(&mut self, event: Event) {
        match event {
            Event::Dns(dns_event) => {
                self.handle_dns_snapshot(dns_event);
            }
            Event::Api(api_event) => {
                self.handle_api_event(api_event);
            }
            Event::Transport(TransportEvent::Metrics(metrics)) => {
                let labels = &metrics.labels;
                let stats = &metrics.stats;
                debug!(
                    "{:?} {:?} {}: {} batches/{} pkts/{} bytes ok, {} batches/{} pkts/{} bytes dropped",
                    labels.kind,
                    labels.direction,
                    labels.peer_id.as_deref().unwrap_or("local"),
                    stats.succeeded.batches,
                    stats.succeeded.packets,
                    stats.succeeded.bytes,
                    stats.dropped.batches,
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
                self.metrics_store.update(metrics);
            }
            Event::Transport(TransportEvent::H3Connected(event)) => {
                self.handle_h3_connection(event).await;
            }
            Event::Transport(TransportEvent::BareConnected(event)) => {
                self.handle_bare_connection(event);
            }
            Event::Other(msg) => {
                debug!("other event: {}", msg);
            }
        }
    }

    /// Handles a DNS state snapshot: update resolved IPs, prune stale bounds, try reconnect.
    ///
    /// Always rebuilds routing and accepted sources, since this is the
    /// authoritative point where peer connectivity state is reconciled
    /// after DNS changes or peer mutations (add/remove via API).
    fn handle_dns_snapshot(&mut self, dns_event: DnsEvent) {
        let dns_state = dns_event.state;

        for entry in self.peers.values_mut() {
            let hostname = peer_dns_hostname(&entry.config);
            entry.resolved_ips = hostname
                .and_then(|h| dns_state.get(h))
                .cloned()
                .unwrap_or_default();

            entry.prune();
            entry.try_connect(&self.events_tx, &self.tun_if, self.mtu, &self.tuning);
        }

        self.update_accepted_sources();
        self.update_routing();
    }

    /// Registers a bound connection for a peer.
    ///
    /// Appends to the end of the bounds Vec, then prunes.
    /// Updates routing if this is the first bound or if prune changed the first TX.
    fn update_bound(
        &mut self,
        peer_id: &str,
        endpoint: Option<Endpoint>,
        dest: SocketAddr,
        tx: mpsc::Sender<Vec<PooledBuf>>,
    ) {
        let Some(entry) = self.peers.get_mut(peer_id) else {
            warn!(peer = %peer_id, addr = %dest, "connection for unknown peer");
            return;
        };
        let was_empty = entry.bounds.is_empty();
        entry.push_bound(endpoint, dest, tx);
        let first_changed = entry.prune();
        if was_empty || first_changed {
            self.update_routing();
        }
    }

    /// Handles a BareUDP TX connection event.
    ///
    /// Unconditionally registers the TX actor JoinHandle for lifecycle
    /// monitoring, then attempts to bind the peer via [`update_bound`].
    fn handle_bare_connection(&mut self, event: BareConnectedEvent) {
        let BareConnectedEvent {
            peer_id,
            endpoint,
            dest,
            tx,
            tx_handle,
        } = event;
        // Always register: actor is already running, must be supervised
        self.join_set.spawn(tx_handle);
        self.update_bound(&peer_id, Some(endpoint), dest, tx);
    }

    /// Handles an H3 connection event (inbound or outbound).
    ///
    /// Unified handler for both listener and dialer connections.
    /// Spawns RX/TX actors and updates routing via [`update_bound`].
    async fn handle_h3_connection(&mut self, event: H3ConnectedEvent) {
        let H3ConnectedEvent {
            connection: conn,
            direction,
        } = event;
        let peer_id = conn.peer_id.clone();
        let remote_addr = conn.remote_addr;

        // Pre-check before destructive conn.into_actors(): peer must exist
        if !self.peers.contains_key(&peer_id) {
            warn!(
                peer = %peer_id,
                addr = %remote_addr,
                direction = ?direction,
                "H3 connection from unknown peer"
            );
            return;
        }

        // Extract endpoint for outbound connections; inbound has None (listener-originated).
        let endpoint = match direction {
            ConnectionDirection::Outbound => self
                .peers
                .get(&peer_id)
                .unwrap()
                .config
                .h3
                .as_ref()
                .and_then(|h3| h3.endpoint.as_ref())
                .map(|ep| Endpoint::H3(ep.clone())),
            ConnectionDirection::Inbound => None,
        };

        debug!(
            peer = %peer_id,
            addr = %remote_addr,
            direction = ?direction,
            "H3 connection accepted"
        );

        // Split connection into actor states
        let (rx_state, tx_state) = conn.into_actors();

        // Spawn RX actor
        let rx_handle = spawn_h3_rx(
            rx_state,
            self.tun_packet_tx.clone(),
            self.events_tx.clone(),
            self.tuning.metrics_push_interval,
        );

        // Spawn TX actor
        let (packet_tx, tx_handle) = spawn_h3_tx(
            tx_state,
            self.events_tx.clone(),
            self.tuning.metrics_push_interval,
            self.tuning.packet_queue_depth,
            self.tuning.h3_keepalive_interval,
        );

        self.join_set.spawn(rx_handle);
        self.join_set.spawn(tx_handle);
        self.update_bound(&peer_id, endpoint, remote_addr, packet_tx);
    }
}

fn strip_ipv6_brackets(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

/// Resolves a listen address from host and port, using synchronous DNS lookup for hostnames.
///
/// Handles IPv6 bracket notation (e.g., "[::1]" -> "::1") for compatibility with
/// both UDP and H3 endpoint formats.
fn resolve_listen_addr(host: &str, port: u16) -> Result<SocketAddr, OrchestratorError> {
    // Strip IPv6 bracket notation (safe no-op for non-bracketed hosts)
    let host = strip_ipv6_brackets(host);

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

fn collect_allowed_ips(peers: &[Peer]) -> Vec<IpNet> {
    peers
        .iter()
        .flat_map(|peer| peer.tun.allowed_ips.iter().copied())
        .collect()
}

/// Collects all unique hostnames from peer configurations.
///
/// Handles both BareUDP and H3 endpoints. Endpoints are pre-parsed during
/// config deserialization, so this function cannot fail.
fn collect_hostnames(peers: &[Peer]) -> HashSet<String> {
    let mut hosts = HashSet::new();
    for peer in peers {
        if let Some(h) = peer_dns_hostname(peer) {
            hosts.insert(h.to_string());
        }
    }
    hosts
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
        tun_addrs: Vec<IpNet>,
        local: Option<crate::config::Local>,
    }

    impl Default for TestableOrchestratorBuilder {
        fn default() -> Self {
            Self {
                tun_if: "test0".to_string(),
                mtu: crate::config::default_mtu() as usize,
                peers: HashMap::new(),
                tun_addrs: Vec::new(),
                local: None,
            }
        }
    }

    /// Test handles for verifying commands sent by the orchestrator.
    #[allow(dead_code)]
    pub struct TestHandles {
        pub events_tx: mpsc::UnboundedSender<Event>,
        pub tun_cmd_rx: mpsc::UnboundedReceiver<TunRxCommand>,
        pub bare_rx_cmd_rx: mpsc::UnboundedReceiver<BareUdpRxCommand>,
        pub dns_cmd_rx: mpsc::UnboundedReceiver<DnsCommand>,
        pub route_cmd_rx: mpsc::UnboundedReceiver<RouteCommand>,
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
            tx: mpsc::Sender<Vec<PooledBuf>>,
        ) -> Self {
            if let Some(entry) = self.peers.get_mut(peer_id) {
                let endpoint = entry.config_endpoint();
                entry.push_bound(endpoint, dest, tx);
            }
            self
        }

        pub fn with_resolved_ips(mut self, peer_id: &str, ips: HashSet<IpAddr>) -> Self {
            if let Some(entry) = self.peers.get_mut(peer_id) {
                entry.resolved_ips = ips;
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
            let (route_cmd_tx, route_cmd_rx) = mpsc::unbounded_channel();

            let local = self.local.unwrap_or_else(|| crate::config::Local {
                table: false,
                dns: crate::config::LocalDns {
                    server: "1.1.1.1:53".parse().unwrap(),
                    bindif: None,
                },
                h3: None,
                bare: None,
                api: None,
                tun: crate::config::LocalTun {
                    ifname: "test0".to_string(),
                    addrs: vec!["192.168.180.1/32".parse().unwrap()],
                    mtu: 1393,
                },
            });

            let metrics_store = MetricsStore::new();
            let mut metrics_registry = Registry::default();
            metrics_registry.register_collector(Box::new(metrics_store.clone()));

            let orch = Orchestrator {
                events_rx,
                events_tx: events_tx.clone(),
                join_set: JoinSet::new(),
                tun_if: self.tun_if,
                mtu: self.mtu,
                tuning: Tuning::default(),
                peers: self.peers,
                tun_cmd_tx,
                bare_rx_cmd_tx: Some(bare_rx_cmd_tx),
                h3_listener_cmd_tx: None,
                tun_packet_tx,
                dns_cmd_tx,
                route_cmd_tx: Some(route_cmd_tx),
                tun_addrs: self.tun_addrs,
                local,
                metrics_store,
                metrics_registry,
            };

            (
                orch,
                TestHandles {
                    events_tx,
                    tun_cmd_rx,
                    bare_rx_cmd_rx,
                    dns_cmd_rx,
                    route_cmd_rx,
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
        Direction, DnsEvent, TransportEvent, TransportKind, TransportLabels, TransportMetrics,
        TransportStats,
    };

    // ========== PeerEntry unit tests ==========

    /// Helper to create test peers with BareUDP configuration.
    fn bare_peer(id: &str, allowed: &[&str]) -> Peer {
        use crate::config::UdpEndpoint;
        Peer {
            id: id.to_string(),

            h3: None,
            bare: Some(PeerBare {
                endpoint: UdpEndpoint {
                    host: "127.0.0.1".to_string(),
                    port: 5353,
                },
                bindif: None,
            }),
            tun: PeerTun {
                allowed_ips: allowed.iter().map(|s| s.parse().unwrap()).collect(),
            },
        }
    }

    /// Helper to create test peers with BareUDP configuration at a specific hostname.
    fn bare_peer_at_host(id: &str, hostname: &str, port: u16, allowed: &[&str]) -> Peer {
        use crate::config::UdpEndpoint;
        Peer {
            id: id.to_string(),

            h3: None,
            bare: Some(PeerBare {
                endpoint: UdpEndpoint {
                    host: hostname.to_string(),
                    port,
                },
                bindif: None,
            }),
            tun: PeerTun {
                allowed_ips: allowed.iter().map(|s| s.parse().unwrap()).collect(),
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
    fn collect_allowed_ips_collects_valid_cidrs() {
        let peers = vec![
            bare_peer("peer1", &["10.0.0.0/24", "192.168.1.0/24"]),
            bare_peer("peer2", &["172.16.0.0/16"]),
        ];
        let result = collect_allowed_ips(&peers);
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"10.0.0.0/24".parse().unwrap()));
        assert!(result.contains(&"192.168.1.0/24".parse().unwrap()));
        assert!(result.contains(&"172.16.0.0/16".parse().unwrap()));
    }

    // Note: collect_allowed_ips_rejects_invalid_cidr test removed - CIDR parsing
    // now happens during config deserialization

    #[test]
    fn collect_allowed_ips_handles_empty_peers() {
        let peers: Vec<Peer> = vec![];
        let result = collect_allowed_ips(&peers);
        assert!(result.is_empty());
    }

    // Note: tun_prefixes tests removed - function deleted; LocalTun.addrs is now Vec<IpNet>

    // ========== OrchestratorError tests ==========

    // Note: orchestrator_error_missing_bare_listen test removed - this error
    // variant was removed; validation moved to Config::validate()

    // Note: orchestrator_error_invalid_bare_listen test removed - URI parsing
    // now happens during config deserialization

    // Note: orchestrator_error_invalid_peer_endpoint test removed - URI parsing
    // now happens during config deserialization

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
        assert!(!orch.peers.get("peer1").unwrap().bounds.is_empty());

        // No commands sent to child actors
        assert!(handles.tun_cmd_rx.try_recv().is_err());
        assert!(handles.bare_rx_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_metrics_event_stores_snapshot() {
        let (mut orch, _handles) = TestableOrchestratorBuilder::default().build();
        assert!(orch.metrics_store.is_empty());
        orch.handle_event(make_metrics_event()).await;
        assert_eq!(orch.metrics_store.len(), 1);
    }

    #[tokio::test]
    async fn handle_metrics_event_replaces_on_same_labels() {
        let (mut orch, _handles) = TestableOrchestratorBuilder::default().build();
        orch.handle_event(make_metrics_event()).await;
        assert_eq!(orch.metrics_store.len(), 1);

        // Push again with different values but same labels
        let event = Event::Transport(TransportEvent::Metrics(TransportMetrics {
            labels: TransportLabels {
                kind: TransportKind::Tun,
                direction: Direction::Rx,
                peer_id: None,
                ip_addr: None,
            },
            stats: TransportStats {
                succeeded: crate::events::PktCounters {
                    packets: 42,
                    ..Default::default()
                },
                ..Default::default()
            },
        }));
        orch.handle_event(event).await;
        let store = orch.metrics_store.lock();
        assert_eq!(store.len(), 1);
        let stored = store.values().next().unwrap();
        assert_eq!(stored.stats.succeeded.packets, 42);
    }

    #[tokio::test]
    async fn api_get_metrics_returns_prometheus_text() {
        let (mut orch, _handles) = TestableOrchestratorBuilder::default().build();
        orch.handle_event(make_metrics_event()).await;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        orch.handle_api_event(ApiEvent::GetMetrics { reply_tx });

        let text = reply_rx.await.expect("should receive metrics text");
        assert!(
            text.contains("h3llo_transport_packets_total"),
            "missing packets metric: {text}"
        );
        assert!(
            text.contains("h3llo_transport_bytes_total"),
            "missing bytes metric: {text}"
        );
        assert!(text.contains("# EOF"), "missing EOF marker: {text}");
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

    fn make_dns_snapshot_event(state: HashMap<String, HashSet<IpAddr>>) -> Event {
        Event::Dns(DnsEvent { state })
    }

    #[tokio::test]
    async fn handle_dns_snapshot_ignores_unknown_host() {
        // Peer configured for known.example.com, but we send snapshot for unknown host
        let peer = bare_peer_at_host("peer1", "known.example.com", 5353, &["10.0.0.0/24"]);

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        // Snapshot for a host that doesn't match any peer
        let mut state = HashMap::new();
        state.insert(
            "unknown.example.com".to_string(),
            HashSet::from(["1.2.3.4".parse().unwrap()]),
        );
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // No bound created (hostname doesn't match)
        assert!(orch.peers.get("peer1").unwrap().bounds.is_empty());
        // Accepted sources always updated (unconditionally), but empty since no hostname matched
        let cmd = handles
            .bare_rx_cmd_rx
            .try_recv()
            .expect("accepted sources always sent");
        assert_eq!(cmd, BareUdpRxCommand::UpdateAcceptedSources(HashSet::new()));
        // Routing always updated unconditionally
        handles
            .tun_cmd_rx
            .try_recv()
            .expect("routing update always sent");
    }

    #[tokio::test]
    async fn handle_dns_snapshot_iterates_all_matching_peers() {
        let peer1 = bare_peer_at_host("peer1", "shared.example.com", 5353, &["10.0.0.0/24"]);
        let peer2 = bare_peer_at_host("peer2", "shared.example.com", 5354, &["172.16.0.0/16"]);

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer1, peer2])
            .build();

        let mut state = HashMap::new();
        state.insert(
            "shared.example.com".to_string(),
            HashSet::from(["1.2.3.4".parse().unwrap()]),
        );
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Both peers should be processed (iteration covers all matching)
        // Note: actual socket binding may fail in test environment,
        // but the iteration logic is exercised
    }

    #[tokio::test]
    async fn handle_dns_snapshot_ignores_non_matching_hostnames() {
        let peer = bare_peer_at_host("peer1", "different.example.com", 5353, &["10.0.0.0/24"]);

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        let mut state = HashMap::new();
        state.insert(
            "other.example.com".to_string(),
            HashSet::from(["1.2.3.4".parse().unwrap()]),
        );
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Accepted sources always updated (unconditionally), but empty since no hostname matched
        let cmd = handles
            .bare_rx_cmd_rx
            .try_recv()
            .expect("accepted sources always sent");
        assert_eq!(cmd, BareUdpRxCommand::UpdateAcceptedSources(HashSet::new()));
        // Routing always updated unconditionally
        handles
            .tun_cmd_rx
            .try_recv()
            .expect("routing update always sent");
    }

    #[tokio::test]
    async fn handle_dns_snapshot_removes_bound_on_ip_disappearance() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let (tx, _rx) = mpsc::channel(1);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", "1.2.3.4:5353".parse().unwrap(), tx)
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        // Verify bound exists before expiration
        assert!(!orch.peers.get("peer1").unwrap().bounds.is_empty());

        // Send snapshot WITHOUT the IP (simulating expiration)
        let mut state = HashMap::new();
        state.insert("example.com".to_string(), HashSet::new());
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Bound should be removed
        assert!(orch.peers.get("peer1").unwrap().bounds.is_empty());
    }

    #[tokio::test]
    async fn handle_dns_snapshot_respects_hostname_on_removal() {
        // Two peers with DIFFERENT hostnames but SAME resolved IP
        let peer_a = bare_peer_at_host("peer-a", "alpha.example.com", 5353, &["10.0.0.0/24"]);
        let peer_b = bare_peer_at_host("peer-b", "beta.example.com", 5353, &["172.16.0.0/16"]);

        let (tx_a, _rx_a) = mpsc::channel(1);
        let (tx_b, _rx_b) = mpsc::channel(1);

        // Both peers connected to the SAME IP (simulating shared hosting / CDN)
        let shared_ip: IpAddr = "1.2.3.4".parse().unwrap();
        let dest = SocketAddr::new(shared_ip, 5353);

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer_a, peer_b])
            .with_peer_tx("peer-a", dest, tx_a)
            .with_resolved_ips("peer-a", HashSet::from([shared_ip]))
            .with_peer_tx("peer-b", dest, tx_b)
            .with_resolved_ips("peer-b", HashSet::from([shared_ip]))
            .build();

        // Verify both peers are connected
        assert!(!orch.peers.get("peer-a").unwrap().bounds.is_empty());
        assert!(!orch.peers.get("peer-b").unwrap().bounds.is_empty());

        // New snapshot: alpha expired, beta still alive
        let mut state = HashMap::new();
        state.insert("alpha.example.com".to_string(), HashSet::new());
        state.insert("beta.example.com".to_string(), HashSet::from([shared_ip]));
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Only peer-a should be disconnected (endpoint matches, IP no longer in resolved_ips)
        assert!(orch.peers.get("peer-a").unwrap().bounds.is_empty());
        // peer-b should remain connected (different hostname, IP still in resolved_ips)
        assert!(!orch.peers.get("peer-b").unwrap().bounds.is_empty());
    }

    #[tokio::test]
    async fn handle_dns_snapshot_ignores_inbound_bound() {
        // Simulate inbound connection (no endpoint)
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let (tx, _rx) = mpsc::channel(1);
        let dest: SocketAddr = "1.2.3.4:5353".parse().unwrap();

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        // Manually set bound with None endpoint (simulating inbound)
        orch.peers
            .get_mut("peer1")
            .unwrap()
            .push_bound(None, dest, tx);

        assert!(!orch.peers.get("peer1").unwrap().bounds.is_empty());

        // Send snapshot without the IP
        let mut state = HashMap::new();
        state.insert("example.com".to_string(), HashSet::new());
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Bound should remain (endpoint is None, so never pruned by DNS/endpoint checks)
        assert!(!orch.peers.get("peer1").unwrap().bounds.is_empty());
    }

    // ========== collect_hostnames helper function tests ==========

    #[test]
    fn collect_hostnames_deduplicates() {
        let peers = vec![
            bare_peer_at_host("peer1", "shared.example.com", 5353, &["10.0.0.0/24"]),
            bare_peer_at_host("peer2", "shared.example.com", 5354, &["172.16.0.0/16"]),
        ];

        let peer_configs: Vec<_> = peers.iter().map(|p| p.clone()).collect();
        let result = collect_hostnames(&peer_configs);

        // Deduplicated to single hostname
        assert_eq!(result.len(), 1);
        assert!(result.contains("shared.example.com"));
    }

    #[test]
    fn collect_hostnames_skips_non_bare_peers() {
        let peer = Peer {
            id: "h3only".to_string(),

            h3: None,
            bare: None,
            tun: PeerTun {
                allowed_ips: vec![],
            },
        };

        let result = collect_hostnames(&[peer]);
        assert!(result.is_empty(), "no hostnames should be collected");
    }

    // Note: collect_hostnames_returns_error_for_invalid_endpoint test removed -
    // invalid endpoint URIs now fail at config deserialization time, and
    // collect_hostnames is now infallible.

    #[test]
    fn collect_hostnames_includes_ip_literals() {
        let peer = bare_peer("peer1", &["10.0.0.0/24"]); // Uses 127.0.0.1

        let result = collect_hostnames(&[peer]);
        assert!(
            result.contains("127.0.0.1"),
            "IP literals should be collected for DNS module to handle"
        );
    }

    // ========== Non-blocking H3 dial test ==========

    /// Helper to create test peers with H3 configuration at a specific host.
    fn h3_peer_at_host(id: &str, host: &str, port: u16, allowed: &[&str]) -> Peer {
        use crate::config::{H3Endpoint, PeerH3};
        Peer {
            id: id.to_string(),

            h3: Some(PeerH3 {
                endpoint: Some(H3Endpoint {
                    host: host.to_string(),
                    port,
                    path: "/".to_string(),
                }),
                token: "test-token-12chars".to_string(),
                bindif: None,
                sni: None,
            }),
            bare: None,
            tun: PeerTun {
                allowed_ips: allowed.iter().map(|s| s.parse().unwrap()).collect(),
            },
        }
    }

    #[tokio::test]
    async fn handle_dns_snapshot_does_not_block_on_h3_dial() {
        use std::time::Instant;

        // Create peer with H3 endpoint pointing to non-routable address (will timeout)
        let peer = h3_peer_at_host("h3-peer", "10.255.255.1", 443, &["10.0.0.0/24"]);

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        let mut state = HashMap::new();
        state.insert(
            "10.255.255.1".to_string(),
            HashSet::from(["10.255.255.1".parse().unwrap()]),
        );
        let event = make_dns_snapshot_event(state);

        // The key assertion: handle_dns_snapshot should return immediately
        // (within milliseconds), not block for 30 seconds waiting for dial timeout
        let start = Instant::now();
        orch.handle_event(event).await;
        let elapsed = start.elapsed();

        // If dial was blocking, this would take ~30 seconds (H3_HANDSHAKE_TIMEOUT)
        // With non-blocking spawn, it should return in < 500ms
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "handle_dns_snapshot blocked for {:?}, expected < 500ms (dial should be non-blocking)",
            elapsed
        );
    }

    // ========== update_accepted_sources / update_routing independence tests ==========

    #[tokio::test]
    async fn update_accepted_sources_independent_of_routing() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let (orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        orch.update_accepted_sources();

        let BareUdpRxCommand::UpdateAcceptedSources(ips) = handles
            .bare_rx_cmd_rx
            .try_recv()
            .expect("accepted sources update expected");
        assert_eq!(ips.len(), 1);
        assert!(ips.contains(&ip));

        // Routing command should NOT be sent
        assert!(handles.tun_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn update_routing_independent_of_accepted_sources() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let (tx, _rx) = mpsc::channel(1);
        let (orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", "1.2.3.4:5353".parse().unwrap(), tx)
            .build();

        orch.update_routing();

        // Routing command SHOULD be sent
        assert!(handles.tun_cmd_rx.try_recv().is_ok());

        // Accepted sources command should NOT be sent
        assert!(handles.bare_rx_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_dns_snapshot_always_updates_accepted_sources() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let (tx, _rx) = mpsc::channel(1);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", "1.2.3.4:5353".parse().unwrap(), tx)
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        // Peer already connected — no bounds_changed will occur
        let mut state = HashMap::new();
        state.insert(
            "example.com".to_string(),
            HashSet::from(["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()]),
        );
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Accepted sources SHOULD be updated (unconditionally, from resolved_ips)
        let BareUdpRxCommand::UpdateAcceptedSources(ips) = handles
            .bare_rx_cmd_rx
            .try_recv()
            .expect("accepted sources update expected");
        assert!(ips.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"5.6.7.8".parse::<IpAddr>().unwrap()));

        // Routing always updated unconditionally
        handles
            .tun_cmd_rx
            .try_recv()
            .expect("routing update always sent");
    }

    // ========== BareConnected event handling tests ==========

    #[tokio::test]
    async fn handle_dns_snapshot_does_not_block_on_bare_tx() {
        use std::time::Instant;

        let peer = bare_peer_at_host("bare-peer", "10.255.255.1", 5353, &["10.0.0.0/24"]);

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        let mut state = HashMap::new();
        state.insert(
            "10.255.255.1".to_string(),
            HashSet::from(["10.255.255.1".parse().unwrap()]),
        );
        let event = make_dns_snapshot_event(state);

        let start = Instant::now();
        orch.handle_event(event).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "handle_dns_snapshot blocked for {:?}, expected < 500ms",
            elapsed
        );
    }

    #[tokio::test]
    async fn handle_bare_connection_rejects_unknown_peer() {
        use crate::config::UdpEndpoint;
        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![])
            .build();

        let (tx, _rx) = mpsc::channel(1);
        let tx_handle = tokio::spawn(async { Ok(()) });

        let event = BareConnectedEvent {
            peer_id: "unknown-peer".to_string(),
            endpoint: Endpoint::Udp(UdpEndpoint {
                host: "example.com".to_string(),
                port: 5353,
            }),
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx,
            tx_handle,
        };

        orch.handle_bare_connection(event);
        assert!(!orch.peers.contains_key("unknown-peer"));
    }

    #[tokio::test]
    async fn handle_bare_connection_appends_second_bound() {
        use crate::config::UdpEndpoint;
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let (existing_tx, _existing_rx) = mpsc::channel(1);

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", "1.2.3.4:5353".parse().unwrap(), existing_tx)
            .with_resolved_ips("peer1", HashSet::from([ip, ip2]))
            .build();

        let (tx, _rx) = mpsc::channel(1);
        let tx_handle = tokio::spawn(async { Ok(()) });

        let event = BareConnectedEvent {
            peer_id: "peer1".to_string(),
            endpoint: Endpoint::Udp(UdpEndpoint {
                host: "example.com".to_string(),
                port: 5353,
            }),
            dest: "5.6.7.8:5353".parse().unwrap(),
            tx,
            tx_handle,
        };

        orch.handle_bare_connection(event);

        // Both bounds should exist
        assert_eq!(orch.peers.get("peer1").unwrap().bounds.len(), 2);
        // First bound preserved
        assert_eq!(
            orch.peers.get("peer1").unwrap().bounds[0].dest,
            "1.2.3.4:5353".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn handle_bare_connection_sets_bound_and_updates_routing() {
        use crate::config::UdpEndpoint;
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        let (tx, _rx) = mpsc::channel(1);
        let tx_handle = tokio::spawn(async { Ok(()) });

        let event = BareConnectedEvent {
            peer_id: "peer1".to_string(),
            endpoint: Endpoint::Udp(UdpEndpoint {
                host: "example.com".to_string(),
                port: 5353,
            }),
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx,
            tx_handle,
        };

        orch.handle_bare_connection(event);

        // Bound should be set
        assert!(!orch.peers.get("peer1").unwrap().bounds.is_empty());
        let bound = orch.peers.get("peer1").unwrap().bounds.first().unwrap();
        assert_eq!(bound.dest, "1.2.3.4:5353".parse::<SocketAddr>().unwrap());
        assert_eq!(
            bound.endpoint,
            Some(Endpoint::Udp(UdpEndpoint {
                host: "example.com".to_string(),
                port: 5353,
            }))
        );

        // Routing should be updated (TUN command sent)
        assert!(handles.tun_cmd_rx.try_recv().is_ok());
    }

    // ========== PeerEntry prune/try_connect tests ==========

    #[test]
    fn prune_removes_closed_tx() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);
        entry.resolved_ips.insert("1.2.3.4".parse().unwrap());

        let (tx, rx) = mpsc::channel(1);
        entry.push_bound(entry.config_endpoint(), "1.2.3.4:5353".parse().unwrap(), tx);

        assert!(!entry.bounds.is_empty());
        // Drop receiver to close channel
        drop(rx);

        let changed = entry.prune();
        assert!(entry.bounds.is_empty());
        assert!(changed); // first TX changed from Some to None
    }

    #[test]
    fn prune_removes_stale_dns_ip() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);
        // resolved_ips does NOT contain 1.2.3.4
        entry.resolved_ips.insert("5.6.7.8".parse().unwrap());

        let (tx, _rx) = mpsc::channel(1);
        entry.push_bound(entry.config_endpoint(), "1.2.3.4:5353".parse().unwrap(), tx);

        let changed = entry.prune();
        assert!(entry.bounds.is_empty());
        assert!(changed);
    }

    #[test]
    fn prune_returns_true_when_first_tx_changes() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);
        entry.resolved_ips.insert("1.2.3.4".parse().unwrap());
        entry.resolved_ips.insert("5.6.7.8".parse().unwrap());

        let (tx1, rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);
        let ep = entry.config_endpoint();
        entry.push_bound(ep.clone(), "1.2.3.4:5353".parse().unwrap(), tx1);
        entry.push_bound(ep, "5.6.7.8:5353".parse().unwrap(), tx2);

        // Drop first receiver -> first bound becomes invalid
        drop(rx1);

        let changed = entry.prune();
        assert!(changed);
        assert_eq!(entry.bounds.len(), 1);
        assert_eq!(
            entry.bounds[0].dest,
            "5.6.7.8:5353".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn prune_detects_change_with_same_dest() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);
        entry.resolved_ips.insert("1.2.3.4".parse().unwrap());

        // Two bounds to the same dest but different TX channels
        let (tx1, rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);
        let ep = entry.config_endpoint();
        entry.push_bound(ep.clone(), "1.2.3.4:5353".parse().unwrap(), tx1);
        entry.push_bound(ep, "1.2.3.4:5353".parse().unwrap(), tx2);

        // Drop first receiver -> first bound becomes invalid
        drop(rx1);

        let changed = entry.prune();
        assert!(changed); // must detect change even though dest is identical
        assert_eq!(entry.bounds.len(), 1);
    }

    #[test]
    fn prune_preserves_inbound_bounds() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);
        // resolved_ips is EMPTY -- but inbound bounds (endpoint: None) should survive

        let (tx, _rx) = mpsc::channel(1);
        entry.push_bound(None, "9.8.7.6:12345".parse().unwrap(), tx);

        let changed = entry.prune();
        assert!(!changed);
        assert_eq!(entry.bounds.len(), 1);
    }

    #[tokio::test]
    async fn try_connect_rate_limited() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);
        entry.resolved_ips.insert("127.0.0.1".parse().unwrap());

        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        // First call should set last_try_connect
        entry.try_connect(&events_tx, "test0", 1393, &Tuning::default());
        assert!(entry.last_try_connect.is_some());

        let first_time = entry.last_try_connect.unwrap();

        // Second immediate call should be rate-limited (timestamp unchanged)
        entry.try_connect(&events_tx, "test0", 1393, &Tuning::default());
        assert_eq!(entry.last_try_connect.unwrap(), first_time);
    }

    // ========== API event handling tests ==========

    #[tokio::test]
    async fn api_get_config_returns_snapshot() {
        let peer = Peer {
            id: "peer-1".to_string(),
            h3: Some(crate::config::PeerH3 {
                endpoint: None,
                token: "test-token-12ch".to_string(),
                bindif: None,
                sni: None,
            }),
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            },
        };
        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        orch.handle_api_event(ApiEvent::GetConfig { reply_tx });

        let config = reply_rx.await.expect("should receive config");
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].id, "peer-1");
        // Verify local section is included in snapshot
        assert_eq!(config.local.tun.ifname, "test0");
    }

    #[tokio::test]
    async fn api_post_config_adds_peer() {
        let (mut orch, _handles) = TestableOrchestratorBuilder::default().build();
        assert!(orch.peers.is_empty());

        let new_peer = Peer {
            id: "new-peer".to_string(),
            h3: Some(crate::config::PeerH3 {
                endpoint: None,
                token: "test-token-12ch".to_string(),
                bindif: None,
                sni: None,
            }),
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
            },
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        orch.handle_api_event(ApiEvent::PostConfig {
            peers: vec![new_peer],
            reply_tx,
        });

        let result = reply_rx.await.expect("should receive reply");
        let config = result.expect("should succeed");
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].id, "new-peer");
        assert_eq!(orch.peers.len(), 1);
        assert!(orch.peers.contains_key("new-peer"));
    }

    #[tokio::test]
    async fn api_post_config_rejects_invalid_peer() {
        let (mut orch, _handles) = TestableOrchestratorBuilder::default().build();

        let bad_peer = Peer {
            id: "".to_string(), // empty id is invalid
            h3: None,
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            },
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        orch.handle_api_event(ApiEvent::PostConfig {
            peers: vec![bad_peer],
            reply_tx,
        });

        let result = reply_rx.await.expect("should receive reply");
        assert!(result.is_err());
        assert!(orch.peers.is_empty());
    }

    #[tokio::test]
    async fn api_delete_config_removes_peer() {
        let peer = Peer {
            id: "peer-1".to_string(),
            h3: Some(crate::config::PeerH3 {
                endpoint: None,
                token: "test-token-12ch".to_string(),
                bindif: None,
                sni: None,
            }),
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            },
        };
        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();
        assert_eq!(orch.peers.len(), 1);

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        orch.handle_api_event(ApiEvent::DeleteConfig {
            peer_ids: vec!["peer-1".to_string()],
            reply_tx,
        });

        let result = reply_rx.await.expect("should receive reply");
        let config = result.expect("should succeed");
        assert!(config.peers.is_empty());
        assert!(orch.peers.is_empty());
    }

    #[tokio::test]
    async fn api_delete_config_ignores_unknown_ids() {
        let peer = Peer {
            id: "keeper".to_string(),
            h3: Some(crate::config::PeerH3 {
                endpoint: None,
                token: "test-token-12ch".to_string(),
                bindif: None,
                sni: None,
            }),
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            },
        };
        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        orch.handle_api_event(ApiEvent::DeleteConfig {
            peer_ids: vec!["nonexistent".to_string()],
            reply_tx,
        });

        let result = reply_rx.await.expect("should receive reply");
        let config = result.expect("should succeed");
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].id, "keeper");
    }
}
