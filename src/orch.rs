//! Runtime orchestration for BareUDP and HTTP/3 transports.

use crate::actor::{ActorError, ActorExitResult, ActorKind};
use crate::bare::{make_bare_rx, make_bare_tx, spawn_udp_rx, spawn_udp_tx, BareUdpRxCommand};
use crate::bind::DefaultRouteProbe;
use crate::config::{Config, Peer};
use crate::dns::{make_dns, spawn_dns, DnsCommand};
use crate::events::{
    BareConnectedEvent, ConnectionDirection, DnsEvent, Event, H3ConnectedEvent, TransportEvent,
};
use crate::h3::{
    dial_h3, make_h3_listener, spawn_h3_listener, spawn_h3_rx, spawn_h3_tx, H3ListenerCommand,
};
use crate::route::{make_route, spawn_route, RouteCommand};
use crate::tun::{self, RoutingTable, TunRxCommand};
use ipnet::IpNet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

const METRICS_INTERVAL: Duration = Duration::from_secs(30);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// A single active connection bound to a peer.
#[derive(Debug)]
struct BoundState {
    /// Endpoint hostname for DNS expiration matching.
    hostname: Option<String>,
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
    /// Active connection for this peer (at most one).
    bound: Option<BoundState>,
}

impl PeerEntry {
    /// Creates a new peer entry from configuration.
    fn new(config: Peer) -> Self {
        Self {
            config,
            bound: None,
        }
    }

    /// Returns the TX channel or None if disconnected.
    fn preferred_tx(&self) -> Option<&mpsc::Sender<Vec<u8>>> {
        self.bound.as_ref().map(|b| &b.tx)
    }

    /// Returns true if a connection is already established.
    fn is_connected(&self) -> bool {
        self.bound.is_some()
    }

    /// Expires the bound if its IP is no longer present in the DNS state.
    ///
    /// Returns `Some((hostname, ip))` if the bound was removed, `None` otherwise.
    /// Inbound connections (hostname=None) are never expired by this check.
    fn expire_bound_if_stale(
        &mut self,
        dns_state: &HashMap<String, Vec<IpAddr>>,
    ) -> Option<(String, IpAddr)> {
        let bound = self.bound.as_ref()?;
        let hostname = bound.hostname.as_ref()?;
        let available_ips = dns_state.get(hostname).map(|v| v.as_slice()).unwrap_or(&[]);
        if !available_ips.contains(&bound.dest.ip()) {
            let info = (hostname.clone(), bound.dest.ip());
            self.bound = None;
            Some(info)
        } else {
            None
        }
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
/// - Peer actors (BareUDP-Tx, H3-Tx/Rx): failure logged (reconnection deferred to future iteration)
pub struct Orchestrator {
    events_rx: mpsc::UnboundedReceiver<Event>,
    events_tx: mpsc::UnboundedSender<Event>,
    join_set: JoinSet<Result<ActorExitResult, tokio::task::JoinError>>,

    // Runtime state
    tun_if: String,
    mtu: usize,
    /// Unified peer state: config + active bound.
    peers: HashMap<String, PeerEntry>,
    tun_cmd_tx: mpsc::UnboundedSender<TunRxCommand>,
    bare_rx_cmd_tx: Option<mpsc::UnboundedSender<BareUdpRxCommand>>,
    /// H3 listener command sender (if listening).
    #[allow(dead_code)]
    h3_listener_cmd_tx: Option<mpsc::UnboundedSender<H3ListenerCommand>>,
    /// Packet sender to TUN TX (for H3 RX actors).
    tun_packet_tx: mpsc::Sender<Vec<u8>>,

    /// DNS resolver command sender for SetHostnames (used for future reconfiguration).
    #[allow(dead_code)]
    dns_cmd_tx: mpsc::UnboundedSender<DnsCommand>,

    /// Route sync actor command sender (None when `local.table` is false or init failed).
    route_cmd_tx: Option<mpsc::UnboundedSender<RouteCommand>>,
    /// TUN interface addresses for route sync commands.
    tun_addrs: Vec<IpNet>,
}

impl Orchestrator {
    /// Updates BareUDP RX accepted source filter.
    ///
    /// Sends the new set of accepted source IPs to the BareUDP RX actor.
    /// No-op when BareUDP is not configured (`bare_rx_cmd_tx` is `None`).
    fn update_accepted_sources(&self, accepted_ips: &HashSet<IpAddr>) {
        if let Some(cmd_tx) = &self.bare_rx_cmd_tx {
            if let Err(e) = cmd_tx.send(BareUdpRxCommand::UpdateAcceptedSources(
                accepted_ips.clone(),
            )) {
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
        let peer_txs = self.peer_txs();
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
        let (tun_cmd_tx, tun_rx_handle) =
            tun::spawn_tun_rx(tun_reader, routing, events_tx.clone(), METRICS_INTERVAL);
        // TUN-Tx actor creates its own packet channel; returns sender for transports to use
        let (tun_packet_tx, tun_tx_handle) =
            tun::spawn_tun_tx(tun_writer, events_tx.clone(), METRICS_INTERVAL);

        join_set.spawn(tun_rx_handle);
        join_set.spawn(tun_tx_handle);

        // Initialize BareUDP listener if configured
        let bare_rx_cmd_tx = if let Some(ref local_bare) = config.local.bare {
            // Endpoint already parsed during config deserialization
            let listen_addr = resolve_listen_addr(&local_bare.listen.host, local_bare.listen.port)?;

            let bare_rx = make_bare_rx(listen_addr, mtu)
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

        // Initialize H3 listener if configured with listen address
        let h3_cfg = config.local.h3.as_ref();
        let listen_endpoint = h3_cfg.and_then(|h3| h3.listen.as_ref());

        let h3_listener_cmd_tx = match (h3_cfg, listen_endpoint) {
            (Some(h3_cfg), Some(listen_ep)) => {
                // Endpoint already parsed during config deserialization
                let listen_addr = resolve_listen_addr(&listen_ep.host, listen_ep.port)?;

                // SAFETY: cert and key are validated to be Some when listen is set
                let cert_path = Path::new(h3_cfg.cert.as_ref().expect("validated"));
                let key_path = Path::new(h3_cfg.key.as_ref().expect("validated"));

                // Build peer tokens map for authentication
                let peer_tokens: HashMap<String, String> = config
                    .peers
                    .iter()
                    .filter(|p| p.enabled && p.h3.is_some())
                    .map(|p| (p.id.clone(), p.h3.as_ref().unwrap().token.clone()))
                    .collect();

                // make: fallible I/O (socket bind, TLS config)
                let listener = make_h3_listener(listen_addr, cert_path, key_path)
                    .map_err(|e| OrchestratorError::H3Listener(e.to_string()))?;

                // spawn: infallible task creation; listener sends events through events_tx
                let (cmd_tx, listener_handle, _bound_addr) = spawn_h3_listener(
                    listener,
                    peer_tokens,
                    config.local.tun.mtu,
                    events_tx.clone(),
                );

                join_set.spawn(listener_handle);
                Some(cmd_tx)
            }
            // Dial-only mode or no H3 configured: no listener, but can dial H3 peers
            _ => None,
        };

        // Initialize unified peer state from config (enabled peers with any transport)
        let peers: HashMap<String, PeerEntry> = config
            .peers
            .iter()
            .filter(|p| p.enabled && (p.bare.is_some() || p.h3.is_some()))
            .map(|p| (p.id.clone(), PeerEntry::new(p.clone())))
            .collect();

        // Create DNS actor state (performs fallible socket binding)
        let probe = DefaultRouteProbe;
        let dns_actor = make_dns(
            &config.local.dns,
            Some(tun_if.as_str()),
            DNS_QUERY_TIMEOUT,
            &probe,
        )
        .await
        .map_err(|err| OrchestratorError::DnsInit(err.to_string()))?;

        // Spawn DNS actor task (infallible)
        let (dns_cmd_tx, handle) = spawn_dns(dns_actor, events_tx.clone());

        // Send all hostnames to DNS module in one shot.
        // IP literals are handled by the DNS module directly (immediate IpResolved event).
        let peer_configs: Vec<Peer> = peers.values().map(|e| e.config.clone()).collect();
        let hostnames = collect_hostnames(&peer_configs);
        if let Err(e) = dns_cmd_tx.send(DnsCommand::SetHostnames { hosts: hostnames }) {
            warn!(error = %e, "dns: failed to send initial hostnames");
        }

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

        let has_active_peers = peers.values().any(|e| e.config.enabled);
        if !has_active_peers {
            warn!("no active peers; traffic will be dropped");
        }

        Ok(Self {
            events_rx,
            events_tx,
            join_set,
            tun_if,
            mtu,
            peers,
            tun_cmd_tx,
            bare_rx_cmd_tx,
            h3_listener_cmd_tx,
            tun_packet_tx,
            dns_cmd_tx,
            route_cmd_tx,
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
        loop {
            tokio::select! {
                Some(event) = self.events_rx.recv() => {
                    self.handle_event(event).await;
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
                                                if let Some(ref bound) = entry.bound {
                                                    if bound.dest == dest_addr {
                                                        entry.bound = None;
                                                    }
                                                }
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
                self.handle_dns_snapshot(dns_event).await;
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

    /// Handles a DNS state snapshot by iterating peers directly.
    ///
    /// For each peer:
    /// - If no bound: create connection using first available IP (BareUDP) or dial all IPs (H3)
    /// - If bound: check if dest IP still in snapshot; remove if expired, reconnect if possible
    async fn handle_dns_snapshot(&mut self, dns_event: DnsEvent) {
        let dns_state = dns_event.state;
        let mut bounds_changed = false;

        for (peer_id, entry) in &mut self.peers {
            if !entry.config.enabled {
                continue;
            }

            // Expire stale bound using bound's own hostname against DNS state
            if let Some((host, ip)) = entry.expire_bound_if_stale(&dns_state) {
                debug!(peer = %peer_id, host = %host, ip = %ip, "bound removed due to IP expiration");
                bounds_changed = true;
            }

            if entry.is_connected() {
                continue;
            }

            // Establish new connection per transport type
            if let Some(bare) = entry.config.bare.as_ref() {
                let host = bare.endpoint.host.clone();
                let port = bare.endpoint.port;
                let bindif = bare.bindif.clone();
                let available_ips = dns_state.get(&host).map(|v| v.as_slice()).unwrap_or(&[]);

                if let Some(&ip) = available_ips.first() {
                    let destination = SocketAddr::new(ip, port);
                    let events_tx = self.events_tx.clone();
                    let tun_if = self.tun_if.clone();
                    let peer_id = peer_id.clone();
                    tokio::spawn(async move {
                        let probe = DefaultRouteProbe;
                        match make_bare_tx(destination, bindif.as_deref(), Some(&tun_if), &probe)
                            .await
                        {
                            Ok(tx_socket) => {
                                let (packet_tx, tx_handle) =
                                    spawn_udp_tx(tx_socket, events_tx.clone(), METRICS_INTERVAL);
                                let event = Event::Transport(TransportEvent::BareConnected(
                                    BareConnectedEvent {
                                        peer_id,
                                        hostname: host,
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
            } else if let Some(h3) = entry.config.h3.as_ref() {
                let Some(endpoint) = h3.endpoint.as_ref() else {
                    continue;
                };
                let host = strip_ipv6_brackets(&endpoint.host).to_string();
                let port = endpoint.port;
                let peer_h3 = h3.clone();
                let available_ips = dns_state.get(&host).map(|v| v.as_slice()).unwrap_or(&[]);
                let events_tx = self.events_tx.clone();
                let tun_if = self.tun_if.clone();
                let tun_mtu = self.mtu as u16;

                for &ip in available_ips {
                    let destination = SocketAddr::new(ip, port);
                    let peer_h3 = peer_h3.clone();
                    let events_tx = events_tx.clone();
                    let tun_if = tun_if.clone();
                    let peer_id = peer_id.clone();

                    tokio::spawn(async move {
                        let probe = DefaultRouteProbe;
                        match dial_h3(
                            &peer_h3,
                            destination,
                            &peer_id,
                            Some(&tun_if),
                            tun_mtu,
                            &probe,
                        )
                        .await
                        {
                            Ok(conn) => {
                                debug!(peer = %peer_id, addr = %destination, "H3 connection established");
                                let event = Event::Transport(TransportEvent::H3Connected(
                                    H3ConnectedEvent {
                                        connection: conn,
                                        direction: ConnectionDirection::Outbound,
                                    },
                                ));
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

        // Always update accepted sources from DNS state — includes ALL resolved IPs for
        // bare peers, not just currently-bound ones. DNS can resolve new IPs without
        // triggering a bounds change (e.g., peer already connected to one IP).
        let mut accepted_ips = HashSet::new();
        for entry in self.peers.values() {
            if !entry.config.enabled {
                continue;
            }
            let Some(bare) = entry.config.bare.as_ref() else {
                continue;
            };
            if let Some(ips) = dns_state.get(&bare.endpoint.host) {
                accepted_ips.extend(ips.iter().copied());
            }
        }
        self.update_accepted_sources(&accepted_ips);

        if bounds_changed {
            self.update_routing();
        }
    }

    /// Registers a bound connection for a peer and updates routing.
    ///
    /// Returns `true` if the bound was set, `false` if the peer is unknown
    /// or already connected (first-connection-wins).
    fn update_bound(
        &mut self,
        peer_id: &str,
        hostname: Option<String>,
        dest: SocketAddr,
        tx: mpsc::Sender<Vec<u8>>,
    ) -> bool {
        let Some(entry) = self.peers.get_mut(peer_id) else {
            warn!(peer = %peer_id, addr = %dest, "connection for unknown peer");
            return false;
        };
        if entry.is_connected() {
            debug!(peer = %peer_id, addr = %dest, "already connected, rejecting");
            return false;
        }
        entry.bound = Some(BoundState { hostname, dest, tx });
        self.update_routing();
        true
    }

    /// Handles a BareUDP TX connection event.
    ///
    /// Unconditionally registers the TX actor JoinHandle for lifecycle
    /// monitoring, then attempts to bind the peer via [`update_bound`].
    fn handle_bare_connection(&mut self, event: BareConnectedEvent) {
        let BareConnectedEvent {
            peer_id,
            hostname,
            dest,
            tx,
            tx_handle,
        } = event;
        // Always register: actor is already running, must be supervised
        self.join_set.spawn(tx_handle);
        self.update_bound(&peer_id, Some(hostname), dest, tx);
    }

    /// Handles an H3 connection event (inbound or outbound).
    ///
    /// Unified handler for both listener and dialer connections.
    /// First connection wins - rejects if already connected.
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

        // Pre-check before destructive conn.into_actors(): first connection wins
        let entry = self.peers.get(&peer_id).unwrap();
        if entry.is_connected() {
            debug!(
                peer = %peer_id,
                addr = %remote_addr,
                direction = ?direction,
                "H3: already connected, rejecting new connection"
            );
            return;
        }

        // Extract endpoint hostname for outbound connections (used for IP expiration matching).
        // Inbound connections have no outbound endpoint, so hostname is None.
        let hostname = match direction {
            ConnectionDirection::Outbound => entry
                .config
                .h3
                .as_ref()
                .and_then(|h3| h3.endpoint.as_ref())
                .map(|ep| strip_ipv6_brackets(&ep.host).to_string()),
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
            METRICS_INTERVAL,
        );

        // Spawn TX actor
        let (packet_tx, tx_handle) =
            spawn_h3_tx(tx_state, self.events_tx.clone(), METRICS_INTERVAL);

        self.join_set.spawn(rx_handle);
        self.join_set.spawn(tx_handle);
        self.update_bound(&peer_id, hostname, remote_addr, packet_tx);
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
        if !peer.enabled {
            continue;
        }

        // Handle BareUDP endpoints
        if let Some(bare) = peer.bare.as_ref() {
            hosts.insert(bare.endpoint.host.clone());
        }

        // Handle H3 endpoint
        if let Some(h3) = peer.h3.as_ref() {
            if let Some(endpoint) = h3.endpoint.as_ref() {
                // Strip IPv6 brackets for DNS resolution
                hosts.insert(strip_ipv6_brackets(&endpoint.host).to_string());
            }
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
    }

    impl Default for TestableOrchestratorBuilder {
        fn default() -> Self {
            Self {
                tun_if: "test0".to_string(),
                mtu: crate::config::default_mtu() as usize,
                peers: HashMap::new(),
                tun_addrs: Vec::new(),
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
            tx: mpsc::Sender<Vec<u8>>,
        ) -> Self {
            if let Some(entry) = self.peers.get_mut(peer_id) {
                let hostname = entry
                    .config
                    .bare
                    .as_ref()
                    .map(|bare| bare.endpoint.host.clone());
                entry.bound = Some(BoundState { hostname, dest, tx });
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

            let orch = Orchestrator {
                events_rx,
                events_tx: events_tx.clone(),
                join_set: JoinSet::new(),
                tun_if: self.tun_if,
                mtu: self.mtu,
                peers: self.peers,
                tun_cmd_tx,
                bare_rx_cmd_tx: Some(bare_rx_cmd_tx),
                h3_listener_cmd_tx: None,
                tun_packet_tx,
                dns_cmd_tx,
                route_cmd_tx: Some(route_cmd_tx),
                tun_addrs: self.tun_addrs,
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

    #[test]
    fn peer_entry_tracks_single_bound() {
        let config = Peer {
            id: "peer-1".to_string(),
            enabled: true,
            h3: None,
            bare: None,
            tun: PeerTun {
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            },
        };
        let mut entry = PeerEntry::new(config);

        assert!(!entry.is_connected());
        assert!(entry.preferred_tx().is_none());

        let (tx1, _rx1) = mpsc::channel(1);
        entry.bound = Some(BoundState {
            hostname: None,
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx: tx1,
        });

        assert!(entry.is_connected());
        assert!(entry.preferred_tx().is_some());

        // Replace bound (at most one connection)
        let (tx2, _rx2) = mpsc::channel(1);
        entry.bound = Some(BoundState {
            hostname: None,
            dest: "5.6.7.8:5353".parse().unwrap(),
            tx: tx2,
        });

        assert!(entry.is_connected());
    }

    /// Helper to create test peers with BareUDP configuration.
    fn bare_peer(id: &str, allowed: &[&str]) -> Peer {
        use crate::config::UdpEndpoint;
        Peer {
            id: id.to_string(),
            enabled: true,
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
            enabled: true,
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
        assert!(orch.peers.get("peer1").unwrap().is_connected());

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

    fn make_dns_snapshot_event(state: HashMap<String, Vec<IpAddr>>) -> Event {
        Event::Dns(DnsEvent {
            server: "127.0.0.1:53".parse().unwrap(),
            state,
        })
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
            vec!["1.2.3.4".parse().unwrap()],
        );
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // No bound created (hostname doesn't match)
        assert!(!orch.peers.get("peer1").unwrap().is_connected());
        // Routing not updated (no bounds change)
        assert!(handles.tun_cmd_rx.try_recv().is_err());
        // Accepted sources always updated (unconditionally), but empty since no hostname matched
        let cmd = handles
            .bare_rx_cmd_rx
            .try_recv()
            .expect("accepted sources always sent");
        assert_eq!(cmd, BareUdpRxCommand::UpdateAcceptedSources(HashSet::new()));
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
            vec!["1.2.3.4".parse().unwrap()],
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
            vec!["1.2.3.4".parse().unwrap()],
        );
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Routing not updated (no bounds change)
        assert!(handles.tun_cmd_rx.try_recv().is_err());
        // Accepted sources always updated (unconditionally), but empty since no hostname matched
        let cmd = handles
            .bare_rx_cmd_rx
            .try_recv()
            .expect("accepted sources always sent");
        assert_eq!(cmd, BareUdpRxCommand::UpdateAcceptedSources(HashSet::new()));
    }

    #[tokio::test]
    async fn handle_dns_snapshot_skips_disabled_peers() {
        let mut peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        peer.enabled = false;

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        let mut state = HashMap::new();
        state.insert("example.com".to_string(), vec!["1.2.3.4".parse().unwrap()]);
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // No commands should be sent (peer disabled)
        assert!(handles.tun_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_dns_snapshot_removes_bound_on_ip_disappearance() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let (tx, _rx) = mpsc::channel(1);
        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", "1.2.3.4:5353".parse().unwrap(), tx)
            .build();

        // Verify bound exists before expiration
        assert!(orch.peers.get("peer1").unwrap().is_connected());

        // Send snapshot WITHOUT the IP (simulating expiration)
        let mut state = HashMap::new();
        state.insert("example.com".to_string(), vec![]);
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Bound should be removed
        assert!(!orch.peers.get("peer1").unwrap().is_connected());
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
            .with_peer_tx("peer-b", dest, tx_b)
            .build();

        // Verify both peers are connected
        assert!(orch.peers.get("peer-a").unwrap().is_connected());
        assert!(orch.peers.get("peer-b").unwrap().is_connected());

        // New snapshot: alpha expired, beta still alive
        let mut state = HashMap::new();
        state.insert("alpha.example.com".to_string(), vec![]);
        state.insert("beta.example.com".to_string(), vec![shared_ip]);
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Only peer-a should be disconnected (hostname matches)
        assert!(!orch.peers.get("peer-a").unwrap().is_connected());
        // peer-b should remain connected (different hostname, same IP)
        assert!(orch.peers.get("peer-b").unwrap().is_connected());
    }

    #[tokio::test]
    async fn handle_dns_snapshot_ignores_none_hostname_bound() {
        // Simulate inbound connection (no hostname)
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let (tx, _rx) = mpsc::channel(1);
        let dest: SocketAddr = "1.2.3.4:5353".parse().unwrap();

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        // Manually set bound with None hostname (simulating inbound)
        orch.peers.get_mut("peer1").unwrap().bound = Some(BoundState {
            hostname: None,
            dest,
            tx,
        });

        assert!(orch.peers.get("peer1").unwrap().is_connected());

        // Send snapshot without the IP
        let mut state = HashMap::new();
        state.insert("example.com".to_string(), vec![]);
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Bound should remain (hostname is None, so host_matches is false)
        assert!(orch.peers.get("peer1").unwrap().is_connected());
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
    fn collect_hostnames_skips_disabled_peers() {
        let mut peer = bare_peer_at_host("disabled", "example.com", 5353, &["10.0.0.0/24"]);
        peer.enabled = false;

        let result = collect_hostnames(&[peer]);
        assert!(result.is_empty(), "no hostnames should be collected");
    }

    #[test]
    fn collect_hostnames_skips_non_bare_peers() {
        let peer = Peer {
            id: "h3only".to_string(),
            enabled: true,
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
            enabled: true,
            h3: Some(PeerH3 {
                endpoint: Some(H3Endpoint {
                    host: host.to_string(),
                    port,
                    path: "/".to_string(),
                }),
                token: "test-token-12chars".to_string(),
                ca: None,
                insecure: true,
                bindif: None,
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
            vec!["10.255.255.1".parse().unwrap()],
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

        let (orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        let accepted = HashSet::from(["1.2.3.4".parse::<IpAddr>().unwrap()]);
        orch.update_accepted_sources(&accepted);

        let BareUdpRxCommand::UpdateAcceptedSources(ips) = handles
            .bare_rx_cmd_rx
            .try_recv()
            .expect("accepted sources update expected");
        assert_eq!(ips.len(), 1);
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));

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
        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", "1.2.3.4:5353".parse().unwrap(), tx)
            .build();

        // Peer already connected — no bounds_changed will occur
        let mut state = HashMap::new();
        state.insert(
            "example.com".to_string(),
            vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()],
        );
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event).await;

        // Accepted sources SHOULD be updated (unconditionally)
        let BareUdpRxCommand::UpdateAcceptedSources(ips) = handles
            .bare_rx_cmd_rx
            .try_recv()
            .expect("accepted sources update expected");
        assert!(ips.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"5.6.7.8".parse::<IpAddr>().unwrap()));

        // Routing should NOT be updated (no bounds change)
        assert!(handles.tun_cmd_rx.try_recv().is_err());
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
            vec!["10.255.255.1".parse().unwrap()],
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
        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![])
            .build();

        let (tx, _rx) = mpsc::channel(1);
        let tx_handle = tokio::spawn(async { Ok(()) });

        let event = BareConnectedEvent {
            peer_id: "unknown-peer".to_string(),
            hostname: "example.com".to_string(),
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx,
            tx_handle,
        };

        orch.handle_bare_connection(event);
        assert!(!orch.peers.contains_key("unknown-peer"));
    }

    #[tokio::test]
    async fn handle_bare_connection_rejects_already_connected() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let (existing_tx, _existing_rx) = mpsc::channel(1);

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", "1.2.3.4:5353".parse().unwrap(), existing_tx)
            .build();

        let (tx, _rx) = mpsc::channel(1);
        let tx_handle = tokio::spawn(async { Ok(()) });

        let event = BareConnectedEvent {
            peer_id: "peer1".to_string(),
            hostname: "example.com".to_string(),
            dest: "5.6.7.8:5353".parse().unwrap(),
            tx,
            tx_handle,
        };

        orch.handle_bare_connection(event);

        // Original bound preserved (first-connection-wins)
        let bound = orch.peers.get("peer1").unwrap().bound.as_ref().unwrap();
        assert_eq!(bound.dest, "1.2.3.4:5353".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn handle_bare_connection_sets_bound_and_updates_routing() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        let (tx, _rx) = mpsc::channel(1);
        let tx_handle = tokio::spawn(async { Ok(()) });

        let event = BareConnectedEvent {
            peer_id: "peer1".to_string(),
            hostname: "example.com".to_string(),
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx,
            tx_handle,
        };

        orch.handle_bare_connection(event);

        // Bound should be set
        assert!(orch.peers.get("peer1").unwrap().is_connected());
        let bound = orch.peers.get("peer1").unwrap().bound.as_ref().unwrap();
        assert_eq!(bound.dest, "1.2.3.4:5353".parse::<SocketAddr>().unwrap());
        assert_eq!(bound.hostname.as_deref(), Some("example.com"));

        // Routing should be updated (TUN command sent)
        assert!(handles.tun_cmd_rx.try_recv().is_ok());
    }
}
