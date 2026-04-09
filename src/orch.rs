//! Runtime orchestration for `BareUDP` and HTTP/3 transports.

use crate::actor::{ActorError, ActorExitResult, DedicatedRuntime, SupervisionPolicy};
use crate::api;
use crate::bare::{dial_bare_tx, make_bare_rx, spawn_bare_rx, BareUdpRxCommand};
use crate::bind::{DefaultRouteProbe, RouteProbe};
use crate::config::{validate_peers, Config, ConfigError, Local, Peer, PeerTransport, Tuning};
use crate::dns::{make_dns, spawn_dns, DnsCommand};
use crate::events::{
    ApiEvent, ConnectedEvent, DialContext, DialFailedEvent, DnsEvent, Endpoint, Event,
};
use crate::h3dialer::dial_h3_client;
use crate::h3listener::{make_h3_dispatcher, spawn_h3_dispatcher, DispatcherCommand};
use crate::metrics::{log_quic_metrics, log_transport_metrics, Direction, Labels, Metrics};
use crate::route::{make_route, spawn_route, RouteCommand};
use crate::router::{spawn_router, RouterCommand, RoutingTable};
use crate::tun;
use ipnet::IpNet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::ops::ControlFlow;
use std::path::Path;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_quiche::buf_factory::PooledBuf;
use tracing::{debug, error, info, warn};

/// A single active connection bound to a peer.
#[derive(Debug)]
struct ActiveConn {
    /// Configured endpoint that originated this connection.
    ///
    /// `None` for listener-originated (inbound) connections.
    endpoint: Option<Endpoint>,
    /// Destination socket address.
    dest: SocketAddr,
    /// TX channel for sending packet batches.
    tx: mpsc::Sender<Vec<PooledBuf>>,
    /// Latest cumulative RX metrics for this connection.
    rx_metrics: Option<Metrics>,
    /// Latest cumulative TX metrics for this connection.
    tx_metrics: Option<Metrics>,
}

/// Per-IP dial state for tracking in-flight connections and exponential backoff.
///
/// Created when a dial attempt is initiated for a specific IP.
/// Removed when `update_bound` registers a successful outbound connection.
#[derive(Debug)]
struct DialState {
    /// Number of consecutive failed dial attempts (reset on success via removal).
    attempt: u32,
    /// Earliest instant at which the next dial attempt is permitted.
    next_allowed_at: Instant,
    /// Whether a dial task is currently in flight for this IP.
    in_flight: bool,
}

impl DialState {
    /// Creates initial dial state with in-flight flag set.
    fn new_in_flight() -> Self {
        Self {
            attempt: 0,
            next_allowed_at: Instant::now(),
            in_flight: true,
        }
    }

    /// Records a dial failure: clears in-flight, increments attempt, and
    /// computes the next allowed time using capped exponential backoff.
    fn record_failure(&mut self, backoff_min: Duration, backoff_max: Duration) {
        self.in_flight = false;
        // delay = min(max, min * 2^attempt); first failure (attempt 0) → backoff_min.
        let multiplier = 1u32.checked_shl(self.attempt.min(30)).unwrap_or(u32::MAX);
        let delay = std::cmp::min(backoff_max, backoff_min.saturating_mul(multiplier));
        self.attempt = self.attempt.saturating_add(1);
        self.next_allowed_at = Instant::now() + delay;
    }
}

/// Entry for a single peer in the unified pool.
#[derive(Debug)]
struct PeerEntry {
    /// Peer configuration (read-only after creation).
    config: Peer,
    /// Active connections for this peer, ordered by preference (first = preferred TX).
    bounds: Vec<ActiveConn>,
    /// Current DNS-resolved IPs for this peer's endpoint.
    resolved_ips: HashSet<IpAddr>,
    /// Per-IP dial tracking: in-flight status, attempt count, and backoff timing.
    ///
    /// An entry exists while a dial is in progress or has failed with pending backoff.
    /// Removed on successful connection registration via `update_bound`.
    dials: HashMap<IpAddr, DialState>,
}

impl PeerEntry {
    /// Creates a new peer entry from configuration.
    fn new(config: Peer) -> Self {
        Self {
            config,
            bounds: Vec::new(),
            resolved_ips: HashSet::new(),
            dials: HashMap::new(),
        }
    }

    /// Returns the preferred TX channel (first bound) or `None` if no active connections.
    fn preferred_tx(&self) -> Option<&mpsc::Sender<Vec<PooledBuf>>> {
        self.bounds.first().map(|b| &b.tx)
    }

    /// Returns the current config endpoint as an `Endpoint` enum, if configured.
    fn config_endpoint(&self) -> Option<Endpoint> {
        match &self.config.transport {
            PeerTransport::Bare(bare) => Some(Endpoint::Udp(bare.endpoint.clone())),
            PeerTransport::H3(h3) => h3.endpoint.as_ref().map(|ep| Endpoint::H3(ep.clone())),
        }
    }

    /// Removes invalid bounds and returns whether the first (preferred) TX changed.
    ///
    /// A bound is invalid if:
    /// - Its TX channel is closed (actor exited).
    /// - Its endpoint is `Some` but differs from the current config endpoint (reconfig).
    /// - Its endpoint is `Some` and its dest IP is not in `resolved_ips` (DNS changed).
    fn prune(&mut self) -> bool {
        let old_first_tx = self.bounds.first().map(|b| b.tx.clone());
        let config_ep = self.config_endpoint();

        let peer_id = &self.config.id;
        self.bounds.retain(|bound| {
            // TX channel closed -> remove
            if bound.tx.is_closed() {
                info!(peer = %peer_id, dest = %bound.dest, "pruned: tx channel closed");
                return false;
            }
            // Inbound connections (endpoint: None) are never pruned by DNS/endpoint checks
            let Some(ref bound_ep) = bound.endpoint else {
                return true;
            };
            // Endpoint changed (dynamic reconfig)
            if config_ep.as_ref() != Some(bound_ep) {
                info!(peer = %peer_id, dest = %bound.dest, "pruned: endpoint changed");
                return false;
            }
            // Dest IP no longer in resolved_ips (DNS changed)
            if !self.resolved_ips.contains(&bound.dest.ip()) {
                info!(peer = %peer_id, dest = %bound.dest, "pruned: IP no longer in DNS");
                return false;
            }
            true
        });

        // Clean up dial state for IPs no longer in resolved_ips to prevent
        // stale backoff from blocking reconnection when DNS re-resolves an IP.
        self.dials.retain(|ip, _| self.resolved_ips.contains(ip));

        match (&old_first_tx, self.bounds.first()) {
            (Some(old), Some(new)) => !old.same_channel(&new.tx),
            (None, None) => false,
            _ => true,
        }
    }

    /// Spawns connections for resolved IPs not already covered by an existing bound
    /// or blocked by in-flight / backoff state.
    ///
    /// Per-IP rate-limited: skips IPs with an in-flight dial or whose backoff
    /// `next_allowed_at` has not yet elapsed. Does nothing if `resolved_ips` is empty.
    #[allow(clippy::too_many_arguments)]
    fn try_connect(
        &mut self,
        events_tx: &mpsc::UnboundedSender<Event>,
        tun_if: &str,
        tun_mtu: u16,
        tuning: &Tuning,
        udp_handle: &Handle,
        crypto_handle: &Handle,
        ingress_tx: &mpsc::Sender<Vec<PooledBuf>>,
    ) {
        if self.resolved_ips.is_empty() {
            return;
        }

        let covered_ips: HashSet<IpAddr> = self.bounds.iter().map(|b| b.dest.ip()).collect();

        let uncovered: Vec<IpAddr> = self
            .resolved_ips
            .difference(&covered_ips)
            .copied()
            .filter(|ip| match self.dials.get(ip) {
                Some(state) if state.in_flight => {
                    debug!(ip = %ip, "skipping dial: in-flight");
                    false
                }
                Some(state) if Instant::now() < state.next_allowed_at => {
                    debug!(ip = %ip, "skipping dial: backoff active");
                    false
                }
                _ => true,
            })
            .collect();

        if uncovered.is_empty() {
            return;
        }

        let peer_id = self.config.id.clone();

        for ip in &uncovered {
            // Mark in-flight (preserving attempt count from prior failures)
            let attempt = self.dials.get(ip).map_or(0, |s| s.attempt);
            self.dials
                .entry(*ip)
                .and_modify(|s| s.in_flight = true)
                .or_insert_with(DialState::new_in_flight);
            info!(peer = %self.config.id, ip = %ip, attempt, "dialing peer");

            let ctx = DialContext {
                peer_id: peer_id.clone(),
                dial_ip: *ip,
                tun_if: tun_if.to_string(),
                tun_mtu,
                tuning: tuning.clone(),
                probe: DefaultRouteProbe,
                udp_rt: udp_handle.clone(),
                crypto_rt: crypto_handle.clone(),
                events_tx: events_tx.clone(),
            };

            match &self.config.transport {
                PeerTransport::Bare(bare) => {
                    let bare = bare.clone();
                    tokio::spawn(async move {
                        let result = dial_bare_tx(&bare, &ctx).await;
                        report_dial(result, ctx, "bare");
                    });
                }
                PeerTransport::H3(h3) => {
                    let peer_h3 = h3.clone();
                    let ingress_tx = ingress_tx.clone();
                    tokio::spawn(async move {
                        let result = dial_h3_client(&peer_h3, &ctx, ingress_tx).await;
                        report_dial(result, ctx, "H3");
                    });
                }
            }
        }
    }
}

/// Returns the DNS hostname for a peer's configured endpoint, if any.
///
/// Extracts the hostname from `BareUDP` or H3 endpoint configuration,
/// stripping IPv6 brackets from H3 hosts.
fn peer_dns_hostname(peer: &Peer) -> Option<&str> {
    match &peer.transport {
        PeerTransport::Bare(bare) => Some(&bare.endpoint.host),
        PeerTransport::H3(h3) => h3.endpoint.as_ref().map(|ep| strip_ipv6_brackets(&ep.host)),
    }
}

/// Reports a dial outcome to the orchestrator via the event channel.
///
/// Logs the result and sends [`Event::Connected`] on success or
/// [`Event::DialFailed`] on failure.
fn report_dial<E: std::fmt::Display, P: RouteProbe>(
    result: Result<ConnectedEvent, E>,
    ctx: DialContext<P>,
    protocol: &str,
) {
    match result {
        Ok(event) => {
            info!(peer = %event.peer_id, addr = %event.remote_addr, protocol, "connected");
            let _ = ctx.events_tx.send(Event::Connected(event));
        }
        Err(err) => {
            warn!(peer = %ctx.peer_id, ip = %ctx.dial_ip, error = %err, protocol, "dial failed");
            let _ = ctx.events_tx.send(Event::DialFailed(DialFailedEvent {
                peer_id: ctx.peer_id,
                ip: ctx.dial_ip,
            }));
        }
    }
}

/// Errors returned by the orchestrator.
#[derive(Debug, Error)]
pub enum OrchestratorError {
    /// `BareUDP` listen host could not be resolved.
    #[error("failed to resolve bare listen host '{host}': {reason}")]
    ListenResolveFailed { host: String, reason: String },
    /// HTTP/3 listener failed to start.
    #[error("h3 listener failed: {0}")]
    H3Listener(String),
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
    /// Dedicated runtime creation failed.
    #[error("dedicated runtime '{name}' failed: {source}")]
    Runtime {
        name: String,
        source: std::io::Error,
    },
    /// An actor exited with an error.
    #[error("actor error: {0}")]
    ActorError(#[from] ActorError),
    /// A runtime task failed to join (panic or cancel).
    #[error("runtime task join failed: {0}")]
    TaskJoin(String),
}

/// Runtime orchestrator for `BareUDP` and HTTP/3 transports.
///
/// Manages child actors with selective supervision:
/// - Critical actors (TUN, BareUDP-Rx, H3-Listener): failure causes immediate exit
/// - Peer actors (BareUDP-Tx, H3-Engine): failure triggers maintenance cycle (prune + reconnect)
pub struct Orchestrator {
    events_rx: mpsc::UnboundedReceiver<Event>,
    events_tx: mpsc::UnboundedSender<Event>,
    join_set: JoinSet<Result<ActorExitResult, tokio::task::JoinError>>,

    // Runtime state
    tun_if: String,
    tun_mtu: u16,
    /// Tuning parameters from config.
    tuning: Tuning,
    /// Unified peer state: config + active bound.
    peers: HashMap<String, PeerEntry>,
    router_cmd_tx: mpsc::UnboundedSender<RouterCommand>,
    ingress_tx: mpsc::Sender<Vec<PooledBuf>>,
    bare_rx_cmd_tx: Option<mpsc::UnboundedSender<BareUdpRxCommand>>,
    /// H3v2 listener command sender (if listening).
    h3_listener_cmd_tx: Option<mpsc::UnboundedSender<DispatcherCommand>>,

    /// DNS resolver command sender for `SetHostnames`.
    dns_cmd_tx: mpsc::UnboundedSender<DnsCommand>,

    /// Route sync actor command sender (None when `local.table` is false or init failed).
    route_cmd_tx: Option<mpsc::UnboundedSender<RouteCommand>>,
    /// Input channel (TUN TX) for local host routes in the routing table.
    input_tx: mpsc::Sender<Vec<PooledBuf>>,
    /// Stored local config (TUN addrs, routing, GET /config snapshot).
    local: Local,

    /// Metrics from non-peer-scoped actors (TUN RX/TX, `BareUDP` RX).
    ///
    /// At most 3 entries. Peer-scoped metrics live in `ActiveConn`.
    non_peer_metrics: HashMap<Labels, Metrics>,

    /// Dedicated runtime for TUN Tx/Rx actors (thread: `h3llo-tun`).
    ///
    /// Not read after init — kept alive for its `Drop` impl (RAII shutdown).
    _tun_rt: DedicatedRuntime,
    /// Router + H3 Engine actors (thread: `h3llo-crypto`).
    crypto_rt: DedicatedRuntime,
    /// All UDP I/O actors: `BareUDP` + H3 (thread: `h3llo-udp`).
    udp_rt: DedicatedRuntime,
}

impl Orchestrator {
    /// Updates `BareUDP` RX accepted source filter.
    ///
    /// Sends the new set of accepted source IPs to the `BareUDP` RX actor.
    /// No-op when `BareUDP` is not configured (`bare_rx_cmd_tx` is `None`).
    fn update_accepted_sources(&self) {
        if let Some(cmd_tx) = &self.bare_rx_cmd_tx {
            let accepted_ips: HashSet<IpAddr> = self
                .peers
                .values()
                .filter(|e| matches!(e.config.transport, PeerTransport::Bare(_)))
                .flat_map(|e| e.resolved_ips.iter().copied())
                .collect();
            if let Err(e) = cmd_tx.send(BareUdpRxCommand::UpdateAcceptedSources(accepted_ips)) {
                warn!(error = %e, "failed to send accepted sources update to bare_rx actor");
            }
        }
    }

    /// Synchronizes peer-derived state to downstream actors (H3 listener, DNS).
    ///
    /// Called after any peer set mutation to fan out the latest snapshot.
    fn sync_peers_to_actors(&self) {
        // H3 listener: peer tokens
        if let Some(cmd_tx) = &self.h3_listener_cmd_tx {
            let tokens = self
                .peers
                .values()
                .filter_map(|p| match &p.config.transport {
                    PeerTransport::H3(h3) => Some((p.config.id.clone(), h3.token.clone())),
                    PeerTransport::Bare(_) => None,
                })
                .collect::<HashMap<_, _>>();

            if let Err(e) = cmd_tx.send(DispatcherCommand::UpdatePeerTokens(tokens)) {
                warn!(error = %e, "failed to send peer tokens update to h3_listener actor");
            }
        }

        // DNS: hostnames
        let peer_configs = self.peer_configs();
        let hostnames = collect_hostnames(&peer_configs);
        if let Err(e) = self
            .dns_cmd_tx
            .send(DnsCommand::SetHostnames { hosts: hostnames })
        {
            warn!(error = %e, "failed to send hostnames update to DNS actor");
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
        match RoutingTable::make(&peer_configs, &peer_txs, &self.local.tun, &self.input_tx) {
            Ok(routing) => {
                if let Err(e) = self
                    .router_cmd_tx
                    .send(RouterCommand::UpdateRouting { routing })
                {
                    warn!(error = %e, "failed to send routing update to router actor; routing may be stale");
                }
            }
            Err(e) => {
                error!(error = %e, "routing table build failed; routing NOT updated");
            }
        }

        if let Some(route_cmd_tx) = &self.route_cmd_tx {
            let allowed = collect_allowed_ips(&peer_configs);
            if let Err(e) = route_cmd_tx.send(RouteCommand::SyncRoutes {
                tun_addrs: self.local.tun.addrs.clone(),
                allowed,
            }) {
                warn!(error = %e, "failed to send route sync command to route actor");
            }
        }
    }

    /// Returns peer configurations as a Vec (for routing table and route sync).
    fn peer_configs(&self) -> Vec<Peer> {
        self.peers.values().map(|e| e.config.clone()).collect()
    }

    /// Creates a new orchestrator from configuration.
    ///
    /// Initializes TUN interface, transport listeners (`BareUDP` and/or H3),
    /// routing table, and spawns child actors. Listen hostnames are resolved
    /// synchronously; peer hostnames are resolved asynchronously via the event loop.
    ///
    /// # Errors
    ///
    /// Returns `OrchestratorError` when initialization fails.
    ///
    /// # Panics
    ///
    /// Panics if dedicated I/O runtimes cannot be created.
    pub async fn new(config: Config) -> Result<Self, OrchestratorError> {
        let tuning = &config.tuning;
        let tun_if = config.local.tun.ifname.clone();
        let tun_mtu = config.local.tun.mtu;
        let manage_routes = config.local.table;

        // Create dedicated current_thread runtimes for data-plane actors.
        // Each runtime runs on its own OS thread, eliminating cross-thread
        // task migration on data-plane hot paths (thread-per-core).
        let make_runtime = |name: &str| {
            DedicatedRuntime::new(name).map_err(|source| OrchestratorError::Runtime {
                name: name.to_string(),
                source,
            })
        };
        let tun_rt = make_runtime("h3llo-tun")?;
        let crypto_rt = make_runtime("h3llo-crypto")?;
        let udp_rt = make_runtime("h3llo-udp")?;

        // Setup TUN — enter guard ensures AsyncFd registers with the TUN
        // runtime's I/O reactor. make_tun is async in signature but has no
        // internal .await points, so the guard stays effective.
        let (tun_reader, tun_writer) = {
            let _guard = tun_rt.handle().enter();
            tun::make_tun(
                &config.local.tun,
                tuning.io.tun_tx_queue_len,
                tuning.io.tun_enable_offload,
            )
            .map_err(|err| OrchestratorError::Tun(err.to_string()))?
        };

        // Control plane: unbounded to prevent deadlocks from actor cycles.
        let (events_tx, events_rx) = mpsc::unbounded_channel();

        let mut join_set = JoinSet::new();

        // Start with empty routing table; routes populated as DNS answers arrive
        let routing = RoutingTable::new();

        // RUNTIME CONTEXT: All spawn_* calls below MUST be wrapped in a
        // Handle::enter() guard targeting the correct dedicated runtime.
        // The guard sets the thread-local runtime context; tokio::spawn
        // inside the called function picks up this context. All spawn_*
        // functions are synchronous (no .await crossing).

        // TUN-Tx on TUN runtime (sync fn — enter guard is safe, no .await).
        let (input_tx, tun_tx_handle) = {
            let _guard = tun_rt.handle().enter();
            tun::spawn_tun_tx(tun_writer, events_tx.clone(), &tuning.io)
        };

        // Router on crypto runtime (sync fn — enter guard is safe, no .await).
        let (output_tx, ingress_tx, router_cmd_tx, router_handle) = {
            let _guard = crypto_rt.handle().enter();
            spawn_router(
                routing,
                input_tx.clone(),
                events_tx.clone(),
                tuning.io.metrics_push_interval,
                tuning.io.packet_queue_depth,
            )
        };

        // TUN-Rx on TUN runtime (sync fn — enter guard is safe, no .await).
        let tun_rx_handle = {
            let _guard = tun_rt.handle().enter();
            tun::spawn_tun_rx(tun_reader, output_tx, events_tx.clone(), &tuning.io)
        };

        join_set.spawn(tun_tx_handle);
        join_set.spawn(router_handle);
        join_set.spawn(tun_rx_handle);

        // Initialize BareUDP listener if configured
        let bare_rx_cmd_tx = if let Some(ref local_bare) = config.local.bare {
            let listen_addr = resolve_listen_addr(&local_bare.listen.host, local_bare.listen.port)?;

            let udp_rx = make_bare_rx(listen_addr, tun_mtu, tuning, udp_rt.handle())
                .map_err(|err| OrchestratorError::Udp(err.to_string()))?;

            let (cmd_tx, bare_rx_handle, udp_rx_handle) = spawn_bare_rx(
                udp_rx,
                HashSet::new(),
                ingress_tx.clone(),
                events_tx.clone(),
                tuning,
                udp_rt.handle(),
                crypto_rt.handle(),
            );

            join_set.spawn(udp_rx_handle);
            join_set.spawn(bare_rx_handle);
            Some(cmd_tx)
        } else {
            None
        };

        // Initialize H3 dispatcher if configured (dispatcher on crypto_rt, UDP I/O on udp_rt)
        let h3_listener_cmd_tx = if let Some(ref h3_cfg) = config.local.h3 {
            let listen_addr = resolve_listen_addr(&h3_cfg.listen.host, h3_cfg.listen.port)?;
            let cert_path = Path::new(&h3_cfg.cert);
            let key_path = Path::new(&h3_cfg.key);

            // make: fallible I/O (socket bind, TLS config, UDP actor setup)
            let (dispatcher, _bound_addr) = make_h3_dispatcher(
                listen_addr,
                cert_path,
                key_path,
                tun_mtu,
                &tuning.io,
                &tuning.h3,
                udp_rt.handle(),
                ingress_tx.clone(),
                events_tx.clone(),
            )
            .map_err(|e| OrchestratorError::H3Listener(e.to_string()))?;

            // spawn: infallible task creation
            // Initial peer tokens are empty; sync_peers_to_actors() populates them
            // immediately after construction.
            let (cmd_tx, dispatcher_handle, udp_rx_handle, udp_tx_handle, _) = spawn_h3_dispatcher(
                dispatcher,
                HashMap::new(),
                udp_rt.handle(),
                crypto_rt.handle(),
            );

            join_set.spawn(dispatcher_handle);
            join_set.spawn(udp_rx_handle);
            join_set.spawn(udp_tx_handle);
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
            warn!(
                configured = config.peers.len(),
                "no active peers; traffic will be dropped"
            );
        }

        // Initialize management API if configured
        if let Some(ref local_api) = config.local.api {
            let api_listen_addr =
                resolve_listen_addr(&local_api.listen.host, local_api.listen.port)?;
            let api_listener = api::make_api(api_listen_addr)
                .await
                .map_err(|e| OrchestratorError::ApiInit(e.to_string()))?;
            let api_handle = api::spawn_api(
                api_listener,
                local_api.listen.path.clone(),
                events_tx.clone(),
            );
            join_set.spawn(api_handle);
        }

        let orch = Self {
            events_rx,
            events_tx,
            join_set,
            tun_if,
            tun_mtu,
            tuning: config.tuning,
            peers,
            router_cmd_tx,
            ingress_tx,
            bare_rx_cmd_tx,
            h3_listener_cmd_tx,
            dns_cmd_tx,
            route_cmd_tx,
            input_tx,
            local: config.local,
            non_peer_metrics: HashMap::new(),
            _tun_rt: tun_rt,
            crypto_rt,
            udp_rt,
        };
        orch.sync_peers_to_actors();
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
        // Reconcile at the configured interval to detect closed channels and
        // attempt reconnection for uncovered IPs.
        let mut reconcile_ticker = tokio::time::interval(self.tuning.reconcile_interval);
        let mut metrics_log_ticker = tokio::time::interval(self.tuning.metrics_log_interval);
        loop {
            tokio::select! {
                Some(event) = self.events_rx.recv() => {
                    self.handle_event(event);
                }
                _ = reconcile_ticker.tick() => {
                    self.reconcile();
                }
                _ = metrics_log_ticker.tick() => {
                    log_quic_metrics();
                    for m in self.collect_metrics_snapshot().values() {
                        log_transport_metrics(m);
                    }
                }
                result = self.join_set.join_next() => {
                    if let ControlFlow::Break(outcome) = self.handle_actor_exit(result) {
                        return outcome;
                    }
                }
                result = tokio::signal::ctrl_c() => {
                    match result {
                        Ok(()) => {
                            info!("shutdown signal received, stopping...");
                            break;
                        }
                        Err(e) => {
                            error!("signal handler error (process may be unkillable): {e}");
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Handles the result of a completed actor task from the join set.
    ///
    /// Returns `ControlFlow::Continue` to keep the event loop running,
    /// or `ControlFlow::Break` with the final result to exit.
    fn handle_actor_exit(
        &mut self,
        result: Option<
            Result<Result<ActorExitResult, tokio::task::JoinError>, tokio::task::JoinError>,
        >,
    ) -> ControlFlow<Result<(), OrchestratorError>> {
        let Some(result) = result else {
            // All actors have exited
            return ControlFlow::Break(Ok(()));
        };

        // Flatten the two JoinError layers (outer from JoinSet, inner from nested spawn)
        let actor_result = match result {
            Ok(Ok(r)) => r,
            Ok(Err(join_err)) | Err(join_err) => {
                error!("task join failed (panic/cancel): {}", join_err);
                return ControlFlow::Break(Err(OrchestratorError::TaskJoin(join_err.to_string())));
            }
        };

        match actor_result {
            Ok(()) => {
                info!("an actor exited gracefully; reconciling peer state");
                self.reconcile();
            }
            Err(actor_error) => match actor_error.kind() {
                SupervisionPolicy::Critical => {
                    error!("critical actor failed: {}", actor_error);
                    return ControlFlow::Break(Err(OrchestratorError::ActorError(actor_error)));
                }
                SupervisionPolicy::Restartable => {
                    warn!("peer actor failed: {}; reconciling", actor_error);
                    self.reconcile();
                }
            },
        }
        ControlFlow::Continue(())
    }

    /// Periodic reconciliation: prune stale bounds and attempt reconnection.
    fn reconcile(&mut self) {
        let udp_handle = self.udp_rt.handle().clone();
        let crypto_handle = self.crypto_rt.handle().clone();
        let mut routing_changed = false;
        for entry in self.peers.values_mut() {
            routing_changed |= entry.prune();
            entry.try_connect(
                &self.events_tx,
                &self.tun_if,
                self.tun_mtu,
                &self.tuning,
                &udp_handle,
                &crypto_handle,
                &self.ingress_tx,
            );
        }
        if routing_changed {
            self.update_routing();
        }
    }

    /// Collects all transport metrics from `ActiveConn` and non-peer sources into a snapshot.
    ///
    /// Called on Prometheus scrape (`GetMetricsSnapshot`) and periodic metrics logging.
    /// Only includes metrics from currently live connections — pruned bounds are absent.
    fn collect_metrics_snapshot(&self) -> HashMap<Labels, Metrics> {
        let mut snapshot = self.non_peer_metrics.clone();
        snapshot.extend(
            self.peers
                .values()
                .flat_map(|e| &e.bounds)
                .flat_map(|b| [&b.rx_metrics, &b.tx_metrics])
                .flatten()
                .map(|m| (m.labels.clone(), m.clone())),
        );
        snapshot
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
            ApiEvent::GetMetricsSnapshot { reply_tx } => {
                let _ = reply_tx.send(self.collect_metrics_snapshot());
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

        self.sync_peers_to_actors();
        info!(count = count, "API: peers upserted");
        Ok(())
    }

    /// Handles DELETE /config — remove peers by ID.
    fn handle_delete_config(&mut self, peer_ids: &[String]) {
        let before = self.peers.len();
        for id in peer_ids {
            if self.peers.remove(id).is_some() {
                info!(peer = %id, "API: peer removed");
            }
        }
        if self.peers.len() < before {
            self.sync_peers_to_actors();
        }
    }

    /// Handles an event from a child actor.
    fn handle_event(&mut self, event: Event) {
        match event {
            Event::Dns(dns_event) => {
                self.handle_dns_snapshot(dns_event);
            }
            Event::Api(api_event) => {
                self.handle_api_event(api_event);
            }
            Event::Metrics(boxed) => {
                let metrics = *boxed;
                let labels = &metrics.labels;

                let (Some(pid), Some(addr)) = (labels.peer_id.as_deref(), labels.remote_addr)
                else {
                    // Non-peer-scoped (TUN, Router, BareUDP RX)
                    self.non_peer_metrics.insert(labels.clone(), metrics);
                    return;
                };

                let Some(bound) = self
                    .peers
                    .get_mut(pid)
                    .and_then(|entry| entry.bounds.iter_mut().find(|b| b.dest == addr))
                else {
                    warn!(
                        peer = %pid,
                        addr = %addr,
                        "metrics for unknown peer or bound (already removed/pruned?)"
                    );
                    return;
                };

                match labels.direction {
                    Direction::Rx => bound.rx_metrics = Some(metrics),
                    Direction::Tx => bound.tx_metrics = Some(metrics),
                }
            }
            Event::H3Connected(event) => {
                // Deprecated: old h3.rs path no longer used in production.
                // Kept for compilation compatibility while h3.rs exists.
                error!(
                    peer_id = %event.connection.peer_id,
                    "received old-style H3Connected event (h3.rs path); ignoring"
                );
            }
            Event::Connected(event) => {
                self.handle_connected(event);
            }
            Event::DialFailed(event) => {
                self.handle_dial_failed(&event);
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
        let udp_handle = self.udp_rt.handle().clone();
        let crypto_handle = self.crypto_rt.handle().clone();

        for entry in self.peers.values_mut() {
            let hostname = peer_dns_hostname(&entry.config);
            entry.resolved_ips = hostname
                .and_then(|h| dns_state.get(h))
                .cloned()
                .unwrap_or_default();

            entry.prune();
            entry.try_connect(
                &self.events_tx,
                &self.tun_if,
                self.tun_mtu,
                &self.tuning,
                &udp_handle,
                &crypto_handle,
                &self.ingress_tx,
            );
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
        // Clear dial state on successful outbound connection.
        // Inbound connections (endpoint: None) do not have dial state.
        let retries = endpoint
            .as_ref()
            .and_then(|_| entry.dials.remove(&dest.ip()))
            .map_or(0, |s| s.attempt);
        info!(peer = %peer_id, addr = %dest, retries, inbound = endpoint.is_none(), "connected");
        let was_empty = entry.bounds.is_empty();
        entry.bounds.push(ActiveConn {
            endpoint,
            dest,
            tx,
            rx_metrics: None,
            tx_metrics: None,
        });
        let first_changed = entry.prune();
        if was_empty || first_changed {
            self.update_routing();
        }
    }

    /// Handles a `BareUDP` TX connection event.
    ///
    /// Unconditionally registers the TX actor `JoinHandle` for lifecycle
    /// monitoring, then attempts to bind the peer via [`update_bound`].
    /// Handles a dial failure event: clears in-flight flag and updates backoff.
    fn handle_dial_failed(&mut self, event: &DialFailedEvent) {
        let Some(entry) = self.peers.get_mut(&event.peer_id) else {
            debug!(
                peer = %event.peer_id, ip = %event.ip,
                "dial failed for unknown peer (removed?)"
            );
            return;
        };
        if let Some(state) = entry.dials.get_mut(&event.ip) {
            state.record_failure(
                self.tuning.reconnect_backoff_min,
                self.tuning.reconnect_backoff_max,
            );
            warn!(
                peer = %event.peer_id, ip = %event.ip,
                attempt = state.attempt,
                next_allowed_at = ?state.next_allowed_at,
                "dial failed, backoff updated"
            );
        } else {
            debug!(
                peer = %event.peer_id, ip = %event.ip,
                "dial failed but no dial state found (already connected?)"
            );
        }
    }

    /// Handles a transport connection event (H3 or BareUDP).
    ///
    /// Spawns all present actor join handles into the [`JoinSet`] for
    /// lifecycle monitoring, then registers the TX bound via [`update_bound`].
    fn handle_connected(&mut self, event: ConnectedEvent) {
        let ConnectedEvent {
            peer_id,
            remote_addr,
            tx,
            endpoint,
            main_handle,
            udp_tx_handle,
            udp_rx_handle,
        } = event;

        if let Some(h) = main_handle {
            self.join_set.spawn(h);
        }
        if let Some(h) = udp_tx_handle {
            self.join_set.spawn(h);
        }
        if let Some(h) = udp_rx_handle {
            self.join_set.spawn(h);
        }

        self.update_bound(&peer_id, endpoint, remote_addr, tx);
    }
}

fn strip_ipv6_brackets(host: &str) -> &str {
    host.trim_start_matches('[').trim_end_matches(']')
}

/// Resolves a listen address from host and port, using synchronous DNS lookup for hostnames.
///
/// Handles IPv6 bracket notation (e.g., "[`::1`]" -> "`::1`") for compatibility with
/// both UDP and H3 endpoint formats.
fn resolve_listen_addr(host: &str, port: u16) -> Result<SocketAddr, OrchestratorError> {
    use std::net::ToSocketAddrs;

    // Strip IPv6 bracket notation (safe no-op for non-bracketed hosts)
    let host = strip_ipv6_brackets(host);

    // Fast path: IP literal
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // Synchronous DNS lookup for hostname
    let addr_str = format!("{host}:{port}");
    let mut addrs =
        addr_str
            .to_socket_addrs()
            .map_err(|err| OrchestratorError::ListenResolveFailed {
                host: host.to_string(),
                reason: err.to_string(),
            })?;

    let first = addrs
        .next()
        .ok_or_else(|| OrchestratorError::ListenResolveFailed {
            host: host.to_string(),
            reason: "no resolved addresses".to_string(),
        })?;
    if addrs.next().is_some() {
        warn!("listen resolved multiple addresses for {host}; using {first}");
    }
    Ok(first)
}

fn collect_allowed_ips(peers: &[Peer]) -> Vec<IpNet> {
    peers
        .iter()
        .flat_map(|peer| peer.tun.allowed_ips.iter().copied())
        .collect()
}

/// Collects all unique hostnames from peer configurations.
///
/// Handles both `BareUDP` and H3 endpoints. Endpoints are pre-parsed during
/// config deserialization, so this function cannot fail.
fn collect_hostnames(peers: &[Peer]) -> HashSet<String> {
    peers
        .iter()
        .filter_map(|peer| peer_dns_hostname(peer).map(str::to_string))
        .collect()
}

#[cfg(test)]
mod test_support {
    use super::*;
    use crate::config::{default_mtu, LocalDns, LocalTun};

    /// Test-only builder for creating an Orchestrator with injected dependencies.
    ///
    /// Bypasses all I/O operations (TUN creation, UDP binding, DNS spawning)
    /// to enable isolated unit testing of event handling logic.
    pub struct TestableOrchestratorBuilder {
        tun_if: String,
        tun_mtu: u16,
        peers: HashMap<String, PeerEntry>,
        local: Option<Local>,
    }

    impl Default for TestableOrchestratorBuilder {
        fn default() -> Self {
            Self {
                tun_if: "test0".to_string(),
                tun_mtu: default_mtu(),
                peers: HashMap::new(),
                local: None,
            }
        }
    }

    /// Test handles for verifying commands sent by the orchestrator.
    #[allow(dead_code)]
    pub struct TestHandles {
        pub events_tx: mpsc::UnboundedSender<Event>,
        pub router_cmd_rx: mpsc::UnboundedReceiver<RouterCommand>,
        pub bare_rx_cmd_rx: mpsc::UnboundedReceiver<BareUdpRxCommand>,
        pub dns_cmd_rx: mpsc::UnboundedReceiver<DnsCommand>,
        pub route_cmd_rx: mpsc::UnboundedReceiver<RouteCommand>,
        pub h3_listener_cmd_rx: mpsc::UnboundedReceiver<DispatcherCommand>,
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
                entry.bounds.push(ActiveConn {
                    endpoint,
                    dest,
                    tx,
                    rx_metrics: None,
                    tx_metrics: None,
                });
            }
            self
        }

        pub fn with_tun_addrs(mut self, addrs: Vec<IpNet>) -> Self {
            let local = self.local.get_or_insert_with(Self::default_local);
            local.tun.addrs = addrs;
            self
        }

        pub fn with_resolved_ips(mut self, peer_id: &str, ips: HashSet<IpAddr>) -> Self {
            if let Some(entry) = self.peers.get_mut(peer_id) {
                entry.resolved_ips = ips;
            }
            self
        }

        fn default_local() -> Local {
            Local {
                table: false,
                dns: LocalDns {
                    server: "1.1.1.1:53".parse().unwrap(),
                    bindif: None,
                },
                h3: None,
                bare: None,
                api: None,
                tun: LocalTun {
                    ifname: "test0".to_string(),
                    addrs: vec!["192.168.180.1/32".parse().unwrap()],
                    mtu: 1393,
                },
            }
        }

        /// Builds a testable orchestrator with dummy channels.
        ///
        /// Returns the orchestrator and test handles that allow verifying
        /// commands sent to child actors.
        pub fn build(self) -> (Orchestrator, TestHandles) {
            let (events_tx, events_rx) = mpsc::unbounded_channel();
            let (router_cmd_tx, router_cmd_rx) = mpsc::unbounded_channel();
            let (bare_rx_cmd_tx, bare_rx_cmd_rx) = mpsc::unbounded_channel();
            let (dns_cmd_tx, dns_cmd_rx) = mpsc::unbounded_channel();
            let (ingress_tx, _ingress_rx) = mpsc::channel(1);
            let (input_tx, _input_rx) = mpsc::channel(1);
            let (route_cmd_tx, route_cmd_rx) = mpsc::unbounded_channel();
            let (h3_listener_cmd_tx, h3_listener_cmd_rx) = mpsc::unbounded_channel();

            let local = self.local.unwrap_or_else(Self::default_local);

            let orch = Orchestrator {
                events_rx,
                events_tx: events_tx.clone(),
                join_set: JoinSet::new(),
                tun_if: self.tun_if,
                tun_mtu: self.tun_mtu,
                tuning: Tuning::default(),
                peers: self.peers,
                router_cmd_tx,
                bare_rx_cmd_tx: Some(bare_rx_cmd_tx),
                h3_listener_cmd_tx: Some(h3_listener_cmd_tx),
                ingress_tx,
                dns_cmd_tx,
                route_cmd_tx: Some(route_cmd_tx),
                input_tx,
                local,
                non_peer_metrics: HashMap::new(),
                _tun_rt: DedicatedRuntime::new("test-tun").expect("test runtime"),
                crypto_rt: DedicatedRuntime::new("test-crypto").expect("test runtime"),
                udp_rt: DedicatedRuntime::new("test-udp").expect("test runtime"),
            };

            (
                orch,
                TestHandles {
                    events_tx,
                    router_cmd_rx,
                    bare_rx_cmd_rx,
                    dns_cmd_rx,
                    route_cmd_rx,
                    h3_listener_cmd_rx,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::TestableOrchestratorBuilder;
    use super::*;
    use crate::config::{PeerBare, PeerH3, PeerTun, UdpEndpoint};
    use crate::events::DnsEvent;
    use crate::metrics::{Direction, Labels, Metrics, PktCounters, Source, Stats};

    // ========== PeerEntry unit tests ==========

    /// Helper to create test peers with BareUDP configuration.
    fn bare_peer(id: &str, allowed: &[&str]) -> Peer {
        Peer {
            id: id.to_string(),

            transport: PeerTransport::Bare(PeerBare {
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
        Peer {
            id: id.to_string(),

            transport: PeerTransport::Bare(PeerBare {
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
        Event::Metrics(Box::new(Metrics {
            labels: Labels {
                source: Source::Tun,
                direction: Direction::Rx,
                peer_id: None,
                remote_addr: None,
            },
            stats: Stats::default(),
        }))
    }

    #[test]
    fn orchestrator_error_includes_actor_context() {
        // Verify that OrchestratorError::ActorError includes actor context
        use std::io;

        let actor_err = ActorError::TunRxRecv {
            name: "tun0".to_string(),
            source: io::Error::other("test error"),
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

    #[test]
    fn collect_allowed_ips_handles_empty_peers() {
        let peers: Vec<Peer> = vec![];
        let result = collect_allowed_ips(&peers);
        assert!(result.is_empty());
    }

    // ========== OrchestratorError tests ==========

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

        orch.handle_event(make_metrics_event());

        // State preserved: existing entries not modified
        assert_eq!(orch.peers.len(), 1);
        assert!(orch.peers.contains_key("peer1"));
        assert!(!orch.peers.get("peer1").unwrap().bounds.is_empty());

        // No commands sent to child actors
        assert!(handles.router_cmd_rx.try_recv().is_err());
        assert!(handles.bare_rx_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_metrics_event_stores_snapshot() {
        let (mut orch, _handles) = TestableOrchestratorBuilder::default().build();
        assert!(orch.non_peer_metrics.is_empty());
        orch.handle_event(make_metrics_event());
        assert_eq!(orch.non_peer_metrics.len(), 1);
    }

    #[tokio::test]
    async fn handle_metrics_event_replaces_on_same_labels() {
        let (mut orch, _handles) = TestableOrchestratorBuilder::default().build();
        orch.handle_event(make_metrics_event());
        assert_eq!(orch.non_peer_metrics.len(), 1);

        // Push again with different values but same labels
        let event = Event::Metrics(Box::new(Metrics {
            labels: Labels {
                source: Source::Tun,
                direction: Direction::Rx,
                peer_id: None,
                remote_addr: None,
            },
            stats: Stats {
                succeeded: PktCounters {
                    packets: 42,
                    ..Default::default()
                },
                ..Default::default()
            },
        }));
        orch.handle_event(event);
        assert_eq!(orch.non_peer_metrics.len(), 1);
        let stored = orch.non_peer_metrics.values().next().unwrap();
        assert_eq!(stored.stats.succeeded.packets, 42);
    }

    /// Helper to create a peer-scoped metrics event for a specific bound.
    fn make_peer_metrics_event(
        peer_id: &str,
        remote_addr: SocketAddr,
        direction: Direction,
        packets: u64,
    ) -> Event {
        Event::Metrics(Box::new(Metrics {
            labels: Labels {
                source: Source::BareUdp,
                direction,
                peer_id: Some(peer_id.to_string()),
                remote_addr: Some(remote_addr),
            },
            stats: Stats {
                succeeded: PktCounters {
                    packets,
                    ..Default::default()
                },
                ..Default::default()
            },
        }))
    }

    #[tokio::test]
    async fn api_get_metrics_returns_prometheus_text() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let (tx, _rx) = mpsc::channel(1);
        let dest: SocketAddr = "1.2.3.4:5353".parse().unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", dest, tx)
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        // Add both non-peer and peer-scoped metrics
        orch.handle_event(make_metrics_event());
        orch.handle_event(make_peer_metrics_event("peer1", dest, Direction::Tx, 10));

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        orch.handle_api_event(ApiEvent::GetMetricsSnapshot { reply_tx });

        let snapshot = reply_rx.await.expect("should receive metrics snapshot");
        assert_eq!(snapshot.len(), 2);
        let text = crate::metrics::encode_metrics_snapshot(snapshot);
        assert!(
            text.contains("h3llo_transport_packets_total"),
            "missing packets metric: {text}"
        );
        assert!(
            text.contains("h3llo_transport_bytes_total"),
            "missing bytes metric: {text}"
        );
        assert!(
            text.contains("h3llo_transport_batches_total"),
            "missing batches metric: {text}"
        );
        assert!(text.contains("# EOF"), "missing EOF marker: {text}");
    }

    #[tokio::test]
    async fn handle_metrics_stores_in_bound_state() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let (tx, _rx) = mpsc::channel(1);
        let dest: SocketAddr = "1.2.3.4:5353".parse().unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", dest, tx)
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        let event = make_peer_metrics_event("peer1", dest, Direction::Tx, 100);
        orch.handle_event(event);

        let bound = &orch.peers.get("peer1").unwrap().bounds[0];
        assert!(bound.tx_metrics.is_some());
        assert_eq!(
            bound.tx_metrics.as_ref().unwrap().stats.succeeded.packets,
            100
        );
        assert!(bound.rx_metrics.is_none());

        let event = make_peer_metrics_event("peer1", dest, Direction::Rx, 50);
        orch.handle_event(event);

        let bound = &orch.peers.get("peer1").unwrap().bounds[0];
        assert!(bound.rx_metrics.is_some());
        assert_eq!(
            bound.rx_metrics.as_ref().unwrap().stats.succeeded.packets,
            50
        );

        assert!(orch.non_peer_metrics.is_empty());
    }

    #[tokio::test]
    async fn metrics_pruned_with_bound_state() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let (tx, rx) = mpsc::channel(1);
        let dest: SocketAddr = "1.2.3.4:5353".parse().unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", dest, tx)
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        let event = make_peer_metrics_event("peer1", dest, Direction::Tx, 100);
        orch.handle_event(event);

        let snapshot = orch.collect_metrics_snapshot();
        assert!(snapshot.values().any(|m| m.stats.succeeded.packets == 100));

        drop(rx);
        orch.peers.get_mut("peer1").unwrap().prune();

        let snapshot = orch.collect_metrics_snapshot();
        assert!(!snapshot.values().any(|m| m.stats.succeeded.packets == 100));
    }

    #[tokio::test]
    async fn collect_metrics_snapshot_combines_sources() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let (tx, _rx) = mpsc::channel(1);
        let dest: SocketAddr = "1.2.3.4:5353".parse().unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", dest, tx)
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        orch.handle_event(make_metrics_event());
        orch.handle_event(make_peer_metrics_event("peer1", dest, Direction::Tx, 200));

        let snapshot = orch.collect_metrics_snapshot();
        assert_eq!(snapshot.len(), 2);
    }

    #[tokio::test]
    async fn handle_metrics_warns_unknown_peer() {
        let (mut orch, _handles) = TestableOrchestratorBuilder::default().build();

        let event = make_peer_metrics_event(
            "nonexistent",
            "1.2.3.4:5353".parse().unwrap(),
            Direction::Tx,
            42,
        );
        orch.handle_event(event);

        assert!(orch.non_peer_metrics.is_empty());
        assert!(orch.collect_metrics_snapshot().is_empty());
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
        orch.handle_event(event);

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
            .router_cmd_rx
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
        orch.handle_event(event);

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
        orch.handle_event(event);

        // Accepted sources always updated (unconditionally), but empty since no hostname matched
        let cmd = handles
            .bare_rx_cmd_rx
            .try_recv()
            .expect("accepted sources always sent");
        assert_eq!(cmd, BareUdpRxCommand::UpdateAcceptedSources(HashSet::new()));
        // Routing always updated unconditionally
        handles
            .router_cmd_rx
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
        orch.handle_event(event);

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
        orch.handle_event(event);

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
            .bounds
            .push(ActiveConn {
                endpoint: None,
                dest,
                tx,
                rx_metrics: None,
                tx_metrics: None,
            });

        assert!(!orch.peers.get("peer1").unwrap().bounds.is_empty());

        // Send snapshot without the IP
        let mut state = HashMap::new();
        state.insert("example.com".to_string(), HashSet::new());
        let event = make_dns_snapshot_event(state);
        orch.handle_event(event);

        // Bound should remain (endpoint is None, so never pruned by DNS/endpoint checks)
        assert!(!orch.peers.get("peer1").unwrap().bounds.is_empty());
    }

    // ========== collect_hostnames helper function tests ==========

    #[test]
    fn collect_hostnames_deduplicates() {
        let peers = [
            bare_peer_at_host("peer1", "shared.example.com", 5353, &["10.0.0.0/24"]),
            bare_peer_at_host("peer2", "shared.example.com", 5354, &["172.16.0.0/16"]),
        ];

        let peer_configs = peers.to_vec();
        let result = collect_hostnames(&peer_configs);

        // Deduplicated to single hostname
        assert_eq!(result.len(), 1);
        assert!(result.contains("shared.example.com"));
    }

    #[test]
    fn collect_hostnames_skips_non_bare_peers() {
        let peer = Peer {
            id: "h3only".to_string(),
            transport: PeerTransport::H3(PeerH3 {
                endpoint: None,
                token: "test-token-12chars".to_string(),
                bindif: None,
                sni: None,
            }),
            tun: PeerTun {
                allowed_ips: vec![],
            },
        };

        let result = collect_hostnames(&[peer]);
        assert!(result.is_empty(), "no hostnames should be collected");
    }

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
        use crate::config::H3Endpoint;
        Peer {
            id: id.to_string(),

            transport: PeerTransport::H3(PeerH3 {
                endpoint: Some(H3Endpoint {
                    host: host.to_string(),
                    port,
                    path: "/".to_string(),
                }),
                token: "test-token-12chars".to_string(),
                bindif: None,
                sni: None,
            }),
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
        orch.handle_event(event);
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
        assert!(handles.router_cmd_rx.try_recv().is_err());
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
        assert!(handles.router_cmd_rx.try_recv().is_ok());

        // Accepted sources command should NOT be sent
        assert!(handles.bare_rx_cmd_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn update_routing_includes_local_tun_routes() {
        use crate::router::LOCAL_PEER_ID;

        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let (tx, _rx) = mpsc::channel(1);
        let (orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_peer_tx("peer1", "1.2.3.4:5353".parse().unwrap(), tx)
            .with_tun_addrs(vec!["10.0.0.1/24".parse().unwrap()])
            .build();

        orch.update_routing();

        let RouterCommand::UpdateRouting { routing } = handles
            .router_cmd_rx
            .try_recv()
            .expect("routing update expected");

        // Local host route should be present as /32
        let local_route = routing
            .lookup("10.0.0.1".parse().unwrap())
            .expect("local TUN address should be routable");
        assert_eq!(local_route.peer_id, LOCAL_PEER_ID);
        assert_eq!(
            local_route.prefix,
            "10.0.0.1/32".parse::<ipnet::IpNet>().unwrap()
        );

        // Other addresses in the subnet should route to the peer, not local
        let peer_route = routing
            .lookup("10.0.0.2".parse().unwrap())
            .expect("peer subnet should be routable");
        assert_eq!(peer_route.peer_id, "peer1");
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
        orch.handle_event(event);

        // Accepted sources SHOULD be updated (unconditionally, from resolved_ips)
        let BareUdpRxCommand::UpdateAcceptedSources(ips) = handles
            .bare_rx_cmd_rx
            .try_recv()
            .expect("accepted sources update expected");
        assert!(ips.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"5.6.7.8".parse::<IpAddr>().unwrap()));

        // Routing always updated unconditionally
        handles
            .router_cmd_rx
            .try_recv()
            .expect("routing update always sent");
    }

    // ========== Connected event handling tests ==========

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
        orch.handle_event(event);
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "handle_dns_snapshot blocked for {:?}, expected < 500ms",
            elapsed
        );
    }

    #[tokio::test]
    async fn handle_connected_rejects_unknown_peer() {
        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![])
            .build();

        let (tx, _rx) = mpsc::channel(1);
        let tx_handle = tokio::spawn(async { Ok(()) });
        let udp_tx_handle = tokio::spawn(async { Ok(()) });

        let event = ConnectedEvent {
            peer_id: "unknown-peer".to_string(),
            endpoint: Some(Endpoint::Udp(UdpEndpoint {
                host: "example.com".to_string(),
                port: 5353,
            })),
            remote_addr: "1.2.3.4:5353".parse().unwrap(),
            tx,
            main_handle: Some(tx_handle),
            udp_tx_handle: Some(udp_tx_handle),
            udp_rx_handle: None,
        };

        orch.handle_connected(event);
        assert!(!orch.peers.contains_key("unknown-peer"));
    }

    #[tokio::test]
    async fn handle_connected_appends_second_bound() {
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
        let udp_tx_handle = tokio::spawn(async { Ok(()) });

        let event = ConnectedEvent {
            peer_id: "peer1".to_string(),
            endpoint: Some(Endpoint::Udp(UdpEndpoint {
                host: "example.com".to_string(),
                port: 5353,
            })),
            remote_addr: "5.6.7.8:5353".parse().unwrap(),
            tx,
            main_handle: Some(tx_handle),
            udp_tx_handle: Some(udp_tx_handle),
            udp_rx_handle: None,
        };

        orch.handle_connected(event);

        // Both bounds should exist
        assert_eq!(orch.peers.get("peer1").unwrap().bounds.len(), 2);
        // First bound preserved
        assert_eq!(
            orch.peers.get("peer1").unwrap().bounds[0].dest,
            "1.2.3.4:5353".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn handle_connected_sets_bound_and_updates_routing() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        let (tx, _rx) = mpsc::channel(1);
        let tx_handle = tokio::spawn(async { Ok(()) });
        let udp_tx_handle = tokio::spawn(async { Ok(()) });

        let event = ConnectedEvent {
            peer_id: "peer1".to_string(),
            endpoint: Some(Endpoint::Udp(UdpEndpoint {
                host: "example.com".to_string(),
                port: 5353,
            })),
            remote_addr: "1.2.3.4:5353".parse().unwrap(),
            tx,
            main_handle: Some(tx_handle),
            udp_tx_handle: Some(udp_tx_handle),
            udp_rx_handle: None,
        };

        orch.handle_connected(event);

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
        assert!(handles.router_cmd_rx.try_recv().is_ok());
    }

    // ========== PeerEntry prune/try_connect tests ==========

    #[test]
    fn prune_removes_closed_tx() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);
        entry.resolved_ips.insert("1.2.3.4".parse().unwrap());

        let (tx, rx) = mpsc::channel(1);
        let ep = entry.config_endpoint();
        entry.bounds.push(ActiveConn {
            endpoint: ep,
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx,
            rx_metrics: None,
            tx_metrics: None,
        });

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
        let ep = entry.config_endpoint();
        entry.bounds.push(ActiveConn {
            endpoint: ep,
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx,
            rx_metrics: None,
            tx_metrics: None,
        });

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
        entry.bounds.push(ActiveConn {
            endpoint: ep.clone(),
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx: tx1,
            rx_metrics: None,
            tx_metrics: None,
        });
        entry.bounds.push(ActiveConn {
            endpoint: ep,
            dest: "5.6.7.8:5353".parse().unwrap(),
            tx: tx2,
            rx_metrics: None,
            tx_metrics: None,
        });

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
        entry.bounds.push(ActiveConn {
            endpoint: ep.clone(),
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx: tx1,
            rx_metrics: None,
            tx_metrics: None,
        });
        entry.bounds.push(ActiveConn {
            endpoint: ep,
            dest: "1.2.3.4:5353".parse().unwrap(),
            tx: tx2,
            rx_metrics: None,
            tx_metrics: None,
        });

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
        entry.bounds.push(ActiveConn {
            endpoint: None,
            dest: "9.8.7.6:12345".parse().unwrap(),
            tx,
            rx_metrics: None,
            tx_metrics: None,
        });

        let changed = entry.prune();
        assert!(!changed);
        assert_eq!(entry.bounds.len(), 1);
    }

    #[test]
    fn prune_cleans_up_stale_dial_state() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);

        let old_ip: IpAddr = "1.2.3.4".parse().unwrap();
        let new_ip: IpAddr = "5.6.7.8".parse().unwrap();

        // Insert dial state for old IP and set resolved_ips to new IP only.
        entry.dials.insert(old_ip, DialState::new_in_flight());
        entry.dials.insert(new_ip, DialState::new_in_flight());
        entry.resolved_ips.insert(new_ip);

        entry.prune();

        // old_ip dial state removed; new_ip dial state preserved.
        assert!(!entry.dials.contains_key(&old_ip));
        assert!(entry.dials.contains_key(&new_ip));
    }

    #[tokio::test]
    async fn try_connect_skips_in_flight() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        entry.resolved_ips.insert(ip);

        let (events_tx, _events_rx) = mpsc::unbounded_channel();

        // First call should mark IP as in-flight
        let (ingress_tx, _ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(1);
        entry.try_connect(
            &events_tx,
            "test0",
            1393,
            &Tuning::default(),
            &Handle::current(),
            &Handle::current(),
            &ingress_tx,
        );
        assert!(entry.dials.contains_key(&ip));
        assert!(entry.dials[&ip].in_flight);

        // Second immediate call should skip (in-flight)
        let attempt_before = entry.dials[&ip].attempt;
        let (ingress_tx, _ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(1);
        entry.try_connect(
            &events_tx,
            "test0",
            1393,
            &Tuning::default(),
            &Handle::current(),
            &Handle::current(),
            &ingress_tx,
        );
        assert_eq!(entry.dials[&ip].attempt, attempt_before);
    }

    #[tokio::test]
    async fn try_connect_skips_backoff_not_elapsed() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        entry.resolved_ips.insert(ip);

        entry.dials.insert(
            ip,
            DialState {
                attempt: 1,
                next_allowed_at: Instant::now() + Duration::from_secs(60),
                in_flight: false,
            },
        );

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let (ingress_tx, _ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(1);
        entry.try_connect(
            &events_tx,
            "test0",
            1393,
            &Tuning::default(),
            &Handle::current(),
            &Handle::current(),
            &ingress_tx,
        );

        assert!(!entry.dials[&ip].in_flight);
        assert_eq!(entry.dials[&ip].attempt, 1);
    }

    #[tokio::test]
    async fn try_connect_allows_after_backoff_elapsed() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let mut entry = PeerEntry::new(peer);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        entry.resolved_ips.insert(ip);

        entry.dials.insert(
            ip,
            DialState {
                attempt: 2,
                next_allowed_at: Instant::now() - Duration::from_secs(1),
                in_flight: false,
            },
        );

        let (events_tx, _events_rx) = mpsc::unbounded_channel();
        let (ingress_tx, _ingress_rx) = mpsc::channel::<Vec<PooledBuf>>(1);
        entry.try_connect(
            &events_tx,
            "test0",
            1393,
            &Tuning::default(),
            &Handle::current(),
            &Handle::current(),
            &ingress_tx,
        );

        // Should have re-triggered: in_flight set, attempt preserved
        assert!(entry.dials[&ip].in_flight);
    }

    #[test]
    fn dial_state_exponential_backoff() {
        let min = Duration::from_secs(3);
        let max = Duration::from_secs(60);
        let mut state = DialState::new_in_flight();

        state.record_failure(min, max);
        assert!(!state.in_flight);
        assert_eq!(state.attempt, 1); // delay = min(60, 3*1) = 3s

        state.record_failure(min, max);
        assert_eq!(state.attempt, 2); // delay = min(60, 3*2) = 6s

        state.record_failure(min, max);
        assert_eq!(state.attempt, 3); // delay = min(60, 3*4) = 12s
    }

    #[test]
    fn dial_state_backoff_caps_at_max() {
        let min = Duration::from_secs(3);
        let max = Duration::from_secs(60);
        let mut state = DialState::new_in_flight();

        // Drive through enough failures to exceed max (3*2^5 = 96 > 60).
        for _ in 0..10 {
            let before = Instant::now();
            state.record_failure(min, max);
            let delay = state.next_allowed_at.duration_since(before);
            assert!(delay <= max + Duration::from_millis(10));
        }
        // After many attempts, delay must be capped at max.
        let before = Instant::now();
        state.record_failure(min, max);
        let delay = state.next_allowed_at.duration_since(before);
        assert!(delay >= max - Duration::from_millis(10));
        assert!(delay <= max + Duration::from_millis(10));
    }

    #[tokio::test]
    async fn handle_dial_failed_updates_backoff() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        orch.peers
            .get_mut("peer1")
            .unwrap()
            .dials
            .insert(ip, DialState::new_in_flight());

        orch.handle_dial_failed(&DialFailedEvent {
            peer_id: "peer1".to_string(),
            ip,
        });

        let state = &orch.peers.get("peer1").unwrap().dials[&ip];
        assert!(!state.in_flight);
        assert_eq!(state.attempt, 1);
        assert!(state.next_allowed_at > Instant::now());
    }

    #[tokio::test]
    async fn handle_dial_failed_ignores_unknown_peer() {
        let (mut orch, _handles) = TestableOrchestratorBuilder::default().build();

        // Should not panic
        orch.handle_dial_failed(&DialFailedEvent {
            peer_id: "nonexistent".to_string(),
            ip: "1.2.3.4".parse().unwrap(),
        });
    }

    #[tokio::test]
    async fn update_bound_clears_dial_state() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        orch.peers
            .get_mut("peer1")
            .unwrap()
            .dials
            .insert(ip, DialState::new_in_flight());

        let (tx, _rx) = mpsc::channel(1);
        orch.update_bound(
            "peer1",
            Some(Endpoint::Udp(UdpEndpoint {
                host: "example.com".to_string(),
                port: 5353,
            })),
            SocketAddr::new(ip, 5353),
            tx,
        );

        assert!(!orch.peers.get("peer1").unwrap().dials.contains_key(&ip));
    }

    #[tokio::test]
    async fn update_bound_preserves_dial_state_for_inbound() {
        let peer = bare_peer_at_host("peer1", "example.com", 5353, &["10.0.0.0/24"]);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        let (mut orch, _handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .with_resolved_ips("peer1", HashSet::from([ip]))
            .build();

        orch.peers
            .get_mut("peer1")
            .unwrap()
            .dials
            .insert(ip, DialState::new_in_flight());

        let (tx, _rx) = mpsc::channel(1);
        orch.update_bound("peer1", None, SocketAddr::new(ip, 5353), tx);

        // Inbound should NOT clear dial state
        assert!(orch.peers.get("peer1").unwrap().dials.contains_key(&ip));
    }

    // ========== API event handling tests ==========

    #[tokio::test]
    async fn api_get_config_returns_snapshot() {
        let peer = Peer {
            id: "peer-1".to_string(),
            transport: PeerTransport::H3(PeerH3 {
                endpoint: None,
                token: "test-token-12ch".to_string(),
                bindif: None,
                sni: None,
            }),
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
            transport: PeerTransport::H3(PeerH3 {
                endpoint: None,
                token: "test-token-12ch".to_string(),
                bindif: None,
                sni: None,
            }),
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
            transport: PeerTransport::Bare(PeerBare {
                endpoint: UdpEndpoint {
                    host: "127.0.0.1".to_string(),
                    port: 5353,
                },
                bindif: None,
            }),
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
            transport: PeerTransport::H3(PeerH3 {
                endpoint: None,
                token: "test-token-12ch".to_string(),
                bindif: None,
                sni: None,
            }),
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
            transport: PeerTransport::H3(PeerH3 {
                endpoint: None,
                token: "test-token-12ch".to_string(),
                bindif: None,
                sni: None,
            }),
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

    // ========== H3 peer token sync tests ==========

    #[tokio::test]
    async fn api_post_config_sends_h3_token_update() {
        let (mut orch, mut handles) = TestableOrchestratorBuilder::default().build();

        let peer = Peer {
            id: "h3-peer".to_string(),
            transport: PeerTransport::H3(PeerH3 {
                endpoint: None,
                token: "secure-token-12ch".to_string(),
                bindif: None,
                sni: None,
            }),
            tun: PeerTun {
                allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
            },
        };

        orch.handle_post_config(vec![peer]).unwrap();

        let cmd = handles
            .h3_listener_cmd_rx
            .try_recv()
            .expect("H3 listener should receive UpdatePeerTokens");
        let DispatcherCommand::UpdatePeerTokens(tokens) = cmd;
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens.get("h3-peer").unwrap(), "secure-token-12ch");
    }

    #[tokio::test]
    async fn api_delete_config_sends_h3_token_update() {
        let peer = Peer {
            id: "h3-peer".to_string(),
            transport: PeerTransport::H3(PeerH3 {
                endpoint: None,
                token: "secure-token-12ch".to_string(),
                bindif: None,
                sni: None,
            }),
            tun: PeerTun {
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            },
        };
        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        orch.handle_delete_config(&["h3-peer".to_string()]);

        let cmd = handles
            .h3_listener_cmd_rx
            .try_recv()
            .expect("H3 listener should receive UpdatePeerTokens after delete");
        let DispatcherCommand::UpdatePeerTokens(tokens) = cmd;
        assert!(
            tokens.is_empty(),
            "tokens should be empty after removing the only H3 peer"
        );
    }

    #[tokio::test]
    async fn api_delete_config_no_h3_update_when_unchanged() {
        let peer = Peer {
            id: "keeper".to_string(),
            transport: PeerTransport::H3(PeerH3 {
                endpoint: None,
                token: "test-token-12ch1".to_string(),
                bindif: None,
                sni: None,
            }),
            tun: PeerTun {
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            },
        };
        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![peer])
            .build();

        orch.handle_delete_config(&["nonexistent".to_string()]);

        // No change -> no command sent
        assert!(
            handles.h3_listener_cmd_rx.try_recv().is_err(),
            "should not send UpdatePeerTokens when no peers were actually removed"
        );
    }

    #[tokio::test]
    async fn api_post_config_h3_tokens_exclude_bare_peers() {
        let h3_peer = Peer {
            id: "h3-peer".to_string(),
            transport: PeerTransport::H3(PeerH3 {
                endpoint: None,
                token: "h3-token-12chars1".to_string(),
                bindif: None,
                sni: None,
            }),
            tun: PeerTun {
                allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
            },
        };
        let bare_only = bare_peer("bare-peer", &["10.0.2.0/24"]);

        let (mut orch, mut handles) = TestableOrchestratorBuilder::default()
            .with_peers(vec![bare_only])
            .build();

        orch.handle_post_config(vec![h3_peer]).unwrap();

        let cmd = handles
            .h3_listener_cmd_rx
            .try_recv()
            .expect("should receive UpdatePeerTokens");
        let DispatcherCommand::UpdatePeerTokens(tokens) = cmd;
        assert_eq!(tokens.len(), 1, "only H3 peers should be included");
        assert!(tokens.contains_key("h3-peer"));
        assert!(!tokens.contains_key("bare-peer"));
    }
}
