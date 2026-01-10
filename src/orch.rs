//! BareUDP-only runtime orchestration.

use crate::bare::{spawn_udp_rx, spawn_udp_tx, BareUdpRx, BareUdpTx, PeerEndpoints};
use crate::bind::{BindWarning, DefaultRouteProbe};
use crate::config::{parse_udp_uri, Config, Peer, UdpEndpoint};
use crate::dns::{DnsCommand, DnsResolver};
use crate::events::{DnsEventDetail, DnsRecordType, Event};
use crate::route::{sync_tun_routes, RouteManagerHandle, RouteSyncWarning};
use crate::tun::{self, RoutingTable};
use ipnet::IpNet;
use log::warn;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{self, Instant};

const PACKET_QUEUE_DEPTH: usize = 256;
const EVENTS_QUEUE_DEPTH: usize = 64;
const METRICS_INTERVAL: Duration = Duration::from_secs(30);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_OVERALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Errors returned by the BareUDP runtime.
#[derive(Debug, Error)]
pub enum BareRuntimeError {
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

/// Runs the BareUDP-only runtime until a task exits.
///
/// # Errors
///
/// Returns `BareRuntimeError` when initialization fails or a runtime task exits unexpectedly.
pub async fn run_bare(config: Config) -> Result<(), BareRuntimeError> {
    let local_bare = config
        .local
        .bare
        .as_ref()
        .ok_or(BareRuntimeError::MissingBareListen)?;
    let listen_endpoint =
        parse_udp_uri(&local_bare.listen).map_err(BareRuntimeError::InvalidBareListen)?;

    let parsed_peers = collect_bare_peers(&config)?;
    let hosts = collect_hosts(&listen_endpoint, &parsed_peers);
    let resolved_hosts =
        resolve_hosts_once(&config.local.dns, &config.local.tun.ifname, &hosts).await?;

    let listen_addr = select_listen_addr(&listen_endpoint, &resolved_hosts)?;
    let (tun_reader, tun_writer) = tun::from_config(&config.local.tun)
        .await
        .map_err(|err| BareRuntimeError::Tun(err.to_string()))?;
    let mtu = config.local.tun.mtu as usize;

    let bare_rx = BareUdpRx::from_config(listen_addr, mtu)
        .await
        .map_err(|err| BareRuntimeError::Udp(err.to_string()))?;

    let (events_tx, mut events_rx) = mpsc::channel(EVENTS_QUEUE_DEPTH);
    tokio::spawn(async move { while events_rx.recv().await.is_some() {} });

    let mut active_peers = build_active_peers(
        parsed_peers,
        &resolved_hosts,
        &config.local.tun.ifname,
        events_tx.clone(),
    )
    .await;

    if active_peers.is_empty() {
        warn!("no active BareUDP peers resolved; traffic will be dropped");
    }

    let routing_peers: Vec<Peer> = active_peers.iter().map(|peer| peer.peer.clone()).collect();
    let routing = RoutingTable::from_peers(&routing_peers)
        .map_err(|err| BareRuntimeError::Routing(err.to_string()))?;

    if config.local.table {
        let allowed = collect_allowed_ips(&routing_peers)?;
        let tun_addrs = tun_prefixes(&config.local.tun.addrs)?;
        match RouteManagerHandle::new() {
            Ok(mut handle) => {
                match sync_tun_routes(&config.local.tun.ifname, &tun_addrs, &allowed, &mut handle)
                    .await
                {
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

    let (bare_packet_tx, bare_packet_rx) = mpsc::channel(PACKET_QUEUE_DEPTH);

    let allowed_sources = collect_allowed_sources(&active_peers);
    let (_allowed_tx, allowed_rx) = mpsc::channel(1);

    let peer_txs = active_peers
        .iter()
        .map(|peer| (peer.peer.id.clone(), peer.packet_tx.clone()))
        .collect::<HashMap<_, _>>();

    let tun_rx_handle = tun::spawn_tun_rx(
        tun_reader,
        routing.clone(),
        peer_txs.clone(),
        events_tx.clone(),
        METRICS_INTERVAL,
    );
    let tun_tx_handle = tun::spawn_tun_tx(
        tun_writer,
        bare_packet_rx,
        events_tx.clone(),
        METRICS_INTERVAL,
    );
    let bare_rx_handle = spawn_udp_rx(
        bare_rx,
        allowed_sources,
        allowed_rx,
        bare_packet_tx,
        events_tx.clone(),
        METRICS_INTERVAL,
    );

    let mut join_set = JoinSet::new();
    join_set.spawn(wrap_task("tun_rx", tun_rx_handle));
    join_set.spawn(wrap_task("tun_tx", tun_tx_handle));
    join_set.spawn(wrap_task("bare_rx", bare_rx_handle));

    for peer in active_peers.drain(..) {
        let label = format!("bare_tx:{}", peer.peer.id);
        join_set.spawn(wrap_task(label, peer.tx_handle));
    }

    match join_set.join_next().await {
        Some(Ok(label)) => Err(BareRuntimeError::TaskExited(label)),
        Some(Err(err)) => Err(BareRuntimeError::TaskJoin(err.to_string())),
        None => Ok(()),
    }
}

struct ParsedBarePeer {
    peer: Peer,
    endpoint: UdpEndpoint,
    bindif: Option<String>,
}

struct ActivePeer {
    peer: Peer,
    packet_tx: mpsc::Sender<Vec<u8>>,
    tx_handle: JoinHandle<()>,
    endpoints: PeerEndpoints,
}

fn collect_bare_peers(config: &Config) -> Result<Vec<ParsedBarePeer>, BareRuntimeError> {
    let mut peers = Vec::new();

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
        let endpoint =
            parse_udp_uri(&bare.endpoint).map_err(|err| BareRuntimeError::InvalidPeerEndpoint {
                peer_id: peer.id.clone(),
                reason: err,
            })?;
        peers.push(ParsedBarePeer {
            peer: peer.clone(),
            endpoint,
            bindif: bare.bindif.clone(),
        });
    }

    Ok(peers)
}

fn collect_hosts(listen: &UdpEndpoint, peers: &[ParsedBarePeer]) -> HashSet<String> {
    let mut hosts = HashSet::new();
    if parse_ip_literal(&listen.host).is_none() {
        hosts.insert(listen.host.clone());
    }
    for peer in peers {
        if parse_ip_literal(&peer.endpoint.host).is_none() {
            hosts.insert(peer.endpoint.host.clone());
        }
    }
    hosts
}

async fn resolve_hosts_once(
    dns: &crate::config::LocalDns,
    tun_if: &str,
    hosts: &HashSet<String>,
) -> Result<HashMap<String, Vec<IpAddr>>, BareRuntimeError> {
    if hosts.is_empty() {
        return Ok(HashMap::new());
    }

    let resolver = DnsResolver::from_config(dns, Some(tun_if.to_string()), DNS_QUERY_TIMEOUT)
        .map_err(|err| BareRuntimeError::DnsInit(err.to_string()))?;

    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (events_tx, mut events_rx) = mpsc::channel(32);
    let probe = DefaultRouteProbe;
    let handle = resolver
        .spawn(probe, cmd_rx, events_tx)
        .await
        .map_err(|err| BareRuntimeError::DnsInit(err.to_string()))?;

    for host in hosts {
        cmd_tx
            .send(DnsCommand::Resolve { host: host.clone() })
            .await
            .map_err(|err| BareRuntimeError::DnsInit(err.to_string()))?;
    }
    drop(cmd_tx);

    let mut states: HashMap<String, HostResolution> = hosts
        .iter()
        .map(|host| (host.clone(), HostResolution::default()))
        .collect();

    let deadline = Instant::now() + DNS_OVERALL_TIMEOUT;
    loop {
        if states.values().all(|state| state.done()) {
            break;
        }

        let now = Instant::now();
        if now >= deadline {
            warn!("dns resolution timed out after {:?}", DNS_OVERALL_TIMEOUT);
            break;
        }

        let remaining = deadline - now;
        match time::timeout(remaining, events_rx.recv()).await {
            Ok(Some(Event::Dns(dns_event))) => match dns_event.detail {
                DnsEventDetail::Answer(answer) => {
                    if let Some(state) = states.get_mut(&answer.host) {
                        for record in &answer.records {
                            state.insert(record.address);
                        }
                        match answer.record_type {
                            DnsRecordType::A => state.a_done = true,
                            DnsRecordType::Aaaa => state.aaaa_done = true,
                            DnsRecordType::Other(_) => {}
                        }
                        for warning in answer.warnings {
                            warn!("dns warning for {}: {:?}", answer.host, warning);
                        }
                    }
                }
                DnsEventDetail::Timeout(timeout) => {
                    warn!(
                        "dns timeout resolving {} ({:?})",
                        timeout.host, timeout.record_type
                    );
                }
                DnsEventDetail::Unexpected(unexpected) => {
                    warn!("dns unexpected packet: {:?}", unexpected);
                }
                DnsEventDetail::BindWarning(warning) => {
                    log_bind_warning("dns", &warning);
                }
            },
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                warn!("dns resolution timed out waiting for answers");
                break;
            }
        }
    }

    handle.abort();

    let mut resolved = HashMap::new();
    for (host, state) in states {
        if state.addrs.is_empty() {
            warn!("dns resolved no addresses for {host}");
        }
        resolved.insert(host, state.addrs);
    }
    Ok(resolved)
}

#[derive(Default)]
struct HostResolution {
    a_done: bool,
    aaaa_done: bool,
    addrs: Vec<IpAddr>,
    seen: HashSet<IpAddr>,
}

impl HostResolution {
    fn done(&self) -> bool {
        self.a_done && self.aaaa_done
    }

    fn insert(&mut self, addr: IpAddr) {
        if self.seen.insert(addr) {
            self.addrs.push(addr);
        }
    }
}

fn select_listen_addr(
    listen: &UdpEndpoint,
    resolved: &HashMap<String, Vec<IpAddr>>,
) -> Result<SocketAddr, BareRuntimeError> {
    if let Some(ip) = parse_ip_literal(&listen.host) {
        return Ok(SocketAddr::new(ip, listen.port));
    }

    let addrs = resolved.get(&listen.host).cloned().unwrap_or_default();
    if addrs.is_empty() {
        return Err(BareRuntimeError::ListenResolveFailed {
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
    Ok(SocketAddr::new(addrs[0], listen.port))
}

async fn build_active_peers(
    peers: Vec<ParsedBarePeer>,
    resolved: &HashMap<String, Vec<IpAddr>>,
    tun_if: &str,
    events_tx: mpsc::Sender<Event>,
) -> Vec<ActivePeer> {
    let probe = DefaultRouteProbe;
    let mut active = Vec::new();

    for peer in peers {
        let ip_list = if let Some(ip) = parse_ip_literal(&peer.endpoint.host) {
            vec![ip]
        } else {
            resolved
                .get(&peer.endpoint.host)
                .cloned()
                .unwrap_or_default()
        };

        if ip_list.is_empty() {
            warn!(
                "bare peer '{}' resolved no addresses for {}",
                peer.peer.id, peer.endpoint.host
            );
            continue;
        }

        let socket_addrs = ip_list
            .into_iter()
            .map(|ip| SocketAddr::new(ip, peer.endpoint.port))
            .collect::<Vec<_>>();
        let endpoints = match PeerEndpoints::new(socket_addrs) {
            Ok(endpoints) => endpoints,
            Err(err) => {
                warn!("bare peer '{}' endpoints invalid: {err}", peer.peer.id);
                continue;
            }
        };

        let destination = endpoints.destination();
        let (tx_socket, warnings) =
            match BareUdpTx::from_config(destination, peer.bindif.as_deref(), Some(tun_if), &probe)
                .await
            {
                Ok(result) => result,
                Err(err) => {
                    warn!("bare peer '{}' socket setup failed: {err}", peer.peer.id);
                    continue;
                }
            };

        for warning in warnings {
            log_bind_warning(&format!("peer {}", peer.peer.id), &warning);
        }

        let (packet_tx, packet_rx) = mpsc::channel(PACKET_QUEUE_DEPTH);
        let tx_handle = spawn_udp_tx(
            tx_socket,
            destination,
            packet_rx,
            events_tx.clone(),
            METRICS_INTERVAL,
        );

        active.push(ActivePeer {
            peer: peer.peer,
            packet_tx,
            tx_handle,
            endpoints,
        });
    }

    active
}

fn collect_allowed_sources(peers: &[ActivePeer]) -> HashSet<IpAddr> {
    let mut allowed = HashSet::new();
    for peer in peers {
        for ip in peer.endpoints.allowed_sources() {
            allowed.insert(*ip);
        }
    }
    allowed
}

fn collect_allowed_ips(peers: &[Peer]) -> Result<Vec<IpNet>, BareRuntimeError> {
    let mut allowed = Vec::new();
    for peer in peers {
        for cidr in &peer.tun.allowed_ips {
            let net = cidr
                .parse::<IpNet>()
                .map_err(|err| BareRuntimeError::Routing(err.to_string()))?;
            allowed.push(net);
        }
    }
    Ok(allowed)
}

fn tun_prefixes(addrs: &[String]) -> Result<Vec<IpNet>, BareRuntimeError> {
    let mut prefixes = Vec::new();
    for addr in addrs {
        let ip = addr
            .parse::<IpAddr>()
            .map_err(|err| BareRuntimeError::Routing(err.to_string()))?;
        let net = match ip {
            IpAddr::V4(ip) => IpNet::new(ip.into(), 32).map_err(|e| {
                BareRuntimeError::Routing(format!("invalid IPv4 TUN addr {addr}: {e}"))
            })?,
            IpAddr::V6(ip) => IpNet::new(ip.into(), 128).map_err(|e| {
                BareRuntimeError::Routing(format!("invalid IPv6 TUN addr {addr}: {e}"))
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
