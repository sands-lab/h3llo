//! Control-plane events exchanged by actors.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use crate::actor::ActorExit;
use crate::bind::RouteProbe;
use crate::config::{Config, H3Endpoint, Peer, Tuning, UdpEndpoint};
use crate::metrics::{Labels, Metrics};
use crate::router::RoutingTable;
use buffer_pool::PooledBuf;
use ipnet::IpNet;
use tokio::sync::{mpsc, oneshot};

/// Endpoint type discriminator for bound connections.
///
/// Captures the configured endpoint that originated an outbound connection,
/// enabling prune logic to detect endpoint reconfiguration and DNS staleness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// `BareUDP` endpoint (host:port).
    Udp(UdpEndpoint),
    /// HTTP/3 endpoint (host:port/path).
    H3(H3Endpoint),
}

/// Common parameters for outbound dial operations.
///
/// Shared by [`crate::h3dialer::dial_h3_client`] and
/// [`crate::bare::dial_bare_tx`] to avoid parameter duplication.
pub(crate) struct DialContext<P: RouteProbe> {
    /// Peer identifier from configuration.
    pub peer_id: String,
    /// Target IP address for this dial attempt.
    pub dial_ip: IpAddr,
    /// TUN interface name (for route-probe exclusion).
    pub tun_if: String,
    /// TUN MTU in bytes.
    pub tun_mtu: u16,
    /// Tuning parameters (timeouts, buffers, congestion control).
    pub tuning: Tuning,
    /// Route probe for interface selection.
    pub probe: P,
}

#[cfg(test)]
impl<P: RouteProbe> DialContext<P> {
    /// Creates a `DialContext` for tests with minimal boilerplate.
    pub fn test(peer_id: &str, dial_ip: IpAddr, tuning: Tuning, probe: P) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            dial_ip,
            tun_if: String::new(),
            tun_mtu: crate::config::default_mtu(),
            tuning,
            probe,
        }
    }
}

/// Transport connection established event (H3 or `BareUDP`).
///
/// Emitted by H3 listener/dialer or `BareUDP` dial task when connection
/// setup completes. Carries the per-connection egress channel, optional
/// endpoint. Actor tasks register with `ActorBus` when they are spawned.
pub struct ConnectedEvent {
    /// Authenticated peer identifier.
    pub peer_id: String,
    /// Remote socket address.
    pub remote_addr: SocketAddr,
    /// Channel for sending IP packet batches to the peer.
    pub tx: mpsc::Sender<Vec<PooledBuf>>,
    /// Configured endpoint (present for outbound connections, absent for inbound).
    pub endpoint: Option<Endpoint>,
}

impl std::fmt::Debug for ConnectedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectedEvent")
            .field("peer_id", &self.peer_id)
            .field("remote_addr", &self.remote_addr)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// Control-plane event exchanged through [`crate::actor::ActorBus`].
pub enum Event {
    /// Requests graceful actor shutdown.
    Stop,
    /// Notifies an actor that one of its supervised actors exited.
    ActorExited(ActorExit),
    /// Cumulative metrics snapshot from any source (boxed to reduce enum size).
    Metrics(Box<Metrics>),
    /// Transport connection established (H3 or BareUDP).
    Connected(ConnectedEvent),
    /// A dial attempt failed; orchestrator should clear in-flight state and update backoff.
    DialFailed(DialFailedEvent),
    /// Events originating from DNS resolution.
    Dns(DnsEvent),
    /// GET /config — orchestrator replies with the current configuration.
    GetConfig {
        /// Reply channel carrying the full configuration.
        reply_tx: oneshot::Sender<Config>,
    },
    /// POST /config — upserts peers after orchestrator-side validation.
    PostConfig {
        /// Parsed peer definitions from the request body.
        peers: Vec<Peer>,
        /// Reply channel carrying updated configuration or a validation error.
        reply_tx: oneshot::Sender<Result<Config, String>>,
    },
    /// DELETE /config — removes peers by ID.
    DeleteConfig {
        /// Peer IDs to remove.
        peer_ids: Vec<String>,
        /// Reply channel carrying updated configuration or an error.
        reply_tx: oneshot::Sender<Result<Config, String>>,
    },
    /// GET /metrics — returns the raw metrics snapshot for API-side rendering.
    GetMetricsSnapshot {
        /// Reply channel carrying cloned metrics data.
        reply_tx: oneshot::Sender<HashMap<Labels, Metrics>>,
    },
    /// Replaces the router's routing table atomically.
    UpdateRouting {
        /// New routing table with embedded packet senders.
        routing: RoutingTable,
    },
    /// Replaces the accepted source IP set for inbound `BareUDP` packets.
    UpdateAcceptedSources {
        /// Complete accepted source set.
        sources: HashSet<IpAddr>,
    },
    /// Replaces the peer token map used for H3 authentication.
    UpdatePeerTokens {
        /// Complete peer token map.
        tokens: HashMap<String, String>,
    },
    /// Replaces the hostnames tracked by the DNS resolver.
    SetHostnames {
        /// Complete hostname set.
        hosts: HashSet<String>,
    },
    /// Synchronizes host routes with the desired configuration.
    SyncRoutes {
        /// TUN interface addresses whose OS-managed routes must be preserved.
        tun_addrs: Vec<IpNet>,
        /// Desired allowed IP prefixes.
        allowed: Vec<IpNet>,
    },
}

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stop => f.write_str("Stop"),
            Self::ActorExited(exit) => f.debug_tuple("ActorExited").field(exit).finish(),
            Self::Metrics(m) => f.debug_tuple("Metrics").field(m).finish(),
            Self::Connected(e) => f.debug_tuple("Connected").field(e).finish(),
            Self::DialFailed(e) => f.debug_tuple("DialFailed").field(e).finish(),
            Self::Dns(e) => f.debug_tuple("Dns").field(e).finish(),
            Self::GetConfig { .. } => f.debug_struct("GetConfig").finish_non_exhaustive(),
            Self::PostConfig { peers, .. } => f
                .debug_struct("PostConfig")
                .field("peers_count", &peers.len())
                .finish_non_exhaustive(),
            Self::DeleteConfig { peer_ids, .. } => f
                .debug_struct("DeleteConfig")
                .field("peer_ids", peer_ids)
                .finish_non_exhaustive(),
            Self::GetMetricsSnapshot { .. } => {
                f.debug_struct("GetMetricsSnapshot").finish_non_exhaustive()
            }
            Self::UpdateRouting { routing } => f
                .debug_struct("UpdateRouting")
                .field("routing", routing)
                .finish(),
            Self::UpdateAcceptedSources { sources } => f
                .debug_struct("UpdateAcceptedSources")
                .field("sources", sources)
                .finish(),
            Self::UpdatePeerTokens { tokens } => f
                .debug_struct("UpdatePeerTokens")
                .field("tokens", tokens)
                .finish(),
            Self::SetHostnames { hosts } => f
                .debug_struct("SetHostnames")
                .field("hosts", hosts)
                .finish(),
            Self::SyncRoutes { tun_addrs, allowed } => f
                .debug_struct("SyncRoutes")
                .field("tun_addrs", tun_addrs)
                .field("allowed", allowed)
                .finish(),
        }
    }
}

/// Dial failure notification from a spawned connection task.
///
/// Sent back to the orchestrator when `make_unbound_udp_socket` or `dial_h3` fails,
/// allowing the orchestrator to clear the in-flight flag and advance backoff.
#[derive(Debug)]
pub struct DialFailedEvent {
    /// Peer identifier from configuration.
    pub peer_id: String,
    /// The IP address that failed to connect.
    pub ip: IpAddr,
}

/// DNS resolution state change notification.
///
/// Emitted by the DNS resolver when the resolution state changes.
/// Contains the complete hostname→IP mapping snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEvent {
    /// Complete resolution state: hostname -> resolved IPs.
    ///
    /// Each hostname maps to its currently valid IPs (TTL not expired).
    /// Empty set indicates hostname is registered but has no valid IPs.
    pub state: HashMap<String, HashSet<IpAddr>>,
}
