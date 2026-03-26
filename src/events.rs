//! Shared events flowing into the orchestrator.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use crate::actor::ActorExitResult;
use crate::config::{Config, H3Endpoint, Peer, Tuning, UdpEndpoint};
use crate::h3::H3Connection;
use crate::metrics::{Labels, Metrics};
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_quiche::buf_factory::PooledBuf;

/// Endpoint type discriminator for bound connections.
///
/// Captures the configured endpoint that originated an outbound connection,
/// enabling prune logic to detect endpoint reconfiguration and DNS staleness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// BareUDP endpoint (host:port).
    Udp(UdpEndpoint),
    /// HTTP/3 endpoint (host:port/path).
    H3(H3Endpoint),
}

/// Common parameters for outbound dial operations.
///
/// Shared by [`crate::h3dialer::dial_h3_client`] and
/// [`crate::bare::dial_bare_tx`] to avoid parameter duplication.
pub struct DialContext {
    /// Peer identifier from configuration.
    pub peer_id: String,
    /// TUN interface name (for route-probe exclusion).
    pub tun_if: String,
    /// TUN MTU in bytes.
    pub tun_mtu: usize,
    /// Tuning parameters (timeouts, buffers, congestion control).
    pub tuning: Tuning,
    /// Runtime handle for UDP I/O actors.
    pub udp_rt: RuntimeHandle,
    /// Runtime handle for crypto / protocol actors.
    pub crypto_rt: RuntimeHandle,
    /// Channel for emitting events back to the orchestrator.
    pub events_tx: mpsc::UnboundedSender<Event>,
}

/// Indicates connection establishment direction.
///
/// Distinct from `Direction` (Rx/Tx) which describes data flow for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    /// Connection accepted by listener (server-side).
    Inbound,
    /// Connection established by dialer (client-side).
    Outbound,
}

/// HTTP/3 engine-based connection established event.
///
/// Emitted by the H3v2 listener dispatcher (inbound) or dial task (outbound)
/// when QUIC + CONNECT-IP handshake completes. Carries the per-connection
/// egress channel and optional join handles for orchestrator registration.
pub struct H3v2ConnectedEvent {
    /// Authenticated peer identifier (from Bearer token validation).
    pub peer_id: String,
    /// Remote client socket address.
    pub remote_addr: SocketAddr,
    /// Channel for sending IP packets to the connected client.
    pub tx: mpsc::Sender<Vec<PooledBuf>>,
    /// Inbound (listener-accepted) or Outbound (dialer-established).
    pub direction: ConnectionDirection,
    /// Actor join handles for lifecycle tracking.
    ///
    /// Outbound connections carry engine + UDP actor handles for JoinSet
    /// registration. Inbound connections are managed by the dispatcher
    /// and carry no handles (empty Vec).
    pub handles: Vec<JoinHandle<ActorExitResult>>,
}

impl std::fmt::Debug for H3v2ConnectedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3v2ConnectedEvent")
            .field("peer_id", &self.peer_id)
            .field("remote_addr", &self.remote_addr)
            .field("direction", &self.direction)
            .finish_non_exhaustive()
    }
}

/// Carries high-level events emitted by modules to the orchestrator.
pub enum Event {
    /// Cumulative metrics snapshot from any source.
    Metrics(Metrics),
    /// HTTP/3 connection established, ready for actor spawning.
    H3Connected(H3ConnectedEvent),
    /// HTTP/3 engine-based connection established (inbound or outbound).
    H3v2Connected(H3v2ConnectedEvent),
    /// BareUDP TX connection established, ready for bound registration.
    BareConnected(BareConnectedEvent),
    /// A dial attempt failed; orchestrator should clear in-flight state and update backoff.
    DialFailed(DialFailedEvent),
    /// Events originating from DNS resolution.
    Dns(DnsEvent),
    /// Events originating from the management API.
    Api(ApiEvent),
}

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Metrics(m) => f.debug_tuple("Metrics").field(m).finish(),
            Self::H3Connected(e) => f.debug_tuple("H3Connected").field(e).finish(),
            Self::H3v2Connected(e) => f.debug_tuple("H3v2Connected").field(e).finish(),
            Self::BareConnected(e) => f.debug_tuple("BareConnected").field(e).finish(),
            Self::DialFailed(e) => f.debug_tuple("DialFailed").field(e).finish(),
            Self::Dns(e) => f.debug_tuple("Dns").field(e).finish(),
            Self::Api(e) => f.debug_tuple("Api").field(e).finish(),
        }
    }
}

/// Events emitted by the management API actor.
pub enum ApiEvent {
    /// GET /config — orchestrator replies with current config snapshot.
    GetConfig {
        /// Reply channel carrying the full `Config` struct for API-side serialization.
        reply_tx: oneshot::Sender<Config>,
    },
    /// POST /config — upsert peers; orchestrator validates and replies.
    PostConfig {
        /// Parsed peer definitions from the request body.
        peers: Vec<Peer>,
        /// Reply channel carrying updated config on success, or error string on failure.
        reply_tx: oneshot::Sender<Result<Config, String>>,
    },
    /// DELETE /config — remove peers by ID; orchestrator confirms.
    DeleteConfig {
        /// Peer IDs to remove.
        peer_ids: Vec<String>,
        /// Reply channel carrying updated config on success, or error string on failure.
        reply_tx: oneshot::Sender<Result<Config, String>>,
    },
    /// GET /metrics — orchestrator replies with raw metrics snapshot for API-side rendering.
    GetMetricsSnapshot {
        /// Reply channel carrying cloned metrics data. Rendering happens in the API actor.
        reply_tx: oneshot::Sender<HashMap<Labels, Metrics>>,
    },
}

impl std::fmt::Debug for ApiEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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

/// BareUDP TX connection established event.
///
/// Emitted by the async connection task when `udp::make_udp` +
/// `udp::spawn_udp_tx` + `spawn_bare_tx` succeed. Carries the TX channel
/// sender and actor JoinHandles for orchestrator registration.
pub struct BareConnectedEvent {
    /// Peer identifier from configuration.
    pub peer_id: String,
    /// Configured endpoint that originated this connection.
    pub endpoint: Endpoint,
    /// Destination socket address.
    pub dest: SocketAddr,
    /// TX channel for sending packet batches to the bare TX actor.
    pub tx: mpsc::Sender<Vec<PooledBuf>>,
    /// Join handle for the spawned bare TX adapter actor.
    pub tx_handle: JoinHandle<ActorExitResult>,
    /// Join handle for the underlying UDP TX I/O actor.
    pub udp_tx_handle: JoinHandle<ActorExitResult>,
}

impl std::fmt::Debug for BareConnectedEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BareConnectedEvent")
            .field("peer_id", &self.peer_id)
            .field("dest", &self.dest)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// HTTP/3 connection established event with full connection object.
///
/// Emitted by listener (inbound) and dialer (outbound) when connection is
/// established and ready for RX/TX actors to be spawned.
#[derive(Debug)]
pub struct H3ConnectedEvent {
    /// The established connection.
    pub connection: H3Connection,
    /// Whether this is an inbound or outbound connection.
    pub direction: ConnectionDirection,
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
