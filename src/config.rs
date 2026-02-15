use ipnet::IpNet;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// Top-level configuration loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Local node settings.
    pub local: Local,
    /// Tuning parameters for timing, capacity, and protocol settings.
    #[serde(default)]
    pub tuning: Tuning,
    /// Peer definitions.
    #[serde(default)]
    pub peers: Vec<Peer>,
}

/// Local node settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Local {
    /// Whether to manage system routes (default: true).
    #[serde(default = "default_true")]
    pub table: bool,
    /// DNS resolver settings.
    #[serde(default = "default_dns")]
    pub dns: LocalDns,
    /// HTTP/3 server options and credentials.
    #[serde(default)]
    pub h3: Option<LocalH3>,
    /// BareUDP listener options.
    #[serde(default)]
    pub bare: Option<LocalBare>,
    /// Management API server options.
    #[serde(default)]
    pub api: Option<LocalApi>,
    /// Local TUN configuration.
    pub tun: LocalTun,
}

/// HTTP/3 settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalH3 {
    /// HTTP/3 listen address; required when `local.h3` is set.
    pub listen: H3Endpoint,
    /// Certificate path for QUIC/TLS; required when `local.h3` is set.
    pub cert: String,
    /// Private key path for QUIC/TLS; required when `local.h3` is set.
    pub key: String,
}

/// BareUDP settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalBare {
    /// BareUDP listen address (required when BareUDP is configured).
    pub listen: UdpEndpoint,
}

/// DNS resolver settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalDns {
    /// DNS server address as a UDP URI (IPv4/IPv6 literal), e.g., `udp://1.1.1.1:53`.
    /// Parsed as `SocketAddr` during deserialization; serialized back to `udp://` URI format.
    #[serde(
        default = "default_dns_server",
        deserialize_with = "deserialize_dns_server",
        serialize_with = "serialize_dns_server"
    )]
    pub server: SocketAddr,
    /// Optional outbound interface binding for DNS resolution.
    pub bindif: Option<String>,
}

/// TUN settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalTun {
    /// TUN interface name (default: h3llo0).
    #[serde(default = "default_ifname")]
    pub ifname: String,
    /// TUN addresses with CIDR prefixes (IPv4/IPv6, required).
    /// Example: `192.168.180.1/24`, `2001:db8::1/64`
    pub addrs: Vec<IpNet>,
    /// TUN MTU (default: 1393).
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

/// Peer configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    /// Remote node identifier.
    pub id: String,
    /// HTTP/3 transport options.
    #[serde(default)]
    pub h3: Option<PeerH3>,
    /// BareUDP transport options.
    #[serde(default)]
    pub bare: Option<PeerBare>,
    /// Peer routing details.
    pub tun: PeerTun,
}

/// HTTP/3 options per peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerH3 {
    /// Optional dialing endpoint (scheme/host/port/path); omit for listen-only posture.
    #[serde(default)]
    pub endpoint: Option<H3Endpoint>,
    /// Remote peer token (>= 12 characters) required whenever HTTP/3 is configured, including listen-only peers.
    pub token: String,
    /// Optional interface to bind HTTP/3 dialers.
    pub bindif: Option<String>,
    /// Optional TLS Server Name Indication (SNI) override.
    ///
    /// When set, this value is used as the SNI during the QUIC/TLS handshake
    /// instead of the hostname from `endpoint`. The HTTP/3 `:authority`
    /// pseudo-header is derived from the `endpoint` authority (`host`, or
    /// `host:port` when the port is not 443) and is not affected by `sni`.
    pub sni: Option<String>,
}

/// BareUDP options per peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerBare {
    /// BareUDP dialing endpoint (required when BareUDP is configured).
    pub endpoint: UdpEndpoint,
    /// Optional interface binding for BareUDP dialing.
    pub bindif: Option<String>,
}

/// Peer routing details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerTun {
    /// Allowed IP prefixes routed via this peer. Parsed as `IpNet` during deserialization.
    pub allowed_ips: Vec<IpNet>,
}

/// Tuning parameters for timing, capacity, and protocol settings.
///
/// All fields have sensible defaults. The entire section is optional in YAML.
/// When partially specified, unset fields use their defaults.
/// Duration fields are serialized as integer seconds in YAML unless noted otherwise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Tuning {
    /// Data-plane packet queue depth for bounded backpressure channels (default: 2048).
    pub packet_queue_depth: usize,
    /// Socket buffer size in megabytes for SO_RCVBUF and SO_SNDBUF (default: 16).
    ///
    /// Applied to all UDP sockets. Set to 0 to skip buffer configuration and use
    /// system defaults. Actual kernel buffer may be clamped by OS limits.
    pub socket_buffer_size: usize,
    /// Minimum interval between reconnection attempts (default: 3s).
    #[serde(with = "serde_duration_secs")]
    pub reconnect_interval: Duration,
    /// Metrics push interval in milliseconds (default: 1000ms).
    #[serde(with = "serde_duration_millis")]
    pub metrics_push_interval: Duration,
    /// DNS query timeout (default: 2s).
    #[serde(with = "serde_duration_secs")]
    pub dns_query_timeout: Duration,
    /// DNS refresh interval; 0 disables (default: 60s).
    #[serde(with = "serde_duration_secs")]
    pub dns_refresh_interval: Duration,
    /// Delay before emitting a DNS snapshot after the first state change (default: 100ms).
    ///
    /// After a DNS reply marks the state dirty, the resolver waits this duration
    /// before emitting a snapshot to the orchestrator. Subsequent replies within
    /// the window are coalesced into the same snapshot.
    #[serde(with = "serde_duration_millis")]
    pub dns_snapshot_delay: Duration,
    /// Minimum TTL floor in seconds for DNS records (default: 60).
    ///
    /// DNS responses with TTL below this value are raised to this floor
    /// to prevent excessive re-queries.
    pub dns_min_ttl: u32,
    /// HTTP/3 handshake timeout (default: 30s).
    #[serde(with = "serde_duration_secs")]
    pub h3_handshake_timeout: Duration,
    /// HTTP/3 max idle timeout (default: 60s).
    #[serde(with = "serde_duration_secs")]
    pub h3_max_idle_timeout: Duration,
    /// HTTP/3 keepalive interval (default: 20s). Sends QUIC PING frames to prevent idle timeout.
    #[serde(with = "serde_duration_secs")]
    pub h3_keepalive_interval: Duration,
    /// QUIC congestion control algorithm (default: `"bbr2"`).
    ///
    /// Accepted values: `"reno"`, `"cubic"`, `"bbr"`, `"bbr2"`, `"none"`.
    /// Applied to both client (dial) and server (listener) QUIC connections.
    pub h3_cc_algorithm: String,
    /// Enable QUIC packet pacing (default: `true`).
    ///
    /// Smooths out bursty sends at the cost of slight latency increase.
    /// Requires OS-level pacing support (e.g., `SO_TXTIME` on Linux).
    /// Applied to both client and server QUIC connections.
    pub h3_enable_pacing: bool,
    /// Skip TLS certificate verification for all H3 connections (default: `false`).
    ///
    /// When `true`, QUIC/TLS peer verification is disabled. Intended for testing
    /// with self-signed certificates only. **Not recommended for production.**
    #[serde(default)]
    pub h3_insecure_skip_verify: bool,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            packet_queue_depth: 2048,
            socket_buffer_size: 16,
            reconnect_interval: Duration::from_secs(3),
            metrics_push_interval: Duration::from_millis(1000),
            dns_query_timeout: Duration::from_secs(2),
            dns_refresh_interval: Duration::from_secs(60),
            dns_snapshot_delay: Duration::from_millis(100),
            dns_min_ttl: 60,
            h3_handshake_timeout: Duration::from_secs(30),
            h3_max_idle_timeout: Duration::from_secs(60),
            h3_keepalive_interval: Duration::from_secs(20),
            h3_cc_algorithm: "bbr2".to_string(),
            h3_enable_pacing: true,
            h3_insecure_skip_verify: false,
        }
    }
}

impl Tuning {
    /// Returns socket buffer size in bytes, or 0 to skip configuration.
    pub fn socket_buffer_bytes(&self) -> usize {
        self.socket_buffer_size.saturating_mul(1024 * 1024)
    }
}

/// Serde helper: serializes `Duration` as integer seconds in YAML.
mod serde_duration_secs {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Serde helper: serializes `Duration` as integer milliseconds in YAML.
mod serde_duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_millis() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let millis = u64::deserialize(d)?;
        Ok(Duration::from_millis(millis))
    }
}

/// Configuration parsing or validation error.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// YAML parsing failed.
    #[error("failed to parse configuration: {0}")]
    Parse(#[from] serde_yaml::Error),
    /// Validation failed after parsing.
    #[error("validation failed: {0}")]
    Validation(ValidationErrors),
}

/// Validation errors collected during a `Config::validate` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for err in &self.0 {
            if !first {
                write!(f, "; ")?;
            }
            first = false;
            write!(f, "{err}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

/// Individual validation error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    /// `tuning.packet_queue_depth` must be > 0 (mpsc::channel(0) panics).
    #[error("tuning.packet_queue_depth must be greater than 0")]
    TuningPacketQueueDepthZero,
    /// A tuning Duration field must be greater than zero.
    ///
    /// Zero values cause `tokio::time::interval` panics or semantically
    /// broken behavior (instant timeouts, no debouncing).
    #[error("tuning.{field} must be greater than 0")]
    TuningDurationZero {
        /// The field name (e.g., "reconnect_interval").
        field: &'static str,
    },
    /// `tuning.h3_keepalive_interval` must be strictly less than `tuning.h3_max_idle_timeout`.
    #[error(
        "tuning.h3_keepalive_interval ({keepalive:?}) must be less than \
         tuning.h3_max_idle_timeout ({idle_timeout:?})"
    )]
    H3KeepaliveExceedsIdleTimeout {
        /// Configured keepalive interval.
        keepalive: Duration,
        /// Configured idle timeout.
        idle_timeout: Duration,
    },
    /// `local.h3.cert` and `local.h3.key` must not be empty when `local.h3` is set.
    #[error("local.h3.cert and local.h3.key must not be empty when local.h3 is configured")]
    LocalH3CredentialsMissing,
    /// TUN addresses are missing.
    #[error("local.tun.addrs must include at least one address")]
    MissingLocalTunAddrs,
    /// Peer identifier is empty.
    #[error("peer id must not be empty")]
    PeerIdEmpty { peer_id: String },
    /// Peer identifier has leading or trailing whitespace.
    #[error("peer id '{peer_id}' must not have leading or trailing whitespace")]
    PeerIdHasWhitespace { peer_id: String },
    /// Duplicate peer identifier.
    #[error("duplicate peer id '{peer_id}'")]
    DuplicatePeerId { peer_id: String },
    /// Peer token missing or too short.
    #[error("peer '{peer_id}' requires h3.token of at least 12 characters when h3 is configured")]
    PeerTokenTooShort { peer_id: String },
    /// Peer token has leading or trailing whitespace.
    #[error("peer '{peer_id}' h3.token must not have leading or trailing whitespace")]
    PeerTokenHasWhitespace { peer_id: String },
    /// Duplicate peer token.
    #[error("duplicate peer token for peer '{peer_id}'")]
    DuplicatePeerToken { peer_id: String },
    /// Peer SNI is empty.
    #[error("peer '{peer_id}' h3.sni must not be empty")]
    PeerSniEmpty { peer_id: String },
    /// Peer SNI has leading or trailing whitespace.
    #[error("peer '{peer_id}' h3.sni must not have leading or trailing whitespace")]
    PeerSniHasWhitespace { peer_id: String },
    /// Peer bindif has leading or trailing whitespace.
    #[error("peer '{peer_id}' h3.bindif must not have leading or trailing whitespace")]
    PeerBindifHasWhitespace { peer_id: String },
    /// Peer transport fields conflict.
    #[error("peer '{peer_id}' must configure exactly one of h3 or bare")]
    PeerTransportConflict { peer_id: String },
    /// Allowed IP list missing.
    #[error("peer '{peer_id}' must include at least one allowed_ips entry")]
    PeerMissingAllowedIps { peer_id: String },
    /// Allowed IP entry duplicates another entry on the same peer.
    #[error("peer '{peer_id}' has duplicate allowed_ips entry '{cidr}'")]
    PeerDuplicateAllowedIp { peer_id: String, cidr: String },
    /// `tuning.h3_cc_algorithm` is not a recognized congestion control algorithm.
    #[error(
        "tuning.h3_cc_algorithm '{algorithm}' is not recognized \
         (accepted: reno, cubic, bbr, bbr2, none)"
    )]
    InvalidCcAlgorithm {
        /// The unrecognized algorithm name.
        algorithm: String,
    },
}

impl Config {
    /// Loads configuration from a YAML reader and validates it.
    pub fn load_from_reader<R: Read>(reader: R) -> Result<Self, ConfigError> {
        let config: Config = serde_yaml::from_reader(reader)?;
        config.validate()?;
        Ok(config)
    }

    /// Loads configuration from a YAML string and validates it.
    pub fn load_from_str(contents: &str) -> Result<Self, ConfigError> {
        let config: Config = serde_yaml::from_str(contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates structural and semantic constraints.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        // Tuning validation
        if self.tuning.packet_queue_depth == 0 {
            errors.push(ValidationError::TuningPacketQueueDepthZero);
        }

        // Duration fields that must be strictly positive.
        // dns_refresh_interval is intentionally excluded: zero disables periodic refresh.
        let duration_checks: &[(&str, Duration)] = &[
            ("reconnect_interval", self.tuning.reconnect_interval),
            ("metrics_push_interval", self.tuning.metrics_push_interval),
            ("dns_query_timeout", self.tuning.dns_query_timeout),
            ("dns_snapshot_delay", self.tuning.dns_snapshot_delay),
            ("h3_handshake_timeout", self.tuning.h3_handshake_timeout),
            ("h3_max_idle_timeout", self.tuning.h3_max_idle_timeout),
            ("h3_keepalive_interval", self.tuning.h3_keepalive_interval),
        ];
        for &(field, dur) in duration_checks {
            if dur.is_zero() {
                errors.push(ValidationError::TuningDurationZero { field });
            }
        }

        if self.tuning.h3_keepalive_interval >= self.tuning.h3_max_idle_timeout {
            errors.push(ValidationError::H3KeepaliveExceedsIdleTimeout {
                keepalive: self.tuning.h3_keepalive_interval,
                idle_timeout: self.tuning.h3_max_idle_timeout,
            });
        }

        // Subset of quiche::CongestionControlAlgorithm::from_str();
        // excludes internal aliases (bbr2_gcongestion).
        const VALID_CC_ALGORITHMS: &[&str] = &["reno", "cubic", "bbr", "bbr2", "none"];
        if !VALID_CC_ALGORITHMS.contains(&self.tuning.h3_cc_algorithm.as_str()) {
            errors.push(ValidationError::InvalidCcAlgorithm {
                algorithm: self.tuning.h3_cc_algorithm.clone(),
            });
        }

        // H3 validation: cert/key must not be empty when local.h3 is set
        if let Some(h3) = self.local.h3.as_ref() {
            if h3.cert.trim().is_empty() || h3.key.trim().is_empty() {
                errors.push(ValidationError::LocalH3CredentialsMissing);
            }
        }

        if self.local.tun.addrs.is_empty() {
            errors.push(ValidationError::MissingLocalTunAddrs);
        }

        if let Err(ValidationErrors(peer_errors)) = validate_peers(&self.peers) {
            errors.extend(peer_errors);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Validation(ValidationErrors(errors)))
        }
    }
}

/// Validates a peer list in isolation (ID, token, transport, allowed_ips).
pub fn validate_peers(peers: &[Peer]) -> Result<(), ValidationErrors> {
    let mut errors = Vec::new();
    let mut seen_peer_ids = HashSet::new();
    let mut seen_peer_tokens = HashSet::new();

    for peer in peers {
        // Peer ID validation: must be non-empty and have no leading/trailing whitespace
        if peer.id.trim().is_empty() {
            errors.push(ValidationError::PeerIdEmpty {
                peer_id: peer.id.clone(),
            });
        } else if peer.id != peer.id.trim() {
            errors.push(ValidationError::PeerIdHasWhitespace {
                peer_id: peer.id.clone(),
            });
        }

        if !seen_peer_ids.insert(peer.id.clone()) {
            errors.push(ValidationError::DuplicatePeerId {
                peer_id: peer.id.clone(),
            });
        }

        if let Some(h3) = peer.h3.as_ref() {
            // Token validation: must be >= 12 chars and have no leading/trailing whitespace
            if h3.token.len() < 12 {
                errors.push(ValidationError::PeerTokenTooShort {
                    peer_id: peer.id.clone(),
                });
            } else if h3.token != h3.token.trim() {
                errors.push(ValidationError::PeerTokenHasWhitespace {
                    peer_id: peer.id.clone(),
                });
            }

            if !seen_peer_tokens.insert(h3.token.clone()) {
                errors.push(ValidationError::DuplicatePeerToken {
                    peer_id: peer.id.clone(),
                });
            }
            if let Some(sni) = &h3.sni {
                if sni.trim().is_empty() {
                    errors.push(ValidationError::PeerSniEmpty {
                        peer_id: peer.id.clone(),
                    });
                } else if sni != sni.trim() {
                    errors.push(ValidationError::PeerSniHasWhitespace {
                        peer_id: peer.id.clone(),
                    });
                }
            }

            if let Some(bindif) = &h3.bindif {
                if bindif != bindif.trim() {
                    errors.push(ValidationError::PeerBindifHasWhitespace {
                        peer_id: peer.id.clone(),
                    });
                }
            }
        }

        if peer.h3.is_some() == peer.bare.is_some() {
            errors.push(ValidationError::PeerTransportConflict {
                peer_id: peer.id.clone(),
            });
        }

        if peer.tun.allowed_ips.is_empty() {
            errors.push(ValidationError::PeerMissingAllowedIps {
                peer_id: peer.id.clone(),
            });
        }

        let mut seen_allowed = HashSet::new();
        for net in &peer.tun.allowed_ips {
            if !seen_allowed.insert(*net) {
                errors.push(ValidationError::PeerDuplicateAllowedIp {
                    peer_id: peer.id.clone(),
                    cidr: net.to_string(),
                });
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(ValidationErrors(errors))
    }
}

fn default_true() -> bool {
    true
}

fn default_dns() -> LocalDns {
    LocalDns {
        server: default_dns_server(),
        bindif: None,
    }
}

fn default_dns_server() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
}

fn default_ifname() -> String {
    "h3llo0".to_string()
}

/// Default TUN MTU: safe for IPv6 outer transport on a 1500-byte WAN.
/// 1500 (Ethernet MTU) - 48 (IPv6 + UDP) - 59 (CONNECT-IP overhead) = 1393.
pub fn default_mtu() -> u16 {
    1393
}

/// Deserializes a DNS server from a `udp://` URI string to `SocketAddr`.
fn deserialize_dns_server<'de, D>(deserializer: D) -> Result<SocketAddr, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_dns_server_uri(&s).map_err(de::Error::custom)
}

/// Serializes a `SocketAddr` back to `udp://` URI format.
fn serialize_dns_server<S>(addr: &SocketAddr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("udp://{addr}"))
}

/// Represents a UDP endpoint parsed from a `udp://` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpEndpoint {
    /// Host portion of the URI (domain or IP literal).
    pub host: String,
    /// Port number of the endpoint.
    pub port: u16,
}

impl<'de> Deserialize<'de> for UdpEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_udp_uri(&s).map_err(de::Error::custom)
    }
}

impl Serialize for UdpEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("udp://{}:{}", self.host, self.port))
    }
}

/// Represents an HTTP/3 endpoint parsed from an `https://` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H3Endpoint {
    /// Host portion of the URI (domain or IP literal).
    pub host: String,
    /// Port number of the endpoint (defaults to 443 if not specified).
    pub port: u16,
    /// Path portion of the URI.
    pub path: String,
}

impl<'de> Deserialize<'de> for H3Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_h3_uri(&s).map_err(de::Error::custom)
    }
}

impl Serialize for H3Endpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let uri = if self.port == 443 {
            format!("https://{}{}", self.host, self.path)
        } else {
            format!("https://{}:{}{}", self.host, self.port, self.path)
        };
        serializer.serialize_str(&uri)
    }
}

/// Management API settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalApi {
    /// HTTP listen address for the management API (required when `local.api` is set).
    pub listen: ApiEndpoint,
}

/// Represents an HTTP management API endpoint parsed from an `http://` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiEndpoint {
    /// Host portion of the URI (IP literal or hostname).
    pub host: String,
    /// Port number (defaults to 9090 if not specified).
    pub port: u16,
    /// Path portion of the URI.
    pub path: String,
}

impl<'de> Deserialize<'de> for ApiEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_api_uri(&s).map_err(de::Error::custom)
    }
}

impl Serialize for ApiEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Always include the port to avoid round-trip bugs (HTTP default is 80, not 9090).
        let uri = format!("http://{}:{}{}", self.host, self.port, self.path);
        serializer.serialize_str(&uri)
    }
}

/// Parses a scheme-specific endpoint URI into host/port/path components.
///
/// Shared URI validation: scheme, userinfo, host, query/fragment checks.
fn parse_endpoint_uri(
    raw: &str,
    expected_scheme: &str,
) -> Result<(String, Option<u16>, String), String> {
    let url = Url::parse(raw).map_err(|e| e.to_string())?;
    if url.scheme() != expected_scheme {
        return Err(format!("scheme must be {expected_scheme}"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("userinfo is not supported".to_string());
    }
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "host is required".to_string())?;
    let path = url.path().to_string();
    if url.query().is_some() || url.fragment().is_some() {
        return Err("query and fragment are not supported".to_string());
    }
    Ok((host.to_string(), url.port(), path))
}

/// Parses a UDP DNS server URI (e.g., `udp://1.1.1.1:53`) into a socket address, enforcing IP literals.
///
/// Supports both IPv4 (`udp://1.1.1.1:53`) and IPv6 (`udp://[::1]:53`) addresses.
pub fn parse_dns_server_uri(raw: &str) -> Result<SocketAddr, String> {
    let (host, port, path) = parse_endpoint_uri(raw, "udp")?;
    let port = port.ok_or("port is required (e.g., udp://1.1.1.1:53)")?;
    if path != "/" && !path.is_empty() {
        return Err("path must be empty".to_string());
    }
    // For non-special schemes like "udp://", the URL parser treats all hosts as domains.
    // Parse the host string manually, stripping brackets for IPv6.
    let host_stripped = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&host);
    let ip: IpAddr = host_stripped
        .parse()
        .map_err(|_| "host must be an IP literal".to_string())?;
    Ok(SocketAddr::new(ip, port))
}

/// Parses an HTTP/3 URI (e.g., `https://host:443/path`) into host, port, and path components.
///
/// # Arguments
///
/// * `raw` - The URI string to parse.
///
/// # Returns
///
/// Returns an `H3Endpoint` with the parsed components. Port defaults to 443 if not specified.
///
/// # Errors
///
/// Returns an error if the URI is invalid, uses a non-https scheme, or is missing a host.
pub fn parse_h3_uri(raw: &str) -> Result<H3Endpoint, String> {
    let (host, port, path) = parse_endpoint_uri(raw, "https")?;
    Ok(H3Endpoint {
        host,
        port: port.unwrap_or(443),
        path,
    })
}

/// Parses an HTTP management API URI (e.g., `http://127.0.0.1:9090/admin`).
///
/// # Arguments
///
/// * `raw` - The URI string to parse.
///
/// # Returns
///
/// Returns an `ApiEndpoint`. Port defaults to 9090 if not specified.
///
/// # Errors
///
/// Returns an error if the URI is invalid, uses a non-http scheme, or is missing a host.
pub fn parse_api_uri(raw: &str) -> Result<ApiEndpoint, String> {
    let (host, port, path) = parse_endpoint_uri(raw, "http")?;
    Ok(ApiEndpoint {
        host,
        port: port.unwrap_or(9090),
        path,
    })
}

/// Parses a UDP URI (e.g., `udp://host:6635`) into host and port components.
pub fn parse_udp_uri(raw: &str) -> Result<UdpEndpoint, String> {
    let (host, port, path) = parse_endpoint_uri(raw, "udp")?;
    let port = port.ok_or("port is required (e.g., udp://host:6635)")?;
    if path != "/" && !path.is_empty() {
        return Err("path must be empty".to_string());
    }
    Ok(UdpEndpoint { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_h3_config() -> Config {
        Config {
            local: Local {
                table: true,
                dns: LocalDns {
                    server: "1.1.1.1:53".parse().unwrap(),
                    bindif: None,
                },
                h3: Some(LocalH3 {
                    listen: H3Endpoint {
                        host: "[::]".to_string(),
                        port: 443,
                        path: "/path".to_string(),
                    },
                    cert: "./cert.pem".to_string(),
                    key: "./key.pem".to_string(),
                }),
                bare: None,
                api: None,
                tun: LocalTun {
                    ifname: "h3llo0".to_string(),
                    addrs: vec!["192.168.180.1/32".parse().unwrap()],
                    mtu: 1393,
                },
            },
            tuning: Tuning::default(),
            peers: vec![Peer {
                id: "example-node-2".to_string(),
                h3: Some(PeerH3 {
                    token: "example-node-2-token".to_string(), // >= 12 chars
                    endpoint: Some(H3Endpoint {
                        host: "peer.example.com".to_string(),
                        port: 443,
                        path: "/path".to_string(),
                    }),
                    bindif: None,
                    sni: None,
                }),
                bare: None,
                tun: PeerTun {
                    allowed_ips: vec!["192.168.180.2/32".parse().unwrap()],
                },
            }],
        }
    }

    #[test]
    fn validates_good_config() {
        let config = sample_h3_config();
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_empty_peer_id() {
        let mut config = sample_h3_config();
        config.peers[0].id = "".to_string();
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerIdEmpty { .. }))
        ));
    }

    #[test]
    fn accepts_short_peer_id() {
        let mut config = sample_h3_config();
        config.peers[0].id = "a".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_peer_id_with_leading_whitespace() {
        let mut config = sample_h3_config();
        config.peers[0].id = " peer1".to_string();
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerIdHasWhitespace { .. }))
        ));
    }

    #[test]
    fn rejects_peer_id_with_trailing_whitespace() {
        let mut config = sample_h3_config();
        config.peers[0].id = "peer1 ".to_string();
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerIdHasWhitespace { .. }))
        ));
    }

    #[test]
    fn rejects_h3_with_empty_credentials() {
        let mut config = sample_h3_config();
        config.local.h3 = Some(LocalH3 {
            listen: H3Endpoint {
                host: "[::]".to_string(),
                port: 443,
                path: "/".to_string(),
            },
            cert: String::new(),
            key: String::new(),
        });
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.contains(&ValidationError::LocalH3CredentialsMissing)
        ));
    }

    #[test]
    fn rejects_h3_with_partial_credentials() {
        let mut config = sample_h3_config();
        config.local.h3 = Some(LocalH3 {
            listen: H3Endpoint {
                host: "[::]".to_string(),
                port: 443,
                path: "/".to_string(),
            },
            cert: "./cert.pem".to_string(),
            key: String::new(), // missing key
        });
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.contains(&ValidationError::LocalH3CredentialsMissing)
        ));
    }

    #[test]
    fn rejects_h3_without_required_fields() {
        let yaml = r#"
local:
  h3: {}
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        assert!(Config::load_from_str(yaml).is_err());
    }

    #[test]
    fn rejects_peer_transport_conflict() {
        let mut config = sample_h3_config();
        config.peers[0].bare = Some(PeerBare {
            endpoint: UdpEndpoint {
                host: "peer.example.com".to_string(),
                port: 6635,
            },
            bindif: None,
        });
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerTransportConflict { .. }))
        ));
    }

    #[test]
    fn rejects_short_peer_token() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.token = "short".to_string(); // < 12 chars
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerTokenTooShort { .. }))
        ));
    }

    #[test]
    fn accepts_12_char_peer_token() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.token = "123456789012".to_string(); // Exactly 12 chars
        }
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_token_with_leading_whitespace() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.token = " 123456789012".to_string(); // 13 chars but has leading space
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerTokenHasWhitespace { .. }))
        ));
    }

    #[test]
    fn rejects_token_with_trailing_whitespace() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.token = "123456789012 ".to_string(); // 13 chars but has trailing space
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerTokenHasWhitespace { .. }))
        ));
    }

    #[test]
    fn rejects_duplicate_peer_ids() {
        let mut config = sample_h3_config();
        let mut peer2 = config.peers[0].clone();
        peer2.h3.as_mut().unwrap().token = "different-token-123".to_string();
        config.peers.push(peer2);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::DuplicatePeerId { .. }))
        ));
    }

    #[test]
    fn rejects_duplicate_peer_tokens() {
        let mut config = sample_h3_config();
        let mut peer2 = config.peers[0].clone();
        peer2.id = "different-peer-id".to_string();
        config.peers.push(peer2);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::DuplicatePeerToken { .. }))
        ));
    }

    #[test]
    fn rejects_unknown_fields_at_parse_time() {
        // Unknown field at top level
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
unknown_top_level: true
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));

        // Unknown field in nested struct (local.dns)
        let yaml = r#"
local:
  dns:
    server: udp://1.1.1.1:53
    refresh: 1
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));

        // Unknown field in tuning
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  nonexistent_param: 42
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));

        // Unknown field in peer
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
  stale_field: true
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn rejects_empty_allowed_ips() {
        let mut config = sample_h3_config();
        config.peers[0].tun.allowed_ips.clear();
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerMissingAllowedIps { .. }))
        ));
    }

    #[test]
    fn parse_from_str_applies_defaults() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert!(cfg.local.table);
        assert_eq!(
            cfg.local.dns.server,
            "1.1.1.1:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(cfg.local.dns.bindif, None);
        assert_eq!(cfg.local.tun.ifname, "h3llo0");
        assert_eq!(cfg.local.tun.mtu, 1393);
        assert!(cfg.peers[0].h3.is_some());
        if let Some(h3) = cfg.peers[0].h3.as_ref() {
            assert!(h3.endpoint.is_none());
            assert!(h3.bindif.is_none());
        } else {
            panic!("peer h3 should be present");
        }
    }

    #[test]
    fn parses_single_endpoint_and_applies_dns_defaults() {
        let yaml = r#"
local:
  dns:
    server: udp://8.8.8.8:53
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
    endpoint: https://peer.example.com/path
    bindif: eth0
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(
            cfg.local.dns.server,
            "8.8.8.8:53".parse::<SocketAddr>().unwrap()
        );
        let h3 = cfg.peers[0].h3.as_ref().expect("h3 should be present");
        let endpoint = h3.endpoint.as_ref().expect("endpoint should be present");
        assert_eq!(endpoint.host, "peer.example.com");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path, "/path");
        assert_eq!(h3.bindif, Some("eth0".to_string()));
    }

    #[test]
    fn accepts_peer_h3_with_bindif() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.bindif = Some("eth0".to_string());
        }
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_peer_h3_with_sni() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.sni = Some("custom-sni.example.com".to_string());
        }
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_peer_h3_without_sni() {
        let config = sample_h3_config();
        assert!(config.peers[0].h3.as_ref().unwrap().sni.is_none());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_empty_sni() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.sni = Some("".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::PeerSniEmpty { .. }))
        ));
    }

    #[test]
    fn rejects_whitespace_only_sni() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.sni = Some("   ".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::PeerSniEmpty { .. }))
        ));
    }

    #[test]
    fn rejects_sni_with_leading_whitespace() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.sni = Some(" leading".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::PeerSniHasWhitespace { .. }))
        ));
    }

    #[test]
    fn rejects_sni_with_trailing_whitespace() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.sni = Some("trailing ".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::PeerSniHasWhitespace { .. }))
        ));
    }

    #[test]
    fn rejects_bindif_with_leading_whitespace() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.bindif = Some(" eth0".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::PeerBindifHasWhitespace { .. }))
        ));
    }

    #[test]
    fn rejects_bindif_with_trailing_whitespace() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.bindif = Some("eth0 ".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::PeerBindifHasWhitespace { .. }))
        ));
    }

    #[test]
    fn rejects_duplicate_allowed_ip_for_peer() {
        let mut config = sample_h3_config();
        config.peers[0].tun.allowed_ips = vec![
            "192.168.180.2/32".parse().unwrap(),
            "192.168.180.2/32".parse().unwrap(),
        ];
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs
                    .iter()
                    .any(|e| matches!(e, ValidationError::PeerDuplicateAllowedIp { .. }))
        ));
    }

    #[test]
    fn parse_udp_uri_accepts_hostname() {
        let endpoint = parse_udp_uri("udp://example.com:6635").expect("udp uri should parse");
        assert_eq!(endpoint.host, "example.com");
        assert_eq!(endpoint.port, 6635);
    }

    // ========== parse_h3_uri tests ==========

    #[test]
    fn parse_h3_uri_accepts_full_uri() {
        let endpoint = parse_h3_uri("https://example.com:8443/path").expect("should parse");
        assert_eq!(endpoint.host, "example.com");
        assert_eq!(endpoint.port, 8443);
        assert_eq!(endpoint.path, "/path");
    }

    #[test]
    fn parse_h3_uri_defaults_port_443() {
        let endpoint = parse_h3_uri("https://example.com/path").expect("should parse");
        assert_eq!(endpoint.port, 443);
    }

    #[test]
    fn parse_h3_uri_rejects_http() {
        let result = parse_h3_uri("http://example.com/path");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("https"));
    }

    #[test]
    fn parse_h3_uri_rejects_invalid_uri() {
        let result = parse_h3_uri("not-a-valid-uri");
        assert!(result.is_err());
    }

    #[test]
    fn parse_h3_uri_rejects_userinfo() {
        let result = parse_h3_uri("https://user:pass@example.com/path");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("userinfo"));
    }

    #[test]
    fn parse_h3_uri_rejects_query() {
        let result = parse_h3_uri("https://example.com/path?query=1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("query"));
    }

    #[test]
    fn parse_h3_uri_accepts_ipv6_host() {
        let endpoint = parse_h3_uri("https://[::1]:8443/path").expect("should parse");
        assert_eq!(endpoint.host, "[::1]");
        assert_eq!(endpoint.port, 8443);
    }

    #[test]
    fn parse_h3_uri_accepts_root_path() {
        let endpoint = parse_h3_uri("https://example.com/").expect("should parse");
        assert_eq!(endpoint.path, "/");
    }

    // ========== parse_api_uri tests ==========

    #[test]
    fn parse_api_uri_accepts_full_uri() {
        let ep = parse_api_uri("http://127.0.0.1:9090/admin").expect("should parse");
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 9090);
        assert_eq!(ep.path, "/admin");
    }

    #[test]
    fn parse_api_uri_defaults_port_9090() {
        let ep = parse_api_uri("http://localhost/").expect("should parse");
        assert_eq!(ep.host, "localhost");
        assert_eq!(ep.port, 9090);
    }

    #[test]
    fn parse_api_uri_rejects_https() {
        assert!(parse_api_uri("https://127.0.0.1:9090/").is_err());
    }

    #[test]
    fn parse_api_uri_accepts_ipv6() {
        let ep = parse_api_uri("http://[::1]:8080/").expect("should parse");
        assert_eq!(ep.host, "[::1]");
        assert_eq!(ep.port, 8080);
    }

    #[test]
    fn parse_api_uri_rejects_userinfo() {
        assert!(parse_api_uri("http://user:pass@127.0.0.1:9090/").is_err());
    }

    // ========== local.api config tests ==========

    #[test]
    fn parses_config_with_local_api() {
        let yaml = r#"
local:
  api:
    listen: http://127.0.0.1:9090/
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        let api = cfg.local.api.as_ref().expect("api should be present");
        assert_eq!(api.listen.host, "127.0.0.1");
        assert_eq!(api.listen.port, 9090);
        assert_eq!(api.listen.path, "/");
    }

    #[test]
    fn parses_config_with_api_and_h3() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  api:
    listen: http://127.0.0.1:9090/
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert!(cfg.local.h3.is_some());
        assert!(cfg.local.api.is_some());
    }

    #[test]
    fn parses_config_without_any_transport() {
        let yaml = r#"
local:
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert!(cfg.local.h3.is_none());
        assert!(cfg.local.bare.is_none());
        assert!(cfg.local.api.is_none());
    }

    #[test]
    fn parse_h3_config_with_all_required_fields() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: remote-peer
  h3:
    token: remote-peer-token
    endpoint: https://peer.example.com:443/path
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert!(cfg.local.h3.is_some());
        let h3 = cfg.local.h3.as_ref().unwrap();
        assert_eq!(h3.listen.host, "[::]");
        assert_eq!(h3.listen.port, 443);
        assert_eq!(h3.cert, "./cert.pem");
        assert_eq!(h3.key, "./key.pem");
    }

    #[test]
    fn parse_h3_with_singular_bindif() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
    endpoint: https://peer.example.com:443/path
    bindif: eth0
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        let h3 = cfg.peers[0].h3.as_ref().expect("h3 should be present");
        assert_eq!(h3.bindif, Some("eth0".to_string()));
    }

    // ========== Endpoint deserialization tests ==========

    #[test]
    fn udp_endpoint_deserializes_from_string() {
        let yaml = r#""udp://example.com:6635""#;
        let endpoint: UdpEndpoint = serde_yaml::from_str(yaml).expect("should deserialize");
        assert_eq!(endpoint.host, "example.com");
        assert_eq!(endpoint.port, 6635);
    }

    #[test]
    fn udp_endpoint_rejects_invalid_scheme() {
        let yaml = r#""tcp://example.com:6635""#;
        let result: Result<UdpEndpoint, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn udp_endpoint_serializes_to_uri() {
        let endpoint = UdpEndpoint {
            host: "example.com".to_string(),
            port: 6635,
        };
        let yaml = serde_yaml::to_string(&endpoint).expect("should serialize");
        assert!(yaml.contains("udp://example.com:6635"));
    }

    #[test]
    fn h3_endpoint_deserializes_from_string() {
        let yaml = r#""https://example.com:8443/path""#;
        let endpoint: H3Endpoint = serde_yaml::from_str(yaml).expect("should deserialize");
        assert_eq!(endpoint.host, "example.com");
        assert_eq!(endpoint.port, 8443);
        assert_eq!(endpoint.path, "/path");
    }

    #[test]
    fn h3_endpoint_defaults_port_443() {
        let yaml = r#""https://example.com/path""#;
        let endpoint: H3Endpoint = serde_yaml::from_str(yaml).expect("should deserialize");
        assert_eq!(endpoint.port, 443);
    }

    #[test]
    fn h3_endpoint_rejects_http_scheme() {
        let yaml = r#""http://example.com/path""#;
        let result: Result<H3Endpoint, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn h3_endpoint_serializes_omits_default_port() {
        let endpoint = H3Endpoint {
            host: "example.com".to_string(),
            port: 443,
            path: "/path".to_string(),
        };
        let yaml = serde_yaml::to_string(&endpoint).expect("should serialize");
        assert!(yaml.contains("https://example.com/path"));
        assert!(!yaml.contains(":443"));
    }

    #[test]
    fn config_rejects_invalid_endpoint_uri_at_parse_time() {
        let yaml = r#"
local:
  bare:
    listen: not-a-valid-uri
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    // ========== Parse-at-deserialization tests ==========

    #[test]
    fn deserializes_local_tun_addrs_as_ipnet() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.0/24
      - 2001:db8::/64
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.local.tun.addrs.len(), 2);
        assert_eq!(cfg.local.tun.addrs[0].prefix_len(), 24);
        assert_eq!(cfg.local.tun.addrs[1].prefix_len(), 64);
    }

    #[test]
    fn rejects_invalid_tun_addr_at_parse_time() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - not-a-cidr
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn accepts_cidr_in_tun_addrs() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
      - 10.0.0.0/24
"#;
        let cfg = Config::load_from_str(yaml).expect("CIDR should be accepted");
        assert_eq!(cfg.local.tun.addrs.len(), 2);
        assert_eq!(cfg.local.tun.addrs[0].prefix_len(), 32);
        assert_eq!(cfg.local.tun.addrs[1].prefix_len(), 24);
    }

    #[test]
    fn deserializes_allowed_ips_as_ipnet() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 10.0.0.0/24
      - 2001:db8::/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.peers[0].tun.allowed_ips.len(), 2);
        assert_eq!(cfg.peers[0].tun.allowed_ips[0].prefix_len(), 24);
        assert_eq!(cfg.peers[0].tun.allowed_ips[1].prefix_len(), 32);
    }

    #[test]
    fn rejects_invalid_allowed_ip_at_parse_time() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - not-a-cidr
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn deserializes_dns_server_as_socket_addr() {
        let yaml = r#"
local:
  dns:
    server: udp://8.8.8.8:53
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.local.dns.server.ip().to_string(), "8.8.8.8");
        assert_eq!(cfg.local.dns.server.port(), 53);
    }

    #[test]
    fn rejects_invalid_dns_server_at_parse_time() {
        let yaml = r#"
local:
  dns:
    server: tcp://8.8.8.8:53
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn dns_server_round_trip_serialization() {
        let yaml = r#"
local:
  dns:
    server: udp://8.8.8.8:53
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        let serialized = serde_yaml::to_string(&cfg).expect("should serialize");
        // Re-parse to verify round-trip
        let cfg2: Config = serde_yaml::from_str(&serialized).expect("should re-parse");
        assert_eq!(cfg.local.dns.server, cfg2.local.dns.server);
    }

    #[test]
    fn dns_server_ipv6_round_trip_serialization() {
        let yaml = r#"
local:
  dns:
    server: udp://[2001:4860:4860::8888]:53
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        let serialized = serde_yaml::to_string(&cfg).expect("should serialize");
        // Verify IPv6 address is wrapped in brackets in output
        assert!(
            serialized.contains("udp://[2001:4860:4860::8888]:53"),
            "IPv6 should be bracket-wrapped: {serialized}"
        );
        // Re-parse to verify round-trip
        let cfg2: Config = serde_yaml::from_str(&serialized).expect("should re-parse");
        assert_eq!(cfg.local.dns.server, cfg2.local.dns.server);
    }

    #[test]
    fn parse_dns_server_uri_rejects_userinfo() {
        let result = parse_dns_server_uri("udp://user:pass@1.1.1.1:53");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("userinfo"),
            "should reject userinfo in DNS server URI"
        );
    }

    #[test]
    fn tuning_defaults_applied_when_absent() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.tuning.packet_queue_depth, 2048);
        assert_eq!(cfg.tuning.socket_buffer_size, 16);
        assert_eq!(cfg.tuning.reconnect_interval, Duration::from_secs(3));
        assert_eq!(
            cfg.tuning.metrics_push_interval,
            Duration::from_millis(1000)
        );
        assert_eq!(cfg.tuning.dns_query_timeout, Duration::from_secs(2));
        assert_eq!(cfg.tuning.dns_refresh_interval, Duration::from_secs(60));
        assert_eq!(cfg.tuning.dns_snapshot_delay, Duration::from_millis(100));
        assert_eq!(cfg.tuning.dns_min_ttl, 60);
        assert_eq!(cfg.tuning.h3_handshake_timeout, Duration::from_secs(30));
        assert_eq!(cfg.tuning.h3_max_idle_timeout, Duration::from_secs(60));
        assert_eq!(cfg.tuning.h3_keepalive_interval, Duration::from_secs(20));
        assert_eq!(cfg.tuning.h3_cc_algorithm, "bbr2");
        assert!(cfg.tuning.h3_enable_pacing);
        assert!(!cfg.tuning.h3_insecure_skip_verify);
    }

    #[test]
    fn tuning_cc_algorithm_override() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  h3_cc_algorithm: cubic
  h3_enable_pacing: false
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.tuning.h3_cc_algorithm, "cubic");
        assert!(!cfg.tuning.h3_enable_pacing);
    }

    #[test]
    fn rejects_invalid_cc_algorithm() {
        let mut config = sample_h3_config();
        config.tuning.h3_cc_algorithm = "invalid".to_string();
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::InvalidCcAlgorithm { .. }))
        ));
    }

    #[test]
    fn accepts_all_valid_cc_algorithms() {
        for algo in &["reno", "cubic", "bbr", "bbr2", "none"] {
            let mut config = sample_h3_config();
            config.tuning.h3_cc_algorithm = algo.to_string();
            assert!(
                config.validate().is_ok(),
                "should accept cc_algorithm={algo}"
            );
        }
    }

    #[test]
    fn tuning_partial_override() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  packet_queue_depth: 512
  h3_max_idle_timeout: 120
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.tuning.packet_queue_depth, 512);
        assert_eq!(cfg.tuning.h3_max_idle_timeout, Duration::from_secs(120));
        assert_eq!(cfg.tuning.reconnect_interval, Duration::from_secs(3));
        assert_eq!(
            cfg.tuning.metrics_push_interval,
            Duration::from_millis(1000)
        );
    }

    #[test]
    fn rejects_zero_packet_queue_depth() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  packet_queue_depth: 0
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(
            result,
            Err(ConfigError::Validation(ValidationErrors(ref errs)))
                if errs.contains(&ValidationError::TuningPacketQueueDepthZero)
        ));
    }

    #[test]
    fn rejects_keepalive_equal_to_idle_timeout() {
        let mut config = sample_h3_config();
        config.tuning.h3_keepalive_interval = Duration::from_secs(60);
        config.tuning.h3_max_idle_timeout = Duration::from_secs(60);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::H3KeepaliveExceedsIdleTimeout { .. }))
        ));
    }

    #[test]
    fn rejects_keepalive_greater_than_idle_timeout() {
        let mut config = sample_h3_config();
        config.tuning.h3_keepalive_interval = Duration::from_secs(120);
        config.tuning.h3_max_idle_timeout = Duration::from_secs(60);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::H3KeepaliveExceedsIdleTimeout { .. }))
        ));
    }

    #[test]
    fn accepts_keepalive_less_than_idle_timeout() {
        let config = sample_h3_config();
        // Default: keepalive=20s, idle_timeout=60s
        assert!(config.validate().is_ok());
    }

    #[test]
    fn tuning_socket_buffer_size_override() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  socket_buffer_size: 32
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.tuning.socket_buffer_size, 32);
    }

    #[test]
    fn socket_buffer_bytes_conversion() {
        let tuning = Tuning::default();
        assert_eq!(tuning.socket_buffer_bytes(), 16 * 1024 * 1024);

        let tuning = Tuning {
            socket_buffer_size: 0,
            ..Tuning::default()
        };
        assert_eq!(tuning.socket_buffer_bytes(), 0);

        let tuning = Tuning {
            socket_buffer_size: 1,
            ..Tuning::default()
        };
        assert_eq!(tuning.socket_buffer_bytes(), 1024 * 1024);
    }

    #[test]
    fn tuning_insecure_skip_verify_override() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  h3_insecure_skip_verify: true
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert!(cfg.tuning.h3_insecure_skip_verify);
    }

    #[test]
    fn metrics_push_interval_millis_override() {
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  metrics_push_interval: 500
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.tuning.metrics_push_interval, Duration::from_millis(500));
    }

    #[test]
    fn rejects_removed_peer_h3_fields() {
        // `ca` field removed
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: node-2
  h3:
    token: example-node-2-token
    ca: ./ca.pem
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));

        // `insecure` field removed
        let yaml = r#"
local:
  h3:
    listen: https://[::]:443/
    cert: ./cert.pem
    key: ./key.pem
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: node-2
  h3:
    token: example-node-2-token
    insecure: true
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn rejects_zero_duration_fields() {
        let fields: &[(&str, fn(&mut Tuning))] = &[
            ("reconnect_interval", |t| {
                t.reconnect_interval = Duration::ZERO
            }),
            ("metrics_push_interval", |t| {
                t.metrics_push_interval = Duration::ZERO
            }),
            ("dns_query_timeout", |t| {
                t.dns_query_timeout = Duration::ZERO
            }),
            ("dns_snapshot_delay", |t| {
                t.dns_snapshot_delay = Duration::ZERO
            }),
            ("h3_handshake_timeout", |t| {
                t.h3_handshake_timeout = Duration::ZERO
            }),
            ("h3_max_idle_timeout", |t| {
                t.h3_max_idle_timeout = Duration::ZERO
            }),
            ("h3_keepalive_interval", |t| {
                t.h3_keepalive_interval = Duration::ZERO
            }),
        ];
        for &(field_name, setter) in fields {
            let mut config = sample_h3_config();
            setter(&mut config.tuning);
            let err = config.validate().unwrap_err();
            assert!(
                matches!(
                    err,
                    ConfigError::Validation(ValidationErrors(ref errs))
                        if errs.iter().any(|e| matches!(
                            e,
                            ValidationError::TuningDurationZero { field } if *field == field_name
                        ))
                ),
                "expected TuningDurationZero for field '{field_name}'"
            );
        }
    }

    #[test]
    fn allows_zero_dns_refresh_interval() {
        let mut config = sample_h3_config();
        config.tuning.dns_refresh_interval = Duration::ZERO;
        // dns_refresh_interval = 0 means "disable periodic refresh" — this is valid
        assert!(config.validate().is_ok());
    }
}
