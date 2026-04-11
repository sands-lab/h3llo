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
    /// `BareUDP` listener options.
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

/// `BareUDP` settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalBare {
    /// `BareUDP` listen address (required when `BareUDP` is configured).
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
    /// TUN MTU (default: 1291).
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

/// Peer transport selection: exactly one of H3 or `BareUDP`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTransport {
    /// HTTP/3 transport.
    H3(PeerH3),
    /// `BareUDP` transport.
    Bare(PeerBare),
}

/// Peer configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawPeer", into = "RawPeer")]
pub struct Peer {
    /// Remote node identifier.
    pub id: String,
    /// Transport configuration (exactly one of H3 or `BareUDP`).
    pub transport: PeerTransport,
    /// Peer routing details.
    pub tun: PeerTun,
}

/// Wire format for [`Peer`] serde (de)serialization.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    id: String,
    #[serde(default)]
    h3: Option<PeerH3>,
    #[serde(default)]
    bare: Option<PeerBare>,
    tun: PeerTun,
}

impl TryFrom<RawPeer> for Peer {
    type Error = String;
    fn try_from(raw: RawPeer) -> Result<Self, String> {
        let transport = match (raw.h3, raw.bare) {
            (Some(h3), None) => PeerTransport::H3(h3),
            (None, Some(bare)) => PeerTransport::Bare(bare),
            (Some(_), Some(_)) | (None, None) => {
                return Err(format!(
                    "peer '{}' must configure exactly one of h3 or bare",
                    raw.id
                ));
            }
        };
        Ok(Peer {
            id: raw.id,
            transport,
            tun: raw.tun,
        })
    }
}

impl From<Peer> for RawPeer {
    fn from(peer: Peer) -> Self {
        let (h3, bare) = match peer.transport {
            PeerTransport::H3(h3) => (Some(h3), None),
            PeerTransport::Bare(bare) => (None, Some(bare)),
        };
        RawPeer {
            id: peer.id,
            h3,
            bare,
            tun: peer.tun,
        }
    }
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

/// `BareUDP` options per peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerBare {
    /// `BareUDP` dialing endpoint (required when `BareUDP` is configured).
    pub endpoint: UdpEndpoint,
    /// Optional interface binding for `BareUDP` dialing.
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
/// Duration fields use human-readable strings (e.g. `"3s"`, `"500ms"`, `"2m"`).
///
/// Fields are grouped into sub-structs by subsystem (`io`, `dns`, `h3`)
/// and flattened for a single-level YAML layout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Tuning {
    /// Interval for the periodic reconciliation cycle (default: 10s).
    ///
    /// Controls how often the orchestrator prunes stale bounds and attempts
    /// reconnections for uncovered IPs.
    #[serde(with = "humantime_serde")]
    pub reconcile_interval: Duration,
    /// Minimum backoff duration between reconnection attempts per IP (default: 3s).
    ///
    /// The backoff grows exponentially from this base value after each failed attempt.
    #[serde(with = "humantime_serde")]
    pub reconnect_backoff_min: Duration,
    /// Maximum backoff duration between reconnection attempts per IP (default: 60s).
    ///
    /// The exponential backoff is capped at this ceiling.
    /// Must be greater than or equal to `reconnect_backoff_min`.
    #[serde(with = "humantime_serde")]
    pub reconnect_backoff_max: Duration,
    /// Metrics log interval (default: 3s).
    ///
    /// Controls how often the orchestrator logs QUIC and transport metrics at
    /// `debug!` level. Independent of `metrics_push_interval`, which controls
    /// how often actors emit metrics events.
    #[serde(with = "humantime_serde")]
    pub metrics_log_interval: Duration,
    /// I/O and data-plane tuning shared across transport actors.
    #[serde(flatten)]
    pub io: IoTuning,
    /// DNS resolver tuning.
    #[serde(flatten)]
    pub dns: DnsTuning,
    /// HTTP/3 and QUIC transport tuning.
    #[serde(flatten)]
    pub h3: H3Tuning,
}

/// I/O and data-plane tuning shared across transport actors.
///
/// Used by TUN, `BareUDP`, and H3 actors for channel sizing, socket
/// configuration, and offload settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct IoTuning {
    /// Data-plane packet queue depth for bounded backpressure channels (default: 256).
    pub packet_queue_depth: usize,
    /// Socket buffer size in megabytes for `SO_RCVBUF` and `SO_SNDBUF` (default: 16).
    ///
    /// Applied to all UDP sockets. Set to 0 to skip buffer configuration and use
    /// system defaults. Actual kernel buffer may be clamped by OS limits.
    pub socket_buffer_size: usize,
    /// TUN transmit queue length in packets (default: unset, OS default).
    ///
    /// Controls how many packets the kernel queues for transmission on the TUN
    /// interface. Linux only; warns on other platforms if set.
    pub tun_tx_queue_len: Option<u32>,
    /// Enable GSO/GRO offload on the TUN device (default: `false`).
    ///
    /// When `true` on Linux, the TUN device uses batched I/O with
    /// `virtio_net_hdr` for GSO/GRO, significantly improving throughput.
    /// When `false` or on non-Linux platforms, single-packet I/O is used.
    ///
    /// Disabled by default due to compatibility issues with certain kernel
    /// versions and virtualization layers. Enable for better performance
    /// and verify with thorough testing.
    pub tun_enable_offload: bool,
    /// Enable UDP offload for transports (default: `false`).
    ///
    /// Effect varies by transport:
    ///
    /// - **UDP TX** (`BareUDP` and the current H3 data plane): controls GSO
    ///   segment count. When `true`, batches multiple packets into a single
    ///   `sendmsg` via `UDP_SEGMENT`. When `false`, segment count is capped
    ///   to 1 (per-packet sends).
    /// - **UDP RX** (`BareUDP` and the current H3 data plane): **no effect**.
    ///   quinn-udp's `UdpSocketState::new()` unconditionally enables
    ///   `UDP_GRO`; the receive buffer is always sized for the socket's
    ///   actual GRO capability to prevent silent truncation of coalesced
    ///   datagrams.
    ///
    /// Disabled by default due to compatibility issues with certain NIC
    /// drivers and platforms (e.g., incorrect checksums, EINVAL on
    /// aarch64). Enable for better performance and verify with thorough
    /// testing. See troubleshooting guide for known issues.
    pub udp_enable_offload: bool,
    /// Metrics push interval (default: `"1s"`).
    #[serde(with = "humantime_serde")]
    pub metrics_push_interval: Duration,
}

impl IoTuning {
    /// Returns socket buffer size in bytes, or 0 to skip configuration.
    #[must_use]
    pub fn socket_buffer_bytes(&self) -> usize {
        self.socket_buffer_size.saturating_mul(1024 * 1024)
    }
}

impl Default for IoTuning {
    fn default() -> Self {
        Self {
            packet_queue_depth: 256,
            socket_buffer_size: 16,
            tun_tx_queue_len: None,
            tun_enable_offload: false,
            udp_enable_offload: false,
            metrics_push_interval: Duration::from_millis(1000),
        }
    }
}

/// DNS resolver tuning parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DnsTuning {
    /// DNS query timeout (default: 2s).
    #[serde(with = "humantime_serde")]
    pub dns_query_timeout: Duration,
    /// DNS refresh interval; 0 disables (default: 120s).
    ///
    /// **Warning:** `dns_min_ttl` should be at least `2 × dns_refresh_interval`.
    /// Otherwise, cached IPs may expire before the next refresh re-queries them,
    /// causing connections to be pruned and re-established in a loop.
    #[serde(with = "humantime_serde")]
    pub dns_refresh_interval: Duration,
    /// Delay before emitting a DNS snapshot after the first state change (default: 100ms).
    ///
    /// After a DNS reply marks the state dirty, the resolver waits this duration
    /// before emitting a snapshot to the orchestrator. Subsequent replies within
    /// the window are coalesced into the same snapshot.
    #[serde(with = "humantime_serde")]
    pub dns_snapshot_delay: Duration,
    /// Minimum interval between consecutive DNS query sends (default: 50ms).
    ///
    /// Serializes outbound DNS queries to avoid triggering rate limits on
    /// public resolvers (e.g., Cloudflare 1.1.1.1). A sleep of this duration
    /// is inserted before each outbound query send.
    #[serde(with = "humantime_serde")]
    pub dns_query_interval: Duration,
    /// Minimum TTL floor for DNS records (default: `"5m"`).
    ///
    /// DNS responses with TTL below this value are raised to this floor
    /// to prevent excessive re-queries. Recursive DNS servers return the
    /// *remaining* cache TTL, which can be arbitrarily low (even 0) when
    /// the upstream record is about to expire. Without a sufficient floor
    /// the IP expires in the local cache before the next refresh cycle
    /// re-queries it, triggering connection pruning and reconnection.
    ///
    /// **Warning:** Should be at least `2 × dns_refresh_interval` to
    /// guarantee that every refresh cycle renews the TTL before expiry.
    #[serde(with = "humantime_serde")]
    pub dns_min_ttl: Duration,
}

impl Default for DnsTuning {
    fn default() -> Self {
        Self {
            dns_query_timeout: Duration::from_secs(2),
            dns_refresh_interval: Duration::from_secs(120),
            dns_snapshot_delay: Duration::from_millis(100),
            dns_query_interval: Duration::from_millis(50),
            dns_min_ttl: Duration::from_secs(300),
        }
    }
}

/// HTTP/3 and QUIC transport tuning parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct H3Tuning {
    /// HTTP/3 handshake timeout (default: 5s).
    #[serde(with = "humantime_serde")]
    pub h3_handshake_timeout: Duration,
    /// HTTP/3 max idle timeout (default: 60s).
    #[serde(with = "humantime_serde")]
    pub h3_max_idle_timeout: Duration,
    /// HTTP/3 keepalive interval (default: 20s). Sends QUIC PING frames to prevent idle timeout.
    #[serde(with = "humantime_serde")]
    pub h3_keepalive_interval: Duration,
    /// QUIC congestion control algorithm (default: `"none"`).
    ///
    /// Accepted values: `"reno"`, `"cubic"`, `"bbr"`, `"bbr2"`, `"none"`.
    /// Applied to both dialer and listener QUIC connections.
    pub h3_cc_algorithm: String,
    /// Enable QUIC packet pacing (default: `false`).
    ///
    /// Smooths out bursty sends at the cost of slight latency increase.
    /// Requires OS-level pacing support (e.g., `SO_TXTIME` on Linux).
    /// Applied to both dialer and listener QUIC connections.
    pub h3_enable_pacing: bool,
    /// Skip TLS certificate verification for all H3 connections (default: `false`).
    ///
    /// When `true`, QUIC/TLS peer verification is disabled. Intended for testing
    /// with self-signed certificates only. **Not recommended for production.**
    pub h3_insecure_skip_verify: bool,
    /// Optional path to a PEM-encoded CA certificate file for H3 TLS verification.
    ///
    /// When set, the certificates in this file are added to the trust store
    /// alongside system CA certificates. Useful for private PKI or self-signed
    /// CA deployments. When `None` (default), only system CA certificates are
    /// used. Ignored when `h3_insecure_skip_verify` is `true`.
    pub h3_trusted_ca: Option<String>,
}

impl Default for H3Tuning {
    fn default() -> Self {
        Self {
            h3_handshake_timeout: Duration::from_secs(5),
            h3_max_idle_timeout: Duration::from_secs(60),
            h3_keepalive_interval: Duration::from_secs(20),
            h3_cc_algorithm: "none".to_string(),
            h3_enable_pacing: false,
            h3_insecure_skip_verify: false,
            h3_trusted_ca: None,
        }
    }
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            reconcile_interval: Duration::from_secs(10),
            reconnect_backoff_min: Duration::from_secs(3),
            reconnect_backoff_max: Duration::from_secs(60),
            metrics_log_interval: Duration::from_secs(3),
            io: IoTuning::default(),
            dns: DnsTuning::default(),
            h3: H3Tuning::default(),
        }
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
        let joined = self
            .0
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        f.write_str(&joined)
    }
}

impl std::error::Error for ValidationErrors {}

/// Individual validation error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    /// A field that must be positive is zero.
    #[error("{field} must be greater than 0")]
    FieldMustBePositive { field: &'static str },
    /// Two or more fields have conflicting values.
    #[error("field conflict: {description}")]
    FieldConflict { description: String },
    /// A required field is empty (after trimming whitespace) or has no entries.
    #[error("{context}: {field} must not be empty")]
    FieldEmpty {
        context: String,
        field: &'static str,
    },
    /// A string field has leading or trailing whitespace.
    #[error("{context}: {field} must not have leading or trailing whitespace")]
    FieldHasWhitespace {
        context: String,
        field: &'static str,
    },
    /// A field value is duplicated where uniqueness is required.
    #[error("{context}: duplicate {field} '{value}'")]
    DuplicateValue {
        context: String,
        field: &'static str,
        value: String,
    },
    /// Peer token missing or too short.
    #[error("peer '{peer_id}' requires h3.token of at least 12 characters when h3 is configured")]
    PeerTokenTooShort { peer_id: String },
    /// `tuning.h3_cc_algorithm` is not a recognized congestion control algorithm.
    #[error(
        "tuning.h3_cc_algorithm '{algorithm}' is not recognized \
         (accepted: reno, cubic, bbr, bbr2, none)"
    )]
    InvalidCcAlgorithm { algorithm: String },
}

impl Config {
    /// Loads configuration from a YAML reader and validates it.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] on YAML parse failure or validation errors.
    pub fn load_from_reader<R: Read>(reader: R) -> Result<Self, ConfigError> {
        let config: Config = serde_yaml::from_reader(reader)?;
        config.validate()?;
        Ok(config)
    }

    /// Loads configuration from a YAML string and validates it.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] on YAML parse failure or validation errors.
    pub fn load_from_str(contents: &str) -> Result<Self, ConfigError> {
        let config: Config = serde_yaml::from_str(contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates structural and semantic constraints.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] if any structural or semantic constraint is violated.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        // Tuning validation
        if self.tuning.io.packet_queue_depth == 0 {
            errors.push(ValidationError::FieldMustBePositive {
                field: "tuning.packet_queue_depth",
            });
        }

        // Duration fields that must be strictly positive.
        // dns_refresh_interval is intentionally excluded: zero disables periodic refresh.
        let duration_checks: &[(&'static str, Duration)] = &[
            ("tuning.reconcile_interval", self.tuning.reconcile_interval),
            (
                "tuning.reconnect_backoff_min",
                self.tuning.reconnect_backoff_min,
            ),
            (
                "tuning.reconnect_backoff_max",
                self.tuning.reconnect_backoff_max,
            ),
            (
                "tuning.metrics_push_interval",
                self.tuning.io.metrics_push_interval,
            ),
            (
                "tuning.metrics_log_interval",
                self.tuning.metrics_log_interval,
            ),
            (
                "tuning.dns_query_timeout",
                self.tuning.dns.dns_query_timeout,
            ),
            (
                "tuning.dns_snapshot_delay",
                self.tuning.dns.dns_snapshot_delay,
            ),
            (
                "tuning.dns_query_interval",
                self.tuning.dns.dns_query_interval,
            ),
            (
                "tuning.h3_handshake_timeout",
                self.tuning.h3.h3_handshake_timeout,
            ),
            (
                "tuning.h3_max_idle_timeout",
                self.tuning.h3.h3_max_idle_timeout,
            ),
            (
                "tuning.h3_keepalive_interval",
                self.tuning.h3.h3_keepalive_interval,
            ),
        ];
        for &(field, dur) in duration_checks {
            if dur.is_zero() {
                errors.push(ValidationError::FieldMustBePositive { field });
            }
        }

        if self.tuning.h3.h3_keepalive_interval >= self.tuning.h3.h3_max_idle_timeout {
            errors.push(ValidationError::FieldConflict {
                description: format!(
                    "tuning.h3_keepalive_interval ({:?}) must be less than \
                     tuning.h3_max_idle_timeout ({:?})",
                    self.tuning.h3.h3_keepalive_interval, self.tuning.h3.h3_max_idle_timeout,
                ),
            });
        }

        // Subset of quiche::CongestionControlAlgorithm::from_str();
        // excludes internal aliases (bbr2_gcongestion).
        if !["reno", "cubic", "bbr", "bbr2", "none"]
            .contains(&self.tuning.h3.h3_cc_algorithm.as_str())
        {
            errors.push(ValidationError::InvalidCcAlgorithm {
                algorithm: self.tuning.h3.h3_cc_algorithm.clone(),
            });
        }

        // H3-peer-conditional warnings (non-fatal best-practice checks).
        let has_h3_peers = self
            .peers
            .iter()
            .any(|p| matches!(p.transport, PeerTransport::H3(_)));
        if has_h3_peers {
            if self.local.tun.mtu > MAX_H3_IPV4_MTU {
                tracing::warn!(
                    mtu = self.local.tun.mtu,
                    max_safe = MAX_H3_IPV4_MTU,
                    "local.tun.mtu exceeds safe maximum for IPv4 CONNECT-IP with H3 peers; \
                     oversized QUIC DATAGRAMs may fail to send"
                );
            }
            if self.tuning.reconnect_backoff_min <= self.tuning.h3.h3_handshake_timeout {
                tracing::warn!(
                    reconnect_backoff_min = ?self.tuning.reconnect_backoff_min,
                    h3_handshake_timeout = ?self.tuning.h3.h3_handshake_timeout,
                    "tuning.reconnect_backoff_min should be greater than \
                     tuning.h3_handshake_timeout to prevent overlapping handshake attempts"
                );
            }
        }

        // DNS TTL floor vs refresh interval: if min_ttl < 2× refresh, IPs can
        // expire between refresh cycles, causing repeated connection churn.
        if !self.tuning.dns.dns_refresh_interval.is_zero() {
            let min_safe_ttl = self.tuning.dns.dns_refresh_interval.saturating_mul(2);
            if self.tuning.dns.dns_min_ttl < min_safe_ttl {
                tracing::warn!(
                    dns_min_ttl = ?self.tuning.dns.dns_min_ttl,
                    dns_refresh_interval = ?self.tuning.dns.dns_refresh_interval,
                    recommended_min_ttl = ?min_safe_ttl,
                    "tuning.dns_min_ttl should be at least 2× tuning.dns_refresh_interval; \
                     otherwise cached IPs may expire before the next refresh, \
                     causing repeated connection pruning and reconnection"
                );
            }
        }

        if self.tuning.reconnect_backoff_min > self.tuning.reconnect_backoff_max {
            errors.push(ValidationError::FieldConflict {
                description: format!(
                    "tuning.reconnect_backoff_min ({:?}) must not exceed \
                     tuning.reconnect_backoff_max ({:?})",
                    self.tuning.reconnect_backoff_min, self.tuning.reconnect_backoff_max,
                ),
            });
        }

        // H3 validation: cert/key must not be empty when local.h3 is set
        if let Some(h3) = self.local.h3.as_ref() {
            check_trimmed(&h3.cert, "local.h3", "cert", true, &mut errors);
            check_trimmed(&h3.key, "local.h3", "key", true, &mut errors);
        }

        check_not_empty(
            self.local.tun.addrs.is_empty(),
            "local.tun",
            "addrs",
            &mut errors,
        );

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

/// Pushes a `FieldEmpty` error if the collection/field is empty.
fn check_not_empty(
    is_empty: bool,
    context: &str,
    field: &'static str,
    errors: &mut Vec<ValidationError>,
) {
    if is_empty {
        errors.push(ValidationError::FieldEmpty {
            context: context.to_string(),
            field,
        });
    }
}

/// Pushes a `DuplicateValue` error if `value` is already in `seen`.
fn check_unique<T: Eq + std::hash::Hash + Clone + ToString>(
    seen: &mut HashSet<T>,
    value: &T,
    context: &str,
    field: &'static str,
    errors: &mut Vec<ValidationError>,
) {
    if !seen.insert(value.clone()) {
        errors.push(ValidationError::DuplicateValue {
            context: context.to_string(),
            field,
            value: value.to_string(),
        });
    }
}

/// Validates a string field for emptiness and leading/trailing whitespace.
fn check_trimmed(
    value: &str,
    context: &str,
    field: &'static str,
    check_empty: bool,
    errors: &mut Vec<ValidationError>,
) {
    if check_empty && value.trim().is_empty() {
        errors.push(ValidationError::FieldEmpty {
            context: context.to_string(),
            field,
        });
        return;
    }
    if value != value.trim() {
        errors.push(ValidationError::FieldHasWhitespace {
            context: context.to_string(),
            field,
        });
    }
}

/// Validates a peer list in isolation (ID, token, transport, `allowed_ips`).
///
/// # Errors
///
/// Returns [`ValidationErrors`] if any peer has invalid configuration.
pub fn validate_peers(peers: &[Peer]) -> Result<(), ValidationErrors> {
    let mut errors = Vec::new();
    let mut seen_peer_ids = HashSet::new();
    let mut seen_peer_tokens = HashSet::new();

    for peer in peers {
        let ctx = format!("peer '{}'", peer.id);

        check_trimmed(&peer.id, &ctx, "id", true, &mut errors);
        check_unique(&mut seen_peer_ids, &peer.id, &ctx, "id", &mut errors);

        if let PeerTransport::H3(h3) = &peer.transport {
            if h3.token.len() < 12 {
                errors.push(ValidationError::PeerTokenTooShort {
                    peer_id: peer.id.clone(),
                });
            } else {
                check_trimmed(&h3.token, &ctx, "h3.token", false, &mut errors);
            }
            check_unique(
                &mut seen_peer_tokens,
                &h3.token,
                &ctx,
                "h3.token",
                &mut errors,
            );

            if let Some(sni) = &h3.sni {
                check_trimmed(sni, &ctx, "h3.sni", true, &mut errors);
            }
            if let Some(bindif) = &h3.bindif {
                check_trimmed(bindif, &ctx, "h3.bindif", false, &mut errors);
            }
        }

        check_not_empty(
            peer.tun.allowed_ips.is_empty(),
            &ctx,
            "tun.allowed_ips",
            &mut errors,
        );

        let mut seen_allowed = HashSet::new();
        for net in &peer.tun.allowed_ips {
            check_unique(&mut seen_allowed, net, &ctx, "tun.allowed_ips", &mut errors);
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

/// Default TUN MTU derived from tokio-quiche's default `max_udp_payload_size` (1350).
///
/// `max_udp_payload_size` (1350) − CONNECT-IP overhead (59) = 1291.
/// The limit is configurable in quiche.
#[must_use]
pub fn default_mtu() -> u16 {
    1291
}

/// Maximum safe TUN MTU for HTTP/3 CONNECT-IP over a 1500-byte IPv4 WAN path.
///
/// 1500 (Ethernet MTU) − 28 (IPv4 + UDP) − 59 (CONNECT-IP overhead) = 1413.
/// Exceeding this value may cause oversized QUIC DATAGRAM frames that fail
/// to send. See `docs/protocol.md` § MTU Guidance.
const MAX_H3_IPV4_MTU: u16 = 1413;

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

/// Implements `Serialize`/`Deserialize` for a URI-based endpoint type.
macro_rules! impl_uri_serde {
    ($ty:ty, $parse_fn:path, $format_fn:expr) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                $parse_fn(&s).map_err(de::Error::custom)
            }
        }

        impl Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(&$format_fn(self))
            }
        }
    };
}

impl_uri_serde!(UdpEndpoint, parse_udp_uri, |ep: &UdpEndpoint| format!(
    "udp://{}:{}",
    ep.host, ep.port
));

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

impl_uri_serde!(H3Endpoint, parse_h3_uri, |ep: &H3Endpoint| {
    if ep.port == 443 {
        format!("https://{}{}", ep.host, ep.path)
    } else {
        format!("https://{}:{}{}", ep.host, ep.port, ep.path)
    }
});

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

// Always include the port to avoid round-trip bugs (HTTP default is 80, not 9090).
impl_uri_serde!(ApiEndpoint, parse_api_uri, |ep: &ApiEndpoint| format!(
    "http://{}:{}{}",
    ep.host, ep.port, ep.path
));

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
pub(crate) fn parse_dns_server_uri(raw: &str) -> Result<SocketAddr, String> {
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
pub(crate) fn parse_h3_uri(raw: &str) -> Result<H3Endpoint, String> {
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
pub(crate) fn parse_api_uri(raw: &str) -> Result<ApiEndpoint, String> {
    let (host, port, path) = parse_endpoint_uri(raw, "http")?;
    Ok(ApiEndpoint {
        host,
        port: port.unwrap_or(9090),
        path,
    })
}

/// Parses a UDP URI (e.g., `udp://host:6635`) into host and port components.
pub(crate) fn parse_udp_uri(raw: &str) -> Result<UdpEndpoint, String> {
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
    use tracing_test::traced_test;

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
                    mtu: 1291,
                },
            },
            tuning: Tuning::default(),
            peers: vec![Peer {
                id: "example-node-2".to_string(),
                transport: PeerTransport::H3(PeerH3 {
                    token: "example-node-2-token".to_string(), // >= 12 chars
                    endpoint: Some(H3Endpoint {
                        host: "peer.example.com".to_string(),
                        port: 443,
                        path: "/path".to_string(),
                    }),
                    bindif: None,
                    sni: None,
                }),
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
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::FieldEmpty { field: "id", .. }))
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
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::FieldHasWhitespace { field: "id", .. }))
        ));
    }

    #[test]
    fn rejects_peer_id_with_trailing_whitespace() {
        let mut config = sample_h3_config();
        config.peers[0].id = "peer1 ".to_string();
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::FieldHasWhitespace { field: "id", .. }))
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
                if errs.iter().any(|e| matches!(e, ValidationError::FieldEmpty { field: "cert", .. }))
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
                if errs.iter().any(|e| matches!(e, ValidationError::FieldEmpty { field: "key", .. }))
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
    fn rejects_peer_transport_conflict_at_deserialization() {
        let yaml = r#"
local:
  tun:
    addrs:
      - 192.168.180.1/32
peers:
  - id: bad-peer
    h3:
      token: "long-enough-token"
    bare:
      endpoint: udp://127.0.0.1:5353
    tun:
      allowed_ips:
        - 10.0.0.0/24
"#;
        assert!(Config::load_from_str(yaml).is_err());
    }

    #[test]
    fn rejects_short_peer_token() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
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
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.token = "123456789012".to_string(); // Exactly 12 chars
        }
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_token_with_leading_whitespace() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.token = " 123456789012".to_string(); // 13 chars but has leading space
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::FieldHasWhitespace { field: "h3.token", .. }))
        ));
    }

    #[test]
    fn rejects_token_with_trailing_whitespace() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.token = "123456789012 ".to_string(); // 13 chars but has trailing space
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::FieldHasWhitespace { field: "h3.token", .. }))
        ));
    }

    #[test]
    fn rejects_duplicate_peer_ids() {
        let mut config = sample_h3_config();
        let mut peer2 = config.peers[0].clone();
        if let PeerTransport::H3(h3) = &mut peer2.transport {
            h3.token = "different-token-123".to_string();
        }
        config.peers.push(peer2);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::DuplicateValue { field: "id", .. }))
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
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::DuplicateValue { field: "h3.token", .. }))
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
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::FieldEmpty { field: "tun.allowed_ips", .. }))
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
        assert_eq!(cfg.local.tun.mtu, 1291);
        let PeerTransport::H3(h3) = &cfg.peers[0].transport else {
            panic!("peer should be H3");
        };
        assert!(h3.endpoint.is_none());
        assert!(h3.bindif.is_none());
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
        let PeerTransport::H3(h3) = &cfg.peers[0].transport else {
            panic!("should be H3")
        };
        let endpoint = h3.endpoint.as_ref().expect("endpoint should be present");
        assert_eq!(endpoint.host, "peer.example.com");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path, "/path");
        assert_eq!(h3.bindif, Some("eth0".to_string()));
    }

    #[test]
    fn accepts_peer_h3_with_bindif() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.bindif = Some("eth0".to_string());
        }
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_peer_h3_with_sni() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.sni = Some("custom-sni.example.com".to_string());
        }
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_peer_h3_without_sni() {
        let config = sample_h3_config();
        let PeerTransport::H3(h3) = &config.peers[0].transport else {
            panic!("should be H3")
        };
        assert!(h3.sni.is_none());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_empty_sni() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.sni = Some("".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::FieldEmpty { field: "h3.sni", .. }))
        ));
    }

    #[test]
    fn rejects_whitespace_only_sni() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.sni = Some("   ".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::FieldEmpty { field: "h3.sni", .. }))
        ));
    }

    #[test]
    fn rejects_sni_with_leading_whitespace() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.sni = Some(" leading".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::FieldHasWhitespace { field: "h3.sni", .. }))
        ));
    }

    #[test]
    fn rejects_sni_with_trailing_whitespace() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.sni = Some("trailing ".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::FieldHasWhitespace { field: "h3.sni", .. }))
        ));
    }

    #[test]
    fn rejects_bindif_with_leading_whitespace() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.bindif = Some(" eth0".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::FieldHasWhitespace { field: "h3.bindif", .. }))
        ));
    }

    #[test]
    fn rejects_bindif_with_trailing_whitespace() {
        let mut config = sample_h3_config();
        if let PeerTransport::H3(h3) = &mut config.peers[0].transport {
            h3.bindif = Some("eth0 ".to_string());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::FieldHasWhitespace { field: "h3.bindif", .. }))
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
                    .any(|e| matches!(e, ValidationError::DuplicateValue { field: "tun.allowed_ips", .. }))
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
        let PeerTransport::H3(h3) = &cfg.peers[0].transport else {
            panic!("should be H3")
        };
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
        assert_eq!(cfg.tuning.io.packet_queue_depth, 256);
        assert_eq!(cfg.tuning.io.socket_buffer_size, 16);
        assert_eq!(cfg.tuning.reconcile_interval, Duration::from_secs(10));
        assert_eq!(cfg.tuning.reconnect_backoff_min, Duration::from_secs(3));
        assert_eq!(cfg.tuning.reconnect_backoff_max, Duration::from_secs(60));
        assert_eq!(
            cfg.tuning.io.metrics_push_interval,
            Duration::from_millis(1000)
        );
        assert_eq!(cfg.tuning.metrics_log_interval, Duration::from_secs(3));
        assert_eq!(cfg.tuning.dns.dns_query_timeout, Duration::from_secs(2));
        assert_eq!(
            cfg.tuning.dns.dns_refresh_interval,
            Duration::from_secs(120)
        );
        assert_eq!(
            cfg.tuning.dns.dns_snapshot_delay,
            Duration::from_millis(100)
        );
        assert_eq!(cfg.tuning.dns.dns_query_interval, Duration::from_millis(50));
        assert_eq!(cfg.tuning.dns.dns_min_ttl, Duration::from_secs(300));
        assert_eq!(cfg.tuning.h3.h3_handshake_timeout, Duration::from_secs(5));
        assert_eq!(cfg.tuning.h3.h3_max_idle_timeout, Duration::from_secs(60));
        assert_eq!(cfg.tuning.h3.h3_keepalive_interval, Duration::from_secs(20));
        assert_eq!(cfg.tuning.h3.h3_cc_algorithm, "none");
        assert!(!cfg.tuning.h3.h3_enable_pacing);
        assert!(!cfg.tuning.h3.h3_insecure_skip_verify);
        assert!(cfg.tuning.h3.h3_trusted_ca.is_none());
        assert!(cfg.tuning.io.tun_tx_queue_len.is_none());
        assert!(!cfg.tuning.io.tun_enable_offload);
        assert!(!cfg.tuning.io.udp_enable_offload);
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
        assert_eq!(cfg.tuning.h3.h3_cc_algorithm, "cubic");
        assert!(!cfg.tuning.h3.h3_enable_pacing);
    }

    #[test]
    fn rejects_invalid_cc_algorithm() {
        let mut config = sample_h3_config();
        config.tuning.h3.h3_cc_algorithm = "invalid".to_string();
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
            config.tuning.h3.h3_cc_algorithm = algo.to_string();
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
  h3_max_idle_timeout: 120s
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.tuning.io.packet_queue_depth, 512);
        assert_eq!(cfg.tuning.h3.h3_max_idle_timeout, Duration::from_secs(120));
        assert_eq!(cfg.tuning.reconcile_interval, Duration::from_secs(10));
        assert_eq!(
            cfg.tuning.io.metrics_push_interval,
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
                if errs.contains(&ValidationError::FieldMustBePositive { field: "tuning.packet_queue_depth" })
        ));
    }

    #[test]
    fn rejects_keepalive_equal_to_idle_timeout() {
        let mut config = sample_h3_config();
        config.tuning.h3.h3_keepalive_interval = Duration::from_secs(60);
        config.tuning.h3.h3_max_idle_timeout = Duration::from_secs(60);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::FieldConflict { .. }))
        ));
    }

    #[test]
    fn rejects_keepalive_greater_than_idle_timeout() {
        let mut config = sample_h3_config();
        config.tuning.h3.h3_keepalive_interval = Duration::from_secs(120);
        config.tuning.h3.h3_max_idle_timeout = Duration::from_secs(60);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::FieldConflict { .. }))
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
        assert_eq!(cfg.tuning.io.socket_buffer_size, 32);
    }

    #[test]
    fn socket_buffer_bytes_conversion() {
        let tuning = IoTuning::default();
        assert_eq!(tuning.socket_buffer_bytes(), 16 * 1024 * 1024);

        let tuning = IoTuning {
            socket_buffer_size: 0,
            ..IoTuning::default()
        };
        assert_eq!(tuning.socket_buffer_bytes(), 0);

        let tuning = IoTuning {
            socket_buffer_size: 1,
            ..IoTuning::default()
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
        assert!(cfg.tuning.h3.h3_insecure_skip_verify);
    }

    #[test]
    fn tuning_h3_trusted_ca_override() {
        let yaml = r#"
local:
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  h3_trusted_ca: /etc/ssl/custom-ca.pem
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(
            cfg.tuning.h3.h3_trusted_ca.as_deref(),
            Some("/etc/ssl/custom-ca.pem")
        );
    }

    #[test]
    fn tuning_tun_tx_queue_len_override() {
        let yaml = r#"
local:
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  tun_tx_queue_len: 500
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.tuning.io.tun_tx_queue_len, Some(500));
    }

    #[test]
    fn dns_query_interval_millis_override() {
        let yaml = r#"
local:
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  dns_query_interval: 100ms
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(
            cfg.tuning.dns.dns_query_interval,
            Duration::from_millis(100)
        );
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
  metrics_push_interval: 500ms
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(
            cfg.tuning.io.metrics_push_interval,
            Duration::from_millis(500)
        );
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
        type TuningSetter = fn(&mut Tuning);

        let fields: &[(&str, TuningSetter)] = &[
            ("reconcile_interval", |t| {
                t.reconcile_interval = Duration::ZERO
            }),
            ("reconnect_backoff_min", |t| {
                t.reconnect_backoff_min = Duration::ZERO
            }),
            ("reconnect_backoff_max", |t| {
                t.reconnect_backoff_max = Duration::ZERO
            }),
            ("metrics_push_interval", |t| {
                t.io.metrics_push_interval = Duration::ZERO
            }),
            ("metrics_log_interval", |t| {
                t.metrics_log_interval = Duration::ZERO
            }),
            ("dns_query_timeout", |t| {
                t.dns.dns_query_timeout = Duration::ZERO
            }),
            ("dns_snapshot_delay", |t| {
                t.dns.dns_snapshot_delay = Duration::ZERO
            }),
            ("dns_query_interval", |t| {
                t.dns.dns_query_interval = Duration::ZERO
            }),
            ("h3_handshake_timeout", |t| {
                t.h3.h3_handshake_timeout = Duration::ZERO
            }),
            ("h3_max_idle_timeout", |t| {
                t.h3.h3_max_idle_timeout = Duration::ZERO
            }),
            ("h3_keepalive_interval", |t| {
                t.h3.h3_keepalive_interval = Duration::ZERO
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
                            ValidationError::FieldMustBePositive { field }
                                if field.ends_with(field_name)
                        ))
                ),
                "expected FieldMustBePositive for field '{field_name}'"
            );
        }
    }

    #[test]
    fn metrics_log_interval_secs_override() {
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
  metrics_log_interval: 5s
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowed_ips:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.tuning.metrics_log_interval, Duration::from_secs(5));
    }

    #[test]
    fn allows_zero_dns_refresh_interval() {
        let mut config = sample_h3_config();
        config.tuning.dns.dns_refresh_interval = Duration::ZERO;
        // dns_refresh_interval = 0 means "disable periodic refresh" — this is valid
        assert!(config.validate().is_ok());
    }

    #[test]
    fn tuning_offload_defaults_false() {
        let yaml = r#"
local:
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert!(!cfg.tuning.io.tun_enable_offload);
        assert!(!cfg.tuning.io.udp_enable_offload);
    }

    #[test]
    fn tuning_offload_override_true() {
        let yaml = r#"
local:
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  tun_enable_offload: true
  udp_enable_offload: true
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert!(cfg.tuning.io.tun_enable_offload);
        assert!(cfg.tuning.io.udp_enable_offload);
    }

    #[test]
    fn tuning_offload_partial_override() {
        let yaml = r#"
local:
  tun:
    addrs:
      - 192.168.180.1/32
tuning:
  udp_enable_offload: true
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert!(!cfg.tuning.io.tun_enable_offload); // still default
        assert!(cfg.tuning.io.udp_enable_offload);
    }

    // ========== H3 validation warning tests ==========

    #[test]
    #[traced_test]
    fn warns_mtu_exceeds_h3_ipv4_safe_max() {
        let mut config = sample_h3_config();
        config.local.tun.mtu = 1414;
        assert!(config.validate().is_ok());
        assert!(logs_contain("exceeds safe maximum"));
        assert!(logs_contain("mtu=1414"));
    }

    #[test]
    #[traced_test]
    fn no_mtu_warning_at_boundary() {
        let mut config = sample_h3_config();
        config.local.tun.mtu = 1413;
        assert!(config.validate().is_ok());
        assert!(!logs_contain("exceeds safe maximum"));
    }

    #[test]
    #[traced_test]
    fn no_mtu_warning_without_h3_peers() {
        let mut config = sample_h3_config();
        config.local.tun.mtu = 1500;
        config.peers[0].transport = PeerTransport::Bare(PeerBare {
            endpoint: UdpEndpoint {
                host: "peer.example.com".to_string(),
                port: 6635,
            },
            bindif: None,
        });
        assert!(config.validate().is_ok());
        assert!(!logs_contain("exceeds safe maximum"));
    }

    #[test]
    #[traced_test]
    fn warns_backoff_min_equals_handshake_timeout() {
        let mut config = sample_h3_config();
        config.tuning.reconnect_backoff_min = Duration::from_secs(5);
        config.tuning.h3.h3_handshake_timeout = Duration::from_secs(5);
        assert!(config.validate().is_ok());
        assert!(logs_contain("reconnect_backoff_min should be greater"));
    }

    #[test]
    #[traced_test]
    fn warns_backoff_min_less_than_handshake_timeout() {
        let mut config = sample_h3_config();
        config.tuning.reconnect_backoff_min = Duration::from_secs(2);
        config.tuning.h3.h3_handshake_timeout = Duration::from_secs(5);
        assert!(config.validate().is_ok());
        assert!(logs_contain("reconnect_backoff_min should be greater"));
    }

    #[test]
    #[traced_test]
    fn no_backoff_warning_when_min_longer() {
        let mut config = sample_h3_config();
        config.tuning.reconnect_backoff_min = Duration::from_secs(10);
        assert!(config.validate().is_ok());
        assert!(!logs_contain("reconnect_backoff_min should be greater"));
    }

    #[test]
    #[traced_test]
    fn no_backoff_warning_without_h3_peers() {
        let mut config = sample_h3_config();
        config.tuning.reconnect_backoff_min = Duration::from_secs(1);
        config.tuning.h3.h3_handshake_timeout = Duration::from_secs(5);
        config.peers[0].transport = PeerTransport::Bare(PeerBare {
            endpoint: UdpEndpoint {
                host: "peer.example.com".to_string(),
                port: 6635,
            },
            bindif: None,
        });
        assert!(config.validate().is_ok());
        assert!(!logs_contain("reconnect_backoff_min should be greater"));
    }

    #[test]
    #[traced_test]
    fn emits_both_warnings_simultaneously() {
        let mut config = sample_h3_config();
        config.local.tun.mtu = 1500;
        config.tuning.reconnect_backoff_min = Duration::from_secs(2);
        config.tuning.h3.h3_handshake_timeout = Duration::from_secs(5);
        assert!(config.validate().is_ok());
        assert!(logs_contain("exceeds safe maximum"));
        assert!(logs_contain("reconnect_backoff_min should be greater"));
    }

    #[test]
    fn rejects_backoff_min_exceeds_max() {
        let mut config = sample_h3_config();
        config.tuning.reconnect_backoff_min = Duration::from_secs(120);
        config.tuning.reconnect_backoff_max = Duration::from_secs(60);
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.iter().any(|e| matches!(e, ValidationError::FieldConflict { .. }))
        ));
    }
}
