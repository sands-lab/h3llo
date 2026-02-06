use ipnet::IpNet;
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use thiserror::Error;
use url::Url;

/// Top-level configuration loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// Local node settings.
    pub local: Local,
    /// Peer definitions.
    #[serde(default)]
    pub peers: Vec<Peer>,
}

/// Local node settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    /// Local TUN configuration.
    pub tun: LocalTun,
}

/// HTTP/3 settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalH3 {
    /// HTTP/3 listen address (scheme/host/port/path); optional (dial-only when absent).
    #[serde(default)]
    pub listen: Option<H3Endpoint>,
    /// Certificate path for QUIC/TLS; required when `listen` is set.
    #[serde(default)]
    pub cert: Option<String>,
    /// Private key path for QUIC/TLS; required when `listen` is set.
    #[serde(default)]
    pub key: Option<String>,
    /// Optional control-plane credentials scoped to HTTP/3.
    pub admin: Option<LocalAdmin>,
}

/// Control-plane Basic Auth credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalAdmin {
    /// Stores the admin username (> 8 characters) enabling control-plane.
    pub name: String,
    /// Stores the admin password (> 8 characters) enabling control-plane.
    pub pass: String,
}

/// BareUDP settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalBare {
    /// BareUDP listen address (required when BareUDP is configured).
    pub listen: UdpEndpoint,
}

/// DNS resolver settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalDns {
    /// DNS server address as a UDP URI (IPv4/IPv6 literal), e.g., `udp://1.1.1.1:53`.
    /// Parsed as `SocketAddr` during deserialization; serialized back to `udp://` URI format.
    #[serde(
        default = "default_dns_server",
        deserialize_with = "deserialize_dns_server",
        serialize_with = "serialize_dns_server"
    )]
    pub server: SocketAddr,
    /// DNS refresh interval in seconds (`0` disables; any non-zero value enables refresh; 30s+ recommended for production).
    #[serde(default = "default_dns_refresh")]
    pub refresh: u64,
    /// Optional outbound interface binding for DNS resolution.
    pub bindif: Option<String>,
}

/// TUN settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalTun {
    /// TUN interface name (default: h3llo0).
    #[serde(default = "default_ifname")]
    pub ifname: String,
    /// TUN addresses with CIDR prefixes (IPv4/IPv6, required).
    /// Example: `192.168.180.1/24`, `2001:db8::1/64`
    pub addrs: Vec<IpNet>,
    /// TUN MTU (default: 1410).
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

/// Peer configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Peer {
    /// Remote node identifier.
    pub id: String,
    /// Whether the peer entry is active (default: true).
    #[serde(default = "default_true")]
    pub enabled: bool,
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
pub struct PeerH3 {
    /// Optional dialing endpoint (scheme/host/port/path); omit for listen-only posture.
    #[serde(default)]
    pub endpoint: Option<H3Endpoint>,
    /// Remote peer token (>= 12 characters) required whenever HTTP/3 is configured, including listen-only peers.
    pub token: String,
    /// Optional custom CA bundle.
    pub ca: Option<String>,
    /// Whether to skip TLS validation (default: false).
    #[serde(default)]
    pub insecure: bool,
    /// Optional interface to bind HTTP/3 dialers.
    pub bindif: Option<String>,
}

/// BareUDP options per peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerBare {
    /// BareUDP dialing endpoint (required when BareUDP is configured).
    pub endpoint: UdpEndpoint,
    /// Optional interface binding for BareUDP dialing.
    pub bindif: Option<String>,
}

/// Peer routing details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerTun {
    /// Allowed IP prefixes routed via this peer. Parsed as `IpNet` during deserialization.
    #[serde(rename = "allowedIPs")]
    pub allowed_ips: Vec<IpNet>,
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
    /// `local.h3.cert` and `local.h3.key` are required when `local.h3.listen` is set.
    #[error("local.h3.cert and local.h3.key must be set when local.h3.listen is configured")]
    LocalH3CredentialsMissing,
    /// `local.h3.admin` is present but too short.
    #[error(
        "local.h3.admin.name and local.h3.admin.pass must be longer than 8 characters when set"
    )]
    LocalAdminTooShort,
    /// `local.h3.admin` requires a listener.
    #[error("local.h3.admin requires local.h3.listen to be set")]
    LocalAdminMissingListener,
    // Note: LocalDnsRefreshTooShort removed - u64 has no values between 0 and 1.
    // Note: LocalDnsServerInvalid removed - parsing now happens during deserialization.
    /// TUN addresses are missing.
    #[error("local.tun.addrs must include at least one address")]
    MissingLocalTunAddrs,
    // Note: InvalidLocalTunAddr removed - parsing now happens during deserialization.
    /// No transport configured (neither H3 nor BareUDP).
    #[error("at least one transport must be configured (local.h3 or local.bare)")]
    NoTransportConfigured,
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
    /// Peer transport fields conflict.
    #[error("peer '{peer_id}' must configure exactly one of h3 or bare")]
    PeerTransportConflict { peer_id: String },
    /// Allowed IP list missing.
    #[error("peer '{peer_id}' must include at least one allowedIPs entry")]
    PeerMissingAllowedIps { peer_id: String },
    // Note: PeerInvalidAllowedIp removed - parsing now happens during deserialization.
    /// Allowed IP entry duplicates another entry on the same peer.
    #[error("peer '{peer_id}' has duplicate allowedIPs entry '{cidr}'")]
    PeerDuplicateAllowedIp { peer_id: String, cidr: String },
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
        let mut seen_peer_ids = HashSet::new();
        let mut seen_peer_tokens = HashSet::new();

        // At least one transport must be configured
        if self.local.h3.is_none() && self.local.bare.is_none() {
            errors.push(ValidationError::NoTransportConfigured);
        }

        // H3 listener validation: cert/key required only when listen is set
        let has_h3_listener = self
            .local
            .h3
            .as_ref()
            .and_then(|h3| h3.listen.as_ref())
            .is_some();

        if let Some(h3) = self.local.h3.as_ref() {
            if has_h3_listener {
                let has_cert = h3
                    .cert
                    .as_ref()
                    .map(|c| !c.trim().is_empty())
                    .unwrap_or(false);
                let has_key = h3
                    .key
                    .as_ref()
                    .map(|k| !k.trim().is_empty())
                    .unwrap_or(false);
                if !has_cert || !has_key {
                    errors.push(ValidationError::LocalH3CredentialsMissing);
                }
            }

            if let Some(admin) = &h3.admin {
                if admin.name.trim().len() <= 8 || admin.pass.trim().len() <= 8 {
                    errors.push(ValidationError::LocalAdminTooShort);
                }
                if !has_h3_listener {
                    errors.push(ValidationError::LocalAdminMissingListener);
                }
            }
        }

        // Note: local.bare.listen URI validation now happens during deserialization

        if self.local.tun.addrs.is_empty() {
            errors.push(ValidationError::MissingLocalTunAddrs);
        }
        // Note: local.tun.addrs and local.dns.server parsing now happens during deserialization

        for peer in &self.peers {
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
                // bindif is now Option<String>; no empty-list validation needed
            }

            match (&peer.h3, &peer.bare) {
                (Some(_), Some(_)) | (None, None) => {
                    errors.push(ValidationError::PeerTransportConflict {
                        peer_id: peer.id.clone(),
                    })
                }
                // Note: peer endpoint URI validation now happens during deserialization
                (Some(_), None) | (None, Some(_)) => {}
            }

            if peer.tun.allowed_ips.is_empty() {
                errors.push(ValidationError::PeerMissingAllowedIps {
                    peer_id: peer.id.clone(),
                });
            }

            // Check for duplicate allowed_ips (parsing already happened during deserialization)
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
            Err(ConfigError::Validation(ValidationErrors(errors)))
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_dns() -> LocalDns {
    LocalDns {
        server: default_dns_server(),
        refresh: default_dns_refresh(),
        bindif: None,
    }
}

fn default_dns_server() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
}

fn default_dns_refresh() -> u64 {
    60
}

fn default_ifname() -> String {
    "h3llo0".to_string()
}

fn default_mtu() -> u16 {
    1410
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
///
/// IPv6 addresses are wrapped in brackets per RFC 2732 (e.g., `udp://[::1]:53`).
fn serialize_dns_server<S>(addr: &SocketAddr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use std::net::IpAddr;
    let host = match addr.ip() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    serializer.serialize_str(&format!("udp://{host}:{}", addr.port()))
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

/// Parses a UDP DNS server URI (e.g., `udp://1.1.1.1:53`) into a socket address, enforcing IP literals.
///
/// Supports both IPv4 (`udp://1.1.1.1:53`) and IPv6 (`udp://[::1]:53`) addresses.
pub fn parse_dns_server_uri(raw: &str) -> Result<SocketAddr, String> {
    let url = Url::parse(raw).map_err(|e| e.to_string())?;

    if url.scheme() != "udp" {
        return Err("scheme must be udp".to_string());
    }

    let host = url
        .host_str()
        .ok_or_else(|| "host is required".to_string())?;

    // For non-special schemes like "udp://", the URL parser treats all hosts as domains.
    // We need to parse the host string manually, stripping brackets for IPv6.
    let host_stripped = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let ip: IpAddr = host_stripped
        .parse()
        .map_err(|_| "host must be an IP literal".to_string())?;

    let port = url
        .port()
        .ok_or_else(|| "port is required (e.g., udp://1.1.1.1:53)".to_string())?;
    if url.path() != "/" && !url.path().is_empty() {
        return Err("path must be empty".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("query and fragment are not supported".to_string());
    }

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
    let url = Url::parse(raw).map_err(|e| e.to_string())?;

    if url.scheme() != "https" {
        return Err("scheme must be https".to_string());
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("userinfo is not supported".to_string());
    }

    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "host is required".to_string())?;

    let port = url.port().unwrap_or(443);
    let path = url.path().to_string();

    if url.query().is_some() || url.fragment().is_some() {
        return Err("query and fragment are not supported".to_string());
    }

    Ok(H3Endpoint {
        host: host.to_string(),
        port,
        path,
    })
}

/// Parses a UDP URI (e.g., `udp://host:6635`) into host and port components.
pub fn parse_udp_uri(raw: &str) -> Result<UdpEndpoint, String> {
    let url = Url::parse(raw).map_err(|e| e.to_string())?;

    if url.scheme() != "udp" {
        return Err("scheme must be udp".to_string());
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("userinfo is not supported".to_string());
    }

    let host = url
        .host_str()
        .ok_or_else(|| "host is required".to_string())?;

    let port = url
        .port()
        .ok_or_else(|| "port is required (e.g., udp://host:6635)".to_string())?;

    if url.path() != "/" && !url.path().is_empty() {
        return Err("path must be empty".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("query and fragment are not supported".to_string());
    }

    Ok(UdpEndpoint {
        host: host.to_string(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_h3_config() -> Config {
        Config {
            local: Local {
                table: true,
                dns: LocalDns {
                    server: "1.1.1.1:53".parse().unwrap(),
                    refresh: 60,
                    bindif: None,
                },
                h3: Some(LocalH3 {
                    listen: Some(H3Endpoint {
                        host: "[::]".to_string(),
                        port: 443,
                        path: "/path".to_string(),
                    }),
                    cert: Some("./cert.pem".to_string()),
                    key: Some("./key.pem".to_string()),
                    admin: Some(LocalAdmin {
                        name: "admin-username".to_string(),
                        pass: "admin-password".to_string(),
                    }),
                }),
                bare: None,
                tun: LocalTun {
                    ifname: "h3llo0".to_string(),
                    addrs: vec!["192.168.180.1/32".parse().unwrap()],
                    mtu: 1410,
                },
            },
            peers: vec![Peer {
                id: "example-node-2".to_string(),
                enabled: true,
                h3: Some(PeerH3 {
                    token: "example-node-2-token".to_string(), // >= 12 chars
                    endpoint: Some(H3Endpoint {
                        host: "peer.example.com".to_string(),
                        port: 443,
                        path: "/path".to_string(),
                    }),
                    ca: None,
                    insecure: false,
                    bindif: None,
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
    fn rejects_missing_admin_listener() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.local.h3.as_mut() {
            h3.listen = None;
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.contains(&ValidationError::LocalAdminMissingListener)
        ));
    }

    #[test]
    fn rejects_h3_listener_without_credentials() {
        let mut config = sample_h3_config();
        config.local.h3 = Some(LocalH3 {
            listen: Some(H3Endpoint {
                host: "[::]".to_string(),
                port: 443,
                path: "/".to_string(),
            }),
            cert: None,
            key: None,
            admin: None,
        });
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.contains(&ValidationError::LocalH3CredentialsMissing)
        ));
    }

    #[test]
    fn rejects_h3_listener_with_partial_credentials() {
        let mut config = sample_h3_config();
        config.local.h3 = Some(LocalH3 {
            listen: Some(H3Endpoint {
                host: "[::]".to_string(),
                port: 443,
                path: "/".to_string(),
            }),
            cert: Some("./cert.pem".to_string()),
            key: None, // missing key
            admin: None,
        });
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.contains(&ValidationError::LocalH3CredentialsMissing)
        ));
    }

    #[test]
    fn accepts_h3_without_listener_dial_only() {
        let mut config = sample_h3_config();
        config.local.h3 = Some(LocalH3 {
            listen: None,
            cert: None,
            key: None,
            admin: None,
        });
        let result = config.validate();
        assert!(result.is_ok(), "dial-only H3 config should be valid");
    }

    #[test]
    fn rejects_short_admin_credentials() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.local.h3.as_mut() {
            h3.admin = Some(LocalAdmin {
                name: "short".to_string(),
                pass: "short".to_string(),
            });
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.contains(&ValidationError::LocalAdminTooShort)
        ));
    }

    // Note: rejects_missing_local_bare_listener test removed - LocalBare.listen is now
    // UdpEndpoint type which requires a valid URI at deserialization time.

    // Note: rejects_invalid_local_bare_listen_uri test removed - URI validation now
    // happens during deserialization (see rejects_invalid_endpoint_uri_at_parse_time).

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

    // Note: rejects_missing_bare_endpoint test removed - PeerBare.endpoint is now
    // UdpEndpoint type which requires a valid URI at deserialization time.

    // Note: rejects_invalid_bare_endpoint_uri test removed - URI validation now
    // happens during deserialization (see rejects_invalid_endpoint_uri_at_parse_time).

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

    // Note: dns.refresh minimum validation test removed - for u64 type, there
    // are no invalid values between 0 (disabled) and 1 (minimum).

    // Note: rejects_invalid_dns_server_uri test removed - validation now happens at parse time.
    // See rejects_invalid_dns_server_at_parse_time for the deserialization test.

    // Note: rejects_dns_server_without_port test removed - validation now happens at parse time.
    // See rejects_invalid_dns_server_at_parse_time for the deserialization test.

    // Note: rejects_local_tun_prefix_instead_of_host test removed - validation now happens at parse time.
    // See rejects_cidr_in_tun_addrs_at_parse_time for the deserialization test.

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
    allowedIPs:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert!(cfg.local.table);
        assert_eq!(
            cfg.local.dns.server,
            "1.1.1.1:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(cfg.local.dns.refresh, 60);
        assert_eq!(cfg.local.dns.bindif, None);
        assert_eq!(cfg.local.tun.ifname, "h3llo0");
        assert_eq!(cfg.local.tun.mtu, 1410);
        assert!(cfg.peers[0].enabled);
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
  h3: {}
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
    allowedIPs:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(
            cfg.local.dns.server,
            "8.8.8.8:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(cfg.local.dns.refresh, 60);
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

    // Note: rejects_invalid_allowed_ip test removed - validation now happens at parse time.
    // See rejects_invalid_allowed_ip_at_parse_time for the deserialization test.

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

    #[test]
    fn parse_dial_only_h3_config() {
        let yaml = r#"
local:
  h3: {}
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: remote-peer
  h3:
    token: remote-peer-token
    endpoint: https://peer.example.com:443/path
  tun:
    allowedIPs:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert!(cfg.local.h3.is_some());
        let h3 = cfg.local.h3.as_ref().unwrap();
        assert!(h3.listen.is_none());
        assert!(h3.cert.is_none());
        assert!(h3.key.is_none());
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
    allowedIPs:
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

    #[test]
    fn rejects_no_transport_configured() {
        let yaml = r#"
local:
  tun:
    addrs:
      - 192.168.180.1/32
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(
            result,
            Err(ConfigError::Validation(ValidationErrors(ref errs)))
                if errs.contains(&ValidationError::NoTransportConfigured)
        ));
    }

    // ========== Parse-at-deserialization tests ==========

    #[test]
    fn deserializes_local_tun_addrs_as_ipnet() {
        let yaml = r#"
local:
  h3: {}
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
  h3: {}
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
  h3: {}
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
  h3: {}
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowedIPs:
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
  h3: {}
  tun:
    addrs:
      - 192.168.180.1/32
peers:
- id: example-node-2
  h3:
    token: example-node-2-token
  tun:
    allowedIPs:
      - not-a-cidr
"#;
        let result = Config::load_from_str(yaml);
        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn deserializes_dns_server_as_socket_addr() {
        let yaml = r#"
local:
  h3: {}
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
  h3: {}
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
  h3: {}
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
  h3: {}
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
}
