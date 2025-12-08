use ipnet::IpNet;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
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
    /// Unique node identifier (minimum 6 characters).
    pub id: String,
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
    /// HTTP/3 listen address (scheme/host/port/path); required when HTTP/3 is configured.
    pub listen: Option<String>,
    /// Certificate path for QUIC/TLS; required when HTTP/3 is configured.
    pub cert: Option<String>,
    /// Private key path for QUIC/TLS; required when HTTP/3 is configured.
    pub key: Option<String>,
    /// Authentication secret for inbound HTTP Basic Auth (> 8 characters; required when HTTP/3 is configured).
    pub secret: Option<String>,
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
    pub listen: Option<String>,
}

/// DNS resolver settings for the local node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalDns {
    /// DNS server address as a UDP URI (IPv4/IPv6 literal), e.g., `udp://1.1.1.1:53`.
    #[serde(default = "default_dns_server")]
    pub server: String,
    /// DNS refresh interval in seconds (`0` disables; minimum 30 when nonzero).
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
    /// TUN addresses without prefixes (IPv4/IPv6, required).
    pub addrs: Vec<String>,
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
    /// Optional dialing endpoints (scheme/host/port/path); omit or leave empty for listen-only posture.
    #[serde(default, deserialize_with = "deserialize_endpoints")]
    pub endpoints: Vec<String>,
    /// Seconds between reconnect attempts when dialing fails (default: 10).
    #[serde(default = "default_peer_h3_retry_secs")]
    pub retry: u64,
    /// Remote peer secret (> 8 characters) required when dialing endpoints; must match the peer's `local.h3.secret`.
    pub secret: Option<String>,
    /// Optional custom CA bundle.
    pub ca: Option<String>,
    /// Whether to skip TLS validation (default: false).
    #[serde(default)]
    pub insecure: bool,
    /// Optional list of interfaces to bind HTTP/3 dialers; must not be empty when set.
    pub bindifs: Option<Vec<String>>,
}

/// BareUDP options per peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerBare {
    /// BareUDP dialing endpoint (required when BareUDP is configured).
    pub endpoint: Option<String>,
    /// Optional interface binding for BareUDP dialing.
    pub bindif: Option<String>,
}

/// Peer routing details.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerTun {
    /// Allowed IP prefixes routed via this peer.
    #[serde(rename = "allowedIPs")]
    pub allowed_ips: Vec<String>,
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
    /// `local.id` is missing or too short.
    #[error("local.id must be at least 6 characters")]
    LocalIdTooShort,
    /// `local.h3.listen` is missing when HTTP/3 is configured.
    #[error("local.h3.listen must be set when local.h3 is configured")]
    LocalH3MissingListen,
    /// `local.h3.cert` is missing when HTTP/3 is configured.
    #[error("local.h3.cert must be set when local.h3 is configured")]
    LocalH3MissingCert,
    /// `local.h3.key` is missing when HTTP/3 is configured.
    #[error("local.h3.key must be set when local.h3 is configured")]
    LocalH3MissingKey,
    /// `local.h3.secret` is missing or too short when HTTP/3 listen is configured.
    #[error(
        "local.h3.secret must be set and longer than 8 characters when local.h3 is configured"
    )]
    LocalSecretTooShort,
    /// `local.h3.admin` is present but too short.
    #[error(
        "local.h3.admin.name and local.h3.admin.pass must be longer than 8 characters when set"
    )]
    LocalAdminTooShort,
    /// `local.h3.admin` requires a listener.
    #[error("local.h3.admin requires local.h3.listen to be set")]
    LocalAdminMissingListener,
    /// `local.dns.refresh` is too small.
    #[error("local.dns.refresh must be 0 or at least 30 seconds (got {refresh})")]
    LocalDnsRefreshTooShort { refresh: u64 },
    /// `local.dns.server` is not a valid UDP URI.
    #[error("local.dns.server must be a udp:// URI with an IP literal and port: {reason}")]
    LocalDnsServerInvalid { reason: String },
    /// TUN addresses are missing.
    #[error("local.tun.addrs must include at least one address")]
    MissingLocalTunAddrs,
    /// A local TUN address is invalid.
    #[error("local.tun.addrs entry '{addr}' is invalid: {error}")]
    InvalidLocalTunAddr { addr: String, error: String },
    /// `local.bare.listen` is missing when BareUDP is configured.
    #[error("local.bare.listen must be set when local.bare is configured")]
    LocalBareMissingListen,
    /// Peer identifier is missing or too short.
    #[error("peer id '{peer_id}' must be at least 6 characters")]
    PeerIdTooShort { peer_id: String },
    /// Peer secret missing or too short.
    #[error("peer '{peer_id}' requires h3.secret longer than 8 characters when dialing endpoints")]
    PeerSecretTooShort { peer_id: String },
    /// Peer bindifs present but empty.
    #[error("peer '{peer_id}' requires h3.bindifs to include at least one interface when set")]
    PeerH3BindifsEmpty { peer_id: String },
    /// Peer transport fields conflict.
    #[error("peer '{peer_id}' must configure exactly one of h3 or bare")]
    PeerTransportConflict { peer_id: String },
    /// BareUDP endpoint missing when BareUDP is configured.
    #[error("peer '{peer_id}' requires bare.endpoint when bare is configured")]
    PeerBareMissingEndpoint { peer_id: String },
    /// Allowed IP list missing.
    #[error("peer '{peer_id}' must include at least one allowedIPs entry")]
    PeerMissingAllowedIps { peer_id: String },
    /// Allowed IP entry is invalid.
    #[error("peer '{peer_id}' has invalid allowedIPs entry '{cidr}': {error}")]
    PeerInvalidAllowedIp {
        peer_id: String,
        cidr: String,
        error: String,
    },
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

        if self.local.id.trim().len() < 6 {
            errors.push(ValidationError::LocalIdTooShort);
        }

        let h3 = self.local.h3.as_ref();
        let has_h3_listener = h3
            .and_then(|h3| h3.listen.as_ref())
            .map(|listen| !listen.trim().is_empty())
            .unwrap_or(false);

        if let Some(h3) = h3 {
            if !has_h3_listener {
                errors.push(ValidationError::LocalH3MissingListen);
            }

            let has_cert = h3
                .cert
                .as_ref()
                .map(|cert| !cert.trim().is_empty())
                .unwrap_or(false);
            if !has_cert {
                errors.push(ValidationError::LocalH3MissingCert);
            }

            let has_key = h3
                .key
                .as_ref()
                .map(|key| !key.trim().is_empty())
                .unwrap_or(false);
            if !has_key {
                errors.push(ValidationError::LocalH3MissingKey);
            }

            let secret_len = h3.secret.as_ref().map(|s| s.trim().len()).unwrap_or(0);
            if secret_len <= 8 {
                errors.push(ValidationError::LocalSecretTooShort);
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

        if let Some(bare) = self.local.bare.as_ref() {
            let has_bare_listener = bare
                .listen
                .as_ref()
                .map(|listen| !listen.trim().is_empty())
                .unwrap_or(false);
            if !has_bare_listener {
                errors.push(ValidationError::LocalBareMissingListen);
            }
        }

        if self.local.tun.addrs.is_empty() {
            errors.push(ValidationError::MissingLocalTunAddrs);
        }
        for addr in &self.local.tun.addrs {
            if let Err(err) = addr.parse::<IpAddr>() {
                errors.push(ValidationError::InvalidLocalTunAddr {
                    addr: addr.clone(),
                    error: err.to_string(),
                });
            }
        }

        if self.local.dns.refresh != 0 && self.local.dns.refresh < 30 {
            errors.push(ValidationError::LocalDnsRefreshTooShort {
                refresh: self.local.dns.refresh,
            });
        }

        if let Err(reason) = parse_dns_server_uri(&self.local.dns.server) {
            errors.push(ValidationError::LocalDnsServerInvalid { reason });
        }

        for peer in &self.peers {
            if peer.id.trim().len() < 6 {
                errors.push(ValidationError::PeerIdTooShort {
                    peer_id: peer.id.clone(),
                });
            }

            if let Some(h3) = peer.h3.as_ref() {
                let peer_secret_len = h3.secret.as_ref().map(|s| s.trim().len()).unwrap_or(0);
                let requires_peer_secret = !h3.endpoints.is_empty() || h3.secret.is_some();
                if requires_peer_secret && peer_secret_len <= 8 {
                    errors.push(ValidationError::PeerSecretTooShort {
                        peer_id: peer.id.clone(),
                    });
                }
                if let Some(bindifs) = h3.bindifs.as_ref() {
                    if bindifs.is_empty() {
                        errors.push(ValidationError::PeerH3BindifsEmpty {
                            peer_id: peer.id.clone(),
                        });
                    }
                }
            }

            match (&peer.h3, &peer.bare) {
                (Some(_), Some(_)) | (None, None) => {
                    errors.push(ValidationError::PeerTransportConflict {
                        peer_id: peer.id.clone(),
                    })
                }
                (Some(_), None) => {}
                (None, Some(bare)) => {
                    if bare.endpoint.as_ref().map(String::is_empty).unwrap_or(true) {
                        errors.push(ValidationError::PeerBareMissingEndpoint {
                            peer_id: peer.id.clone(),
                        });
                    }
                }
            }

            if peer.tun.allowed_ips.is_empty() {
                errors.push(ValidationError::PeerMissingAllowedIps {
                    peer_id: peer.id.clone(),
                });
            }

            let mut seen_allowed = HashSet::new();
            for cidr in &peer.tun.allowed_ips {
                match cidr.parse::<IpNet>() {
                    Ok(net) => {
                        if !seen_allowed.insert(net) {
                            errors.push(ValidationError::PeerDuplicateAllowedIp {
                                peer_id: peer.id.clone(),
                                cidr: cidr.clone(),
                            });
                        }
                    }
                    Err(err) => errors.push(ValidationError::PeerInvalidAllowedIp {
                        peer_id: peer.id.clone(),
                        cidr: cidr.clone(),
                        error: err.to_string(),
                    }),
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

fn default_dns_server() -> String {
    "udp://1.1.1.1:53".to_string()
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

fn default_peer_h3_retry_secs() -> u64 {
    10
}

/// Parses a UDP DNS server URI (e.g., `udp://1.1.1.1:53`) into a socket address, enforcing IP literals.
pub fn parse_dns_server_uri(raw: &str) -> Result<SocketAddr, String> {
    let url = Url::parse(raw).map_err(|e| e.to_string())?;

    if url.scheme() != "udp" {
        return Err("scheme must be udp".to_string());
    }

    let host = url
        .host_str()
        .ok_or_else(|| "host is required".to_string())?;

    let ip: IpAddr = host
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

fn deserialize_endpoints<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let endpoints: Vec<String> = Vec::deserialize(deserializer)?;
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for ep in endpoints {
        if seen.insert(ep.clone()) {
            deduped.push(ep);
        }
    }
    Ok(deduped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_h3_config() -> Config {
        Config {
            local: Local {
                id: "example-node-1".to_string(),
                table: true,
                dns: LocalDns {
                    server: "udp://1.1.1.1:53".to_string(),
                    refresh: 60,
                    bindif: None,
                },
                h3: Some(LocalH3 {
                    listen: Some("https://[::]:443/path".to_string()),
                    cert: Some("./cert.pem".to_string()),
                    key: Some("./key.pem".to_string()),
                    secret: Some("example-node-1-secret".to_string()),
                    admin: Some(LocalAdmin {
                        name: "admin-username".to_string(),
                        pass: "admin-password".to_string(),
                    }),
                }),
                bare: None,
                tun: LocalTun {
                    ifname: "h3llo0".to_string(),
                    addrs: vec!["192.168.180.1".to_string()],
                    mtu: 1410,
                },
            },
            peers: vec![Peer {
                id: "example-node-2".to_string(),
                enabled: true,
                h3: Some(PeerH3 {
                    secret: Some("example-node-2-secret".to_string()),
                    endpoints: vec!["https://peer.example.com:443/path".to_string()],
                    retry: 10,
                    ca: None,
                    insecure: false,
                    bindifs: None,
                }),
                bare: None,
                tun: PeerTun {
                    allowed_ips: vec!["192.168.180.2/32".to_string()],
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
    fn rejects_short_local_id() {
        let mut config = sample_h3_config();
        config.local.id = "abc".to_string();
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.contains(&ValidationError::LocalIdTooShort)
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
    fn rejects_missing_local_secret_when_listening() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.local.h3.as_mut() {
            h3.secret = None;
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.contains(&ValidationError::LocalSecretTooShort)
        ));
    }

    #[test]
    fn rejects_missing_required_local_h3_fields() {
        let mut config = sample_h3_config();
        config.local.h3 = Some(LocalH3 {
            listen: None,
            cert: None,
            key: None,
            secret: None,
            admin: None,
        });
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs.contains(&ValidationError::LocalH3MissingListen)
                    && errs.contains(&ValidationError::LocalH3MissingCert)
                    && errs.contains(&ValidationError::LocalH3MissingKey)
                    && errs.contains(&ValidationError::LocalSecretTooShort)
        ));
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

    #[test]
    fn rejects_missing_local_bare_listener() {
        let mut config = sample_h3_config();
        config.local.h3 = None;
        config.local.bare = Some(LocalBare { listen: None });
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.contains(&ValidationError::LocalBareMissingListen)
        ));
    }

    #[test]
    fn rejects_peer_transport_conflict() {
        let mut config = sample_h3_config();
        config.peers[0].bare = Some(PeerBare {
            endpoint: Some("udp://peer.example.com:6635".to_string()),
            bindif: None,
        });
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerTransportConflict { .. }))
        ));
    }

    #[test]
    fn rejects_missing_bare_endpoint() {
        let mut config = sample_h3_config();
        config.peers[0].h3 = None;
        config.peers[0].bare = Some(PeerBare {
            endpoint: None,
            bindif: None,
        });
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerBareMissingEndpoint { .. }))
        ));
    }

    #[test]
    fn rejects_missing_peer_secret() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.secret = None;
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::PeerSecretTooShort { .. }))
        ));
    }

    #[test]
    fn allows_listen_only_peer_without_secret() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.secret = None;
            h3.endpoints.clear();
        }
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_dns_refresh_too_small() {
        let mut config = sample_h3_config();
        config.local.dns.refresh = 10;
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs)) if errs.iter().any(|e| matches!(e, ValidationError::LocalDnsRefreshTooShort { refresh: 10 }))
        ));
    }

    #[test]
    fn rejects_invalid_dns_server_uri() {
        let mut config = sample_h3_config();
        config.local.dns.server = "tcp://1.1.1.1:53".to_string();
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs
                    .iter()
                    .any(|e| matches!(e, ValidationError::LocalDnsServerInvalid { .. }))
        ));
    }

    #[test]
    fn rejects_dns_server_without_port() {
        let mut config = sample_h3_config();
        config.local.dns.server = "udp://1.1.1.1".to_string();
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs
                    .iter()
                    .any(|e| matches!(e, ValidationError::LocalDnsServerInvalid { reason } if reason.contains("port")))
        ));
    }

    #[test]
    fn rejects_local_tun_prefix_instead_of_host() {
        let mut config = sample_h3_config();
        config.local.tun.addrs = vec!["192.168.180.1/32".to_string()];
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs
                    .iter()
                    .any(|e| matches!(e, ValidationError::InvalidLocalTunAddr { .. }))
        ));
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
  id: example-node-1
  h3:
    listen: https://[::]:443/path
    cert: ./cert.pem
    key: ./key.pem
    secret: example-node-1-secret
  tun:
    addrs:
      - 192.168.180.1
peers:
- id: example-node-2
  h3:
    secret: example-node-2-secret
  tun:
    allowedIPs:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.local.table, true);
        assert_eq!(cfg.local.dns.server, "udp://1.1.1.1:53");
        assert_eq!(cfg.local.dns.refresh, 60);
        assert_eq!(cfg.local.dns.bindif, None);
        assert_eq!(cfg.local.tun.ifname, "h3llo0");
        assert_eq!(cfg.local.tun.mtu, 1410);
        assert_eq!(cfg.peers[0].enabled, true);
        assert_eq!(cfg.peers[0].h3.is_some(), true);
        if let Some(h3) = cfg.peers[0].h3.as_ref() {
            assert!(h3.endpoints.is_empty());
            assert_eq!(h3.retry, 10);
            assert!(h3.bindifs.is_none());
        } else {
            panic!("peer h3 should be present");
        }
    }

    #[test]
    fn deduplicates_endpoints_and_applies_dns_defaults() {
        let yaml = r#"
local:
  id: example-node-1
  dns:
    server: udp://8.8.8.8:53
  tun:
    addrs:
      - 192.168.180.1
peers:
- id: example-node-2
  h3:
    secret: example-node-2-secret
    retry: 5
    endpoints:
      - https://peer.example.com/path
      - https://peer.example.com/path
      - https://peer2.example.com/path
    bindifs:
      - eth0
      - eth0
  tun:
    allowedIPs:
      - 192.168.180.2/32
"#;
        let cfg = Config::load_from_str(yaml).expect("config should load");
        assert_eq!(cfg.local.dns.server, "udp://8.8.8.8:53");
        assert_eq!(cfg.local.dns.refresh, 60);
        let h3 = cfg.peers[0].h3.as_ref().expect("h3 should be present");
        assert_eq!(h3.retry, 5);
        assert_eq!(
            h3.endpoints,
            vec![
                "https://peer.example.com/path".to_string(),
                "https://peer2.example.com/path".to_string()
            ]
        );
        assert_eq!(
            h3.bindifs,
            Some(vec!["eth0".to_string(), "eth0".to_string()])
        );
    }

    #[test]
    fn rejects_empty_bindifs_when_set() {
        let mut config = sample_h3_config();
        if let Some(h3) = config.peers[0].h3.as_mut() {
            h3.bindifs = Some(Vec::new());
        }
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs
                    .iter()
                    .any(|e| matches!(e, ValidationError::PeerH3BindifsEmpty { .. }))
        ));
    }

    #[test]
    fn rejects_invalid_allowed_ip() {
        let mut config = sample_h3_config();
        config.peers[0].tun.allowed_ips = vec!["10.0.0.1".to_string()];
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Validation(ValidationErrors(ref errs))
                if errs
                    .iter()
                    .any(|e| matches!(e, ValidationError::PeerInvalidAllowedIp { .. }))
        ));
    }

    #[test]
    fn rejects_duplicate_allowed_ip_for_peer() {
        let mut config = sample_h3_config();
        config.peers[0].tun.allowed_ips = vec![
            "192.168.180.2/32".to_string(),
            "192.168.180.2/32".to_string(),
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
}
