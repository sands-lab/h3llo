//! Provides interface-binding helpers for DNS sockets and route probing.
use socket2::{Domain, Socket};
use thiserror::Error;

use std::io;
use std::net::IpAddr;

#[cfg(target_os = "windows")]
use std::ffi::CStr;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::{CStr, CString};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::num::NonZeroU32;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawSocket;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use ipnet::{Ipv4Net, Ipv6Net};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use net_route::{Handle, Route};

/// Decides how to bind outbound sockets for DNS queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindDecision {
    /// Optional interface name to bind.
    pub interface: Option<String>,
    /// Warning emitted when probing fails and we fall back to unbound.
    pub warning: Option<BindWarning>,
}

impl BindDecision {
    /// Chooses a bind interface using the preferred configuration or a route probe, ignoring the TUN.
    ///
    /// # Arguments
    /// - `preferred`: Optional interface name from configuration; trimmed and validated before use.
    /// - `server`: DNS server address used as the probe target.
    /// - `tun_if`: TUN interface name to exclude from probe results.
    /// - `probe`: Route probe implementation used to gather interface candidates.
    ///
    /// # Returns
    /// A bind decision containing the selected interface, if any, and warnings describing fallbacks.
    pub async fn choose<P: RouteProbe>(
        preferred: Option<&str>,
        server: &str,
        tun_if: &str,
        probe: &P,
    ) -> Self {
        match probe.probe_interfaces(server, Some(tun_if)).await {
            Ok(ifaces) => {
                let cleaned: Vec<String> = ifaces
                    .into_iter()
                    .map(|iface| iface.trim().to_string())
                    .filter(|iface| !iface.is_empty())
                    .collect();

                let mut warning = None;
                if let Some(preferred_iface) = preferred
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                {
                    let matched = cleaned.iter().any(|iface| iface == &preferred_iface);
                    if matched && preferred_iface != tun_if {
                        return BindDecision {
                            interface: Some(preferred_iface),
                            warning: None,
                        };
                    }
                    if !matched {
                        warning = Some(BindWarning::PreferredNotFound {
                            interface: preferred_iface,
                        });
                    }
                }

                for iface in cleaned.into_iter() {
                    if iface != tun_if {
                        return BindDecision {
                            interface: Some(iface),
                            warning,
                        };
                    }
                }
                BindDecision {
                    interface: None,
                    warning,
                }
            }
            Err(err) => BindDecision {
                interface: None,
                warning: Some(BindWarning::ProbeFailed(err.to_string())),
            },
        }
    }
}

/// Captures warnings emitted during bind decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindWarning {
    /// Route probing failed; continuing unbound.
    ProbeFailed(String),
    /// Preferred interface was not found in probe results.
    PreferredNotFound { interface: String },
    /// Binding to the requested interface failed; continuing unbound.
    BindFailed { interface: String, error: String },
    /// Binding is not supported on this platform; continuing unbound.
    BindUnsupported { interface: String, platform: String },
}

/// Binds `socket` to `interface` for the given `domain` using platform-specific mechanisms.
///
/// # Arguments
/// - `socket`: Socket to be bound to an outbound interface.
/// - `domain`: Address family (`Domain::IPV4` or `Domain::IPV6`).
/// - `interface`: Interface name to bind; trimmed before use.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns a `BindWarning` when binding fails or is unsupported; callers should log and continue unbound.
pub fn bind_to_device(socket: &Socket, domain: Domain, interface: &str) -> Result<(), BindWarning> {
    let iface = interface.trim();
    if iface.is_empty() {
        return Err(BindWarning::BindFailed {
            interface: interface.to_string(),
            error: "interface is empty".to_string(),
        });
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        bind_to_device_impl(socket, domain, iface).map_err(|err| BindWarning::BindFailed {
            interface: iface.to_string(),
            error: err.to_string(),
        })
    }

    #[cfg(target_os = "windows")]
    {
        bind_to_device_impl(socket, domain, iface).map_err(|err| BindWarning::BindFailed {
            interface: iface.to_string(),
            error: err.to_string(),
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(BindWarning::BindUnsupported {
        interface: iface.to_string(),
        platform: std::env::consts::OS.to_string(),
    })
}

/// Probes the system routing table to identify the outbound interface.
pub trait RouteProbe {
    /// Returns all interface names that could be used to reach `target` in priority order.
    ///
    /// # Arguments
    /// - `target`: Destination IP address to probe routes for.
    /// - `tun_if`: Optional TUN interface name to exclude from results.
    ///
    /// # Returns
    /// A future resolving to interface names ordered by preference, or a `RouteProbeError`.
    fn probe_interfaces(
        &self,
        target: &str,
        tun_if: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Vec<String>, RouteProbeError>> + Send;
}

/// Uses `net-route` to discover reachable outbound interfaces on supported platforms.
///
/// # Errors
/// Returns `UnsupportedPlatform` on unsupported operating systems (BSD placeholder).
#[derive(Debug, Default, Clone)]
pub struct DefaultRouteProbe;

impl RouteProbe for DefaultRouteProbe {
    async fn probe_interfaces(
        &self,
        target: &str,
        tun_if: Option<&str>,
    ) -> Result<Vec<String>, RouteProbeError> {
        probe_interfaces_impl(target, tun_if).await
    }
}

/// Represents route probe failure details.
///
/// # Errors
/// Surface parse failures, route lookups, interface lookups, or unsupported platforms from probing.
#[derive(Debug, Error, Clone)]
pub enum RouteProbeError {
    /// Target address could not be parsed.
    #[error("invalid target {target}: {error}")]
    InvalidTarget { target: String, error: String },
    /// Route lookup failed.
    #[error("route probe failed: {0}")]
    Probe(String),
    /// Mapping an interface index back to a name failed.
    #[error("interface lookup failed for index {ifindex}: {error}")]
    InterfaceLookup { ifindex: u32, error: String },
    /// Route probing is not supported on this platform (placeholder for BSD backends).
    #[error("route probe is not supported on this platform: {platform}")]
    UnsupportedPlatform { platform: String },
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// Binds a socket to an interface index on Unix platforms via `bind_device_by_index_*`.
fn bind_to_device_impl(socket: &Socket, domain: Domain, interface: &str) -> io::Result<()> {
    let index = interface_index(interface)?;
    match domain {
        Domain::IPV4 => socket.bind_device_by_index_v4(Some(index)),
        Domain::IPV6 => socket.bind_device_by_index_v6(Some(index)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported domain for binding",
        )),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// Resolves an interface name into a non-zero ifindex for binding.
fn interface_index(interface: &str) -> io::Result<NonZeroU32> {
    let name = CString::new(interface).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains interior null",
        )
    })?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    NonZeroU32::new(index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))
}

#[cfg(target_os = "windows")]
/// Binds a socket to an interface index on Windows using `setsockopt`.
fn bind_to_device_impl(socket: &Socket, domain: Domain, interface: &str) -> io::Result<()> {
    use std::mem::size_of;

    use windows_sys::Win32::Networking::WinSock::{
        if_nametoindex, setsockopt, WSAGetLastError, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF,
        IP_UNICAST_IF, SOCKET_ERROR,
    };

    let mut wide: Vec<u16> = interface.encode_utf16().collect();
    wide.push(0);

    let index = unsafe { if_nametoindex(wide.as_ptr()) };
    if index == 0 {
        let code = unsafe { WSAGetLastError() };
        return Err(io::Error::from_raw_os_error(code));
    }

    let raw = socket.as_raw_socket();
    let (level, optname, value) = match domain {
        Domain::IPV4 => (IPPROTO_IP as i32, IP_UNICAST_IF, index.to_be()),
        Domain::IPV6 => (IPPROTO_IPV6 as i32, IPV6_UNICAST_IF, index),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported domain for binding",
            ))
        }
    };

    let ret = unsafe {
        setsockopt(
            raw as _,
            level,
            optname,
            &value as *const u32 as *const _,
            size_of::<u32>() as i32,
        )
    };
    if ret == SOCKET_ERROR {
        let code = unsafe { WSAGetLastError() };
        return Err(io::Error::from_raw_os_error(code));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
/// Probes outbound route candidates using `net-route`, excluding the provided TUN interface.
async fn probe_interfaces_impl(
    target: &str,
    tun_if: Option<&str>,
) -> Result<Vec<String>, RouteProbeError> {
    let target_ip = target
        .parse::<IpAddr>()
        .map_err(|err| RouteProbeError::InvalidTarget {
            target: target.to_string(),
            error: err.to_string(),
        })?;

    let tun_index = tun_if.and_then(lookup_ifindex);

    let routes = {
        let handle = Handle::new().map_err(|err| RouteProbeError::Probe(err.to_string()))?;
        handle
            .list()
            .await
            .map_err(|err| RouteProbeError::Probe(err.to_string()))?
    };

    let mut names = Vec::new();
    for ifindex in matching_route_indexes(&routes, target_ip, tun_index) {
        let name = ifindex_to_name(ifindex).map_err(|err| RouteProbeError::InterfaceLookup {
            ifindex,
            error: err.to_string(),
        })?;
        names.push(name);
    }

    Ok(names)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
/// Signals unsupported probing on platforms without a `net-route` backend.
async fn probe_interfaces_impl(
    _target: &str,
    _tun_if: Option<&str>,
) -> Result<Vec<String>, RouteProbeError> {
    Err(RouteProbeError::UnsupportedPlatform {
        platform: std::env::consts::OS.to_string(),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
/// Returns interface indexes ordered by longest-prefix match while skipping the TUN index.
fn matching_route_indexes(routes: &[Route], target: IpAddr, tun_index: Option<u32>) -> Vec<u32> {
    let mut matches: Vec<(u8, u32)> = routes
        .iter()
        .filter_map(|route| route_match(route, target))
        .collect();
    matches.sort_by(|a, b| b.0.cmp(&a.0));

    let mut deduped = Vec::new();
    for (_, idx) in matches {
        if tun_index == Some(idx) {
            continue;
        }
        if !deduped.contains(&idx) {
            deduped.push(idx);
        }
    }

    deduped
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
/// Returns the route's prefix length and ifindex when `target` fits the destination network.
fn route_match(route: &Route, target: IpAddr) -> Option<(u8, u32)> {
    let ifindex = route.ifindex?;
    let prefix = route.prefix;

    match (route.destination, target) {
        (IpAddr::V4(dest), IpAddr::V4(target_v4)) => {
            let net = Ipv4Net::new(dest, prefix).ok()?;
            if net.contains(&target_v4) {
                Some((prefix, ifindex))
            } else {
                None
            }
        }
        (IpAddr::V6(dest), IpAddr::V6(target_v6)) => {
            let net = Ipv6Net::new(dest, prefix).ok()?;
            if net.contains(&target_v6) {
                Some((prefix, ifindex))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// Looks up an interface index by name using libc on Unix platforms.
fn lookup_ifindex(name: &str) -> Option<u32> {
    interface_index(name).ok().map(NonZeroU32::get)
}

#[cfg(target_os = "windows")]
/// Looks up an interface index by name using WinSock on Windows.
fn lookup_ifindex(name: &str) -> Option<u32> {
    use windows_sys::Win32::Networking::WinSock::if_nametoindex;

    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);

    let idx = unsafe { if_nametoindex(wide.as_ptr()) };
    (idx != 0).then_some(idx)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
/// Returns `None` because interface lookup is unsupported on this platform.
fn lookup_ifindex(_name: &str) -> Option<u32> {
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// Resolves an interface name from an index using libc.
fn ifindex_to_name(ifindex: u32) -> io::Result<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE + 1];
    let ptr = buf.as_mut_ptr() as *mut libc::c_char;
    let ret = unsafe { libc::if_indextoname(ifindex, ptr) };
    if ret.is_null() {
        return Err(io::Error::last_os_error());
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str()
        .map(|s| s.to_string())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(target_os = "windows")]
/// Resolves an interface name from an index using Windows IP Helper APIs.
fn ifindex_to_name(ifindex: u32) -> io::Result<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::if_indextoname;
    use windows_sys::Win32::NetworkManagement::Ndis::IF_MAX_STRING_SIZE;

    let mut buf = [0u8; IF_MAX_STRING_SIZE as usize + 1];
    let ptr = buf.as_mut_ptr() as *mut i8;

    let ret = unsafe { if_indextoname(ifindex, ptr) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str()
        .map(|s| s.to_string())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocalDns;

    /// Test double that returns a preconfigured route probe result.
    #[derive(Clone)]
    struct FakeRouteProbe {
        result: Result<Vec<String>, RouteProbeError>,
        expected_target: Option<String>,
    }

    impl RouteProbe for FakeRouteProbe {
        /// Returns the canned probe result and optionally asserts the requested target.
        async fn probe_interfaces(
            &self,
            _target: &str,
            _tun_if: Option<&str>,
        ) -> Result<Vec<String>, RouteProbeError> {
            let expected = self.expected_target.clone();
            let result = self.result.clone();
            if let Some(expected) = expected {
                assert_eq!(_target, expected);
            }
            result
        }
    }

    /// Prefers the explicitly configured interface when it is present in probe results.
    #[tokio::test]
    async fn binding_prefers_explicit_interface() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string(), "eth1".to_string()]),
            expected_target: None,
        };
        let decision = BindDecision::choose(Some("eth1"), "1.1.1.1", "tun0", &probe).await;
        assert_eq!(decision.interface.as_deref(), Some("eth1"));
        assert!(decision.warning.is_none());
    }

    /// Binds to the first probed interface when no preference is supplied.
    #[tokio::test]
    async fn binding_uses_probe_when_no_preference() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string()]),
            expected_target: None,
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe).await;
        assert_eq!(decision.interface.as_deref(), Some("eth0"));
        assert!(decision.warning.is_none());
    }

    /// Emits a warning and falls back when the preferred interface is missing.
    #[tokio::test]
    async fn binding_warns_when_preferred_missing() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string(), "eth2".to_string()]),
            expected_target: None,
        };
        let decision = BindDecision::choose(Some("eth1"), "1.1.1.1", "tun0", &probe).await;
        assert_eq!(decision.interface.as_deref(), Some("eth0"));
        assert!(matches!(
            decision.warning,
            Some(BindWarning::PreferredNotFound { interface }) if interface == "eth1"
        ));
    }

    /// Skips the TUN interface when an alternative exists.
    #[tokio::test]
    async fn binding_skips_tun_when_alternative_exists() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["tun0".to_string(), "eth0".to_string()]),
            expected_target: None,
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe).await;
        assert_eq!(decision.interface.as_deref(), Some("eth0"));
        assert!(decision.warning.is_none());
    }

    /// Leaves binding unset when only the TUN interface is found.
    #[tokio::test]
    async fn binding_filters_tun_probe() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["tun0".to_string()]),
            expected_target: None,
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe).await;
        assert!(decision.interface.is_none());
        assert!(decision.warning.is_none());
    }

    /// Reports probe failures as warnings and avoids binding.
    #[tokio::test]
    async fn binding_warns_on_probe_error() {
        let probe = FakeRouteProbe {
            result: Err(RouteProbeError::Probe("route probe failed".to_string())),
            expected_target: None,
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe).await;
        assert!(decision.interface.is_none());
        assert!(matches!(
            decision.warning,
            Some(BindWarning::ProbeFailed(msg)) if msg.contains("route probe failed")
        ));
    }

    /// Ensures DNS binding delegates to the shared chooser and propagates warnings.
    #[tokio::test]
    async fn decide_dns_binding_bridges_to_choose() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string()]),
            expected_target: Some("1.1.1.1".to_string()),
        };
        let decision = crate::dns::decide_dns_binding(
            &LocalDns {
                server: "udp://1.1.1.1:53".to_string(),
                refresh: 60,
                bindif: Some("eth1".to_string()),
            },
            "tun0",
            &probe,
        )
        .await;
        assert_eq!(decision.interface.as_deref(), Some("eth0"));
        assert!(matches!(
            decision.warning,
            Some(BindWarning::PreferredNotFound { interface }) if interface == "eth1"
        ));
    }

    /// Prefers longest-prefix matches and deduplicates interface indexes.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn matching_routes_prefers_longest_prefix_and_dedupes() {
        use std::net::Ipv4Addr;

        let routes = vec![
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).with_ifindex(1),
            Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).with_ifindex(2),
            Route::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16).with_ifindex(3),
            Route::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 24).with_ifindex(3),
        ];

        let indexes = matching_route_indexes(&routes, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), None);
        assert_eq!(indexes, vec![3, 2, 1]);
    }

    /// Filters out the TUN interface index from route matches.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn matching_routes_filters_tun_index() {
        use std::net::Ipv4Addr;

        let routes = vec![
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).with_ifindex(1),
            Route::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 24).with_ifindex(2),
        ];

        let indexes =
            matching_route_indexes(&routes, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)), Some(2));
        assert_eq!(indexes, vec![1]);
    }
}
