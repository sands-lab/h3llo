//! Provides interface-binding helpers for DNS sockets and route probing.
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};

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
use route_manager::{AsyncRouteManager, Route};

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
    /// Socket remains unbound to any interface; continuing unbound.
    Unbound { reason: String },
    /// Multiple interfaces were found; using the first entry.
    AmbiguousInterfaces {
        chosen: String,
        alternatives: Vec<String>,
    },
}

/// Creates a UDP socket bound to `bind_addr` and optionally pinned to `bind_interface`.
///
/// # Arguments
/// - `bind_addr`: Local address to bind.
/// - `bind_interface`: Optional interface name for binding.
///
/// # Returns
/// A tokio `UdpSocket` plus accumulated bind warnings.
///
/// # Errors
/// Returns an `io::Error` when socket creation or binding fails.
pub fn bind_udp_socket(
    bind_addr: SocketAddr,
    bind_interface: Option<&str>,
) -> io::Result<(tokio::net::UdpSocket, Vec<BindWarning>)> {
    let domain = match bind_addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    let mut warnings = Vec::new();

    if let Some(interface) = bind_interface {
        if let Err(warning) = bind_to_device(&socket, domain, interface) {
            warnings.push(warning);
        }
    }

    socket.bind(&bind_addr.into())?;
    let udp = tokio::net::UdpSocket::from_std(socket.into())?;
    Ok((udp, warnings))
}

/// Selects a bind interface by probing routes toward `target`, emitting warnings on probe failures, empty sets, or ambiguity.
///
/// # Arguments
/// - `target`: Destination IP used for route probing.
/// - `tun_if`: Optional TUN interface name to exclude.
/// - `preferred_if`: Optional preferred interface; blank values are ignored. Missing preferred entries emit warnings and fall back to probed results.
/// - `probe`: Route probe implementation.
///
/// # Returns
/// The chosen interface name (first entry) and accumulated warnings; returns `None` when probing fails or yields no match.
pub async fn select_bind_interface<P: RouteProbe>(
    target: IpAddr,
    tun_if: Option<&str>,
    preferred_if: Option<&str>,
    probe: &P,
) -> (Option<String>, Vec<BindWarning>) {
    match probe.probe_interfaces(&target.to_string(), tun_if).await {
        Ok(interfaces) => {
            if interfaces.is_empty() {
                return (
                    None,
                    vec![BindWarning::Unbound {
                        reason: format!("no interface found for {target}"),
                    }],
                );
            }

            let mut warnings = Vec::new();
            let mut candidates = if let Some(preferred) = preferred_if {
                let filtered = filter_preferred_interfaces(
                    interfaces.clone(),
                    Some(vec![preferred.to_string()]),
                );
                if filtered.is_empty() {
                    warnings.push(BindWarning::PreferredNotFound {
                        interface: preferred.to_string(),
                    });
                    interfaces
                } else {
                    filtered
                }
            } else {
                interfaces
            };

            let chosen = candidates.remove(0);
            if !candidates.is_empty() {
                warnings.push(BindWarning::AmbiguousInterfaces {
                    chosen: chosen.clone(),
                    alternatives: candidates,
                });
            }
            (Some(chosen), warnings)
        }
        Err(err) => (None, vec![BindWarning::ProbeFailed(err.to_string())]),
    }
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

/// Uses `route_manager` to discover reachable outbound interfaces on supported platforms.
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
pub(crate) fn interface_index(interface: &str) -> io::Result<NonZeroU32> {
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
/// Probes outbound route candidates using `route_manager`, excluding the provided TUN interface.
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
        let mut manager =
            AsyncRouteManager::new().map_err(|err| RouteProbeError::Probe(err.to_string()))?;
        manager
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
/// Signals unsupported probing on platforms without a `route_manager` backend.
async fn probe_interfaces_impl(
    _target: &str,
    _tun_if: Option<&str>,
) -> Result<Vec<String>, RouteProbeError> {
    Err(RouteProbeError::UnsupportedPlatform {
        platform: std::env::consts::OS.to_string(),
    })
}

/// Filters probed interfaces against an optional preferred list while preserving route order.
fn filter_preferred_interfaces(
    names: Vec<String>,
    preferred_ifs: Option<Vec<String>>,
) -> Vec<String> {
    let Some(preferred) = preferred_ifs else {
        return names;
    };

    let allowed: HashSet<String> = preferred
        .into_iter()
        .map(|iface| iface.trim().to_string())
        .filter(|iface| !iface.is_empty())
        .collect();

    if allowed.is_empty() {
        return Vec::new();
    }

    names
        .into_iter()
        .filter(|name| allowed.contains(name))
        .collect()
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
    let ifindex = route.if_index()?;
    let prefix = route.prefix();

    match (route.destination(), target) {
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
pub fn lookup_ifindex(name: &str) -> Option<u32> {
    interface_index(name).ok().map(NonZeroU32::get)
}

#[cfg(target_os = "windows")]
/// Looks up an interface index by name using WinSock on Windows.
pub fn lookup_ifindex(name: &str) -> Option<u32> {
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

    /// Test double that returns a fixed probe result.
    #[derive(Clone)]
    struct FakeRouteProbe {
        result: Result<Vec<String>, RouteProbeError>,
    }

    impl RouteProbe for FakeRouteProbe {
        async fn probe_interfaces(
            &self,
            _target: &str,
            _tun_if: Option<&str>,
        ) -> Result<Vec<String>, RouteProbeError> {
            self.result.clone()
        }
    }

    #[test]
    fn filters_interfaces_by_preference() {
        let names = vec!["eth0".to_string(), "eth1".to_string(), "wlan0".to_string()];
        let preferred = Some(vec![" wlan0".to_string(), "eth1".to_string()]);
        let filtered = filter_preferred_interfaces(names, preferred);
        assert_eq!(filtered, vec!["eth1".to_string(), "wlan0".to_string()]);
    }

    #[test]
    fn returns_empty_when_preferences_provided_but_no_match() {
        let names = vec!["eth0".to_string(), "eth1".to_string()];
        let filtered = filter_preferred_interfaces(names, Some(Vec::new()));
        assert!(filtered.is_empty());
    }

    #[tokio::test]
    async fn select_bind_interface_warns_on_empty_results() {
        let probe = FakeRouteProbe {
            result: Ok(Vec::new()),
        };
        let (iface, warnings) =
            select_bind_interface(IpAddr::V4("1.1.1.1".parse().unwrap()), None, None, &probe).await;
        assert!(iface.is_none());
        assert!(matches!(
            warnings.as_slice(),
            [BindWarning::Unbound { reason }] if reason.contains("no interface")
        ));
    }

    #[tokio::test]
    async fn select_bind_interface_warns_on_missing_preference_and_falls_back() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string(), "eth1".to_string()]),
        };
        let (iface, warnings) = select_bind_interface(
            IpAddr::V4("8.8.4.4".parse().unwrap()),
            None,
            Some("wlan0"),
            &probe,
        )
        .await;
        assert_eq!(iface.as_deref(), Some("eth0"));
        assert!(warnings.iter().any(|warn| matches!(
            warn,
            BindWarning::PreferredNotFound { interface } if interface == "wlan0"
        )));
        assert!(warnings.iter().any(|warn| matches!(
            warn,
            BindWarning::AmbiguousInterfaces { chosen, alternatives }
                if chosen == "eth0" && alternatives == &vec!["eth1".to_string()]
        )));
    }

    #[tokio::test]
    async fn select_bind_interface_warns_on_ambiguity_and_picks_first() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string(), "eth1".to_string()]),
        };
        let (iface, warnings) =
            select_bind_interface(IpAddr::V4("8.8.8.8".parse().unwrap()), None, None, &probe).await;
        assert_eq!(iface.as_deref(), Some("eth0"));
        assert!(matches!(
            warnings.as_slice(),
            [BindWarning::AmbiguousInterfaces { chosen, alternatives }]
                if chosen == "eth0" && alternatives == &vec!["eth1".to_string()]
        ));
    }

    #[tokio::test]
    async fn select_bind_interface_warns_on_probe_error() {
        let probe = FakeRouteProbe {
            result: Err(RouteProbeError::Probe("boom".into())),
        };
        let (iface, warnings) =
            select_bind_interface(IpAddr::V4("9.9.9.9".parse().unwrap()), None, None, &probe).await;
        assert!(iface.is_none());
        assert!(matches!(
            warnings.as_slice(),
            [BindWarning::ProbeFailed(msg)] if msg.contains("boom")
        ));
    }

    /// Prefers longest-prefix matches and deduplicates interface indexes.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn matching_routes_prefers_longest_prefix_and_dedupes() {
        use std::net::Ipv4Addr;

        let routes = vec![
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).with_if_index(1),
            Route::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).with_if_index(2),
            Route::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16).with_if_index(3),
            Route::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 24).with_if_index(3),
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
            Route::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).with_if_index(1),
            Route::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 24).with_if_index(2),
        ];

        let indexes =
            matching_route_indexes(&routes, IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)), Some(2));
        assert_eq!(indexes, vec![1]);
    }
}
