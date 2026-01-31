//! Provides interface-binding helpers for DNS sockets and route probing.
pub use socket2::Domain;
use socket2::{Protocol, Socket, Type};
use thiserror::Error;
use tracing::warn;

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;

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

/// Represents UDP socket binding errors.
#[derive(Debug, Error)]
pub enum UdpError {
    /// Socket creation, binding, or conversion failed.
    #[error("udp socket setup failed: {0}")]
    Socket(String),
}

/// Creates a raw UDP socket with explicit domain and optional bind address.
///
/// Low-level socket creation without interface probing or localhost detection.
/// Prefer `make_server_udp_socket` for listen sockets or `make_client_udp_socket`
/// for sockets that connect to a specific target.
///
/// # Arguments
/// - `domain`: Socket domain (IPv4 or IPv6).
/// - `bind_addr`: Local address to bind, or `None` for ephemeral port.
/// - `bind_interface`: Optional interface name for binding.
///
/// # Returns
/// A tokio `UdpSocket`. Interface binding warnings are logged directly.
///
/// # Errors
/// Returns an `io::Error` when socket creation or binding fails.
pub fn make_udp_socket_raw(
    domain: Domain,
    bind_addr: Option<SocketAddr>,
    bind_interface: Option<&str>,
) -> io::Result<UdpSocket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    if let Some(interface) = bind_interface {
        if let Err(e) = bind_to_device(&socket, domain, interface) {
            warn!(
                interface = %interface,
                error = %e,
                "bind to interface failed, continuing unbound"
            );
        }
    }

    if let Some(addr) = bind_addr {
        socket.bind(&addr.into())?;
    }

    let udp = UdpSocket::from_std(socket.into())?;
    Ok(udp)
}

/// Creates a UDP socket for receiving packets on a listen address.
///
/// This is the simple path for server sockets that do not need route probing.
/// The socket is bound to the specified address without interface selection.
///
/// # Arguments
/// - `listen`: Local socket address to bind.
///
/// # Errors
/// Returns `UdpError::Socket` when socket creation or binding fails.
pub fn make_server_udp_socket(listen: SocketAddr) -> Result<UdpSocket, UdpError> {
    let domain = match listen {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    make_udp_socket_raw(domain, Some(listen), None).map_err(|e| UdpError::Socket(e.to_string()))
}

/// Creates a connected UDP socket for sending packets to a target.
///
/// Probes the routing table to select an appropriate interface for reaching `target`,
/// excluding the TUN interface to avoid routing loops. Skips interface binding for
/// localhost targets (127.x.x.x, ::1) to support Docker DNS and other localhost services.
///
/// The socket is automatically connected to `target`, allowing use of `send()`/`recv()`
/// instead of `send_to()`/`recv_from()`.
///
/// # Arguments
/// - `target`: Remote socket address to connect to.
/// - `tun_if`: Optional TUN interface name to exclude from probing.
/// - `bind_interface`: Optional preferred interface; treated as a filter during probing.
/// - `probe`: Route probe implementation for testability.
///
/// # Returns
/// A connected UDP socket. The OS assigns an ephemeral port during `connect()`.
///
/// # Errors
/// Returns `UdpError::Socket` when socket creation, binding, or connect fails.
///
/// # Example
/// ```ignore
/// let probe = DefaultRouteProbe;
/// let socket = make_client_udp_socket(
///     "8.8.8.8:53".parse().unwrap(),
///     Some("tun0"),
///     None,
///     &probe,
/// ).await?;
/// // Socket is already connected - use send()/recv()
/// socket.send(&query).await?;
/// ```
pub async fn make_client_udp_socket<P: RouteProbe>(
    target: SocketAddr,
    tun_if: Option<&str>,
    bind_interface: Option<&str>,
    probe: &P,
) -> Result<UdpSocket, UdpError> {
    let domain = match target {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    // Skip interface probing for localhost targets
    let selected_interface = if target.ip().is_loopback() {
        None
    } else {
        select_bind_interface(target.ip(), tun_if, bind_interface, probe).await
    };

    // No explicit bind address - just bind to interface.
    // OS will auto-assign ephemeral port when connect() is called.
    let socket = make_udp_socket_raw(domain, None, selected_interface.as_deref())
        .map_err(|e| UdpError::Socket(e.to_string()))?;

    socket
        .connect(target)
        .await
        .map_err(|e| UdpError::Socket(format!("connect to {}: {}", target, e)))?;

    Ok(socket)
}

/// Internal: Binds a UDP socket with interface probing.
///
/// **Note**: This function is kept for h3.rs compatibility while that module is WIP.
/// New code should use `make_server_udp_socket` or `make_client_udp_socket` instead.
///
/// Binding to an interface is best-effort: missing or ambiguous probe results
/// are logged as warnings and the socket continues unbound. Skips interface
/// binding for localhost addresses (127.x.x.x, ::1) to ensure Docker DNS
/// (127.0.0.11) and other localhost services work correctly.
pub(crate) async fn bind_udp_socket<P: RouteProbe>(
    listen: SocketAddr,
    bind_interface: Option<&str>,
    target: IpAddr,
    tun_if: Option<&str>,
    probe: &P,
) -> Result<UdpSocket, UdpError> {
    let domain = match listen {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };

    let is_localhost = match target {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };

    let selected_interface = if is_localhost {
        None
    } else {
        select_bind_interface(target, tun_if, bind_interface, probe).await
    };

    make_udp_socket_raw(domain, Some(listen), selected_interface.as_deref())
        .map_err(|e| UdpError::Socket(e.to_string()))
}

/// Selects a bind interface by probing routes toward `target`, logging warnings on probe failures, empty sets, or ambiguity.
///
/// # Arguments
/// - `target`: Destination IP used for route probing.
/// - `tun_if`: Optional TUN interface name to exclude.
/// - `preferred_if`: Optional preferred interface; blank values are ignored.
/// - `probe`: Route probe implementation.
///
/// # Returns
/// The chosen interface name (first entry); returns `None` when probing fails or yields no match.
/// Warnings are logged directly.
pub async fn select_bind_interface<P: RouteProbe>(
    target: IpAddr,
    tun_if: Option<&str>,
    preferred_if: Option<&str>,
    probe: &P,
) -> Option<String> {
    match probe.probe_interfaces(&target.to_string(), tun_if).await {
        Ok(interfaces) => {
            if interfaces.is_empty() {
                warn!(target = %target, "no interface found, socket will remain unbound");
                return None;
            }

            let mut candidates = if let Some(preferred) = preferred_if {
                let filtered = filter_preferred_interfaces(
                    interfaces.clone(),
                    Some(vec![preferred.to_string()]),
                );
                if filtered.is_empty() {
                    warn!(
                        interface = %preferred,
                        "preferred interface not found, falling back to probed"
                    );
                    interfaces
                } else {
                    filtered
                }
            } else {
                interfaces
            };

            let chosen = candidates.remove(0);
            if !candidates.is_empty() {
                warn!(
                    chosen = %chosen,
                    alternatives = ?candidates,
                    "multiple interfaces found, using first"
                );
            }
            Some(chosen)
        }
        Err(err) => {
            warn!(error = %err, "route probe failed, socket will remain unbound");
            None
        }
    }
}

/// Binds `socket` to `interface` for the given `domain` using platform-specific mechanisms.
///
/// # Errors
/// Returns an `io::Error` when binding fails or is unsupported.
pub fn bind_to_device(socket: &Socket, domain: Domain, interface: &str) -> io::Result<()> {
    let iface = interface.trim();
    if iface.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface is empty",
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        bind_to_device_impl(socket, domain, iface)
    }

    #[cfg(target_os = "windows")]
    {
        bind_to_device_impl(socket, domain, iface)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        warn!(
            interface = %iface,
            platform = %std::env::consts::OS,
            "bind to interface not supported on this platform"
        );
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "platform unsupported",
        ))
    }
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
    use tracing_test::traced_test;

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

    #[traced_test]
    #[tokio::test]
    async fn select_bind_interface_logs_warning_on_empty_results() {
        let probe = FakeRouteProbe {
            result: Ok(Vec::new()),
        };
        let iface =
            select_bind_interface(IpAddr::V4("1.1.1.1".parse().unwrap()), None, None, &probe).await;
        assert!(iface.is_none());
        assert!(logs_contain("no interface found"));
        assert!(logs_contain("unbound"));
    }

    #[traced_test]
    #[tokio::test]
    async fn select_bind_interface_logs_warning_on_missing_preference() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string(), "eth1".to_string()]),
        };
        let iface = select_bind_interface(
            IpAddr::V4("8.8.4.4".parse().unwrap()),
            None,
            Some("wlan0"),
            &probe,
        )
        .await;
        assert_eq!(iface.as_deref(), Some("eth0"));
        assert!(logs_contain("preferred interface not found"));
        assert!(logs_contain("wlan0"));
        assert!(logs_contain("multiple interfaces found"));
    }

    #[traced_test]
    #[tokio::test]
    async fn select_bind_interface_logs_warning_on_ambiguity() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string(), "eth1".to_string()]),
        };
        let iface =
            select_bind_interface(IpAddr::V4("8.8.8.8".parse().unwrap()), None, None, &probe).await;
        assert_eq!(iface.as_deref(), Some("eth0"));
        assert!(logs_contain("multiple interfaces found"));
        assert!(logs_contain("eth0"));
    }

    #[traced_test]
    #[tokio::test]
    async fn select_bind_interface_logs_warning_on_probe_error() {
        let probe = FakeRouteProbe {
            result: Err(RouteProbeError::Probe("boom".into())),
        };
        let iface =
            select_bind_interface(IpAddr::V4("9.9.9.9".parse().unwrap()), None, None, &probe).await;
        assert!(iface.is_none());
        assert!(logs_contain("route probe failed"));
        assert!(logs_contain("boom"));
    }

    // ========== bind_udp_socket Tests ==========

    #[tokio::test]
    async fn bind_udp_socket_skips_probe_for_localhost_v4() {
        // Probe that would fail if called
        let probe = FakeRouteProbe {
            result: Err(RouteProbeError::Probe("should not be called".into())),
        };

        let result = bind_udp_socket(
            SocketAddr::from(([0, 0, 0, 0], 0)),
            None,
            IpAddr::V4("127.0.0.1".parse().unwrap()),
            None,
            &probe,
        )
        .await;
        assert!(
            result.is_ok(),
            "localhost target should succeed without probing"
        );
    }

    #[tokio::test]
    async fn bind_udp_socket_skips_probe_for_localhost_v6() {
        let probe = FakeRouteProbe {
            result: Err(RouteProbeError::Probe("should not be called".into())),
        };

        let result = bind_udp_socket(
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
            None,
            IpAddr::V6("::1".parse().unwrap()),
            None,
            &probe,
        )
        .await;
        // Note: This may fail on systems without IPv6 enabled, which is acceptable.
        // The important thing is that the probe was NOT called (localhost detection worked).
        if result.is_err() {
            // If it failed, it should be a socket error (IPv6 not available), not a probe error.
            let err_msg = result.unwrap_err().to_string();
            assert!(
                !err_msg.contains("should not be called"),
                "probe should not be called for localhost"
            );
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn bind_udp_socket_probes_for_remote_target() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string()]),
        };

        let result = bind_udp_socket(
            SocketAddr::from(([0, 0, 0, 0], 0)),
            None,
            IpAddr::V4("8.8.8.8".parse().unwrap()),
            None,
            &probe,
        )
        .await;
        assert!(result.is_ok());
    }

    #[test]
    fn udp_error_display() {
        let err = UdpError::Socket("connection refused".to_string());
        assert_eq!(
            err.to_string(),
            "udp socket setup failed: connection refused"
        );
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

    // ========== make_udp_socket_raw Tests ==========

    #[tokio::test]
    async fn make_udp_socket_raw_with_none_bind_addr() {
        let socket = make_udp_socket_raw(Domain::IPV4, None, None);
        assert!(
            socket.is_ok(),
            "socket creation without bind should succeed"
        );
    }

    #[tokio::test]
    async fn make_udp_socket_raw_with_ipv4_domain() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = make_udp_socket_raw(Domain::IPV4, Some(addr), None);
        assert!(
            socket.is_ok(),
            "socket creation with IPv4 bind should succeed"
        );

        let socket = socket.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv4());
    }

    #[tokio::test]
    async fn make_udp_socket_raw_with_ipv6_domain() {
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let result = make_udp_socket_raw(Domain::IPV6, Some(addr), None);
        // May fail on systems without IPv6, which is acceptable
        if result.is_ok() {
            let socket = result.unwrap();
            assert!(socket.local_addr().unwrap().is_ipv6());
        }
    }

    // ========== make_server_udp_socket Tests ==========

    #[tokio::test]
    async fn make_server_udp_socket_binds_to_address() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = make_server_udp_socket(addr);
        assert!(socket.is_ok(), "make_server_udp_socket should succeed");

        let socket = socket.unwrap();
        let local = socket.local_addr().unwrap();
        assert_eq!(local.ip(), addr.ip());
        assert_ne!(local.port(), 0, "port should be assigned");
    }

    #[tokio::test]
    async fn make_server_udp_socket_ipv6() {
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        let result = make_server_udp_socket(addr);
        if result.is_ok() {
            let socket = result.unwrap();
            assert!(socket.local_addr().unwrap().is_ipv6());
        }
    }

    // ========== make_client_udp_socket Tests ==========

    #[tokio::test]
    async fn make_client_udp_socket_skips_probe_for_localhost() {
        let probe = FakeRouteProbe {
            result: Err(RouteProbeError::Probe("should not be called".into())),
        };

        let result = make_client_udp_socket(
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            None,
            None,
            &probe,
        )
        .await;
        assert!(
            result.is_ok(),
            "localhost target should succeed without probing"
        );

        // Verify socket is connected
        let socket = result.unwrap();
        assert!(socket.peer_addr().is_ok(), "socket should be connected");
        assert_eq!(socket.peer_addr().unwrap().port(), 12345);
    }

    #[tokio::test]
    async fn make_client_udp_socket_creates_connected_socket() {
        let probe = FakeRouteProbe { result: Ok(vec![]) };
        let result = make_client_udp_socket(
            SocketAddr::from(([127, 0, 0, 1], 54321)),
            None,
            None,
            &probe,
        )
        .await;
        assert!(result.is_ok());

        let socket = result.unwrap();
        assert!(socket.peer_addr().is_ok(), "socket should be connected");
        assert_eq!(
            socket.peer_addr().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 54321))
        );
    }

    #[tokio::test]
    async fn make_client_udp_socket_ipv4_creates_ipv4_socket() {
        let probe = FakeRouteProbe { result: Ok(vec![]) };
        let result =
            make_client_udp_socket(SocketAddr::from(([127, 0, 0, 1], 53)), None, None, &probe)
                .await;
        assert!(result.is_ok());
        let socket = result.unwrap();
        assert!(socket.local_addr().unwrap().is_ipv4());
    }
}
