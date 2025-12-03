use socket2::{Domain, Socket};
use thiserror::Error;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::CString;
use std::io;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::num::NonZeroU32;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawSocket;

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
    pub fn choose<P: RouteProbe>(
        preferred: Option<&str>,
        server: &str,
        tun_if: &str,
        probe: &P,
    ) -> Self {
        match probe.probe_interfaces(server) {
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

/// Attempts to bind `socket` to `interface` for the given `domain` using platform-specific mechanisms.
///
/// Returns `Ok(())` when binding succeeds, or `Err(BindWarning)` when binding is
/// unsupported or fails (callers should log and continue unbound).
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
    fn probe_interfaces(&self, target: &str) -> Result<Vec<String>, RouteProbeError>;
}

/// Uses `ip route show match` on Linux to discover reachable outbound interfaces and returns `UnsupportedPlatform` on other OS as a placeholder for macOS/Windows/BSD support.
#[derive(Debug, Default, Clone)]
pub struct DefaultRouteProbe;

impl RouteProbe for DefaultRouteProbe {
    fn probe_interfaces(&self, target: &str) -> Result<Vec<String>, RouteProbeError> {
        probe_interfaces_impl(target)
    }
}

/// Represents route probe failure details.
#[derive(Debug, Error, Clone)]
pub enum RouteProbeError {
    /// Failed to run the probe command.
    #[error("failed to run route probe: {0}")]
    Command(String),
    /// Probe command returned a nonzero exit code.
    #[error("route probe command failed with status: {0:?}")]
    CommandStatus(Option<i32>),
    /// Probe output was not valid UTF-8.
    #[error("route probe output is not valid UTF-8")]
    InvalidOutput,
    /// Route probing is not supported on this platform (placeholder for macOS/Windows/BSD backends).
    #[error("route probe is not supported on this platform: {platform}")]
    UnsupportedPlatform { platform: String },
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(target_os = "linux")]
fn probe_interfaces_impl(target: &str) -> Result<Vec<String>, RouteProbeError> {
    use std::process::Command;
    use std::str;

    let output = Command::new("ip")
        .arg("route")
        .arg("show")
        .arg("match")
        .arg(target)
        .output()
        .map_err(|e| RouteProbeError::Command(e.to_string()))?;

    if !output.status.success() {
        return Err(RouteProbeError::CommandStatus(output.status.code()));
    }

    let stdout = str::from_utf8(&output.stdout).map_err(|_| RouteProbeError::InvalidOutput)?;
    Ok(parse_interfaces_from_route_output(stdout))
}

#[cfg(target_os = "linux")]
fn parse_interfaces_from_route_output(stdout: &str) -> Vec<String> {
    let mut ifaces = Vec::new();

    for line in stdout.lines() {
        let mut tokens = line.split_whitespace().peekable();
        while let Some(tok) = tokens.next() {
            if tok == "dev" {
                if let Some(iface) = tokens.next() {
                    if iface.is_empty() {
                        continue;
                    }
                    ifaces.push(iface.to_string());
                }
            }
        }
    }

    ifaces
}

#[cfg(not(target_os = "linux"))]
fn probe_interfaces_impl(_target: &str) -> Result<Vec<String>, RouteProbeError> {
    Err(RouteProbeError::UnsupportedPlatform {
        platform: std::env::consts::OS.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocalDns;

    #[derive(Clone)]
    struct FakeRouteProbe {
        result: Result<Vec<String>, RouteProbeError>,
        expected_target: Option<String>,
    }

    impl RouteProbe for FakeRouteProbe {
        fn probe_interfaces(&self, _target: &str) -> Result<Vec<String>, RouteProbeError> {
            if let Some(expected) = &self.expected_target {
                assert_eq!(_target, expected);
            }
            self.result.clone()
        }
    }

    #[test]
    fn binding_prefers_explicit_interface() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string(), "eth1".to_string()]),
            expected_target: None,
        };
        let decision = BindDecision::choose(Some("eth1"), "1.1.1.1", "tun0", &probe);
        assert_eq!(decision.interface.as_deref(), Some("eth1"));
        assert!(decision.warning.is_none());
    }

    #[test]
    fn binding_uses_probe_when_no_preference() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string()]),
            expected_target: None,
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe);
        assert_eq!(decision.interface.as_deref(), Some("eth0"));
        assert!(decision.warning.is_none());
    }

    #[test]
    fn binding_warns_when_preferred_missing() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string(), "eth2".to_string()]),
            expected_target: None,
        };
        let decision = BindDecision::choose(Some("eth1"), "1.1.1.1", "tun0", &probe);
        assert_eq!(decision.interface.as_deref(), Some("eth0"));
        assert!(matches!(
            decision.warning,
            Some(BindWarning::PreferredNotFound { interface }) if interface == "eth1"
        ));
    }

    #[test]
    fn binding_skips_tun_when_alternative_exists() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["tun0".to_string(), "eth0".to_string()]),
            expected_target: None,
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe);
        assert_eq!(decision.interface.as_deref(), Some("eth0"));
        assert!(decision.warning.is_none());
    }

    #[test]
    fn binding_filters_tun_probe() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["tun0".to_string()]),
            expected_target: None,
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe);
        assert!(decision.interface.is_none());
        assert!(decision.warning.is_none());
    }

    #[test]
    fn binding_warns_on_probe_error() {
        let probe = FakeRouteProbe {
            result: Err(RouteProbeError::InvalidOutput),
            expected_target: None,
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe);
        assert!(decision.interface.is_none());
        assert!(matches!(
            decision.warning,
            Some(BindWarning::ProbeFailed(msg)) if msg.contains("route probe output")
        ));
    }

    #[test]
    fn decide_dns_binding_bridges_to_choose() {
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
        );
        assert_eq!(decision.interface.as_deref(), Some("eth0"));
        assert!(matches!(
            decision.warning,
            Some(BindWarning::PreferredNotFound { interface }) if interface == "eth1"
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_route_show_match_lists_all_ifaces_and_bind_skips_tun() {
        let sample = "\
default via 172.18.0.11 dev eno1 proto static
10.200.2.0/24 dev cx7p0 proto kernel scope link src 10.200.2.27
10.200.2.0/24 dev bf3p0 proto kernel scope link src 10.200.2.117
10.200.2.0/24 dev bf3p1 proto kernel scope link src 10.200.2.127";
        let ifaces = parse_interfaces_from_route_output(sample);
        assert_eq!(
            ifaces,
            vec![
                "eno1".to_string(),
                "cx7p0".to_string(),
                "bf3p0".to_string(),
                "bf3p1".to_string()
            ]
        );

        let probe = FakeRouteProbe {
            result: Ok(ifaces),
            expected_target: None,
        };
        let decision = BindDecision::choose(None, "10.200.2.27", "tun0", &probe);
        assert_eq!(decision.interface.as_deref(), Some("eno1"));
        assert!(decision.warning.is_none());
    }
}
