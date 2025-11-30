use thiserror::Error;

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
    }

    impl RouteProbe for FakeRouteProbe {
        fn probe_interfaces(&self, _target: &str) -> Result<Vec<String>, RouteProbeError> {
            self.result.clone()
        }
    }

    #[test]
    fn binding_prefers_explicit_interface() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string(), "eth1".to_string()]),
        };
        let decision = BindDecision::choose(Some("eth1"), "1.1.1.1", "tun0", &probe);
        assert_eq!(decision.interface.as_deref(), Some("eth1"));
        assert!(decision.warning.is_none());
    }

    #[test]
    fn binding_uses_probe_when_no_preference() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string()]),
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe);
        assert_eq!(decision.interface.as_deref(), Some("eth0"));
        assert!(decision.warning.is_none());
    }

    #[test]
    fn binding_warns_when_preferred_missing() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["eth0".to_string(), "eth2".to_string()]),
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
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe);
        assert_eq!(decision.interface.as_deref(), Some("eth0"));
        assert!(decision.warning.is_none());
    }

    #[test]
    fn binding_filters_tun_probe() {
        let probe = FakeRouteProbe {
            result: Ok(vec!["tun0".to_string()]),
        };
        let decision = BindDecision::choose(None, "1.1.1.1", "tun0", &probe);
        assert!(decision.interface.is_none());
        assert!(decision.warning.is_none());
    }

    #[test]
    fn binding_warns_on_probe_error() {
        let probe = FakeRouteProbe {
            result: Err(RouteProbeError::InvalidOutput),
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
        };
        let decision = crate::dns::decide_dns_binding(
            &LocalDns {
                server: "1.1.1.1".to_string(),
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

        let probe = FakeRouteProbe { result: Ok(ifaces) };
        let decision = BindDecision::choose(None, "10.200.2.27", "tun0", &probe);
        assert_eq!(decision.interface.as_deref(), Some("eno1"));
        assert!(decision.warning.is_none());
    }
}
