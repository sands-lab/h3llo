use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};

use crate::bind::{BindDecision, RouteProbe};
use crate::config::LocalDns;
use thiserror::Error;

/// Describes DNS resolution errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// DNS resolution failed.
    #[error("failed to resolve {host}: {error}")]
    Failed { host: String, error: String },
}

/// Provides a hostname resolver abstraction to allow deterministic tests.
pub trait HostResolver: Send + Sync {
    /// Resolves a hostname into IP addresses.
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError>;
}

/// Uses the platform DNS settings to resolve hostnames.
#[derive(Debug, Default, Clone)]
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
        let addrs = (host, 0)
            .to_socket_addrs()
            .map_err(|e| ResolveError::Failed {
                host: host.to_string(),
                error: e.to_string(),
            })?;

        let mut seen = HashSet::new();
        let mut ips = Vec::new();
        for addr in addrs {
            if seen.insert(addr.ip()) {
                ips.push(addr.ip());
            }
        }
        Ok(ips)
    }
}

/// Stores cached DNS answers and refreshes them on demand.
#[derive(Debug)]
pub struct DnsResolver<R: HostResolver> {
    cache: HashMap<String, Vec<IpAddr>>,
    resolver: R,
}

impl<R: HostResolver> DnsResolver<R> {
    /// Creates a new DNS resolver with an empty cache.
    pub fn new(resolver: R) -> Self {
        Self {
            cache: HashMap::new(),
            resolver,
        }
    }

    /// Returns a bind decision using `local_dns` and the provided `probe`.
    pub fn decide_binding<P: RouteProbe>(
        local_dns: &LocalDns,
        tun_if: &str,
        probe: &P,
    ) -> BindDecision {
        decide_dns_binding(local_dns, tun_if, probe)
    }

    /// Refreshes DNS answers for `hosts`, returning whether any entry changed and the current cache.
    pub fn refresh(&mut self, hosts: &[String]) -> RefreshOutcome {
        let mut errors = Vec::new();
        let mut changed = false;
        let mut next_cache = self.cache.clone();

        for host in hosts {
            match self.resolver.resolve(host) {
                Ok(ips) => {
                    let deduped = dedup_ips(ips);
                    let cached = self.cache.get(host);
                    if cached.map(|c| c != &deduped).unwrap_or(true) {
                        changed = true;
                    }
                    next_cache.insert(host.clone(), deduped);
                }
                Err(err) => errors.push(err),
            }
        }

        let records = if changed {
            self.cache = next_cache.clone();
            next_cache
        } else {
            // Keep original cache if nothing changed to preserve previous answers on errors.
            self.cache.clone()
        };

        RefreshOutcome {
            records,
            changed,
            errors,
        }
    }
}

fn dedup_ips(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for ip in ips {
        if seen.insert(ip) {
            out.push(ip);
        }
    }
    out
}

/// Returns a DNS bind decision preferring the configured interface when present and skipping the TUN.
pub fn decide_dns_binding<P: RouteProbe>(
    local_dns: &LocalDns,
    tun_if: &str,
    probe: &P,
) -> BindDecision {
    BindDecision::choose(
        local_dns.bindif.as_deref(),
        &local_dns.server,
        tun_if,
        probe,
    )
}

/// Tracks the result of a DNS refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshOutcome {
    /// Latest answers per host (cached on success; unchanged on all-failure paths).
    pub records: HashMap<String, Vec<IpAddr>>,
    /// True when at least one hostname updated its answers.
    pub changed: bool,
    /// Errors encountered during refresh.
    pub errors: Vec<ResolveError>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct FakeResolver {
        results:
            std::sync::Arc<std::sync::Mutex<HashMap<String, Result<Vec<IpAddr>, ResolveError>>>>,
    }

    impl FakeResolver {
        fn new(results: HashMap<String, Result<Vec<IpAddr>, ResolveError>>) -> Self {
            Self {
                results: std::sync::Arc::new(std::sync::Mutex::new(results)),
            }
        }

        fn set(&self, host: &str, result: Result<Vec<IpAddr>, ResolveError>) {
            let mut guard = self.results.lock().unwrap();
            guard.insert(host.to_string(), result);
        }
    }

    impl HostResolver for FakeResolver {
        fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ResolveError> {
            let guard = self.results.lock().unwrap();
            guard.get(host).cloned().unwrap_or_else(|| {
                Err(ResolveError::Failed {
                    host: host.to_string(),
                    error: "missing".to_string(),
                })
            })
        }
    }

    fn ip(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    #[test]
    fn dns_refresh_updates_changed_hosts() {
        let mut resolver = DnsResolver::new(FakeResolver {
            results: std::sync::Arc::new(std::sync::Mutex::new(HashMap::from([(
                "example.com".to_string(),
                Ok(vec![ip("1.1.1.1")]),
            )]))),
        });
        let first = resolver.refresh(&vec!["example.com".to_string()]);
        assert!(first.changed);
        assert_eq!(first.records["example.com"], vec![ip("1.1.1.1")]);

        // No change on same answer.
        let second = resolver.refresh(&vec!["example.com".to_string()]);
        assert!(!second.changed);
        assert_eq!(second.records["example.com"], vec![ip("1.1.1.1")]);

        // Change when answer differs.
        resolver
            .resolver
            .set("example.com", Ok(vec![ip("2.2.2.2")]));
        let third = resolver.refresh(&vec!["example.com".to_string()]);
        assert!(third.changed);
        assert_eq!(third.records["example.com"], vec![ip("2.2.2.2")]);
    }

    #[test]
    fn dns_refresh_deduplicates_addresses() {
        let resolver = FakeResolver::new(HashMap::from([(
            "example.com".to_string(),
            Ok(vec![ip("1.1.1.1"), ip("1.1.1.1"), ip("2.2.2.2")]),
        )]));
        let mut dns = DnsResolver::new(resolver);
        let outcome = dns.refresh(&vec!["example.com".to_string()]);
        assert!(outcome.changed);
        assert_eq!(
            outcome.records["example.com"],
            vec![ip("1.1.1.1"), ip("2.2.2.2")]
        );
    }

    #[test]
    fn dns_refresh_preserves_cache_on_error() {
        let resolver = FakeResolver::new(HashMap::from([(
            "example.com".to_string(),
            Err(ResolveError::Failed {
                host: "example.com".to_string(),
                error: "boom".to_string(),
            }),
        )]));
        let mut dns = DnsResolver::new(resolver.clone());
        // Seed cache with a good value.
        dns.cache
            .insert("example.com".to_string(), vec![ip("1.1.1.1")]);

        let outcome = dns.refresh(&vec!["example.com".to_string()]);
        assert!(!outcome.changed);
        assert_eq!(outcome.records["example.com"], vec![ip("1.1.1.1")]);
        assert_eq!(outcome.errors.len(), 1);
    }

    #[test]
    fn dns_refresh_adds_new_host() {
        let resolver = FakeResolver::new(HashMap::from([
            ("example.com".to_string(), Ok(vec![ip("1.1.1.1")])),
            ("example.net".to_string(), Ok(vec![ip("2.2.2.2")])),
        ]));
        let mut dns = DnsResolver::new(resolver);
        let outcome = dns.refresh(&vec!["example.com".to_string(), "example.net".to_string()]);
        assert!(outcome.changed);
        assert_eq!(outcome.records["example.com"], vec![ip("1.1.1.1")]);
        assert_eq!(outcome.records["example.net"], vec![ip("2.2.2.2")]);
    }
}
