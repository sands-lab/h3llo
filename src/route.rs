//! System route synchronization using route_manager.
use crate::bind::lookup_ifindex;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use route_manager::{AsyncRouteManager, Route};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Resolves interface indexes from names.
pub trait IfIndexResolver {
    /// Returns the interface index for `name`.
    ///
    /// # Errors
    ///
    /// Returns a `RouteSyncError` when the interface cannot be resolved or the platform is unsupported.
    fn resolve(&self, name: &str) -> Result<u32, RouteSyncError>;
}

/// Uses platform APIs to resolve interface indexes.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformIfIndexResolver;

impl IfIndexResolver for PlatformIfIndexResolver {
    fn resolve(&self, name: &str) -> Result<u32, RouteSyncError> {
        resolve_ifindex(name)
    }
}

/// Abstracts route operations for production and tests.
pub trait RouteHandle: Send {
    /// Lists all routes on the host.
    fn list(&mut self) -> impl std::future::Future<Output = io::Result<Vec<Route>>> + Send;
    /// Adds a route.
    fn add(&mut self, route: &Route) -> impl std::future::Future<Output = io::Result<()>> + Send;
    /// Deletes a route.
    fn delete(&mut self, route: &Route)
        -> impl std::future::Future<Output = io::Result<()>> + Send;
}

/// Wrapper around `route_manager::AsyncRouteManager`.
pub struct RouteManagerHandle {
    inner: AsyncRouteManager,
}

impl RouteManagerHandle {
    /// Creates a handle backed by `route_manager`'s async API.
    pub fn new() -> io::Result<Self> {
        let inner = AsyncRouteManager::new()?;
        Ok(Self { inner })
    }
}

impl RouteHandle for RouteManagerHandle {
    async fn list(&mut self) -> io::Result<Vec<Route>> {
        self.inner.list().await
    }

    async fn add(&mut self, route: &Route) -> io::Result<()> {
        self.inner.add(route).await
    }

    async fn delete(&mut self, route: &Route) -> io::Result<()> {
        self.inner.delete(route).await
    }
}

/// Details about sync issues that do not halt execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteSyncWarning {
    /// Adding a route failed.
    AddFailed { prefix: IpNet, error: String },
    /// Removing a stale route failed.
    DeleteFailed { prefix: IpNet, error: String },
    /// A conflicting route triggered a binary split into two more specific prefixes.
    PrefixSplit {
        /// Conflicted prefix before splitting.
        prefix: IpNet,
        /// Child prefixes that will be added instead.
        fragments: [IpNet; 2],
        /// Interface index that already owned the conflicted prefix.
        existing_ifindex: u32,
    },
    /// A conflicting route cannot be split further (e.g., /32 or /128).
    UnresolvableConflict {
        /// Conflicted prefix that cannot be split.
        prefix: IpNet,
        /// Interface index that already owns the prefix.
        existing_ifindex: u32,
    },
    /// A route entry could not be interpreted and was skipped.
    UnsupportedRoute { reason: String },
}

/// Fatal errors returned by route sync.
#[derive(Debug, Error)]
pub enum RouteSyncError {
    /// Interface index resolution failed.
    #[error("failed to resolve interface '{interface}': {error}")]
    InterfaceLookup {
        /// Interface name.
        interface: String,
        /// Underlying error detail.
        error: String,
    },
    /// Listing routes failed.
    #[error("route listing failed: {0}")]
    ListFailed(String),
}

/// Synchronizes system routes for the TUN interface:
/// - Adds missing `allowed` prefixes on the TUN interface (splitting on conflicts).
/// - Deletes stale TUN routes not present in `allowed` while preserving configured TUN addresses.
/// - Aggregates existing TUN prefixes before deciding whether an `allowed` prefix is already covered.
/// - Emits warnings for conflicts, splits, unsupported entries, or failed operations.
///
/// # Arguments
/// - `tun_if`: TUN interface name.
/// - `tun_addrs`: Host addresses configured on the TUN interface (normalized to /32 or /128).
/// - `allowed`: Desired prefixes that should point to the TUN interface.
/// - `handle`: Route operations implementation.
///
/// # Returns
/// Accumulated warnings when sync completes successfully; errors when listing routes or resolving the interface fails.
pub async fn sync_tun_routes<H: RouteHandle>(
    tun_if: &str,
    tun_addrs: &[IpNet],
    allowed: &[IpNet],
    handle: &mut H,
) -> Result<Vec<RouteSyncWarning>, RouteSyncError> {
    let resolver = PlatformIfIndexResolver;
    sync_tun_routes_with_resolver(tun_if, tun_addrs, allowed, handle, &resolver).await
}

/// Variant of `sync_tun_routes` that allows injecting an interface resolver (for tests).
pub async fn sync_tun_routes_with_resolver<H: RouteHandle, R: IfIndexResolver>(
    tun_if: &str,
    tun_addrs: &[IpNet],
    allowed: &[IpNet],
    handle: &mut H,
    resolver: &R,
) -> Result<Vec<RouteSyncWarning>, RouteSyncError> {
    let tun_ifindex = resolver.resolve(tun_if)?;
    let routes = handle
        .list()
        .await
        .map_err(|err| RouteSyncError::ListFailed(err.to_string()))?;

    let allowed_set: HashSet<IpNet> = allowed.iter().cloned().collect();
    let tun_addr_set: HashSet<IpNet> = tun_addrs.iter().cloned().collect();
    let mut ordered_allowed = Vec::new();
    for net in allowed {
        if !ordered_allowed.contains(net) {
            ordered_allowed.push(*net);
        }
    }
    let mut existing_tun: HashSet<IpNet> = HashSet::new();
    let mut warnings = Vec::new();

    // Collect existing TUN routes and drop stale ones (except configured TUN addresses).
    for route in routes
        .iter()
        .filter(|route| route.if_index() == Some(tun_ifindex))
    {
        match ipnet_from_route(route) {
            Some(net) => {
                let allowed_cover = allowed_set
                    .iter()
                    .any(|allowed_net| prefix_contains(allowed_net, &net));
                let is_tun_addr = tun_addr_set.contains(&net);
                if allowed_cover || is_tun_addr {
                    existing_tun.insert(net);
                } else if let Err(err) = handle.delete(route).await {
                    warnings.push(RouteSyncWarning::DeleteFailed {
                        prefix: net,
                        error: err.to_string(),
                    });
                }
            }
            None => warnings.push(RouteSyncWarning::UnsupportedRoute {
                reason: "unsupported address family".to_string(),
            }),
        }
    }

    // Detect conflicting routes on other interfaces.
    let conflicts = conflict_map(&routes, tun_ifindex);

    // Add missing routes for allowed prefixes.
    for net in ordered_allowed {
        ensure_prefix_present(
            net,
            tun_ifindex,
            &conflicts,
            handle,
            &mut existing_tun,
            &mut warnings,
        )
        .await;
    }

    Ok(warnings)
}

/// Ensures `target` is installed on the TUN interface, splitting on conflicts when possible.
async fn ensure_prefix_present<H: RouteHandle>(
    target: IpNet,
    tun_ifindex: u32,
    conflicts: &HashMap<IpNet, u32>,
    handle: &mut H,
    existing_tun: &mut HashSet<IpNet>,
    warnings: &mut Vec<RouteSyncWarning>,
) {
    let mut stack = vec![target];
    while let Some(net) = stack.pop() {
        if is_prefix_covered(&net, existing_tun) {
            continue;
        }

        if let Some(&ifindex) = conflicts.get(&net) {
            if let Some(children) = split_prefix(&net) {
                warnings.push(RouteSyncWarning::PrefixSplit {
                    prefix: net,
                    fragments: children,
                    existing_ifindex: ifindex,
                });
                // Depth-first placement keeps the route fan-out compact.
                stack.push(children[1]);
                stack.push(children[0]);
                continue;
            } else {
                warnings.push(RouteSyncWarning::UnresolvableConflict {
                    prefix: net,
                    existing_ifindex: ifindex,
                });
            }
        }

        let route = Route::new(net.addr(), net.prefix_len()).with_if_index(tun_ifindex);
        match handle.add(&route).await {
            Ok(_) => {
                existing_tun.insert(net);
            }
            Err(err) => warnings.push(RouteSyncWarning::AddFailed {
                prefix: net,
                error: err.to_string(),
            }),
        }
    }
}

/// Returns true when `prefix` is fully covered by `installed` routes.
fn is_prefix_covered(prefix: &IpNet, installed: &HashSet<IpNet>) -> bool {
    if installed.contains(prefix) {
        return true;
    }

    if max_prefix(prefix) == prefix.prefix_len() {
        return false;
    }

    if let Some(children) = split_prefix(prefix) {
        is_prefix_covered(&children[0], installed) && is_prefix_covered(&children[1], installed)
    } else {
        false
    }
}

/// Returns true when `outer` completely contains `inner`.
fn prefix_contains(outer: &IpNet, inner: &IpNet) -> bool {
    match (outer, inner) {
        (IpNet::V4(outer), IpNet::V4(inner)) => {
            outer.prefix_len() <= inner.prefix_len() && outer.contains(&inner.network())
        }
        (IpNet::V6(outer), IpNet::V6(inner)) => {
            outer.prefix_len() <= inner.prefix_len() && outer.contains(&inner.network())
        }
        _ => false,
    }
}

/// Splits a prefix into two children, returning `None` when at the maximum length.
fn split_prefix(net: &IpNet) -> Option<[IpNet; 2]> {
    let next_prefix = net.prefix_len() + 1;
    match net {
        IpNet::V4(v4) if next_prefix <= 32 => {
            let network = u32::from(v4.network());
            let step = 1u32.checked_shl((32 - next_prefix) as u32)?;
            let left = Ipv4Net::new(Ipv4Addr::from(network), next_prefix).ok()?;
            let right_network = network.checked_add(step)?;
            let right = Ipv4Net::new(Ipv4Addr::from(right_network), next_prefix).ok()?;
            Some([IpNet::V4(left), IpNet::V4(right)])
        }
        IpNet::V6(v6) if next_prefix <= 128 => {
            let network = u128::from(v6.network());
            let step = 1u128.checked_shl((128 - next_prefix) as u32)?;
            let left = Ipv6Net::new(Ipv6Addr::from(network), next_prefix).ok()?;
            let right_network = network.checked_add(step)?;
            let right = Ipv6Net::new(Ipv6Addr::from(right_network), next_prefix).ok()?;
            Some([IpNet::V6(left), IpNet::V6(right)])
        }
        _ => None,
    }
}

/// Returns the maximum prefix length for the given address family.
fn max_prefix(net: &IpNet) -> u8 {
    match net {
        IpNet::V4(_) => 32,
        IpNet::V6(_) => 128,
    }
}

/// Resolves an interface index using the platform helper from `bind`.
fn resolve_ifindex(name: &str) -> Result<u32, RouteSyncError> {
    lookup_ifindex(name).ok_or_else(|| RouteSyncError::InterfaceLookup {
        interface: name.to_string(),
        error: "interface not found".to_string(),
    })
}

/// Converts a `route_manager::Route` into `IpNet` when the address family is supported.
fn ipnet_from_route(route: &Route) -> Option<IpNet> {
    match route.destination() {
        IpAddr::V4(addr) => ipnet::Ipv4Net::new(addr, route.prefix())
            .ok()
            .map(IpNet::V4),
        IpAddr::V6(addr) => ipnet::Ipv6Net::new(addr, route.prefix())
            .ok()
            .map(IpNet::V6),
    }
}

/// Returns prefixes owned by non-TUN interfaces to flag conflicts.
fn conflict_map(routes: &[Route], tun_ifindex: u32) -> HashMap<IpNet, u32> {
    let mut conflicts = HashMap::new();
    for route in routes {
        if route.if_index() == Some(tun_ifindex) {
            continue;
        }
        if let Some(net) = ipnet_from_route(route) {
            if let Some(ifindex) = route.if_index() {
                conflicts.entry(net).or_insert(ifindex);
            }
        }
    }
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Builds a route for tests.
    fn route(prefix: &str, ifindex: Option<u32>) -> Route {
        let net: IpNet = prefix.parse().unwrap();
        match ifindex {
            Some(idx) => Route::new(net.addr(), net.prefix_len()).with_if_index(idx),
            None => Route::new(net.addr(), net.prefix_len()),
        }
    }

    /// Returns a fixed interface index for tests.
    #[derive(Default)]
    struct FakeResolver {
        idx: u32,
    }

    impl IfIndexResolver for FakeResolver {
        fn resolve(&self, _name: &str) -> Result<u32, RouteSyncError> {
            Ok(self.idx)
        }
    }

    /// Test double implementing `RouteHandle`.
    struct FakeHandle {
        routes: Mutex<Vec<Route>>,
        ops: Mutex<Vec<String>>,
        fail_add: bool,
        fail_delete: bool,
    }

    impl FakeHandle {
        /// Creates a fake handle populated with `routes`.
        fn new(routes: Vec<Route>) -> Self {
            Self {
                routes: Mutex::new(routes),
                ops: Mutex::new(Vec::new()),
                fail_add: false,
                fail_delete: false,
            }
        }

        /// Creates a fake handle with optional add/delete failure injection.
        fn with_failures(routes: Vec<Route>, fail_add: bool, fail_delete: bool) -> Self {
            Self {
                routes: Mutex::new(routes),
                ops: Mutex::new(Vec::new()),
                fail_add,
                fail_delete,
            }
        }

        /// Returns the recorded operation log.
        fn ops(&self) -> Vec<String> {
            self.ops.lock().unwrap().clone()
        }

        /// Formats a route for operation logs.
        fn fmt_route(route: &Route) -> String {
            format!("{}/{}", route.destination(), route.prefix())
        }
    }

    impl RouteHandle for FakeHandle {
        async fn list(&mut self) -> io::Result<Vec<Route>> {
            Ok(self.routes.lock().unwrap().clone())
        }

        async fn add(&mut self, route: &Route) -> io::Result<()> {
            self.ops
                .lock()
                .unwrap()
                .push(format!("add {}", Self::fmt_route(route)));
            if self.fail_add {
                return Err(io::Error::new(io::ErrorKind::Other, "add failed"));
            }
            self.routes.lock().unwrap().push(route.clone());
            Ok(())
        }

        async fn delete(&mut self, route: &Route) -> io::Result<()> {
            self.ops
                .lock()
                .unwrap()
                .push(format!("del {}", Self::fmt_route(route)));
            if self.fail_delete {
                return Err(io::Error::new(io::ErrorKind::Other, "delete failed"));
            }
            let mut routes = self.routes.lock().unwrap();
            if let Some(pos) = routes.iter().position(|r| r == route) {
                routes.remove(pos);
            }
            Ok(())
        }
    }

    #[tokio::test]
    /// Adds missing routes while skipping already present TUN prefixes.
    async fn adds_missing_routes_and_skips_existing() {
        let resolver = FakeResolver { idx: 7 };
        let mut handle = FakeHandle::new(vec![route("10.0.0.0/24", Some(7))]);
        let allowed: Vec<IpNet> = vec![
            "10.0.0.0/24".parse().unwrap(),
            "10.0.1.0/24".parse().unwrap(),
        ];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(handle.ops(), vec!["add 10.0.1.0/24"]);
    }

    #[tokio::test]
    /// Deletes TUN routes that are not part of the desired set.
    async fn deletes_stale_tun_routes() {
        let resolver = FakeResolver { idx: 9 };
        let stale = route("10.5.0.0/16", Some(9));
        let mut handle = FakeHandle::new(vec![stale.clone()]);
        let allowed: Vec<IpNet> = vec![];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(handle.ops(), vec!["del 10.5.0.0/16"]);
        assert!(handle.routes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    /// Splits conflicting prefixes and installs more specific routes.
    async fn splits_conflicts_and_installs_children() {
        let resolver = FakeResolver { idx: 3 };
        let mut handle = FakeHandle::new(vec![route("192.168.0.0/24", Some(2))]);
        let allowed: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();

        let fragments: [IpNet; 2] = [
            "192.168.0.0/25".parse().unwrap(),
            "192.168.0.128/25".parse().unwrap(),
        ];
        assert_eq!(
            warnings,
            vec![RouteSyncWarning::PrefixSplit {
                prefix: "192.168.0.0/24".parse().unwrap(),
                fragments,
                existing_ifindex: 2
            }]
        );
        assert_eq!(
            handle.ops(),
            vec!["add 192.168.0.0/25", "add 192.168.0.128/25"]
        );
    }

    #[tokio::test]
    /// Aggregates existing TUN entries before deciding whether to add.
    async fn aggregates_existing_prefixes_before_add() {
        let resolver = FakeResolver { idx: 5 };
        let mut handle = FakeHandle::new(vec![
            route("0.0.0.0/1", Some(5)),
            route("128.0.0.0/1", Some(5)),
        ]);
        let allowed: Vec<IpNet> = vec!["0.0.0.0/0".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();

        assert!(warnings.is_empty());
        assert!(handle.ops().is_empty());
    }

    #[tokio::test]
    /// Emits an unresolvable warning when a conflicting prefix cannot be split.
    async fn warns_when_conflict_cannot_be_split() {
        let resolver = FakeResolver { idx: 4 };
        let mut handle = FakeHandle::new(vec![route("10.0.0.1/32", Some(2))]);
        let allowed: Vec<IpNet> = vec!["10.0.0.1/32".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();

        assert_eq!(
            warnings,
            vec![RouteSyncWarning::UnresolvableConflict {
                prefix: "10.0.0.1/32".parse().unwrap(),
                existing_ifindex: 2
            }]
        );
        assert_eq!(handle.ops(), vec!["add 10.0.0.1/32"]);
    }

    #[tokio::test]
    /// Splits IPv6 conflicts with the same strategy.
    async fn splits_ipv6_conflicts() {
        let resolver = FakeResolver { idx: 12 };
        let mut handle = FakeHandle::new(vec![route("2001:db8::/64", Some(6))]);
        let allowed: Vec<IpNet> = vec!["2001:db8::/64".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();

        let fragments: [IpNet; 2] = [
            "2001:db8::/65".parse().unwrap(),
            "2001:db8:0:0:8000::/65".parse().unwrap(),
        ];
        assert_eq!(
            warnings,
            vec![RouteSyncWarning::PrefixSplit {
                prefix: "2001:db8::/64".parse().unwrap(),
                fragments,
                existing_ifindex: 6
            }]
        );
        assert_eq!(
            handle.ops(),
            vec!["add 2001:db8::/65", "add 2001:db8:0:0:8000::/65"]
        );
    }

    #[tokio::test]
    /// Surfaces add/delete failures as warnings while logging attempted operations.
    async fn surfaces_add_and_delete_failures_as_warnings() {
        let resolver = FakeResolver { idx: 11 };
        let stale = route("10.9.0.0/16", Some(11));
        let allowed: Vec<IpNet> = vec!["10.8.0.0/16".parse().unwrap()];
        let mut handle = FakeHandle::with_failures(vec![stale.clone()], true, true);
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();

        assert_eq!(warnings.len(), 2);
        assert!(matches!(
            warnings[0],
            RouteSyncWarning::DeleteFailed { prefix, .. } if prefix == "10.9.0.0/16".parse::<IpNet>().unwrap()
        ));
        assert!(matches!(
            warnings[1],
            RouteSyncWarning::AddFailed { prefix, .. } if prefix == "10.8.0.0/16".parse::<IpNet>().unwrap()
        ));
        assert_eq!(handle.ops(), vec!["del 10.9.0.0/16", "add 10.8.0.0/16"]);
    }
}
