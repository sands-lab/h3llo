//! System route synchronization using route_manager.
use crate::bind::lookup_ifindex;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use route_manager::{AsyncRouteManager, Route};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
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
    /// A default route was split into two /1 prefixes.
    DefaultRouteSplit { prefix: IpNet },
    /// A conflicting route already exists on another interface.
    Conflict {
        /// Conflicted prefix.
        prefix: IpNet,
        /// Interface index that already owns the prefix.
        existing_ifindex: u32,
    },
    /// A route entry could not be interpreted and was skipped.
    UnsupportedRoute { reason: String },
    /// A route without interface index was encountered and skipped.
    MissingIfIndex { prefix: IpNet },
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

/// Synchronizes system routes for the TUN interface.
///
/// Final semantics:
/// - Routes on the TUN interface will be exactly:
///   * all prefixes derived from `allowed`
///     - default routes (`0.0.0.0/0` / `::/0`) are expanded into two /1 prefixes,
///   * plus the exact prefixes listed in `tun_addrs` (these are preserved but never added).
/// - Any other route currently on the TUN interface is considered stale and will be deleted.
/// - For every prefix we add that is already present on another interface, a `Conflict`
///   warning is emitted, but the add is still attempted.
/// - Failures when adding or deleting are surfaced as `AddFailed` / `DeleteFailed` warnings.
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

    let mut warnings = Vec::new();
    // Expand allowed prefixes, splitting default routes once into two /1 prefixes and warning.
    //
    // These are the prefixes we *want to route through the TUN*.
    let desired_routes: HashSet<IpNet> = expand_allowed_prefixes(allowed, &mut warnings);

    // Prefixes that must exist on the TUN interface when we are done:
    // - desired_routes (from allowed + default split),
    // - plus tun_addrs (interface address routes).
    let tun_addr_set: HashSet<IpNet> = tun_addrs.iter().cloned().collect();
    let mut existing_tun: HashSet<IpNet> = HashSet::new();
    let mut conflicts: HashMap<IpNet, u32> = HashMap::new();

    // Single pass over all routes:
    // - For TUN routes:
    //   * keep if net in keep_set (record in existing_tun),
    //   * otherwise delete.
    // - For non-TUN routes:
    //   * record as potential conflicts (prefix -> first seen ifindex).
    for route in &routes {
        let net = match ipnet_from_route(route) {
            Some(net) => net,
            None => {
                warnings.push(RouteSyncWarning::UnsupportedRoute {
                    reason: "unsupported address family or invalid prefix".to_string(),
                });
                continue;
            }
        };

        match route.if_index() {
            Some(idx) if idx == tun_ifindex => {
                // Route on the TUN interface.
                if desired_routes.contains(&net) || tun_addr_set.contains(&net) {
                    existing_tun.insert(net);
                } else if let Err(err) = handle.delete(route).await {
                    warnings.push(RouteSyncWarning::DeleteFailed {
                        prefix: net,
                        error: err.to_string(),
                    });
                }
            }
            Some(idx) => {
                // Route on some other interface: track as a potential conflict.
                conflicts.entry(net).or_insert(idx);
            }
            None => {
                // Route without ifindex: we cannot attribute it reliably; ignore.
                warnings.push(RouteSyncWarning::MissingIfIndex { prefix: net });
            }
        }
    }

    // Add missing desired routes on the TUN interface.
    //
    // Note:
    // - We only add prefixes from `desired_routes` (i.e. from `allowed`), not from `tun_addrs`.
    //   Interface address routes are assumed to be managed by the OS.
    for net in desired_routes.iter().cloned() {
        if existing_tun.contains(&net) {
            continue;
        }

        if let Some(&ifindex) = conflicts.get(&net) {
            warnings.push(RouteSyncWarning::Conflict {
                prefix: net,
                existing_ifindex: ifindex,
            });
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

    Ok(warnings)
}

/// Builds the set of desired prefixes, expanding default routes into two /1 prefixes.
///
/// - Non-default prefixes are preserved as-is.
/// - `0.0.0.0/0` is expanded into `0.0.0.0/1` and `128.0.0.0/1`.
/// - `::/0` is expanded into `::/1` and `8000::/1`.
/// - Default routes emit a `DefaultRouteSplit` warning.
fn expand_allowed_prefixes(
    allowed: &[IpNet],
    warnings: &mut Vec<RouteSyncWarning>,
) -> HashSet<IpNet> {
    let mut result = HashSet::new();

    for &net in allowed {
        if is_default_prefix(&net) {
            warnings.push(RouteSyncWarning::DefaultRouteSplit { prefix: net });
            if let Some(children) = split_default_prefix(&net) {
                result.insert(children[0]);
                result.insert(children[1]);
            } else {
                // Fallback: should never happen for a valid default route,
                // but in case it does, keep the original prefix.
                result.insert(net);
            }
        } else {
            result.insert(net);
        }
    }

    result
}

/// Returns true when `net` represents a default route (IPv4 or IPv6).
fn is_default_prefix(net: &IpNet) -> bool {
    net.prefix_len() == 0
}

/// Splits a default route into two halves using `ipnet` helper APIs.
///
/// This keeps the behavior of splitting `0.0.0.0/0` / `::/0` into two /1 routes,
/// but avoids manual bit-level arithmetic.
fn split_default_prefix(net: &IpNet) -> Option<[IpNet; 2]> {
    match net {
        IpNet::V4(v4) if v4.prefix_len() == 0 => {
            let mut it = v4.subnets(1).ok()?;
            let left = it.next()?;
            let right = it.next()?;
            Some([IpNet::V4(left), IpNet::V4(right)])
        }
        IpNet::V6(v6) if v6.prefix_len() == 0 => {
            let mut it = v6.subnets(1).ok()?;
            let left = it.next()?;
            let right = it.next()?;
            Some([IpNet::V6(left), IpNet::V6(right)])
        }
        _ => None,
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
        IpAddr::V4(addr) => Ipv4Net::new(addr, route.prefix()).ok().map(IpNet::V4),
        IpAddr::V6(addr) => Ipv6Net::new(addr, route.prefix()).ok().map(IpNet::V6),
    }
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
    /// Warns on conflicts but still installs the requested prefix.
    async fn warns_on_conflict_and_installs_route() {
        let resolver = FakeResolver { idx: 3 };
        let mut handle = FakeHandle::new(vec![route("192.168.0.0/24", Some(2))]);
        let allowed: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();
        assert_eq!(
            warnings,
            vec![RouteSyncWarning::Conflict {
                prefix: "192.168.0.0/24".parse().unwrap(),
                existing_ifindex: 2
            }]
        );
        assert_eq!(handle.ops(), vec!["add 192.168.0.0/24"]);
    }

    #[tokio::test]
    /// Warns when a route lacks an interface index but still installs the prefix.
    async fn warns_on_missing_ifindex_and_installs_route() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![route("10.0.0.0/24", None)]);
        let allowed: Vec<IpNet> = vec!["10.0.0.0/24".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();

        assert_eq!(
            warnings,
            vec![RouteSyncWarning::MissingIfIndex {
                prefix: "10.0.0.0/24".parse().unwrap()
            }]
        );
        assert_eq!(handle.ops(), vec!["add 10.0.0.0/24"]);
    }

    #[tokio::test]
    /// Splits default routes once and adds both halves when missing, without warnings.
    async fn splits_default_route_once() {
        let resolver = FakeResolver { idx: 5 };
        let mut handle = FakeHandle::new(Vec::new());
        let allowed: Vec<IpNet> = vec!["0.0.0.0/0".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();

        assert_eq!(
            warnings,
            vec![RouteSyncWarning::DefaultRouteSplit {
                prefix: "0.0.0.0/0".parse().unwrap()
            }]
        );
        let ops = handle.ops();
        assert_eq!(ops.len(), 2);
        assert!(ops.contains(&"add 0.0.0.0/1".to_string()));
        assert!(ops.contains(&"add 128.0.0.0/1".to_string()));
    }

    #[tokio::test]
    /// If both default halves already exist, they are not re-added.
    async fn skips_existing_default_halves() {
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

        assert_eq!(
            warnings,
            vec![RouteSyncWarning::DefaultRouteSplit {
                prefix: "0.0.0.0/0".parse().unwrap()
            }]
        );
        assert!(handle.ops().is_empty());
    }

    #[tokio::test]
    /// Warns when default halves conflict with other interfaces.
    async fn warns_when_default_halves_conflict() {
        let resolver = FakeResolver { idx: 8 };
        let mut handle = FakeHandle::new(vec![
            route("0.0.0.0/1", Some(2)),
            route("128.0.0.0/1", Some(7)),
        ]);
        let allowed: Vec<IpNet> = vec!["0.0.0.0/0".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();

        assert_eq!(
            warnings,
            vec![
                RouteSyncWarning::DefaultRouteSplit {
                    prefix: "0.0.0.0/0".parse().unwrap()
                },
                RouteSyncWarning::Conflict {
                    prefix: "0.0.0.0/1".parse().unwrap(),
                    existing_ifindex: 2
                },
                RouteSyncWarning::Conflict {
                    prefix: "128.0.0.0/1".parse().unwrap(),
                    existing_ifindex: 7
                }
            ]
        );

        let ops = handle.ops();
        assert_eq!(ops.len(), 2);
        assert!(ops.contains(&"add 0.0.0.0/1".to_string()));
        assert!(ops.contains(&"add 128.0.0.0/1".to_string()));
    }

    #[tokio::test]
    /// Warns when a conflicting host prefix cannot be split.
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
            vec![RouteSyncWarning::Conflict {
                prefix: "10.0.0.1/32".parse().unwrap(),
                existing_ifindex: 2
            }]
        );
        assert_eq!(handle.ops(), vec!["add 10.0.0.1/32"]);
    }

    #[tokio::test]
    /// Warns on IPv6 conflicts without splitting non-default prefixes.
    async fn warns_on_ipv6_conflicts() {
        let resolver = FakeResolver { idx: 12 };
        let mut handle = FakeHandle::new(vec![route("2001:db8::/64", Some(6))]);
        let allowed: Vec<IpNet> = vec!["2001:db8::/64".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        let warnings =
            sync_tun_routes_with_resolver("tun0", &tun_addrs, &allowed, &mut handle, &resolver)
                .await
                .unwrap();

        assert_eq!(
            warnings,
            vec![RouteSyncWarning::Conflict {
                prefix: "2001:db8::/64".parse().unwrap(),
                existing_ifindex: 6
            }]
        );
        assert_eq!(handle.ops(), vec!["add 2001:db8::/64"]);
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
