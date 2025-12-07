//! System route synchronization using net-route.
use crate::bind::lookup_ifindex;
use ipnet::IpNet;
use net_route::{Handle, Route};
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
pub trait RouteHandle: Send + Sync {
    /// Lists all routes on the host.
    fn list(&self) -> impl std::future::Future<Output = io::Result<Vec<Route>>> + Send;
    /// Adds a route.
    fn add(&self, route: &Route) -> impl std::future::Future<Output = io::Result<()>> + Send;
    /// Deletes a route.
    fn delete(&self, route: &Route) -> impl std::future::Future<Output = io::Result<()>> + Send;
}

/// Wrapper around `net_route::Handle`.
pub struct NetRouteHandle {
    inner: Handle,
}

impl NetRouteHandle {
    /// Creates a handle backed by `net_route`.
    pub fn new() -> io::Result<Self> {
        let inner = Handle::new()?;
        Ok(Self { inner })
    }
}

impl RouteHandle for NetRouteHandle {
    async fn list(&self) -> io::Result<Vec<Route>> {
        self.inner.list().await
    }

    async fn add(&self, route: &Route) -> io::Result<()> {
        self.inner.add(route).await
    }

    async fn delete(&self, route: &Route) -> io::Result<()> {
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
    /// A conflicting route already exists on another interface.
    Conflict {
        prefix: IpNet,
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
/// - Adds missing `allowed` prefixes on the TUN interface.
/// - Deletes stale TUN routes not present in `allowed`.
/// - Emits warnings for conflicting routes on other interfaces or failed operations.
///
/// # Arguments
/// - `tun_if`: TUN interface name.
/// - `allowed`: Desired prefixes that should point to the TUN interface.
/// - `handle`: Route operations implementation.
///
/// # Returns
/// Accumulated warnings when sync completes successfully; errors when listing routes or resolving the interface fails.
pub async fn sync_tun_routes<H: RouteHandle>(
    tun_if: &str,
    allowed: &[IpNet],
    handle: &H,
) -> Result<Vec<RouteSyncWarning>, RouteSyncError> {
    let resolver = PlatformIfIndexResolver;
    sync_tun_routes_with_resolver(tun_if, allowed, handle, &resolver).await
}

/// Variant of `sync_tun_routes` that allows injecting an interface resolver (for tests).
pub async fn sync_tun_routes_with_resolver<H: RouteHandle, R: IfIndexResolver>(
    tun_if: &str,
    allowed: &[IpNet],
    handle: &H,
    resolver: &R,
) -> Result<Vec<RouteSyncWarning>, RouteSyncError> {
    let tun_ifindex = resolver.resolve(tun_if)?;
    let routes = handle
        .list()
        .await
        .map_err(|err| RouteSyncError::ListFailed(err.to_string()))?;

    let allowed_set: HashSet<IpNet> = allowed.iter().cloned().collect();
    let mut existing_tun: HashSet<IpNet> = HashSet::new();
    let mut warnings = Vec::new();

    // Collect existing TUN routes and drop stale ones.
    for route in routes
        .iter()
        .filter(|route| route.ifindex == Some(tun_ifindex))
    {
        match ipnet_from_route(route) {
            Some(net) => {
                if allowed_set.contains(&net) {
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
    for net in allowed_set {
        if existing_tun.contains(&net) {
            continue;
        }

        if let Some(ifindex) = conflicts.get(&net) {
            warnings.push(RouteSyncWarning::Conflict {
                prefix: net,
                existing_ifindex: *ifindex,
            });
        }

        let route = Route::new(net.addr(), net.prefix_len()).with_ifindex(tun_ifindex);
        if let Err(err) = handle.add(&route).await {
            warnings.push(RouteSyncWarning::AddFailed {
                prefix: net,
                error: err.to_string(),
            });
        }
    }

    Ok(warnings)
}

/// Resolves an interface index using the platform helper from `bind`.
fn resolve_ifindex(name: &str) -> Result<u32, RouteSyncError> {
    lookup_ifindex(name).ok_or_else(|| RouteSyncError::InterfaceLookup {
        interface: name.to_string(),
        error: "interface not found".to_string(),
    })
}

/// Converts a `net_route::Route` into `IpNet` when the address family is supported.
fn ipnet_from_route(route: &Route) -> Option<IpNet> {
    match route.destination {
        IpAddr::V4(addr) => ipnet::Ipv4Net::new(addr, route.prefix).ok().map(IpNet::V4),
        IpAddr::V6(addr) => ipnet::Ipv6Net::new(addr, route.prefix).ok().map(IpNet::V6),
    }
}

/// Returns prefixes owned by non-TUN interfaces to flag conflicts.
fn conflict_map(routes: &[Route], tun_ifindex: u32) -> HashMap<IpNet, u32> {
    let mut conflicts = HashMap::new();
    for route in routes {
        if route.ifindex == Some(tun_ifindex) {
            continue;
        }
        if let Some(net) = ipnet_from_route(route) {
            if let Some(ifindex) = route.ifindex {
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
        let mut r = Route::new(net.addr(), net.prefix_len());
        r.ifindex = ifindex;
        r
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
    }

    impl RouteHandle for FakeHandle {
        async fn list(&self) -> io::Result<Vec<Route>> {
            Ok(self.routes.lock().unwrap().clone())
        }

        async fn add(&self, route: &Route) -> io::Result<()> {
            self.ops
                .lock()
                .unwrap()
                .push(format!("add {}", route.prefix));
            if self.fail_add {
                return Err(io::Error::new(io::ErrorKind::Other, "add failed"));
            }
            self.routes.lock().unwrap().push(route.clone());
            Ok(())
        }

        async fn delete(&self, route: &Route) -> io::Result<()> {
            self.ops
                .lock()
                .unwrap()
                .push(format!("del {}", route.prefix));
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
        let handle = FakeHandle::new(vec![route("10.0.0.0/24", Some(7))]);
        let allowed: Vec<IpNet> = vec![
            "10.0.0.0/24".parse().unwrap(),
            "10.0.1.0/24".parse().unwrap(),
        ];

        let warnings = sync_tun_routes_with_resolver("tun0", &allowed, &handle, &resolver)
            .await
            .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(handle.ops(), vec!["add 24"]);
    }

    #[tokio::test]
    /// Deletes TUN routes that are not part of the desired set.
    async fn deletes_stale_tun_routes() {
        let resolver = FakeResolver { idx: 9 };
        let stale = route("10.5.0.0/16", Some(9));
        let handle = FakeHandle::new(vec![stale.clone()]);
        let allowed: Vec<IpNet> = vec![];

        let warnings = sync_tun_routes_with_resolver("tun0", &allowed, &handle, &resolver)
            .await
            .unwrap();
        assert!(warnings.is_empty());
        assert_eq!(handle.ops(), vec!["del 16"]);
        assert!(handle.routes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    /// Emits a conflict warning when another interface already owns the prefix and still adds the TUN route.
    async fn warns_on_conflict_but_leaves_existing_route() {
        let resolver = FakeResolver { idx: 3 };
        let handle = FakeHandle::new(vec![route("192.168.0.0/24", Some(2))]);
        let allowed: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];

        let warnings = sync_tun_routes_with_resolver("tun0", &allowed, &handle, &resolver)
            .await
            .unwrap();
        assert_eq!(
            warnings,
            vec![RouteSyncWarning::Conflict {
                prefix: "192.168.0.0/24".parse().unwrap(),
                existing_ifindex: 2
            }]
        );
        // Still adds the TUN route to ensure traffic flows through the tunnel.
        assert_eq!(handle.ops(), vec!["add 24"]);
    }

    #[tokio::test]
    /// Surfaces add/delete failures as warnings while logging attempted operations.
    async fn surfaces_add_and_delete_failures_as_warnings() {
        let resolver = FakeResolver { idx: 11 };
        let stale = route("10.9.0.0/16", Some(11));
        let allowed: Vec<IpNet> = vec!["10.8.0.0/16".parse().unwrap()];
        let handle = FakeHandle::with_failures(vec![stale.clone()], true, true);

        let warnings = sync_tun_routes_with_resolver("tun0", &allowed, &handle, &resolver)
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
        assert_eq!(handle.ops(), vec!["del 16", "add 16"]);
    }
}
