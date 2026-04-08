//! System route synchronization using route_manager.
//!
//! Provides both the core route sync logic (`sync_tun_routes`) and the route
//! actor (`make_route` / `spawn_route`) that serializes system route updates.

use crate::actor::ActorExitResult;
use crate::bind::lookup_ifindex;
use ipnet::IpNet;
pub use route_manager::AsyncRouteManager;
pub use route_manager::Route;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;

/// Resolves interface indexes from names.
pub trait IfIndexResolver: Send + Sync + 'static {
    /// Returns the interface index for `name`.
    ///
    /// # Errors
    ///
    /// Returns a `RouteSyncError` when the interface cannot be resolved or the platform is unsupported.
    fn resolve(&self, name: &str) -> Result<u32, RouteSyncError>;
}

/// Uses platform APIs to resolve interface indexes.
#[derive(Debug)]
pub struct PlatformIfIndexResolver;

impl IfIndexResolver for PlatformIfIndexResolver {
    fn resolve(&self, name: &str) -> Result<u32, RouteSyncError> {
        resolve_ifindex(name)
    }
}

/// Abstracts route operations for production and tests.
pub trait RouteHandle: Send + 'static {
    /// Lists all routes on the host.
    fn list(&mut self) -> impl std::future::Future<Output = io::Result<Vec<Route>>> + Send;
    /// Adds a route.
    fn add(&mut self, route: &Route) -> impl std::future::Future<Output = io::Result<()>> + Send;
    /// Deletes a route.
    fn delete(&mut self, route: &Route)
        -> impl std::future::Future<Output = io::Result<()>> + Send;
}

impl RouteHandle for AsyncRouteManager {
    async fn list(&mut self) -> io::Result<Vec<Route>> {
        AsyncRouteManager::list(self).await
    }

    async fn add(&mut self, route: &Route) -> io::Result<()> {
        AsyncRouteManager::add(self, route).await
    }

    async fn delete(&mut self, route: &Route) -> io::Result<()> {
        AsyncRouteManager::delete(self, route).await
    }
}

/// Commands accepted by the route sync actor.
#[derive(Debug)]
pub enum RouteCommand {
    /// Synchronize system routes for the TUN interface.
    ///
    /// The actor serializes these updates — only one sync runs at a time.
    /// The TUN interface name is captured in the actor at spawn time.
    SyncRoutes {
        /// TUN interface addresses (OS-managed routes to preserve).
        tun_addrs: Vec<IpNet>,
        /// Desired allowed IP prefixes.
        allowed: Vec<IpNet>,
    },
}

/// Route sync actor state.
///
/// Created by [`make_route()`] (production) or struct literal (tests),
/// consumed by [`spawn_route()`].
pub struct RouteActor<H: RouteHandle, R: IfIndexResolver> {
    handle: H,
    resolver: R,
}

/// Creates route sync actor state with production dependencies.
///
/// Performs fallible I/O (netlink socket creation) during construction.
///
/// # Errors
///
/// Returns `io::Error` when the route manager handle cannot be created.
pub fn make_route() -> io::Result<RouteActor<AsyncRouteManager, PlatformIfIndexResolver>> {
    let handle = AsyncRouteManager::new()?;
    Ok(RouteActor {
        handle,
        resolver: PlatformIfIndexResolver,
    })
}

/// Spawns the route sync actor task.
///
/// Creates an unbounded command channel internally. The actor processes
/// `SyncRoutes` commands sequentially, ensuring serialized route updates.
/// Exits gracefully when all senders are dropped.
///
/// # Arguments
///
/// * `actor` - Actor state created by [`make_route()`] or constructed directly in tests.
/// * `tun_if` - TUN interface name, captured for the actor's lifetime.
pub fn spawn_route<H: RouteHandle, R: IfIndexResolver>(
    actor: RouteActor<H, R>,
    tun_if: String,
) -> (
    mpsc::UnboundedSender<RouteCommand>,
    JoinHandle<ActorExitResult>,
) {
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let RouteActor {
        mut handle,
        resolver,
    } = actor;

    let join_handle = tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                RouteCommand::SyncRoutes { tun_addrs, allowed } => {
                    if let Err(err) =
                        sync_tun_routes(&tun_if, &tun_addrs, &allowed, &mut handle, &resolver).await
                    {
                        warn!(
                            tun = %tun_if,
                            allowed_count = allowed.len(),
                            error = %err,
                            "route sync failed"
                        );
                    }
                }
            }
        }
        Ok(())
    });

    (cmd_tx, join_handle)
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
/// - Routes derived from `allowed` (default routes expanded into two /1 prefixes)
///   are actively added/preserved on the TUN interface.
/// - OS-managed routes from `tun_addrs` are preserved but never added. For each TUN
///   address (e.g., `10.0.0.1/24`), the network prefix (`10.0.0.0/24`), host route
///   (`10.0.0.1/32`), and IPv4 broadcast routes (`10.0.0.0/32`, `10.0.0.255/32`) are
///   protected from deletion. The limited broadcast `255.255.255.255/32` is also protected.
/// - IPv6 kernel-managed routes (link-local `fe80::/10` and multicast `ff00::/8`) are
///   always preserved regardless of `tun_addrs` or `allowed`.
/// - Any other route on the TUN interface is considered stale and will be deleted.
/// - If a desired prefix already exists on another interface, a conflict warning is logged.
/// - Failures when adding or deleting are logged as warnings.
pub async fn sync_tun_routes<H: RouteHandle, R: IfIndexResolver>(
    tun_if: &str,
    tun_addrs: &[IpNet],
    allowed: &[IpNet],
    handle: &mut H,
    resolver: &R,
) -> Result<(), RouteSyncError> {
    let tun_ifindex = resolver.resolve(tun_if)?;
    let routes = handle
        .list()
        .await
        .map_err(|err| RouteSyncError::ListFailed(err.to_string()))?;

    let desired_routes: HashSet<IpNet> = expand_allowed_prefixes(allowed);

    // IPv4 OS-managed routes to preserve (never added, only protected from deletion).
    // For each TUN address (e.g., 192.168.1.2/24), include:
    // - the network prefix (192.168.1.0/24) — kernel connected route
    // - the host address (192.168.1.2/32) — kernel host route
    // - broadcast routes (192.168.1.0/32, 192.168.1.255/32) — kernel broadcast routes
    // IPv6 kernel routes (link-local, multicast) are handled by is_ipv6_kernel_route().
    let mut tun_v4_kernel_routes: HashSet<IpNet> = tun_addrs
        .iter()
        .flat_map(|addr| {
            let mut nets = vec![addr.trunc(), addr.addr().into()];
            if let IpNet::V4(v4net) = addr.trunc() {
                if v4net.prefix_len() <= 30 {
                    nets.push(IpAddr::V4(v4net.network()).into());
                    nets.push(IpAddr::V4(v4net.broadcast()).into());
                }
            }
            nets
        })
        .collect();
    // Limited broadcast (255.255.255.255/32) — some systems add this to local table
    tun_v4_kernel_routes.insert(IpAddr::V4(Ipv4Addr::BROADCAST).into());

    let mut existing_routes: HashSet<IpNet> = HashSet::new();

    for route in &routes {
        let Some(net) = ipnet_from_route(route) else {
            warn!(
                reason = "unsupported address family or invalid prefix",
                "route skipped: unsupported"
            );
            continue;
        };

        if route.if_index() == Some(tun_ifindex) {
            if desired_routes.contains(&net) {
                existing_routes.insert(net);
            } else if tun_v4_kernel_routes.contains(&net) || is_ipv6_kernel_route(&net) {
                // OS/kernel-managed: preserve but no need to track in existing_routes
            } else if let Err(err) = handle.delete(route).await {
                warn!(prefix = %net, error = %err, "route delete failed");
            }
        } else if desired_routes.contains(&net) {
            let ifindex = route
                .if_index()
                .map_or("unknown".to_string(), |i| i.to_string());
            warn!(prefix = %net, existing_ifindex = ifindex, "route conflict with existing interface");
        }
    }

    // Add missing desired routes. tun_v4_kernel_routes routes are OS-managed, never added by us.
    for net in &desired_routes {
        if existing_routes.contains(net) {
            continue;
        }

        let route = Route::new(net.addr(), net.prefix_len()).with_if_index(tun_ifindex);
        if let Err(err) = handle.add(&route).await {
            warn!(prefix = %net, error = %err, "route add failed");
        }
    }

    Ok(())
}

/// Builds the set of desired prefixes, expanding default routes into two /1 prefixes.
///
/// - Non-default prefixes are preserved as-is.
/// - `0.0.0.0/0` is expanded into `0.0.0.0/1` and `128.0.0.0/1`.
/// - `::/0` is expanded into `::/1` and `8000::/1`.
/// - Default routes emit a warning when split.
fn expand_allowed_prefixes(allowed: &[IpNet]) -> HashSet<IpNet> {
    let mut result = HashSet::with_capacity(allowed.len() * 2);

    for &net in allowed {
        if net.prefix_len() == 0 {
            warn!(prefix = %net, "default route split into two /1 prefixes");
            match split_default_prefix(&net) {
                Some([a, b]) => result.extend([a, b]),
                None => {
                    result.insert(net);
                }
            }
        } else {
            result.insert(net);
        }
    }

    result
}

/// Splits a `/0` default route into two `/1` halves.
fn split_default_prefix(net: &IpNet) -> Option<[IpNet; 2]> {
    if net.prefix_len() != 0 {
        return None;
    }
    let mut it = net.subnets(1).ok()?;
    Some([it.next()?, it.next()?])
}

/// Resolves an interface index using the platform helper from `bind`.
fn resolve_ifindex(name: &str) -> Result<u32, RouteSyncError> {
    lookup_ifindex(name).ok_or_else(|| RouteSyncError::InterfaceLookup {
        interface: name.to_string(),
        error: "interface not found".to_string(),
    })
}

/// Returns `true` for IPv6 routes auto-managed by the kernel.
///
/// These include:
/// - Link-local routes (`fe80::/10` range) — connected and host routes
/// - Multicast routes (`ff00::/8` range)
fn is_ipv6_kernel_route(net: &IpNet) -> bool {
    match net {
        IpNet::V6(v6) => {
            let addr = v6.network();
            addr.is_unicast_link_local() || addr.is_multicast()
        }
        IpNet::V4(_) => false,
    }
}

/// Converts a `route_manager::Route` into `IpNet` when the address family is supported.
pub fn ipnet_from_route(route: &Route) -> Option<IpNet> {
    IpNet::new(route.destination(), route.prefix()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tracing_test::traced_test;

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
                return Err(io::Error::other("add failed"));
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
                return Err(io::Error::other("delete failed"));
            }
            let mut routes = self.routes.lock().unwrap();
            if let Some(pos) = routes.iter().position(|r| r == route) {
                routes.remove(pos);
            }
            Ok(())
        }
    }

    /// Shorthand for `sync_tun_routes("tun0", ...)` in tests.
    async fn sync_test(
        tun_addrs: &[IpNet],
        allowed: &[IpNet],
        handle: &mut FakeHandle,
        resolver: &FakeResolver,
    ) {
        sync_tun_routes("tun0", tun_addrs, allowed, handle, resolver)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[traced_test]
    /// Adds missing routes while skipping already present TUN prefixes.
    async fn adds_missing_routes_and_skips_existing() {
        let resolver = FakeResolver { idx: 7 };
        let mut handle = FakeHandle::new(vec![route("10.0.0.0/24", Some(7))]);
        let allowed: Vec<IpNet> = vec![
            "10.0.0.0/24".parse().unwrap(),
            "10.0.1.0/24".parse().unwrap(),
        ];
        let tun_addrs: Vec<IpNet> = Vec::new();

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;
        assert_eq!(handle.ops(), vec!["add 10.0.1.0/24"]);
        // No warnings expected for normal operation
        assert!(!logs_contain("route"));
    }

    #[tokio::test]
    #[traced_test]
    /// Deletes TUN routes that are not part of the desired set.
    async fn deletes_stale_tun_routes() {
        let resolver = FakeResolver { idx: 9 };
        let stale = route("10.5.0.0/16", Some(9));
        let mut handle = FakeHandle::new(vec![stale.clone()]);
        let allowed: Vec<IpNet> = vec![];
        let tun_addrs: Vec<IpNet> = Vec::new();

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;
        assert_eq!(handle.ops(), vec!["del 10.5.0.0/16"]);
        assert!(handle.routes.lock().unwrap().is_empty());
        // No warnings expected for normal operation
        assert!(!logs_contain("route"));
    }

    #[tokio::test]
    #[traced_test]
    /// Warns on conflicts but still installs the requested prefix.
    async fn warns_on_conflict_and_installs_route() {
        let resolver = FakeResolver { idx: 3 };
        let mut handle = FakeHandle::new(vec![route("192.168.0.0/24", Some(2))]);
        let allowed: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;
        assert_eq!(handle.ops(), vec!["add 192.168.0.0/24"]);
        assert!(logs_contain("route conflict"));
        assert!(logs_contain("192.168.0.0/24"));
        assert!(logs_contain("existing_ifindex=\"2\""));
    }

    #[tokio::test]
    #[traced_test]
    /// Warns when a route lacks an interface index but still installs the prefix.
    async fn warns_on_missing_ifindex_and_installs_route() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![route("10.0.0.0/24", None)]);
        let allowed: Vec<IpNet> = vec!["10.0.0.0/24".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert_eq!(handle.ops(), vec!["add 10.0.0.0/24"]);
        assert!(logs_contain("route conflict"));
        assert!(logs_contain("existing_ifindex=\"unknown\""));
    }

    #[tokio::test]
    #[traced_test]
    /// Splits default routes once and adds both halves when missing.
    async fn splits_default_route_once() {
        let resolver = FakeResolver { idx: 5 };
        let mut handle = FakeHandle::new(Vec::new());
        let allowed: Vec<IpNet> = vec!["0.0.0.0/0".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        let ops = handle.ops();
        assert_eq!(ops.len(), 2);
        assert!(ops.contains(&"add 0.0.0.0/1".to_string()));
        assert!(ops.contains(&"add 128.0.0.0/1".to_string()));
        assert!(logs_contain("default route split"));
        assert!(logs_contain("0.0.0.0/0"));
    }

    #[tokio::test]
    #[traced_test]
    /// If both default halves already exist, they are not re-added.
    async fn skips_existing_default_halves() {
        let resolver = FakeResolver { idx: 5 };
        let mut handle = FakeHandle::new(vec![
            route("0.0.0.0/1", Some(5)),
            route("128.0.0.0/1", Some(5)),
        ]);
        let allowed: Vec<IpNet> = vec!["0.0.0.0/0".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert!(handle.ops().is_empty());
        // Default route split warning is still emitted during expansion
        assert!(logs_contain("default route split"));
    }

    #[tokio::test]
    #[traced_test]
    /// Warns when default halves conflict with other interfaces.
    async fn warns_when_default_halves_conflict() {
        let resolver = FakeResolver { idx: 8 };
        let mut handle = FakeHandle::new(vec![
            route("0.0.0.0/1", Some(2)),
            route("128.0.0.0/1", Some(7)),
        ]);
        let allowed: Vec<IpNet> = vec!["0.0.0.0/0".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        let ops = handle.ops();
        assert_eq!(ops.len(), 2);
        assert!(ops.contains(&"add 0.0.0.0/1".to_string()));
        assert!(ops.contains(&"add 128.0.0.0/1".to_string()));
        // Verify all expected warnings
        assert!(logs_contain("default route split"));
        assert!(logs_contain("route conflict"));
        assert!(logs_contain("0.0.0.0/1"));
        assert!(logs_contain("128.0.0.0/1"));
    }

    #[tokio::test]
    #[traced_test]
    /// Warns when a conflicting host prefix cannot be split.
    async fn warns_when_conflict_cannot_be_split() {
        let resolver = FakeResolver { idx: 4 };
        let mut handle = FakeHandle::new(vec![route("10.0.0.1/32", Some(2))]);
        let allowed: Vec<IpNet> = vec!["10.0.0.1/32".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert_eq!(handle.ops(), vec!["add 10.0.0.1/32"]);
        assert!(logs_contain("route conflict"));
        assert!(logs_contain("10.0.0.1/32"));
    }

    #[tokio::test]
    #[traced_test]
    /// Warns on IPv6 conflicts without splitting non-default prefixes.
    async fn warns_on_ipv6_conflicts() {
        let resolver = FakeResolver { idx: 12 };
        let mut handle = FakeHandle::new(vec![route("2001:db8::/64", Some(6))]);
        let allowed: Vec<IpNet> = vec!["2001:db8::/64".parse().unwrap()];
        let tun_addrs: Vec<IpNet> = Vec::new();

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert_eq!(handle.ops(), vec!["add 2001:db8::/64"]);
        assert!(logs_contain("route conflict"));
        assert!(logs_contain("2001:db8::/64"));
    }

    #[tokio::test]
    #[traced_test]
    /// Logs add/delete failures while logging attempted operations.
    async fn logs_add_and_delete_failures() {
        let resolver = FakeResolver { idx: 11 };
        let stale = route("10.9.0.0/16", Some(11));
        let allowed: Vec<IpNet> = vec!["10.8.0.0/16".parse().unwrap()];
        let mut handle = FakeHandle::with_failures(vec![stale.clone()], true, true);
        let tun_addrs: Vec<IpNet> = Vec::new();

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert_eq!(handle.ops(), vec!["del 10.9.0.0/16", "add 10.8.0.0/16"]);
        assert!(logs_contain("route delete failed"));
        assert!(logs_contain("10.9.0.0/16"));
        assert!(logs_contain("route add failed"));
        assert!(logs_contain("10.8.0.0/16"));
    }

    // ========== TUN address preservation tests ==========

    #[tokio::test]
    #[traced_test]
    /// Kernel connected route (network prefix) preserved via tun_v4_kernel_routes.
    async fn kernel_connected_route_preserved() {
        let resolver = FakeResolver { idx: 10 };
        // Kernel creates 192.168.1.0/24 when TUN addr is 192.168.1.2/24
        let mut handle = FakeHandle::new(vec![route("192.168.1.0/24", Some(10))]);
        let tun_addrs: Vec<IpNet> = vec!["192.168.1.2/24".parse().unwrap()];
        let allowed: Vec<IpNet> = vec![];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        // Kernel route preserved, not deleted or re-added
        assert!(handle.ops().is_empty());
    }

    #[tokio::test]
    #[traced_test]
    /// Kernel host route (/32) preserved via tun_v4_kernel_routes.
    async fn kernel_host_route_preserved() {
        let resolver = FakeResolver { idx: 10 };
        // Kernel creates host route 192.168.1.2/32 for the assigned address
        let mut handle = FakeHandle::new(vec![route("192.168.1.2/32", Some(10))]);
        let tun_addrs: Vec<IpNet> = vec!["192.168.1.2/24".parse().unwrap()];
        let allowed: Vec<IpNet> = vec![];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert!(handle.ops().is_empty());
    }

    #[tokio::test]
    #[traced_test]
    /// TUN addr routes are preserved but NOT actively added — only allowed routes are added.
    async fn tun_addr_routes_not_added() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![]);
        let tun_addrs: Vec<IpNet> = vec!["10.0.0.1/24".parse().unwrap()];
        let allowed: Vec<IpNet> = vec!["192.168.1.0/24".parse().unwrap()];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        // Only allowed route added; tun_addr routes are OS-managed, not added by us
        assert_eq!(handle.ops(), vec!["add 192.168.1.0/24"]);
    }

    #[tokio::test]
    #[traced_test]
    /// Both kernel routes (connected + host) and allowed routes are preserved together.
    async fn mixed_tun_and_allowed_routes_preserved() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![
            route("192.168.1.0/24", Some(10)), // kernel connected route
            route("192.168.1.2/32", Some(10)), // kernel host route
            route("10.0.0.0/8", Some(10)),     // allowed route
        ]);
        let tun_addrs: Vec<IpNet> = vec!["192.168.1.2/24".parse().unwrap()];
        let allowed: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        // All routes already exist, no operations
        assert!(handle.ops().is_empty());
    }

    #[tokio::test]
    #[traced_test]
    /// Kernel broadcast routes (network /32 and directed broadcast /32) preserved.
    async fn kernel_broadcast_routes_preserved() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![
            route("192.168.1.0/32", Some(10)),   // broadcast network-addr route
            route("192.168.1.255/32", Some(10)), // broadcast directed route
        ]);
        let tun_addrs: Vec<IpNet> = vec!["192.168.1.2/24".parse().unwrap()];
        let allowed: Vec<IpNet> = vec![];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert!(handle.ops().is_empty());
    }

    #[tokio::test]
    #[traced_test]
    /// Limited broadcast 255.255.255.255/32 preserved even with no TUN addresses.
    async fn limited_broadcast_preserved() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![route("255.255.255.255/32", Some(10))]);
        let tun_addrs: Vec<IpNet> = vec![];
        let allowed: Vec<IpNet> = vec![];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert!(handle.ops().is_empty());
    }

    #[tokio::test]
    #[traced_test]
    /// /31 and /32 TUN addresses do not generate broadcast protection entries.
    async fn no_broadcast_for_narrow_prefixes() {
        let resolver = FakeResolver { idx: 10 };
        // 10.0.0.0/32 would be the "network" broadcast — should NOT be protected
        let mut handle = FakeHandle::new(vec![route("10.0.0.0/32", Some(10))]);
        let tun_addrs: Vec<IpNet> = vec!["10.0.0.1/31".parse().unwrap()];
        let allowed: Vec<IpNet> = vec![];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        // 10.0.0.0/31 (connected) and 10.0.0.1/32 (host) are protected,
        // but 10.0.0.0/32 is NOT — it gets deleted as stale
        assert_eq!(handle.ops(), vec!["del 10.0.0.0/32"]);
    }

    // ========== IPv6 kernel route preservation tests ==========

    #[tokio::test]
    #[traced_test]
    /// Link-local connected route (fe80::/64) preserved on TUN interface.
    async fn ipv6_link_local_connected_preserved() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![route("fe80::/64", Some(10))]);
        let tun_addrs: Vec<IpNet> = vec![];
        let allowed: Vec<IpNet> = vec![];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert!(handle.ops().is_empty());
    }

    #[tokio::test]
    #[traced_test]
    /// Link-local host route (fe80::xxx/128) preserved on TUN interface.
    async fn ipv6_link_local_host_preserved() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![route("fe80::ef04:f217:fba2:1858/128", Some(10))]);
        let tun_addrs: Vec<IpNet> = vec![];
        let allowed: Vec<IpNet> = vec![];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert!(handle.ops().is_empty());
    }

    #[tokio::test]
    #[traced_test]
    /// Multicast route (ff00::/8) preserved on TUN interface.
    async fn ipv6_multicast_preserved() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![route("ff00::/8", Some(10))]);
        let tun_addrs: Vec<IpNet> = vec![];
        let allowed: Vec<IpNet> = vec![];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert!(handle.ops().is_empty());
    }

    #[tokio::test]
    #[traced_test]
    /// Non-kernel IPv6 routes on TUN are still deleted as stale.
    async fn ipv6_non_kernel_route_deleted() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![route("2001:db8::/32", Some(10))]);
        let tun_addrs: Vec<IpNet> = vec![];
        let allowed: Vec<IpNet> = vec![];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert_eq!(handle.ops(), vec!["del 2001:db8::/32"]);
    }

    #[tokio::test]
    #[traced_test]
    /// IPv6 kernel routes on other interfaces do not trigger conflict warnings.
    async fn ipv6_kernel_routes_on_other_if_no_conflict() {
        let resolver = FakeResolver { idx: 10 };
        let mut handle = FakeHandle::new(vec![
            route("fe80::/64", Some(2)),   // link-local on eth0
            route("fe80::1/128", Some(2)), // link-local host on eth0
            route("ff00::/8", Some(2)),    // multicast on eth0
            route("ff02::1/128", Some(3)), // multicast host on wlan0
        ]);
        let tun_addrs: Vec<IpNet> = vec![];
        let allowed: Vec<IpNet> = vec![];

        sync_test(&tun_addrs, &allowed, &mut handle, &resolver).await;

        assert!(handle.ops().is_empty());
        assert!(!logs_contain("route conflict"));
    }

    /// Always fails interface resolution (for error path tests).
    struct FailingResolver;

    impl IfIndexResolver for FailingResolver {
        fn resolve(&self, name: &str) -> Result<u32, RouteSyncError> {
            Err(RouteSyncError::InterfaceLookup {
                interface: name.to_string(),
                error: "test failure".to_string(),
            })
        }
    }

    // ========== Route actor lifecycle tests ==========

    #[tokio::test]
    #[traced_test]
    async fn spawn_route_processes_command_and_exits_on_drop() {
        let actor = RouteActor {
            handle: FakeHandle::new(vec![]),
            resolver: FakeResolver { idx: 7 },
        };
        let (cmd_tx, join_handle) = spawn_route(actor, "tun0".to_string());
        cmd_tx
            .send(RouteCommand::SyncRoutes {
                tun_addrs: vec![],
                allowed: vec!["10.0.0.0/24".parse().unwrap()],
            })
            .expect("send should succeed");
        drop(cmd_tx);
        let result = tokio::time::timeout(std::time::Duration::from_millis(200), join_handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "actor should shut down cleanly after processing command, got {result:?}"
        );
        assert!(!logs_contain("route sync failed"));
    }

    #[tokio::test]
    #[traced_test]
    async fn spawn_route_logs_sync_failure() {
        let actor = RouteActor {
            handle: FakeHandle::new(vec![]),
            resolver: FailingResolver,
        };
        let (cmd_tx, join_handle) = spawn_route(actor, "tun0".to_string());
        cmd_tx
            .send(RouteCommand::SyncRoutes {
                tun_addrs: vec![],
                allowed: vec!["10.0.0.0/24".parse().unwrap()],
            })
            .expect("send should succeed");
        drop(cmd_tx);
        let result = tokio::time::timeout(std::time::Duration::from_millis(200), join_handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "actor should shut down cleanly even after sync failure, got {result:?}"
        );
        assert!(logs_contain("route sync failed"));
    }

    #[tokio::test]
    async fn spawn_route_exits_gracefully_on_sender_drop() {
        let actor = RouteActor {
            handle: FakeHandle::new(vec![]),
            resolver: FakeResolver { idx: 7 },
        };
        let (cmd_tx, join_handle) = spawn_route(actor, "tun0".to_string());
        drop(cmd_tx);
        let result = tokio::time::timeout(std::time::Duration::from_millis(200), join_handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "actor should shut down cleanly after sender dropped, got {result:?}"
        );
    }

    #[tokio::test]
    async fn spawn_route_returns_working_cmd_tx() {
        let actor = RouteActor {
            handle: FakeHandle::new(vec![]),
            resolver: FakeResolver { idx: 7 },
        };
        let (cmd_tx, _join_handle) = spawn_route(actor, "tun0".to_string());
        assert!(cmd_tx
            .send(RouteCommand::SyncRoutes {
                tun_addrs: vec![],
                allowed: vec!["10.0.0.0/24".parse().unwrap()],
            })
            .is_ok());
    }

    #[tokio::test]
    #[traced_test]
    async fn spawn_route_processes_multiple_commands_sequentially() {
        let actor = RouteActor {
            handle: FakeHandle::new(vec![]),
            resolver: FakeResolver { idx: 7 },
        };
        let (cmd_tx, join_handle) = spawn_route(actor, "tun0".to_string());
        for prefix in &["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"] {
            cmd_tx
                .send(RouteCommand::SyncRoutes {
                    tun_addrs: vec![],
                    allowed: vec![prefix.parse().unwrap()],
                })
                .expect("send should succeed");
        }
        drop(cmd_tx);
        let result = tokio::time::timeout(std::time::Duration::from_millis(500), join_handle).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "actor should process all commands and shut down cleanly, got {result:?}"
        );
        assert!(!logs_contain("route sync failed"));
    }
}
