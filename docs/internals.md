## Internals

Internals overview: runtime dependencies, guards against recursive routing and DNS resolution loops, actor-based concurrency model, route update strategy, and longest-prefix matching. Protocol/auth specifics live in [docs/protocol.md](protocol.md).

### Dependencies

h3llo primarily depends on tun-rs and tokio-quiche (HTTP/3 with DATAGRAM support enabled). tokio-quiche is statically linkable and provides low-level control over QUIC connections.

### Recursive Routing and DNS Resolution

Recursive routing and DNS resolution summary: probe WAN-facing interfaces (excluding the TUN) for DNS, HTTP/3, and BareUDP, bind sockets per interface when possible, and warn loudly while falling back to unbound sockets if probing or binding fails (risking recursive routing when default routes are overridden).

Why recursive routing happens: if h3llo installs the default route into the TUN and outbound sockets (DNS, HTTP/3, BareUDP) are not explicitly bound to a WAN-facing interface, their traffic can re-enter the tunnel and get forwarded again, creating loops and blocking connectivity. Binding per interface (or at least warning on fallback to unbound) avoids the TUN from becoming both source and sink of control traffic.

Binding workflow for HTTP/3, BareUDP, and DNS:
1. Pick the DNS interface: prefer `local.dns.bindif` when provided and present in probe results; warn and fall back to the first probed non-TUN interface when the preferred one is missing. If no interface is available or probing fails, log a warning and continue with an unbound DNS socket. Probing uses `route_manager` to list routes from all kernel routing tables, performs prefix matches against the target IP, filters entries whose `ifindex` matches the TUN, and maps interface indexes back to names. Route selection priority: (1) longest prefix match, (2) main routing table (254) preferred over custom tables at equal prefix length, (3) lower metric wins within the same table category (main vs. non-main; a non-main route's metric never overrides a main route, but routes from different non-main tables are compared by metric against each other — per-table isolation is not performed because h3llo prioritizes cross-platform compatibility with minimal code; for hosts with policy routing, use explicit `bindif`). **Policy routing caveat**: this heuristic cannot replicate the kernel's RPDB (routing policy database) evaluation. When policy routing rules (`ip rule`) direct traffic to custom tables, h3llo's interface selection may differ from the kernel's actual routing decision. Set `local.dns.bindif` / `peers[].h3.bindif` / `peers[].bare.bindif` explicitly when policy routing is active. **Known limitation**: `route_manager` stores routing table IDs as `u8` (from the netlink `rtm_table` header field, range 0–255). Table IDs above 255 (used by some policy routing setups like Azure accelerated networking) are truncated. In practice, the kernel provides `RT_TABLE_COMPAT` (252) for large table IDs, which is correctly identified as non-main (252 ≠ 254). For environments with complex table ID schemes, use explicit `bindif` configuration.
2. DNS resolver actor: bind a UDP socket by interface index (Linux/macOS via `bind_device_by_index_v4/6`, Windows via `IP_UNICAST_IF` / `IPV6_UNICAST_IF`) when available. The actor runs a `select` over its command queue, UDP socket, a timer tick at `dns_query_timeout / 2` interval, a refresh timer (configurable via `tuning.dns_refresh_interval`), and an on-demand query pacing timer. The orchestrator sends a single `SetHostnames { hosts: HashSet<String> }` command with all peer endpoint hostnames; the DNS module owns hostname registration and refresh scheduling internally. Due A and AAAA requests are represented as `DnsQuery` values and deduplicated in a `HashSet`; the pacing timer is armed while this set is non-empty, sends at most one query per `tuning.dns_query_interval` (default 100ms), and stops when no work remains. Neither refresh discovery nor timeout handling sleeps inside a `select` branch, so a large query backlog does not block commands, response processing, or TTL expiration. In-flight queries live in an actor-wide `IndexMap<DnsQuery, PendingQuery>` whose insertion order is send-time order. Responses use order-preserving removal by `DnsQuery`, while timeout handling drains the expired prefix in one operation and stops at the first unexpired entry. A query is never both queued and pending: refresh scheduling skips pending queries, while timeout handling removes the pending entry before queuing its retry. Per-hostname state contains only resolved IPs with TTL expiration and `next_refresh_at` refresh scheduling. Response matching constructs the `DnsQuery` from the DNS question and validates its transaction ID against the pending entry—providing dual (hostname + txid) validation. `trigger_refresh` skips hostnames whose `next_refresh_at` is still in the future, advances the deadline when it queues work, and relies on `HashSet` insertion to deduplicate overlapping `SetHostnames`, refresh, and retry triggers. The resolver maintains unified internal state tracking each registered hostname's resolved IPs with TTL-based expiration (floor: `tuning.dns_min_ttl`, default 300 seconds). State changes set a dirty flag; the actor emits and clears it immediately after processing the `SetHostnames` command, the current DNS response packet, or a TTL-expiration tick. Multiple records in one DNS response packet are therefore included in one state snapshot (`HashMap<String, HashSet<IpAddr>>`) without a separate debounce timer. The ticker (at `dns_query_timeout / 2` interval) queues query timeout retries and handles TTL-based expiration. The orchestrator computes deltas by diffing the new snapshot against the previous one and applies adds/removes accordingly. DNS warnings (NXDOMAIN, recursion refusal) are logged at origin via `warn!` instead of propagating through events. Truncated (TC) responses are treated as packet loss: the pending entry is preserved until `dns_query_timeout` elapses, then the retry is placed into the paced query set with a new transaction ID assigned at send time.
3. Transport binding: for each resolved IP, probe the WAN-facing interface excluding the TUN; bind transport sockets to that interface. HTTP/3 dials all DNS-resolved IPs in parallel; first successful connection wins. BareUDP uses a single listener socket (RX-only) and one outbound socket per BareUDP peer (TX-only). If probing or binding fails, warn and continue unbound.

Platform tiers and binding behavior:
- Linux (primary): uses `bind_device_by_index_v4` / `bind_device_by_index_v6` with `if_nametoindex` to pin sockets by interface index.
- macOS (second tier): same index-based binding as Linux; warnings on failures or missing interfaces fall back to unbound sockets.
- Windows (second tier): binds via `IP_UNICAST_IF` / `IPV6_UNICAST_IF` using interface index; failures degrade to unbound sockets with warnings.
- BSD (third tier): route probing and interface binding are not supported; h3llo will warn, avoid interface pinning, and cannot install or adjust routes automatically. Users must update the system route table manually to prevent recursive routing.

### Concurrency Model (Actor)

Concurrency model overview: h3llo adopts the actor model—each coroutine (actor) owns private state, communicates exclusively via MPSC message queues, and never shares mutable data with other actors. This eliminates lock contention and simplifies reasoning about concurrent correctness.

Actor design principles:
- **Isolated state**: each actor (TUN-Rx, TUN-Tx, Router, DNS Resolver, UDP-Rx/Tx, BareUDP-Rx/Tx, Route Sync, Orchestrator, H3Dispatcher, H3Engine per connection) maintains its own state; no `Arc<Mutex<_>>` across actors. UDP I/O actors (`udp.rs`) provide protocol-agnostic socket access via `Arc<UdpSocket>`; BareUDP actors (`bare.rs`) layer protocol logic (source-IP filtering, destination tagging) on top without touching sockets.
- **Actor-owned message box**: each actor creates its own channels during spawn. Control-plane command channels use `mpsc::unbounded_channel()`; data-plane packet channels use `mpsc::channel(PACKET_QUEUE_DEPTH)`. The actor owns the receiver; the caller receives the sender via tuple return (e.g., `(cmd_tx, JoinHandle)` or `(packet_tx, JoinHandle)`). This ensures clear ownership and enables graceful shutdown when all senders are dropped.
- **Message passing**: actors communicate through typed `mpsc::channel` queues; the `Event` enum and command types define the message protocol.
- **Async select loop**: each actor runs a `tokio::select!` loop over its input channels, I/O sources, and timers.
- **Supervision**: the Orchestrator holds senders to child actors; task JoinHandles are registered with `JoinSet` for lifecycle monitoring. Actors return `ActorExitResult`:
  - `Ok(())` for graceful shutdown (e.g., command channel closed)
  - `Err(ActorError)` for I/O errors requiring orchestrator action
  The orchestrator continues running on graceful exits but terminates on actor errors or task panics. Route Sync only returns `Ok(())` (graceful exit); sync errors are logged as warnings at origin. If initialization fails, the orchestrator degrades to no system route management.
- **Graceful shutdown**: when all senders to an actor's command channel are dropped, `recv()` returns `None`. The actor detects this and exits its event loop gracefully.

#### Actor Initialization Pattern (make + spawn)

Each actor follows a consistent two-function initialization pattern:

1. **`make_*`** - Creates actor state from configuration:
   - Takes configuration parameters (structured config or resolved types)
   - Performs synchronous or fallible I/O (socket binding, parsing)
   - Returns `Result<ActorState, Error>`
   - Example: `udp::make_udp(socket, mtu, enable_offload) -> Result<(UdpRx, UdpTx), UdpError>`

2. **`spawn_*`** - Spawns the actor task:
   - Takes the state struct and dependencies (events_tx, etc.)
   - Creates channels internally (actor owns receiver)
   - Spawns `tokio::spawn` task
   - Returns `(Sender, JoinHandle)` or similar tuple
   - Example: `spawn_bare_rx(group, packet_queue_depth, udp_rt, crypto_rt) -> (UnboundedSender<Cmd>, JoinHandle, JoinHandle)`

Both `make` and `spawn` are **bare functions** (not associated methods or impl methods). This design:
- Follows [Alice Ryhl's Tokio actor pattern](https://ryhl.io/blog/actors-with-tokio/) recommendation for fewer lifetime issues
- Keeps initialization logic in the actor module, not scattered in orchestrator
- Makes the separation between fallible setup (`make`) and task spawning (`spawn`) explicit

The orchestrator calls `make` then `spawn` sequentially, never performs actor-specific socket/device initialization.

#### Channel Capacity Policy

Actors use two channel categories with different capacity policies:

- **Control plane (unbounded)**: Command queues (orchestrator-to-child) and event queues (child-to-orchestrator) use `mpsc::unbounded_channel()`. This prevents deadlocks from message cycles between actors—a bounded channel can deadlock when actors block on `send()` waiting for each other.
- **Data plane (bounded)**: Packet queues for forwarding IP datagrams use `mpsc::channel::<Vec<PooledBuf>>(tuning.packet_queue_depth)` (default 256). Each channel message carries a batch of packets produced by a single device I/O operation (TUN `recv_batch`, BareUDP GRO, or up to 128 H3 datagrams / 64 KiB with adaptive flush on size change or small packets). This reduces per-packet atomic operations from N to 1 per batch. `packet_queue_depth` counts batch messages, not individual packets. Each batch contains up to `IDEAL_BATCH_SIZE` packets (Linux TUN), `gro_segments` chunks (BareUDP), or up to 128 datagrams (H3). Bounded channels provide backpressure, preventing memory exhaustion when producers outpace consumers. Buffers are allocated from tokio-quiche's `BufFactory` pool; dropped buffers return to the pool for reuse, reducing allocator pressure.

**Buffer allocation strategy**: Data-plane buffers reserve 10 bytes of headroom (9 bytes DGRAM_PREFIX + 1 byte Context ID) via `alloc_uninit_packet_buf(length)`, which selects the smallest pool that fits: packets where `length + HEADROOM ≤ MAX_DGRAM_SIZE` (1500) use `BufFactory::get_max_datagram()` (1.5 KB datagram pool, 64K capacity), while larger payloads fall back to `BufFactory::get_max_buf()` (64 KB generic pool, 16K capacity). Since `get_max_datagram()` internally reserves `DGRAM_PREFIX` (9 bytes) rather than our full `HEADROOM` (10 bytes), the allocator dynamically computes and consumes the 1-byte difference via `pop_front`. This headroom serves dual purposes: (1) zero-copy H3 datagram encoding via `add_prefix(&[CONTEXT_ID_IP])`, and (2) zero-copy TUN TX via `TunBuf`, which prepends a zeroed `virtio_net_hdr` (also 10 bytes) using `add_prefix` without allocation. A compile-time assertion guards the HEADROOM >= VIRTIO_NET_HDR_LEN invariant. H3 datagram decoding uses `pop_front(1)` to strip the Context ID in-place, restoring the headroom for TUN TX. TUN RX receives directly into `TunBuf::alloc_uninit(mtu)` (same headroom allocation), then extracts the inner `PooledBuf` via `into_pooled()` — zero-copy from kernel to packet channel. H3 and BareUDP RX use `alloc_packet_buf()` (copy into pooled buffer with headroom). `alloc_packet_buf` delegates to `alloc_uninit_packet_buf` internally. Buffers without headroom (e.g., `BufFactory::buf_from_slice()` in tests) cause `TunBuf` to fall back to alloc + copy.

**GSO batch sending**: The generic UDP TX actor (`udp::spawn_udp_tx`) concatenates packets from each `(SocketAddr, Vec<PooledBuf>)` batch into a contiguous buffer and sends via a single `sendmsg` with `segment_size` set (UDP GSO). Both BareUDP and H3v2 server transports share this actor. Batches are chunked by `max_gso_segments()` (typically 64 on Linux). On platforms without GSO support (`max_gso_segments() == 1`), `chunks(1)` naturally degrades to per-packet sending.

**H3 session event handling**: `H3Session::poll_h3_events` is the unified H3 event loop shared by client handshake (`h3dialer`), server handshake (`h3listener`), and steady-state forwarding (`h3engine`). It accepts a generic `FnMut` callback for role-specific header processing—client checks `:status`, server validates CONNECT-IP headers + auth and sends 200 OK, steady-state ignores all headers. The callback returns a `HeaderAction` enum (`Accept` / `Ignore`) that tells the session what bookkeeping to perform. This design uses static dispatch (monomorphized at each call site) and keeps authentication logic in `h3listener.rs` without leaking it into the session module.

**Metrics semantic note**: BareUDP TX (`Source::BareUdp, Direction::Tx`) counts packets forwarded to the UDP TX **channel**, not packets physically sent on the wire. The observable operator effect is unchanged (dead peer → pruned).

Reference: [Alice Ryhl - Actors with Tokio](https://ryhl.io/blog/actors-with-tokio/)

**Inbound Datapath**

```mermaid
flowchart TB
    wan[WAN Interface]@{shape: h-cyl}
    tun[TUN Interface]@{shape: h-cyl}
    prog[Programs]@{shape: processes}
    cmd["Commands"]@{shape: braces}

    subgraph cr-h3-1["Actor (H3Engine)"]
        hr1[QUIC Decode + Datagram Reader]
    end

    subgraph cr-h3-2["Actor (H3Engine)"]
        hr2[QUIC Decode + Datagram Reader]
    end

    subgraph cr-bare["Actor (Bare-Rx)"]
        bq[Command Queue]@{shape: h-cyl}
        bsf[Source IP Filter]
        br[Bare Datagram Reader]
    end

    subgraph cr-router["Actor (Router)"]
        rq[Ingress Queue]@{shape: h-cyl}
        rlpm[/LPM + TTL\]
    end

    subgraph cr-tun["Actor (TUN-Tx)"]
        tq[Input Queue]@{shape: h-cyl}
        tw[TUN Writer]
    end

    wan --> bsf --> br --> rq --> rlpm --> tq --> tw --> tun --> prog
    wan --> hr1 & hr2 --> rq
    rlpm -. forwarded packets .-> cr-h3-1 & cr-h3-2
    cmd -.-> bq -.-> bsf
```

**Outbound Datapath**

```mermaid
flowchart TB
    wan[WAN Interface]@{shape: h-cyl}
    tun[TUN Interface]@{shape: h-cyl}
    prog[Programs]@{shape: processes}
    rsys[/System<br>Route Table\]
    cmd["Commands"]@{shape: braces}

    subgraph cr-tun["Actor (TUN-Rx)"]
        tr[TUN Reader]
    end

    subgraph cr-router["Actor (Router)"]
        oq[Output Queue]@{shape: h-cyl}
        rcmd[Command Queue]@{shape: h-cyl}
        rint[/LPM<br>Route Table\]
    end

    subgraph cr-h3-1["Actor (H3Engine)"]
        hw1[QUIC Encode + Datagram Writer]
    end

    subgraph cr-h3-2["Actor (H3Engine)"]
        hw2[QUIC Encode + Datagram Writer]
    end

    subgraph cr-bare["Actor (Bare-Tx)"]
        bw[Bare Datagram Writer]
    end

    cmd -.-> rcmd -.-> rint
    prog --> rsys --> tun --> tr --> oq --> rint --> bw & hw1
    rint -. backup path -.-> hw2
    hw1 & hw2 & bw -- bypass system route table --> wan
```

**Control Path**

```mermaid
flowchart TB
    subgraph cr-orch["Actor (Orchestrator)"]
        oq[Command Queue]@{shape: h-cyl}
        hcp[H3 Conn Pool]
        dr[DNS Answers]
        conf[Configuration]
        oq ~~~ conf ~~~ dr ~~~ hcp
    end

    ctrl["External Controller"]
    cr-api["Actor<br>(API-Server)"]
    cr-h3e["Actor (H3Engine)"]
    cr-h3disp["Actor<br>(H3Dispatcher)"]

    rsys[/System<br>Route Table\]
    cr-router["Actor<br>(Router)"]
    cr-bare["Actor<br>(Bare-Rx)"]
    cr-dns["Actor<br>(DNS-Resolver)"]
    cr-h3d["Actor<br>(H3-Dialer)"]

    ctrl -- HTTP/1.1 GET/POST/DELETE --> cr-api -- emit(conf-update) --> cr-orch
    cr-h3e -- emit(conn-close) --> cr-orch
    cr-h3disp -- emit(conn-estab) --> cr-orch

    cr-route["Actor<br>(Route-Sync)"]
    cr-orch -- cmd(SyncRoutes) --> cr-route -- exec(route add/del) --> rsys
    cr-orch -- cmd(UpdateRouting) --> cr-router
    cr-orch -- cmd(SetHostnames) --> cr-dns -- emit(dns-snapshot)--> cr-orch
    cr-orch -- spawn --> cr-h3d -- emit(conn-estab) --> cr-orch
    cr-orch -- emit(filter-update) --> cr-bare
```

h3llo uses a thread-per-core architecture with multiple Tokio `current_thread` runtimes. Each data-plane actor group runs on a dedicated OS thread:

- **tun_rt** (`h3llo-tun`): TUN Rx/Tx actors.
- **crypto_rt** (`h3llo-crypto`): Router actor and H3 engine actors (QUIC crypto, H3 session, datagram forwarding). Co-locating H3 engines with the Router eliminates cross-thread hops for routed packets.
- **udp_rt** (`h3llo-udp`): All UDP I/O actors (BareUDP Rx/Tx and H3 transport UDP Rx/Tx).

The orchestrator and control-plane actors (DNS, Route Sync, API) share the main thread's `current_thread` runtime. Cross-runtime communication uses Tokio MPSC channels, which are runtime-agnostic. `Handle::enter()` is used during initialization to register I/O resources with the correct runtime's reactor; `JoinHandle`s from foreign runtimes are monitored by the orchestrator's `JoinSet`.

Orchestrator responsibilities and invariants:
- Maintain the latest configuration snapshot and H3 connection pool; receive commands from other actors through its MPSC queue.
- Stay fully async: handle config updates, DNS refresh results, connection close notifications, and timer ticks without blocking other commands.
- Spawn child actors (DNS resolver, H3 dialers, H3Dispatcher) and register newly established H3 connections' TX channels in the Router's routing table via `RouterCommand::UpdateRouting`. `make_h3_dispatcher` prepares an `H3DispatcherGroup` containing the dispatcher and UDP actor states; `spawn_h3_dispatcher` consumes the group and returns their handles for registration with the orchestrator's `JoinSet`.
- Process events from child actors (metrics, DNS) and log them appropriately; child actors control their own metric emission timing.
- Handle graceful shutdown on `ctrl_c` signal; task exit errors include task labels for debugging.

Orchestrator DNS handling:
- **Single event loop**: The orchestrator runs one unified event loop that handles all events including DNS lifecycle events. There is no separate initialization event loop.
- **Listen hostname**: If the listen address is a hostname (not IP literal), perform synchronous DNS lookup before starting the event loop. This ensures BareUDP RX and TUN TX are created immediately.
- **Unified hostname registration**: The orchestrator sends a single `SetHostnames { hosts: HashSet<String> }` command at startup with all unique peer endpoint hostnames. IP literals are handled by the DNS module directly (recorded with max TTL, included in next snapshot). The DNS module owns hostname tracking, refresh scheduling, and TTL-based expiration internally.
- **Event-driven IP lifecycle**: The orchestrator reacts to DNS state snapshot events. When a snapshot arrives, the orchestrator updates each peer's `resolved_ips`, prunes stale bounds, and attempts connections to uncovered IPs via `try_connect`. All resolved IPs are added to the accepted source filter.

Spawn an actor for every I/O path (TUN-Rx, TUN-Tx, Router, H3Dispatcher, each H3Engine, BareUDP-Rx pipeline, DNS resolver). Each H3 connection is managed by a unified H3Engine actor (both Rx and Tx). The H3Dispatcher accepts inbound QUIC connections and spawns per-connection H3Engine actors. BareUDP owns one listener socket for RX (UDP RX actor + source-filter actor pipeline) and a separate TX-only socket per BareUDP peer.

When configuration changes arrive (management API POST/DELETE or initialization), update the accepted-source filter first (fast, in-memory), then the internal routing table, then the system routing table. Dynamic reconfiguration flows through the orchestrator via the event channel.

**Terminology**: "Accepted sources" refers to the BareUDP RX source IP filter. "Allowed IPs" refers to TUN routing prefixes (`peers[].tun.allowed_ips`).

### TLS Certificate Reload

Server credentials are reloaded transactionally for new H3 connections. The listener socket and established `H3Engine` actors remain untouched throughout rotation.

- **Detection**: `notify::RecommendedWatcher` watches the distinct parent directories of `local.h3.cert` and `local.h3.key` non-recursively. Watching directories preserves notifications when a credential inode is replaced with `rename` or a symlink target is rotated.
- **Lifecycle**: `make_h3_dispatcher` performs fallible watcher registration. `H3Dispatcher` owns the native watcher and its event receiver, while the dispatcher loop owns the debounce state; no separate reload actor or control protocol is involved.
- **Coalescing**: Any non-access event, watcher error, or rescan marker starts a 500 ms quiet-period timer. Subsequent events reset the timer so certificate-chain and private-key updates are normally validated together.
- **Validation**: When the debounce timer expires, the dispatcher awaits `spawn_blocking` while it builds a fresh `quiche::Config`, applies the unchanged H3 transport tuning, parses the certificate chain, and loads the private key. The dispatcher pauses packet routing during this bounded reload, while the blocking work runs outside the crypto runtime thread so established `H3Engine` actors continue independently. BoringSSL rejects a private key that does not match the leaf certificate.
- **Commit**: The dispatcher directly swaps in a fully constructed configuration when the blocking task succeeds. Every later `quiche::accept` uses the new TLS context.
- **Isolation**: A `quiche::Connection` creates and owns its TLS handshake state during acceptance, so replacing the dispatcher config neither renegotiates nor closes established connections.
- **Failure handling**: Credential parsing, pairing, or loader-task failures are warnings and retain the last valid config so a later filesystem update can recover automatically. Closing the watcher event channel permanently removes reload capability, so the dispatcher returns a critical actor error and the orchestrator exits h3llo instead of reporting a healthy but stale listener.

Connection management:
- Each peer maintains multiple active connections (`Vec<BoundState>`), one per resolved IP.
- The first element in the bounds Vec is the preferred TX path for outbound data.
- When DNS answers change or an endpoint is reconfigured, stale bounds are pruned and new connections are attempted via `try_connect`.
- `try_connect` uses per-IP dial state tracking (`HashMap<IpAddr, DialState>`):
    - Each IP has independent in-flight detection and exponential backoff (`tuning.reconnect_backoff_min` to `tuning.reconnect_backoff_max`).
    - IPs with an in-flight dial or unexpired backoff are skipped.
    - Dial failure events (`DialFailed`) are sent from spawned tasks back to the orchestrator, which clears the in-flight flag and increments the backoff counter.
    - Successful connections (`update_bound`) remove the dial state entirely, resetting backoff for future reconnection.
    - Stale dial state is cleaned up during pruning when IPs leave `resolved_ips`.
- Listener-originated (inbound) connections have `endpoint: None` and are never pruned by DNS or endpoint changes.
- When a restartable actor fails, all peers are pruned (closed TX channels detected via `tx.is_closed()`), and routing is updated if the preferred TX changed.

Connection pruning rules (`PeerEntry::prune`):
- TX channel closed (actor exited) — always pruned.
- Outbound connection whose endpoint differs from current config — pruned (dynamic reconfig).
- Outbound connection whose dest IP is not in `resolved_ips` — pruned (DNS changed).
- Inbound connections (`endpoint: None`) are never pruned by endpoint/DNS checks.

DNS lifecycle management:
- The DNS module owns the refresh timer internally; every `tuning.dns_refresh_interval` seconds (when nonzero), it queues A and AAAA queries for registered hostnames whose per-entry `next_refresh_at` timestamp has passed. When work is queued, `next_refresh_at` advances by the refresh interval, throttling redundant refresh triggers.
- A `HashSet<DnsQuery>` deduplicates queued work by hostname and record type. An on-demand timer sends at most one query per `tuning.dns_query_interval`; it remains disabled when the set is empty. Refresh and timeout handlers only add work to the set and therefore never sleep inside the actor's main `select` loop.
- An actor-wide `IndexMap<DnsQuery, PendingQuery>` stores in-flight work in send-time order. DNS responses use order-preserving key removal; timeout handling drains the expired prefix as one range and stops at the first unexpired query.
- The DNS module maintains unified state tracking each hostname's resolved IPs with TTL-based expiration (floor: `tuning.dns_min_ttl`, default 300 seconds). A dirty flag tracks whether state changed since the last snapshot emission. The TTL floor must be at least `2× dns_refresh_interval` to guarantee that every refresh cycle renews the entry before expiry; otherwise recursive DNS servers returning near-zero remaining TTLs can cause repeated connection churn.
- On any state change (new IP, IP expiration, hostname add/remove), the dirty flag is set. The DNS module emits a state snapshot containing all hostname→IP mappings immediately after the current command, DNS response packet, or expiration tick finishes, then clears the flag. This preserves a single coherent snapshot for multiple records carried by one response packet without maintaining a separate debounce timer.
- The orchestrator processes DNS snapshots synchronously in three steps:
  1. Update each peer's `resolved_ips: HashSet<IpAddr>` from the snapshot.
  2. Prune stale bounds and attempt reconnection for each peer.
  3. Update accepted-source filter (unconditionally, from `resolved_ips` of bare peers).
  - Routing is updated only when prune detects a change in the preferred TX (first bound).
- A periodic reconciliation loop (`reconcile`, every `tuning.reconcile_interval`) runs prune + try_connect for all peers, ensuring self-healing even without DNS events.
- Refreshing an existing IP extends its TTL without changing the snapshot (no duplicate events).
- DNS warnings (NXDOMAIN, recursion refusal) are logged via `warn!` at the DNS module (origin) rather than propagating through events. Truncated responses are treated as packet loss and retried after `dns_query_timeout`.

During packet forwarding, TUN-Rx sends outbound packets to the Router actor via a bounded MPSC channel. The Router performs first-packet destination IP extraction, LPM lookup, and forwards the entire batch to the matched peer's TX channel (H3Engine or BareUDP writer) — no TTL mutation on the outbound path. For inbound traffic, transport actors (H3Engine, BareUDP-Rx) enqueue packets to the Router's ingress channel; the Router scans each packet's destination IP, performs LPM lookup, and routes accordingly: locally-destined packets (matching TUN addresses) are forwarded directly to TUN-Tx without TTL decrement; forwarded packets (destined for another peer) undergo per-packet TTL decrement with IPv4 checksum update (RFC 1624), and TTL-expired packets are sent to TUN-Tx for ICMP generation.

Key flows:

- TUN Reader → Router (LPM) → H3Engine/BareUDP-Tx.
- H3Engine/BareUDP-Rx → Router (LPM + TTL for forwarded packets) → TUN Writer or another peer.
- Management API updates → internal routes → system routes.

### System Route Updates

Route update summary: keep the TUN interface's routes aligned with `peers[].tun.allowed_ips` using `route_manager` APIs instead of shelling out (`ip route`, `route`, `netsh`). Route sync is performed by a dedicated Route Sync actor that serializes route updates via an MPSC command channel. The orchestrator sends fire-and-forget `SyncRoutes` commands; the actor processes them one at a time in FIFO order. The `AsyncRouteManager` (netlink socket) is created once during actor initialization and reused across all sync operations. The TUN interface name is captured in the actor at spawn time (immutable for the orchestrator's lifetime). If the route manager cannot be initialized (e.g., BSD platforms without netlink), the orchestrator logs a warning and continues without system route management.

Route sync flow: (1) resolve the TUN ifindex, (2) list system routes, (3) drop stale TUN routes that are not covered by `allowed_ips` while preserving the configured TUN host addresses, (4) rely on exact prefix matches instead of aggregated coverage when deciding whether an `allowed_ips` entry already exists, (5) when `allowed_ips` includes a default route, split it into two `/1` entries (IPv4 and IPv6) once and warn about the split; if either `/1` conflicts with another interface, emit a conflict warning but still attempt to add the route without further splitting, and (6) warn on unsupported route entries or add/delete failures while continuing to run. Route sync failures are logged as warnings by the actor at origin.

### Longest-Prefix-Match Algorithm

LPM summary: reuse WireGuard's longest-prefix-match behavior when choosing peers for IP packets.

h3llo should use the same longest-prefix-match algorithm as WireGuard when matching entries in the internal routing table.

### Multi-Path Support

h3llo provides two complementary multi-path capabilities: per-peer subnet routing and per-peer connection redundancy.

- Per-peer subnet routing: different `allowed_ips` prefixes can be assigned to different peers regardless of transport type (H3 or BareUDP). The routing table uses longest-prefix matching to forward packets to the appropriate peer based on destination IP.
- Per-peer connection redundancy: when a peer's hostname resolves to multiple IPs, h3llo establishes a connection to each resolved IP (`Vec<BoundState>`). The first bound is the preferred TX path; when it drops, prune promotes the next available bound automatically, providing failover without waiting for DNS or reconnection. See Connection management above for pruning and rate-limiting details.

Route deduplication: when synchronizing system routes, if a TUN address prefix (from `local.tun.addrs`) exactly matches a desired route (from peer `allowed_ips`), h3llo avoids tracking it as a separate TUN address route since the desired route already covers it.

### Observability

Observability summary: two metric sources are exposed. (1) Transport-level: actor loops emit cumulative metrics (batches/packets/bytes, drops, and drop-reason breakdowns) on a timer (`tuning.metrics_push_interval`); per-connection metrics are stored in `BoundState` (RX and TX fields), while non-peer-scoped metrics (TUN RX/TX, BareUDP RX, Router) are stored in `non_peer_metrics`; on scrape, the orchestrator collects metrics from live peer state into a snapshot via event and renders locally using the `prometheus-client` crate. (2) QUIC-level: `tokio_quiche::metrics::DefaultMetrics` automatically registers metrics in the `foundations` global registry; on scrape, `foundations::telemetry::metrics::collect()` returns the data as Prometheus text and it is appended to the response. Both metric types are periodically logged at `debug!` level by a unified metrics log ticker (`tuning.metrics_log_interval`, default 3s), decoupling logging cadence from emission cadence. No shared mutable state exists in the metrics path.

- Metric shape: every emit carries labels `{kind: Tun|BareUdp|Http3|Router, direction: Rx|Tx, peer_id?: string, remote_addr?: SocketAddr}` plus total succeeded and dropped counters (batches, packets, bytes), a drop-reason map keyed by `DropReason`, and congestion stats (queue_full count/duration, would_block count/duration). Congestion metrics are separate from drops because the affected packets are ultimately delivered — they are only delayed. The `batches` counter tracks `record()` invocations; `packets / batches` reveals GSO/GRO coalescing effectiveness (ratio > 1 indicates active offloading). For H3 TX, batch boundaries additionally reflect channel saturation: all packets flowing through `try_send` without backpressure count as one batch, and each `TrySendError::Full` event starts a new batch. Per-connection actors (BareUDP TX, H3Engine) populate both `peer_id` and `remote_addr`; shared actors (TUN RX/TX, BareUDP RX, Router) emit `(None, None)`.
- Prometheus exposition: per-connection metrics live in `BoundState.rx_metrics` / `BoundState.tx_metrics`; non-peer metrics (TUN, BareUDP RX) live in `Orchestrator.non_peer_metrics` — no `Arc<Mutex<_>>`, fully consistent with the actor model. On `GET /metrics`, the orchestrator collects metrics from all live bounds plus non-peer storage into a `HashMap`, sends it via oneshot channel to the API actor, which builds a temporary `Registry` with a `SnapshotCollector` wrapping the owned data and encodes via `prometheus-client`'s `text::encode()`. Seven counter families are produced: `h3llo_transport_packets`, `h3llo_transport_bytes`, `h3llo_transport_batches`, `h3llo_transport_drops`, `h3llo_transport_drop_bytes`, `h3llo_transport_congestion`, `h3llo_transport_congestion_wait_milliseconds` — using `ConstCounter` values with no atomic operations on data-plane hot paths. Labels: `kind`, `direction`, `peer_id`, `remote_addr`, plus `outcome`, `reason`, or `event` (`queue_full` / `would_block`). Output uses OpenMetrics text format. Metrics lifecycle follows connection lifecycle: when `prune()` removes a bound, its metrics vanish from the next scrape.
- Drop accounting: TUN TX counts oversize and send failures; TUN RX counts channel-closed drops when forwarding to the Router queue fails; Router counts no-route, invalid IP version, TTL-expired, and channel-closed drops; BareUDP RX counts disallowed sources; BareUDP TX counts send failures. All counters saturate to avoid panics.
- Reporting: only the orchestrator prints periodic drop summaries (when counters change); transport loops stay silent, including oversized TUN drops.

### Logging and Warning Handling

Logging summary: h3llo uses the `tracing` crate for structured logging. Warnings are logged directly at origin points rather than propagated through return values.

Logging bridge: tokio-quiche logs via `foundations::telemetry::log` macros (slog-based). h3llo bridges these to the tracing subscriber by calling `foundations::telemetry::init()` with `LogOutput::TracingRsCompat` during startup. This installs `TracingSlogDrain` as foundations' root slog drain, forwarding all slog records into the active tracing subscriber. Init order: (1) `fmt().init()` sets tracing subscriber, (2) `foundations::telemetry::init()` bridges slog → tracing. The init call is one-shot — subsequent calls return `Err`.

Warning handling design principles:
- **Log at origin**: Modules log warnings directly via `warn!` at the point where the condition is detected, using structured fields for context (e.g., `warn!(prefix = %net, error = %err, "route add failed")`).
- **No warning enums for logging**: Warning enums like `BindWarning` and `RouteSyncWarning` have been removed in favor of direct logging. This simplifies function signatures and eliminates boilerplate warning propagation code.
- **DNS warnings logged at origin**: The DNS module logs warnings (NXDOMAIN, recursion refusal) directly via `warn!` instead of propagating them through events. Truncated (TC) responses are treated as packet loss: the pending entry stays in the map until `handle_tick` queues a retry after `dns_query_timeout`; the query pacing timer performs the send. This follows the "log at origin" principle and simplifies event handling.
- **Structured fields**: Warning logs include structured fields (`prefix`, `interface`, `error`, `host`, etc.) to enable filtering and analysis in log aggregation systems.
- **Test assertions**: Tests use `tracing-test` with `#[traced_test]` and `logs_contain()` to verify that expected warnings are logged.

Unhandled event logging policy:
- **Log at wildcard**: All match statements on event enums (e.g., `ServerH3Event`, `ClientH3Event`, `Event`) must log unhandled variants at `debug!` level instead of silently continuing. This ensures that new event types introduced by library updates (such as `tokio-quiche`) are visible during troubleshooting.
- **Named binding**: Use `other => { debug!(..., event = ?other, ...); }` instead of `_ => continue`. The named binding enables Debug formatting in the log message.
- **Structured context**: Include relevant context fields (e.g., `%remote_addr`, `%peer_id`) to aid debugging.
- **Rationale**: External library enums like `ServerH3Event` and `ClientH3Event` may be `#[non_exhaustive]` or evolve over time. Silent wildcards mask missing handler code that should be added when new variants appear.
- **Log level choice**: `debug!` is chosen over `warn!` because unhandled events like `IncomingSettings` or `StreamClosed` are expected during normal operation and do not indicate hazardous situations (per standard logging conventions from [docs.rs/log](https://docs.rs/log/latest/log/enum.Level.html)).
