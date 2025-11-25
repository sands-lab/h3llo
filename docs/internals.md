## Internals

Internals overview: runtime dependencies, guards against recursive routing, coroutine layout for packet flow, route update strategy, longest-prefix matching, and DNS cache servicing (TBD).

### Dependencies

h3llo primarily depends on tun-rs and Cloudflare's tokio-quiche.

### Recursive Routing

Recursive routing summary: bind HTTP/3 dialer sockets to the WAN interface so default-route changes do not loop connections back into the TUN.

Because h3llo takes over the system routing table and switches the default route so that all outbound traffic goes to the TUN interface, HTTP/3 connections to peers might be routed back into the TUN instead of out the WAN interface—i.e., a recursive routing problem.

h3llo prevents this by forcing the UDP socket used by the HTTP/3 dialer to bind to the WAN interface. This should work on Linux, Darwin, and Windows.

Whenever an HTTP/3 connection (or reconnection) is created, h3llo should:

1. Resolve and cache endpoint hostnames; refresh immediately on expiry to ride out transient network loss, and pre-resolve before switching the default route.
2. Probe the WAN interface name (for example, `ip route show match <ip>`) to find the original egress interface while excluding the TUN.
3. Bind the HTTP/3 UDP socket to that WAN interface via `SO_BINDTODEVICE`, `IP_UNICAST_IF`, or `IP_BOUND_IF`.

### Thread Model

Thread model overview: h3llo schedules a coroutine per I/O source (TUN, each HTTP/3 connection, BareUDP endpoint) and uses MPSC queues to serialize cross-component communication; configuration updates flow from the controller into routing tables before affecting system routes.

```mermaid
flowchart TB

        wan1[WAN Interface]@{shape: h-cyl}
        tun1[TUN Interface]@{shape: h-cyl}
        prog1[Programs]@{shape: processes}
        r2[/System<br>Route Table\]
        
        
            

        subgraph cr1["Coroutine 1"]
            tr1[TUN Reader]
            q2[MPSC Queue]@{shape: h-cyl}
            r1[/Internal<br>Route Table\]
            hw1[H3/Bare Datagram Writer]@{shape: st-rect}
        end

        subgraph cr4["Coroutine 3...n+2"]
            hr1[H3/Bare Datagram Reader]@{shape: st-rect}
        end

        subgraph cr2["Coroutine 2"]
            q1[MPSC Queue]@{shape: h-cyl}
            tw1[TUN Writer]
        end

        subgraph cra[Coroutine A]
            q3[MPSC Queue]@{shape: h-cyl}
            dns1[DNS Cache]@{shape: lin-cyl}
        end

        subgraph crb["Coroutine B"]
            t1[Timer]
        end

        ctrl1["External Controller"]

        subgraph crc["Coroutine C"]
            hh1[H3 POST Handler]
        end

        

    prog1 <--> r2 <--> tun1
    tun1 --> tr1 --> r1 --> hw1 --> wan1 --> hr1 --> q1 --> tw1 --> tun1
    
    ctrl1 -. update peers and route -.-> hh1 -.-> q2 -.-> r1 -. sync -.-> r2
    t1 -. update DNS records -.-> q3 -.-> dns1
    dns1 -. update bareudp endpoint -.-> q2

```

h3llo uses the tokio runtime to schedule coroutines and should rely on MPSC queues instead of locks to reduce async complexity, since MPSC queues explicitly linearize async operations.

Spawn a coroutine for every I/O reader to drive the program. With multiple peers, each HTTP/3 connection should own its read coroutine.

When configuration changes arrive (external controller POST or initialization), update the internal routing table first, then the system routing table. Connecting to new peers should establish HTTP/3 connections and spawn coroutines to receive datagrams from those connections.

During packet forwarding, look up the target peer’s HTTP/3 connection via the internal routing table. Enqueue received IP packets into Coroutine 2’s MPSC queue to keep TUN writes thread-safe.

Key flows:

- TUN Reader → internal route table lookup → H3/Bare datagram writer.
- H3/Bare datagram reader → queue → TUN Writer.
- Controller updates → internal routes → system routes.

See DNS cache service for resolver behavior.

### System Route Updates

Route update summary: replace per-route entries with platform commands while keeping traffic uninterrupted.

h3llo should update individual routes without interruptions by executing system commands—such as `ip route replace` on Linux—and provide a simple cross-platform abstraction.

### Longest-Prefix-Match Algorithm

LPM summary: reuse WireGuard’s longest-prefix-match behavior when choosing peers for IP packets.

h3llo should use the same longest-prefix-match algorithm as WireGuard when matching entries in the internal routing table.

### DNS Cache Service (TBD)

DNS cache summary: a coroutine maintains endpoint resolution in the background; cache invalidation and negative caching specifics are pending.

- Handles timer-driven refresh events via an MPSC queue.
- Responds to resolution requests from the coroutine that sets up HTTP/3 connections.
- TBD: cache invalidation strategy, negative cache lifetime, and pre-resolution timing before default-route changes.
