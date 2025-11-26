## Internals

Internals overview: runtime dependencies, guards against recursive routing and DNS resolution loops, coroutine layout for packet flow, route update strategy, and longest-prefix matching.

### Dependencies

h3llo primarily depends on tun-rs and Cloudflare's tokio-quiche.

### Recursive Routing and DNS Resolution

Recursive routing and DNS resolution summary: probe WAN-facing interfaces while excluding the TUN for both the DNS resolver and each resolved endpoint IP; bind per-transport sockets (HTTP/3, BareUDP, DNS) to the matching interface to avoid tunneling loops.

Because h3llo can redirect the default route into the TUN, outbound sockets might otherwise loop back through the tunnel. h3llo avoids this by consistently probing interfaces and binding sockets per destination.

Binding workflow for HTTP/3, BareUDP, and DNS:
1. Probe the default route to `local.dns` (e.g., `ip route show match <local.dns>`) excluding the TUN to pick the WAN-facing interface for DNS.
2. Bind a DNS UDP socket to that interface via `SO_BINDTODEVICE`, `IP_UNICAST_IF`, or `IP_BOUND_IF`, then resolve peer endpoints through `local.dns` (default `1.1.1.1`). BareUDP only accepts a single IP and panics on multiple answers; HTTP/3 keeps the first IP. DNS rotation only happens when reconnects trigger re-resolution.
3. For each endpoint IP, probe the WAN-facing interface (e.g., `ip route show match <endpoint IP>`) excluding the TUN; bind each transport socket to that interface with the same method. Every HTTP/3 connect or reconnect re-resolves before binding its QUIC UDP socket to the chosen IP; each BareUDP socket binds per endpoint. Transport sockets stay separate from the DNS socket and from each other.

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

        ctrl1["External Controller"]

        subgraph crc["Coroutine"]
            hh1[H3 POST Handler]
        end

    prog1 <--> r2 <--> tun1
    tun1 --> tr1 --> r1 --> hw1 --> wan1 --> hr1 --> q1 --> tw1 --> tun1
    
    ctrl1 -. update peers and route -.-> hh1 -.-> q2 -.-> r1 -. sync -.-> r2
```

h3llo uses the tokio runtime to schedule coroutines and should rely on MPSC queues instead of locks to reduce async complexity, since MPSC queues explicitly linearize async operations.

Spawn a coroutine for every I/O reader to drive the program. With multiple peers, each HTTP/3 connection should own its read coroutine.

When configuration changes arrive (external controller POST or initialization), update the internal routing table first, then the system routing table. Connecting to new peers should establish HTTP/3 connections and spawn coroutines to receive datagrams from those connections.

During packet forwarding, look up the target peer’s HTTP/3 connection via the internal routing table. Enqueue received IP packets into Coroutine 2’s MPSC queue to keep TUN writes thread-safe.

Key flows:

- TUN Reader → internal route table lookup → H3/Bare datagram writer.
- H3/Bare datagram reader → queue → TUN Writer.
- Controller updates → internal routes → system routes.

### System Route Updates

Route update summary: replace per-route entries with platform commands while keeping traffic uninterrupted. Typical commands: `ip route replace` on Linux, `route -n add -net` / `route -n change` on Darwin, and `netsh interface ipv4 add route` on Windows.

h3llo should update individual routes without interruptions by executing platform commands best-effort: failures are logged as warnings and processing continues. If the platform lacks a usable route update mechanism, h3llo panics.

### Longest-Prefix-Match Algorithm

LPM summary: reuse WireGuard’s longest-prefix-match behavior when choosing peers for IP packets.

h3llo should use the same longest-prefix-match algorithm as WireGuard when matching entries in the internal routing table.
