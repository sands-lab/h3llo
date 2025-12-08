## Protocol

Protocol overview: HTTP Basic Auth with per-node secrets, HTTP/3 CONNECT-IP as the encrypted default path, BareUDP as an optional fast path, and POST-driven secret/admin rotation plus peer refresh on the shared HTTP path. Runtime connection selection and binding behavior are detailed in `docs/internals.md`.

h3llo uses HTTP Basic Auth for authentication and a subset of MASQUE/CONNECT-IP ([RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)) to encapsulate IP packets and deliver them to peers.

### Authentication

Authentication summary: CONNECT and GET/POST all ride the same HTTP path and require Basic Auth; CONNECT uses the server’s secret copied into the dialer config, while control-plane GET/POST use dedicated admin credentials. HTTP requests do not apply source-IP filtering (unlike BareUDP).

When the HTTP/3 initiator (client) requests the configured HTTP path, the receiver (server) performs HTTP Basic Auth:
- CONNECT-IP: client sends `username = client local.id`, `password = server local.h3.secret`; server checks `username ∈ peers[].id` and `password == local.h3.secret`. Dialing nodes must configure `peers[].h3.secret` (longer than 8 characters) to store the remote server’s `local.h3.secret`; listen-only nodes omit both `peers[].h3.endpoints` and `peers[].h3.secret`.
- Control plane GET/POST (enabled only when both `local.h3.admin.name` and `local.h3.admin.pass` are set, each longer than 8 characters): client sends `username = local.h3.admin.name`, `password = local.h3.admin.pass`; server checks both against its `local.h3.admin`.

On authentication failure, the server requests Basic Auth again. The client waits for a period (default 5 seconds) before attempting to reconnect.

### HTTP/3 Transport (CONNECT-IP)

HTTP/3 summary: h3llo speaks CONNECT-IP over HTTP/3 with datagrams enabled; only mandatory pieces stay to minimize latency and complexity.

Issuing an Extended CONNECT request to h3llo’s HTTP path uses the standard CONNECT-IP protocol to transport IP packets.

h3llo implements only the mandatory pieces of CONNECT-IP:

- connect-ip semantics over HTTP/3
- Context ID (always 0)

h3llo intentionally omits the following optional features from RFC 9484:

- HTTP/2 and HTTP/1.1 fallback: the standard fallback causes TCP-over-TCP, severely degrading latency and throughput.
- All Capsule Types: IP addresses and routes are statically configured, so `ROUTE_ADVERTISEMENT`, `ADDRESS_REQUEST`, and `ADDRESS_ASSIGN` are unnecessary.
- URI template parameters `target` and `ipproto`.

H3 connection management and multipath:
- Dialing set: build one connection for every combination of DNS answer, `peers[].h3.endpoints`, and `peers[].h3.bindifs` when set (auto-detected bindif yields at most one entry when unspecified). Deduplicate endpoints before dialing.
- Preference: no endpoint priority is implied; TUN-Rx prefers the earliest-established connection until it disconnects or is invalidated because the IP left the DNS result set or the interface is not within `bindifs`. New connections join the end of the ordering; warn if more than `10` connections exist for a peer.
- Failures: TLS/handshake failures count as dial failures and retry every `peers[].h3.retry` seconds. Bind failures warn and fall back to unbound sockets, which can risk recursive routing if the system route points to the TUN.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant P as Relay (Server)
    participant N as Target

    %% 1. Establish HTTP/3 connection (QUIC + TLS)
    %% C->>P: QUIC/TLS 1.3 Handshake (ALPN: h3)
    Note over C,P: SETTINGS<br>H3_DATAGRAM = 1

    %% 2. First CONNECT-IP attempt (credentials may be absent)
    C->>P: HEADERS (CONNECT)<br>:method = CONNECT<br>:protocol = connect-ip<br>:scheme = https<br>:authority = node1.example.com<br>:path = /path<br>Capsule-Protocol: ?1<br>Datagram-Format: 1<br>Authorization: ...

    alt Missing or invalid credentials
        %% 3. Server challenges with Basic Auth
        P-->>C: HEADERS<br>:status = 401 Unauthorized<br>WWW-Authenticate: Basic realm="masque"

        %% 4. Client retries CONNECT-IP with Basic Auth
        C->>P: HEADERS (CONNECT)<br>:method = CONNECT<br>:protocol = connect-ip<br>:scheme = https<br>:authority = node1.example.com<br>:path = /path<br>Capsule-Protocol: ?1<br>Datagram-Format: 1<br>Authorization: Basic base64(user:pass)
    end

    %% 5. CONNECT-IP established
    P-->>C: HEADERS<br>:status = 200<br>Capsule-Protocol: ?1<br>Datagram-Format: 1

    %% 7. In-tunnel IP traffic (HTTP Datagrams, Context ID = 0)
    loop IP forwarding
        C-)P: HTTP/3 DATAGRAM<br>Context ID = 0<br>Payload = IP packet (to target)
        P->>N: Forward IP packet to remote network

        N->>P: Return IP packet (from target)
        P-)C: HTTP/3 DATAGRAM<br>Context ID = 0<br>Payload = IP packet (from target)
    end
```

### BareUDP Transport

BareUDP summary: plaintext fast path for trusted networks; not NAT-friendly and requires mutually reachable static IPs. DNS refresh runs on the global timer when enabled; multiple answers are allowed with warnings, filters track the full set, and the first answer becomes the outbound destination.

BareUDP moves IP packets without extra framing: each IP packet read from the TUN becomes the UDP payload sent to the peer’s BareUDP listener, and the listener injects the payload directly into its TUN device. BareUDP only runs when `local.bare.listen` is configured on the node.

- Encapsulation: The sender copies the raw IP packet from the TUN and uses it as the UDP payload to the peer’s `peers[].bare.endpoint`; there is no handshake or session setup. The resolver keeps the full DNS answer set for filtering; outbound chooses the first answer with a warning and rebinds per-interface sockets when the chosen IP changes.
- Receive path: The BareUDP listener accepts the UDP payload and writes it directly to the TUN as an IP packet, without reassembly or additional validation.
- Resolution and binding: The orchestrator resolves BareUDP endpoints before constructing transport sockets; the BareUDP module consumes resolved IPs, binds listener and outbound sockets to the selected WAN interface when available, and logs warnings on binding failures or multi-answer DNS results (first answer used for outbound, full set kept for filtering).
- Security model: BareUDP performs no encryption or authentication. The listener filters by the UDP source IP, dropping packets whose source IP does not match configured BareUDP peer endpoints. Because source IPs can be spoofed, avoid exposing BareUDP to the public Internet and prefer HTTP/3 whenever confidentiality or peer authenticity is required. BareUDP does not attempt NAT traversal.

### Datagram Formats

Datagram format summary: HTTP/3 CONNECT-IP wraps inner IP packets in QUIC DATAGRAM frames with Context ID 0; BareUDP sends the inner IP packet as the UDP payload with only the outer IP/UDP headers.

#### HTTP/3 CONNECT-IP Datagram Layout

CONNECT-IP over HTTP/3 uses QUIC DATAGRAM frames with Context ID set to `0`; no additional MASQUE headers or capsules are present.

[Outer IP Header; (v4)20B/(v6)40B]
[Outer UDP Header; 8B]
[QUIC Short Header; 2-25B]
[QUIC Datagram Frame Header; 1-9B]
[H3 Datagram Header (Context ID); 1-8B]
[Inner IP Packet]

- Outer IP header: IPv4 is 20 bytes; IPv6 is 40 bytes.
- Outer UDP header: always 8 bytes.
- QUIC Short header: 2-25 bytes depending on connection ID length, packet number length, and spin/reserved bits.
- QUIC DATAGRAM frame header: 1-9 bytes depending on length encoding and whether DATAGRAM length is present.
- H3 datagram header: MASQUE Context ID varint; Context ID `0` encodes to a single byte (`0x00`).
- Payload: the inner IP packet read from the TUN (IPv4 or IPv6).

#### BareUDP Datagram Layout

BareUDP sends the inner IP packet directly as the UDP payload; there is no QUIC or MASQUE framing.

[Outer IP Header; (v4)20B/(v6)40B]
[Outer UDP Header; 8B]
[Inner IP Packet]

- Outer headers: IPv4 is 20 bytes; IPv6 is 40 bytes; UDP is 8 bytes.
- Payload: raw IP packet from the TUN; the receiver injects it unchanged into the local TUN.

#### MTU Guidance

MTU summary: pick the lowest MTU across transports using IPv4/IPv6 figures per endpoint’s resolved family; default `1410` is safe for IPv6 CONNECT-IP, IPv4-only CONNECT-IP can go higher, BareUDP-only can go higher still, and mixed H3/BareUDP should stick to the H3 lower bound.

- CONNECT-IP overhead: 20/40 (outer IP) + 8 (UDP) + 25 (max QUIC Short) + 9 (max DATAGRAM frame) + 8 (max H3 datagram Context ID) = 70/90 bytes.
    - With WAN MTU 1500: TUN MTU up to 1500 - 70 = 1430 (IPv4) and 1500 - 90 = 1410 (IPv6).
- BareUDP overhead: 20/40 (outer IP) + 8 (UDP) = 28/48 bytes.
    - with WAN MTU 1500 and only BareUDP peers: TUN MTU up to 1472 (IPv4) and 1452 (IPv6).

Address family: the IPv4/IPv6 values above depend on the resolved address family of each endpoint; use the IPv4 numbers for IPv4 endpoints and the IPv6 numbers for IPv6 endpoints, then pick the lowest applicable MTU across peers.

### Dynamic Reconfiguration

Reconfiguration summary: `GET` returns the current configuration, and `POST` accepts `peers` updates plus `local.h3.secret` and `local.h3.admin` updates applied atomically; control-plane endpoints exist only when both `local.h3.admin.name` and `local.h3.admin.pass` are configured alongside `local.h3.listen`.

Control-plane endpoints are available only when `local.h3.admin` is configured alongside `local.h3.listen`.

`GET https://node1.example.com:443/path` returns the full configuration snapshot in YAML, matching the shape documented in `docs/configuration.md`, and requires Basic Auth with `username = local.h3.admin.name` and `password = local.h3.admin.pass`.

`POST https://node1.example.com:443/path` accepts YAML containing `local.h3.secret`, `local.h3.admin` (with nested `name` and `pass`), and `peers` (merged by `peers[].id`). All other top-level keys are rejected with `400 Bad Request`. Basic Auth is mandatory on the same HTTP path; set `username = local.h3.admin.name` and `password = local.h3.admin.pass`.

Update rules:
- `local.h3.secret` must be longer than 8 characters when HTTP/3 is enabled; updates take effect for subsequent Basic Auth challenges, and existing connections must reconnect to use the new credential.
- `local.h3.admin` updates take effect immediately for new control-plane requests; set both `name` and `pass` together, each longer than 8 characters.
- `peers` merges entries by `peers[].id`; optional fields not present stay unchanged. Transport exclusivity (exactly one of `peers[].h3` or `peers[].bare`) still applies after the merge.
- Use `null` to remove optional transport blocks (`peers[].h3` or `peers[].bare`); other fields clear only when explicitly overwritten.
- Route refresh is zero-downtime: internal route tables update atomically; existing traffic to removed peers drains naturally; system route updates are applied without intentional interruption but may not be atomic.
- If an update payload includes `peers[].h3.endpoints` or `peers[].h3.bindifs`, h3llo deduplicates endpoints, re-resolves DNS, and rebuilds the full connection set across DNS answers, endpoints, and provided bindifs (auto-detected bindif yields at most one entry when unspecified). Existing traffic keeps flowing until new connections are ready; TUN traffic then follows the earliest-established valid connection.
- If an update payload includes `peers[].bare.endpoint` or DNS refresh changes its answers, the BareUDP source-IP filter refreshes with the full answer set, warns when multiple answers exist, picks the first for outbound, and re-probes interfaces and sockets when the chosen IP changes.
- `POST` payloads containing top-level keys outside `local` (with only `h3.secret` / `h3.admin`) and `peers` are rejected with `400 Bad Request`.

Examples:
```yaml
# GET returns the current configuration
local:
  id: example-node-1
  ...
peers:
- id: example-node-2
  ...

# POST: rotate the data-plane secret
local:
  h3:
    secret: new-secret-123

# POST: rotate admin credentials
local:
  h3:
    admin:
      name: new-admin-name
      pass: new-admin-pass

# POST partial update: disable a peer
peers:
- id: example-node-1
  enabled: false

# POST partial update: enable H3 with custom trust
peers:
- id: example-node-1
  enabled: true
  h3:
    secret: peer-secret-123
    retry: 10
    endpoints:
      - https://node1.example.com:443/path
    ca: ./ca.pem
    insecure: false

# POST partial update: switch to BareUDP (null clears H3)
peers:
- id: example-node-1
  enabled: true
  h3: null
  bare:
    endpoint: udp://node1.example.com:6635
    # bindif: eth0
```
