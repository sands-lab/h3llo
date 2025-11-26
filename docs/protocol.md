## Protocol

Protocol overview: HTTP Basic Auth with ID pairs, HTTP/3 CONNECT-IP as the encrypted default path, BareUDP as an optional fast path (details TBD), and POST-driven peer refresh on the HTTP path.

h3llo uses HTTP Basic Auth for authentication and a subset of MASQUE/CONNECT-IP ([RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)) to encapsulate IP packets and deliver them to peers.

### Authentication

Authentication summary: clients present `id` pairs via HTTP Basic Auth on the configured path; servers validate the client ID and the expected server ID before allowing CONNECT-IP.

When the HTTP/3 initiator (client) requests the configured HTTP path, the receiver (server) performs HTTP Basic Auth. The client sends its own ID as the username and the server’s ID as the password, and the server validates both.

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
    C->>P: HEADERS (CONNECT)<br>:method = CONNECT<br>:protocol = connect-ip<br>:scheme = https<br>:authority = node1.example.com<br>:path = /path/<br>Capsule-Protocol: ?1<br>Datagram-Format: 1<br>Authorization: ...

    alt Missing or invalid credentials
        %% 3. Server challenges with Basic Auth
        P-->>C: HEADERS<br>:status = 401 Unauthorized<br>WWW-Authenticate: Basic realm="masque"

        %% 4. Client retries CONNECT-IP with Basic Auth
        C->>P: HEADERS (CONNECT)<br>:method = CONNECT<br>:protocol = connect-ip<br>:scheme = https<br>:authority = node1.example.com<br>:path = /path/<br>Capsule-Protocol: ?1<br>Datagram-Format: 1<br>Authorization: Basic base64(user:pass)
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

### BareUDP Transport (TBD)

BareUDP summary: plaintext fast path for trusted networks; mechanics are pending.

BareUDP moves IP packets without extra framing: each IP packet read from the TUN becomes the UDP payload sent to the peer’s BareUDP listener, and the listener injects the payload directly into its TUN device. BareUDP only runs when `local.bare.listen` is configured on the node.

- Encapsulation: The sender copies the raw IP packet from the TUN and uses it as the UDP payload to the peer’s `peers[].bare.endpoint`; there is no handshake or session setup.
- Receive path: The BareUDP listener accepts the UDP payload and writes it directly to the TUN as an IP packet, without reassembly or additional validation.
- Security model: BareUDP performs no encryption or authentication. The listener filters by the UDP source IP, dropping packets whose source IP does not match configured BareUDP peer endpoints. Because source IPs can be spoofed, avoid exposing BareUDP to the public Internet and prefer HTTP/3 whenever confidentiality or peer authenticity is required.

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

MTU summary: worst-case CONNECT-IP overhead is 70 bytes (IPv4) / 90 bytes (IPv6), yielding TUN MTU up to 1430 / 1410 when the WAN MTU is 1500; BareUDP overhead is 28 / 48 bytes, so TUN MTU can reach 1472 / 1452 without H3 peers.

- CONNECT-IP overhead: 20/40 (outer IP) + 8 (UDP) + 25 (max QUIC Short) + 9 (max DATAGRAM frame) + 8 (max H3 datagram Context ID) = 70/90 bytes.
- With WAN MTU 1500: TUN MTU up to 1500 - 70 = 1430 (IPv4) and 1500 - 90 = 1410 (IPv6).
- BareUDP overhead: 20/40 (outer IP) + 8 (UDP) = 28/48 bytes; with WAN MTU 1500 and only BareUDP peers, TUN MTU up to 1472 (IPv4) and 1452 (IPv6).

### Dynamic Reconfiguration

Reconfiguration summary: POST-only peer refreshes apply atomically to internal routes first, then update system routes without dropping active traffic.

POSTing to h3llo’s HTTP path with a YAML body containing only the `peers` key refreshes peers and routes (both system and h3llo internal routes).

Dynamic reconfiguration targets zero downtime: internal route updates are atomic and affect all subsequent packets; existing connections for removed peers drain naturally instead of being actively closed. System route updates are not guaranteed to be atomic but are applied without intentional interruption.
