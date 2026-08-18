## Performance

Performance overview: h3llo applies a layered optimization strategy — thread-per-core runtime, kernel offload (GSO/GRO), zero-copy buffer pooling, batch channel transmission, and allocator tuning — to minimize per-packet overhead across both BareUDP and HTTP/3 data planes. This page documents the design rationale, implementation techniques, and measured results behind each optimization.

### Benchmark Summary

All benchmarks run on mcnode27 ↔ mcnode26, bf3p1 NIC (NUMA node 3), `iommu=pt`, MTU 1291, `iperf3 -t 10` TCP. VPNs pinned to 4 NUMA-local cores (CPUs 48–51), iperf3 on CPU 52. NIC hardware offload (`tx-udp-segmentation`, `rx-gro-hw`) enabled via `ethtool -K`.

| Solution | Forward | Reverse | Cores | Encryption |
|----------|---------|---------|-------|------------|
| h3llo BareUDP | 11.9 Gbps | 8.91 Gbps | 4 | None |
| h3llo H3 (cc=none) | 5.56 Gbps | 5.60 Gbps | 4 | AES-GCM (QUIC/TLS) |
| wireguard-go | 11.7 Gbps | — | 4 | ChaCha20-Poly1305 |
| Kernel WireGuard | 3.44 Gbps | — | 1 | ChaCha20-Poly1305 |
| OpenVPN DCO | 1.57 Gbps | — | — | AES-256-GCM |

In this MTU 1291 benchmark set, h3llo H3 (cc=none) delivers 1.62× the forward TCP throughput of kernel WireGuard while retaining full QUIC/TLS encryption. BareUDP mode reaches near line-rate on a 10 GbE NIC.

### Thread-per-Core Runtime

h3llo dedicates one OS thread per data-plane function using multiple single-threaded Tokio runtimes (`current_thread`). Each runtime owns a disjoint set of actors, eliminating cross-thread synchronization on the hot path.

| Thread | Name | Actors |
|--------|------|--------|
| TUN | `h3llo-tun` | TUN RX, TUN TX |
| Crypto | `h3llo-crypto` | Router, H3 dispatcher, H3 engines (QUIC crypto + session + datagram forwarding) |
| UDP | `h3llo-udp` | UDP RX/TX (BareUDP and H3 transport) |
| Main | `h3llo` | Orchestrator, DNS, Route Sync, API |

Key design choices:

- **Co-locate H3 dispatcher and engines with router on `crypto_rt`**: the router dispatches packets directly to each H3 engine's TX channel, and inbound QUIC CID routing plus CONNECT-IP session state stay on the same thread. This eliminates a cross-thread hop for routed packets and keeps QUIC control/data-plane state together.
- **Isolate UDP I/O on `udp_rt`**: kernel `sendmsg`/`recvmmsg` syscalls are the dominant cost in the UDP thread (see [profiling data](#profiling-insights)); isolating them prevents syscall latency from blocking TUN or crypto processing.
- **Control plane on main thread**: orchestrator, DNS, and API are low-frequency; sharing the main thread avoids wasting a core.

`ActorBus` owns every runtime and drives supervision. Actors spawn tasks through `ActorContext::spawn`, selecting a runtime explicitly and automatically propagating the context's owner; `ActorContext::run_on()` executes runtime-bound I/O initialization on the selected runtime without exposing its handle.

Profiled CPU distribution (BareUDP, 9.37 Gbps bidirectional, 4 cores):

| Thread | FWD CPU% | REV CPU% |
|--------|----------|----------|
| h3llo-tun | 67% | 102% (saturated) |
| h3llo-udp | 62% | 91% |
| h3llo-crypto (router) | 14% | 19% |
| h3llo (main) | 1% | 1% |

### GSO/GRO Batch I/O

Generic Segmentation Offload (GSO) and Generic Receive Offload (GRO) amortize per-packet syscall and kernel-stack overhead by batching multiple packets into single system calls.

#### UDP GSO (TX)

The UDP TX actor (`src/udp.rs:spawn_udp_tx`) concatenates same-sized packets into a contiguous buffer and sends them via a single `sendmsg` with `UDP_SEGMENT` (GSO). The kernel (or NIC hardware when `tx-udp-segmentation` is enabled) splits the buffer back into individual UDP datagrams.

- Packets are grouped by size into consecutive runs (mixed sizes trigger a batch break).
- Each batch is capped at `max_gso_segments()` packets (typically 64 on Linux) and `65507 / segment_size` to avoid exceeding the IP+UDP payload limit.
- When GSO is unavailable (`max_gso_segments() == 1`), the path degrades to per-packet sends with no code changes.

Both BareUDP and H3 transport share this actor.

#### UDP GRO (RX)

The UDP RX actor (`src/udp.rs:spawn_udp_rx`) allocates a buffer sized for `max_udp_payload × gro_segments` and calls `recv()` once. quinn-udp unconditionally enables `UDP_GRO` on the socket, so the kernel (or NIC) coalesces multiple incoming datagrams into a single buffer. The actor then chunks the buffer by the stride reported by quinn-udp and allocates individual `PooledBuf`s.

#### TUN GSO/GRO

When `tuning.tun_enable_offload` is true, TUN I/O uses tun-rs batch APIs with `virtio_net_hdr` metadata:

- **TUN RX**: `recv_multiple()` reads up to `IDEAL_BATCH_SIZE` packets per syscall with GSO metadata. tun-rs performs software GSO splitting (including TCP/UDP checksum recomputation) to produce individual IP packets.
- **TUN TX**: `send_multiple()` writes a batch of packets with GRO coalescing. tun-rs aggregates same-flow packets via its `GROTable` before handing them to the kernel in a single write, reducing TUN write syscalls.

TUN offload is disabled by default (`tun_enable_offload: false`) due to compatibility issues with certain kernel versions and virtualization layers. When enabled, it adds software checksum overhead (~3–6% CPU in profiling) but reduces syscall count significantly.

#### H3 GSO/GRO

The current H3 transport uses the same shared UDP actors as BareUDP rather than a separate tokio-quiche socket wrapper. As a result, H3 offload behavior matches the generic UDP actor semantics:

- **H3 TX**: `tuning.udp_enable_offload` controls GSO segment count, exactly like BareUDP TX.
- **H3 RX**: GRO follows the socket's actual capability; quinn-udp enables `UDP_GRO` during socket state initialization, and the receive buffer is always sized for `gro_segments()`.

#### NIC Hardware Offload

Software GSO/GRO can be further accelerated by NIC hardware offload. When `tx-udp-segmentation` and `rx-gro-hw` are enabled via `ethtool -K`, the NIC performs segmentation and coalescing in hardware, eliminating kernel `skb_segment` overhead. Measured impact on BareUDP: +72% throughput (6.92 → 11.9 Gbps forward). H3 mode is unaffected because its bottleneck is in the QUIC layer, not kernel UDP processing.

### Zero-Copy Buffer Pool

Data-plane buffers are allocated from two h3llo-owned static `buffer-pool` instances and reused across the packet lifecycle. The pool has two tiers: a 1.5 KB datagram pool (64K retained entries) for typical packets, and a 64 KB generic pool (64 retained entries) for oversized payloads.

#### Headroom Layout

Every data-plane `PooledBuf` reserves 10 bytes of prepend space at the front:

```
[ 10B prepend space ][ packet payload ]
 └── reserved directly by h3llo's packet allocator
```

This prepend space enables zero-copy operations at two points:

- **H3 TX**: `ConnectIpDatagramCodec::prepend()` prepends `QSI varint + Context ID` in-place. In the current one-CONNECT-stream-per-connection design, that prefix is 2 bytes (`QSI=0` + `Context ID=0`), leaving ample prepend space.
- **TUN TX**: `TunBuf::prepend_hdr()` prepends a zeroed 10-byte `virtio_net_hdr` via `add_prefix`, also using prepend space. A compile-time assertion (`HEADROOM >= VIRTIO_NET_HDR_LEN`) guards this invariant.

H3 RX uses `ConnectIpDatagramCodec::strip()` to remove the full CONNECT-IP DATAGRAM prefix (`qsi_len + 1`) in-place, restoring prepend space for the downstream TUN TX path.

#### Size-Aware Dual-Pool Allocation

`alloc_uninit_packet_buf(length)` selects the smallest pool that fits:

- Packets where `length + HEADROOM ≤ MAX_DGRAM_SIZE` (1500): allocated from the **datagram pool** (1.5 KB per buffer, 64K total entries).
- Larger payloads: allocated from the **generic pool** (64 KB per buffer, 64 total entries).

Typical IP packets (≤ MTU 1291) always land in the datagram pool, reducing per-packet memory by ~97% compared to unconditionally using the 64 KB pool.

#### TunBuf GRO Extend and Pool Upgrade

`TunBuf` (`src/tun.rs`) wraps a `PooledBuf` to provide TUN-specific zero-copy semantics:

- `TunBuf::alloc_uninit(mtu)` allocates from the datagram pool with headroom, ready for kernel `recv`.
- `into_pooled(len)` truncates to the actual received length and unwraps the inner `PooledBuf` — zero-copy from kernel to packet channel.
- `prepend_hdr()` prepends the `virtio_net_hdr` using headroom; it falls back to alloc+copy only for externally constructed buffers without headroom.

When TUN GRO is enabled, tun-rs coalesces same-flow packets by extending a `TunBuf` via the `ExpandBuffer` trait. This creates a tension: individual packets are allocated from the small 1.5 KB datagram pool for memory efficiency, but GRO coalescing can grow a buffer well beyond that size (up to ~65535 bytes for a full GSO super-packet).

`TunBuf::buf_extend()` resolves this with a **one-shot pool upgrade**: when an extend operation would cross the `MAX_DGRAM_SIZE` threshold, it allocates a 64 KB buffer from the generic pool, copies the existing data once, and replaces the underlying `PooledBuf`. Subsequent extends operate on the large buffer without further reallocation. If the buffer is already in the generic pool or the extend stays within the datagram pool's capacity, no upgrade occurs.

`buf_capacity()` returns `usize::MAX`, telling tun-rs GRO that coalescing is always possible (capped externally by IP total length ~65535). This maximizes coalescing without artificial limits from pool sizing.

#### Allocation Paths

| Data path | Allocation | Zero-copy? |
|-----------|-----------|------------|
| TUN RX → channel | `TunBuf::alloc_uninit` → kernel fills → `into_pooled` | Yes |
| H3 TX encoding | `ConnectIpDatagramCodec::prepend` consumes prepend space | Yes |
| TUN TX writing | `TunBuf::prepend_hdr` consumes headroom | Yes |
| QUIC DATAGRAM extraction | `dgram_recv` fills `alloc_uninit_packet_buf` | Yes |
| H3 RX decoding | `ConnectIpDatagramCodec::strip` removes QSI + Context ID | Yes |
| UDP socket RX | `alloc_packet_buf` splits the shared GRO receive buffer | Copy once |

### Batch Channel Transmission

Data-plane channels carry `Vec<PooledBuf>` batches rather than individual packets. Each channel message represents one device I/O operation's worth of packets (a TUN `recv_batch`, BareUDP GRO recv, or H3 datagram drain). This reduces per-packet atomic operations from N to 1 per batch.

Channels use `mpsc::channel::<Vec<PooledBuf>>(packet_queue_depth)` with a default depth of 256. `packet_queue_depth` counts batch messages, not individual packets. Bounded channels provide backpressure: when a consumer falls behind, the producer blocks rather than buffering unboundedly.

The router (`src/router.rs`) splits ingress batches by destination IP into consecutive groups, performs one LPM lookup per group, decrements TTL / hop limit per packet (with RFC 1624 incremental checksum for IPv4), and forwards each group as a `Vec<PooledBuf>` to the appropriate peer TX channel.

### Allocator Tuning (mimalloc)

On musl targets (the Docker image uses static musl linking), h3llo replaces the default musl allocator with mimalloc via `#[global_allocator]`. musl's built-in allocator has poor multi-threaded performance; mimalloc provides thread-local heaps with minimal contention.

Configuration:

- `features = ["override"]` — no debug feature. Removing the debug feature eliminated `mi_check_padding` validation and yielded a +21% throughput improvement (3.90 → 4.73 Gbps in H3 mode), far exceeding the ~1% CPU reduction visible in perf profiles. The disproportionate gain is attributed to debug validation destroying memory locality in the hot path, causing icache/dcache pressure.
- `MIMALLOC_PURGE_DELAY=0` (set via Dockerfile env var) — aggressively returns freed pages to the OS, preventing RSS amplification under bursty allocation patterns.

### Upstream Patches

h3llo patches quiche-family crates to [`Tonny-Gu/quiche:master`](https://github.com/Tonny-Gu/quiche/tree/master) and directly pins `buffer-pool` to [`Tonny-Gu/quiche:remove-pooled-buf-metrics`](https://github.com/Tonny-Gu/quiche/tree/remove-pooled-buf-metrics). These forks provide two performance-critical changes:

#### buffer-pool Prometheus Removal

The upstream `buffer-pool` crate updates Prometheus metrics (via `foundations` → `prometools`) on every buffer acquire and release — 6 `HashMap` lookups with SipHash per packet. Profiling showed this cost 5–15% CPU depending on the thread, with cache pollution effects far exceeding the direct CPU cost.

The patch removes `foundations`/`prometools` dependencies from `buffer-pool` entirely. Measured impact: +18% FWD / +28% REV throughput in H3 mode (4.73 → 5.56 / 4.37 → 5.60 Gbps).

#### Congestion Control "none" Algorithm

The patch adds a "none" congestion control algorithm to quiche, which disables QUIC-level congestion control. For overlay networks, congestion control is redundant — the inner TCP flows already perform their own congestion management, and the outer QUIC layer adds unnecessary throttling. Default: `h3_cc_algorithm: "none"`.

### Socket and TUN Tuning

- **`socket_buffer_size`** (default 16 MiB): applied to all UDP sockets via `SO_RCVBUF`/`SO_SNDBUF`. Large buffers absorb burst traffic and reduce `UdpRcvbufErrors` under load. The effective size may be clamped by `net.core.rmem_max`/`net.core.wmem_max`.
- **`tun_tx_queue_len`** (default 1000): kernel transmit queue length for the TUN interface. Profiling found that `qd=2048, txq=2048` is optimal for balanced bidirectional throughput with zero retransmits; higher values induce bufferbloat.
- **`packet_queue_depth`** (default 256): bounded channel capacity between actors. Counts batch messages, not individual packets.

### Profiling Insights

Key findings from `perf record` profiling on the BareUDP and H3 data planes.

#### CPU Budget Breakdown (BareUDP, dominant hotspots by direction)

| Path | CPU% | Notes |
|------|------|-------|
| Forward TX `sendmsg` / UDP GSO | ~30% | `__x64_sys_sendmsg` → `udp_sendmsg` → `skb_segment` → driver |
| Reverse RX `recvmmsg` / copy | ~18% | `_copy_to_iter` is the single largest kernel hotspot (9.6%) |
| Reverse RX TUN write | ~17% | `tun_get_user` → skb build → `netif_receive_skb` (re-traverses stack) |
| Userspace memcpy | 6–10% | Packet data copy between pool buffers and syscalls |
| TUN checksum (GSO/GRO) | 3–6% | `checksum_no_fold_avx2` for software GSO split / GRO |
| Spectre SRSO mitigation | ~2% | `srso_alias_return_thunk` + `srso_alias_safe_ret` (AMD) |

#### H3 (cc=none): quiche as the Primary Bottleneck

The `h3llo-crypto` thread — which runs the quiche QUIC engine (AES-GCM encryption, protocol logic, datagram send/recv) — is the saturated bottleneck for H3 throughput. It consumes 49.3% of total CPU, far exceeding other threads (`h3llo-udp` 36.6%, `h3llo-tun` 14.0%). H3 throughput is capped by this single thread's processing capacity.

Evidence:

- **NIC hardware offload has no effect on H3**: 5.51/5.45 Gbps with or without `tx-udp-segmentation`/`rx-gro-hw`. The bottleneck is in the QUIC layer, not kernel UDP processing.
- **BareUDP vs H3 gap**: BareUDP reaches 11.9 Gbps on the same hardware; the ~2× gap is entirely the cost of quiche (AES-GCM encryption + QUIC protocol + per-packet allocation).
- **`dgram_send` per-packet malloc**: quiche's `dgram_send(&[u8])` calls `buf.to_vec()` internally, allocating a new `Vec` and copying the entire packet for every datagram. This bypasses h3llo's buffer pool and adds ~2% CPU plus allocator pressure (`memset` 1.9% for zero-fill).
- **Microbenchmark confirms theoretical ceiling**: a loopback `dgram_send` → `conn.send()` benchmark (no network I/O, single core, AES-NI) measures the raw QUIC DATAGRAM encryption throughput:

  | MAX_UDP_PAYLOAD | Payload | pps | Throughput |
  |-----------------|---------|-----|-----------|
  | 1350 (TUN MTU 1291) | 1291B | 574K | 5.93 Gbps |
  | 1409 (TUN MTU 1350) | 1350B | 565K | 6.00 Gbps |

  h3llo's measured 5.56 Gbps is **94% of the 5.93 Gbps single-core ceiling** at default MTU, leaving little room for further optimization without changes to quiche itself or multi-core encryption.

Crypto thread CPU breakdown (after all optimizations):

| Category | self% | Key functions |
|----------|-------|---------------|
| AES-GCM encryption | ~11.6% | `_aesni_ctr32_ghash_6x`, `aead_seal`, `aesni_gcm_encrypt` |
| quiche protocol logic | ~8.3% | `send_single`, `recv_single`, `on_ack_received` |
| memcpy | ~6.8% | 1.8% from `CRYPTO_gcm128_encrypt_ctr32`, rest from quiche packet assembly |
| vDSO clock | ~1.4% | `clock_gettime` timestamps in crypto path |

#### Cumulative Optimization Impact (H3 mode)

| Step | Throughput | Gain |
|------|-----------|------|
| Baseline (no offload, no NUMA pin) | 1.44 Gbps | — |
| + GSO/GRO offload + NUMA pinning | 3.90 Gbps | +171% |
| + Remove mimalloc debug feature | 4.73 Gbps | +21% |
| + Remove buffer-pool Prometheus | 5.56 Gbps | +18% |
| **Cumulative** | **5.56 Gbps** | **+286%** |

#### Inherent Overhead: TUN User-Kernel Boundary

Every packet in a TUN-based VPN crosses the user-kernel boundary twice (recv from transport socket + write to TUN), and TUN write re-traverses the entire kernel networking stack. On the receiver, each data packet is copied 3 times:

1. NIC DMA → kernel skb (hardware, near-zero CPU)
2. kernel skb → userspace buffer (`_copy_to_iter` in `recvmmsg`, 9.6%)
3. userspace buffer → kernel skb (`_copy_from_iter` in TUN write, 2.7%)

This ~12% copy overhead is inherent to the TUN architecture. Eliminating it would require XDP/AF_XDP or kernel-side splicing — listed as future work.

### Remaining Bottlenecks

| Bottleneck | Impact | Potential fix |
|------------|--------|--------------|
| `_copy_to_iter` in `recvmmsg` | ~10% CPU (receiver) | Different RX architecture (for example AF_XDP / kernel-bypass receive path) |
| TUN write re-injection | ~17% CPU (receiver) | vhost-net / kernel TUN splice |
| `dgram_send` per-packet `to_vec()` in quiche | ~2% CPU + alloc pressure | Upstream quiche API change |
| TUN checksum (software GSO/GRO) | 3–6% CPU | Verify kernel handles checksums when offload enabled |
| Spectre SRSO (AMD) | ~2% CPU | `spec_rstack_overflow=off` (trusted environments) |
| `CONFIG_HARDENED_USERCOPY` | ~2% CPU | Kernel rebuild with `=n` (trusted environments) |
