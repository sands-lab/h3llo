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

h3llo H3 (cc=none) is 2.15× faster than kernel WireGuard with full QUIC/TLS encryption. BareUDP mode reaches near line-rate on a 10 GbE NIC.

### Thread-per-Core Runtime

h3llo dedicates one OS thread per data-plane function using multiple single-threaded Tokio runtimes (`current_thread`). Each runtime owns a disjoint set of actors, eliminating cross-thread synchronization on the hot path.

| Thread | Name | Actors |
|--------|------|--------|
| TUN | `h3llo-tun` | TUN RX, TUN TX |
| Crypto | `h3llo-crypto` | Router, H3 Engine (QUIC crypto + session + datagram forwarding) |
| UDP | `h3llo-udp` | UDP RX/TX (BareUDP and H3 transport) |
| Main | `h3llo` | Orchestrator, DNS, Route Sync, API |

Key design choices:

- **Co-locate H3 engine with router on `crypto_rt`**: the router dispatches packets directly to the H3 engine's TX channel. Co-location eliminates a cross-thread hop for every routed packet.
- **Isolate UDP I/O on `udp_rt`**: kernel `sendmsg`/`recvmmsg` syscalls are the dominant cost in the UDP thread (see [profiling data](#profiling-insights)); isolating them prevents syscall latency from blocking TUN or crypto processing.
- **Control plane on main thread**: orchestrator, DNS, and API are low-frequency; sharing the main thread avoids wasting a core.

Actors are pinned to runtimes via `Handle::enter()` guards during initialization (`src/orch.rs`). This sets the thread-local runtime context so that `tokio::spawn` inside each actor targets the correct runtime.

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

When `tuning.udp_enable_offload` is true, `apply_max_capabilities()` is called on QUIC sockets for both H3 client and listener transports, enabling GSO for TX and GRO for RX at the tokio-quiche level.

#### NIC Hardware Offload

Software GSO/GRO can be further accelerated by NIC hardware offload. When `tx-udp-segmentation` and `rx-gro-hw` are enabled via `ethtool -K`, the NIC performs segmentation and coalescing in hardware, eliminating kernel `skb_segment` overhead. Measured impact on BareUDP: +72% throughput (6.92 → 11.9 Gbps forward). H3 mode is unaffected because its bottleneck is in the QUIC layer, not kernel UDP processing.

### Zero-Copy Buffer Pool

Data-plane buffers are allocated from tokio-quiche's `BufFactory` pool and reused across the entire packet lifecycle without reallocation. The pool has two tiers: a 1.5 KB datagram pool (64K capacity) for typical packets, and a 64 KB generic pool (16K capacity) for oversized payloads.

#### Headroom Layout

Every data-plane `PooledBuf` reserves 10 bytes of headroom at the front:

```
[ 10B headroom ][ packet payload ]
 └── 9B DGRAM_PREFIX (tokio-quiche)
 └── 1B Context ID (CONNECT-IP)
```

This headroom enables zero-copy operations at two points:

- **H3 TX**: `add_prefix(&[CONTEXT_ID_IP])` prepends the 1-byte Context ID in-place, consuming headroom without allocation.
- **TUN TX**: `TunBuf::prepend_hdr()` prepends a zeroed 10-byte `virtio_net_hdr` via `add_prefix`, also using headroom. A compile-time assertion (`HEADROOM >= VIRTIO_NET_HDR_LEN`) guards this invariant.

H3 RX uses `pop_front(1)` to strip the Context ID in-place, restoring headroom for the downstream TUN TX path.

#### Size-Aware Dual-Pool Allocation

`alloc_uninit_packet_buf(length)` selects the smallest pool that fits:

- Packets where `length + HEADROOM ≤ MAX_DGRAM_SIZE` (1500): allocated from the **datagram pool** (1.5 KB per buffer, 64K capacity).
- Larger payloads: allocated from the **generic pool** (64 KB per buffer, 16K capacity).

Typical IP packets (≤ MTU 1291) always land in the datagram pool, reducing per-packet memory by ~97% compared to unconditionally using the 64 KB pool.

#### TunBuf GRO Extend and Pool Upgrade

`TunBuf` (`src/tun.rs`) wraps a `PooledBuf` to provide TUN-specific zero-copy semantics:

- `TunBuf::alloc_uninit(mtu)` allocates from the datagram pool with headroom, ready for kernel `recv`.
- `into_pooled(len)` truncates to the actual received length and unwraps the inner `PooledBuf` — zero-copy from kernel to packet channel.
- `prepend_hdr()` prepends the `virtio_net_hdr` using headroom; falls back to alloc+copy only when headroom is absent (e.g., test buffers created without headroom).

When TUN GRO is enabled, tun-rs coalesces same-flow packets by extending a `TunBuf` via the `ExpandBuffer` trait. This creates a tension: individual packets are allocated from the small 1.5 KB datagram pool for memory efficiency, but GRO coalescing can grow a buffer well beyond that size (up to ~65535 bytes for a full GSO super-packet).

`TunBuf::buf_extend()` resolves this with a **one-shot pool upgrade**: when an extend operation would cross the `MAX_DGRAM_SIZE` threshold, it allocates a 64 KB buffer from the generic pool, copies the existing data once, and replaces the underlying `PooledBuf`. Subsequent extends operate on the large buffer without further reallocation. If the buffer is already in the generic pool or the extend stays within the datagram pool's capacity, no upgrade occurs.

`buf_capacity()` returns `usize::MAX`, telling tun-rs GRO that coalescing is always possible (capped externally by IP total length ~65535). This maximizes coalescing without artificial limits from pool sizing.

#### Allocation Paths

| Data path | Allocation | Zero-copy? |
|-----------|-----------|------------|
| TUN RX → channel | `TunBuf::alloc_uninit` → kernel fills → `into_pooled` | Yes |
| H3 TX encoding | `add_prefix` consumes headroom | Yes |
| TUN TX writing | `TunBuf::prepend_hdr` consumes headroom | Yes |
| H3 RX decoding | `pop_front(1)` strips Context ID | Yes |
| BareUDP/H3 RX | `alloc_packet_buf` (copy into pooled buffer) | Copy once |

### Batch Channel Transmission

Data-plane channels carry `Vec<PooledBuf>` batches rather than individual packets. Each channel message represents one device I/O operation's worth of packets (a TUN `recv_batch`, BareUDP GRO recv, or H3 datagram drain). This reduces per-packet atomic operations from N to 1 per batch.

Channels use `mpsc::channel::<Vec<PooledBuf>>(packet_queue_depth)` with a default depth of 256. `packet_queue_depth` counts batch messages, not individual packets. Bounded channels provide backpressure: when a consumer falls behind, the producer blocks rather than buffering unboundedly.

The router (`src/router.rs`) splits ingress batches by destination IP into consecutive groups, performs LPM lookup and TTL decrement (RFC 1624 incremental checksum) once per group, and forwards each group as a `Vec<PooledBuf>` to the appropriate peer TX channel.

### Allocator Tuning (mimalloc)

On musl targets (the Docker image uses static musl linking), h3llo replaces the default musl allocator with mimalloc via `#[global_allocator]`. musl's built-in allocator has poor multi-threaded performance; mimalloc provides thread-local heaps with minimal contention.

Configuration:

- `features = ["override"]` — no debug feature. Removing the debug feature eliminated `mi_check_padding` validation and yielded a +21% throughput improvement (3.90 → 4.73 Gbps in H3 mode), far exceeding the ~1% CPU reduction visible in perf profiles. The disproportionate gain is attributed to debug validation destroying memory locality in the hot path, causing icache/dcache pressure.
- `MIMALLOC_PURGE_DELAY=0` (set via Dockerfile env var) — aggressively returns freed pages to the OS, preventing RSS amplification under bursty allocation patterns.

### Upstream Patches

h3llo uses a patched quiche monorepo ([`Tonny-Gu/quiche:remove-pooled-buf-metrics`](https://github.com/Tonny-Gu/quiche/tree/remove-pooled-buf-metrics)) with two performance-critical changes:

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

#### CPU Budget Breakdown (BareUDP, forward direction)

| Category | CPU% | Notes |
|----------|------|-------|
| Kernel `sendmsg` / UDP GSO | ~30% | `__x64_sys_sendmsg` → `udp_sendmsg` → `skb_segment` → driver |
| Kernel `recvmmsg` / copy | ~18% | `_copy_to_iter` is the single largest kernel hotspot (9.6%) |
| Kernel TUN write | ~17% | `tun_get_user` → skb build → `netif_receive_skb` (re-traverses stack) |
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
| `_copy_to_iter` in `recvmmsg` | ~10% CPU (receiver) | io_uring / MSG_ZEROCOPY |
| TUN write re-injection | ~17% CPU (receiver) | vhost-net / kernel TUN splice |
| `dgram_send` per-packet `to_vec()` in quiche | ~2% CPU + alloc pressure | Upstream quiche API change |
| TUN checksum (software GSO/GRO) | 3–6% CPU | Verify kernel handles checksums when offload enabled |
| Spectre SRSO (AMD) | ~2% CPU | `spec_rstack_overflow=off` (trusted environments) |
| `CONFIG_HARDENED_USERCOPY` | ~2% CPU | Kernel rebuild with `=n` (trusted environments) |
