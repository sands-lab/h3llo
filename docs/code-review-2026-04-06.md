# h3llo Full Project Code Review Report

**Date**: 2026-04-06
**Scope**: All 22 source files in `src/`, reviewed against `docs/refactoring.md` categories A–N
**Method**: 67 parallel review agents, each covering one file × one category
**Total findings**: ~200 across all categories

---

## Implementation Progress

Findings are grouped into batches ordered by priority and dependency. Each batch is implemented as one commit after review.

| Batch | Scope | Sections | Status |
|-------|-------|----------|--------|
| **1** | **Critical bug fixes**: ~~TUN RX infinite loop~~, ~~H3v2Connected silent drop~~, ~~auth log level~~ (§1.2 auth timing, §1.4 stale routes: skipped) | §1.2–1.6 | ✅ |
| **2** | **Observability**: ~~bare.rs + udp.rs zero tracing~~, ~~logging level fixes~~, ~~silent drop handling~~ (router.rs send_and_record: kept as-is, already tracked via metrics) | §1.7, §4.1, §4.2 | ✅ |
| **3** | **Cleanup**: ~~visibility narrowing~~ (14 items), ~~redundant derives~~, ~~stale docs~~ (§2.1 H3v2→H3 rename: deferred to batch 6) | §6, §9, §10 | ✅ |
| **4** | **Type-level refinements**: `PeerTransport` enum, `CcAlgorithm` enum, `ConnectState` enum, `ConnParams` removal, other type/API fixes | §2.2, §2.11, §2.12, §2.14, §7 | ⬚ |
| **5** | **Code extraction & dedup**: metrics_encode.rs, buf.rs, serde macro, validation helper, TUN dedup, cross-file dedup patterns | §2.3, §2.4, §2.9, §2.10, §2.15, §2.16, §3 | ⬚ |
| **6** | **h3.rs deletion**: migrate interop tests, delete 2228-LOC deprecated module, remove duplicated header validation | §1.1, §2.13, §11.1 | ⬚ |
| **7** | **Structural refactoring**: config.rs split, Tuning sub-structs, ActorChannels, ConnectContext, handshake loop dedup, other §2.17 items | §2.5–2.8, §2.17, §11.2–11.5, §12, §14 | ⬚ |
| **8** | **Polish**: naming/expression clarity, magic numbers, test quality, type-level enforcement | §4.3, §5, §8, §13 | ⬚ |

Legend: ⬚ = pending, 🔨 = in progress, ✅ = done, ⊘ = skipped

---

## 1. Critical / High Findings (Fix First)

### 1.1 `h3.rs` entire module is deprecated — **-2228 LOC** (H1/A1/D4)

`orch.rs:964-971` explicitly ignores `Event::H3Connected`:

```rust
// orch.rs:964-971
Event::H3Connected(event) => {
    // Deprecated: old h3.rs path no longer used in production.
    warn!(
        origin = ?event.origin,
        "received old-style H3Connected event (h3.rs path); ignoring"
    );
}
```

All production paths use `h3dialer.rs`, `h3listener.rs`, `h3engine.rs`, `h3session.rs`. The 2228-LOC `h3.rs` is only referenced by tests in the newer modules as an interop test server.

Every `pub` item in `h3.rs` has **zero production callers**:

| Item | Production callers | Test-only callers |
|------|-------------------|-------------------|
| `H3Connection` | `events.rs:228` (deprecated path) | h3listener.rs, h3dialer.rs tests |
| `dial_h3` | none | h3listener.rs tests |
| `spawn_h3_rx` / `spawn_h3_tx` | none | h3listener.rs, h3dialer.rs tests |
| `make_h3_listener` / `spawn_h3_listener` | none | h3dialer.rs tests |
| `DialError` / `ListenerError` | none | h3listener.rs tests |

**Action**: Migrate interop tests to the new server infrastructure, then delete `h3.rs` entirely. Short-term: add `#[deprecated]` to all pub items and a `//! # Deprecation` module doc section.

---

### 1.2 `auth.rs:46` timing side-channel (G3)

```rust
// auth.rs:44-49
for (peer_id, peer_token) in peer_tokens {
    let token_match: bool = peer_token.as_bytes().ct_eq(token.as_bytes()).into();
    if token_match {
        return Ok(peer_id.to_string());
    }
}
```

`subtle::ConstantTimeEq` for `[u8]` slices explicitly documents: "This function short-circuits if the lengths of the input slices are different." An attacker can determine the **length** of each configured peer token by measuring response timing.

**Action**: HMAC or keyed-hash both sides to fixed length before `ct_eq`:

```rust
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn token_tag(key: &[u8], token: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
    mac.update(token.as_bytes());
    mac.finalize().into_bytes().into()
}

// In validate_connect_auth:
let presented_tag = token_tag(&server_key, token);
for (peer_id, peer_token) in peer_tokens {
    let expected_tag = token_tag(&server_key, peer_token);
    if presented_tag.ct_eq(&expected_tag).into() {
        return Ok(peer_id.to_string());
    }
}
```

Also missing: no test for different-length token comparison (auth.rs test module has no such test case).

---

### 1.3 `tun.rs:550` TUN RX actor infinite loop bug (E1)

```rust
// tun.rs:548-551
let total_bytes: u64 = batch.iter().map(|p| p.len() as u64).sum();
let pkt_count = batch.len() as u64;
counters.send_and_record(&output_tx, batch, pkt_count, total_bytes).await;
// ^^^ return value IGNORED — if channel is closed, actor loops forever
```

`send_and_record` returns `bool` (`false` when downstream channel closed). Other actors check it:

```rust
// bare.rs:112 — correct pattern
if !counters.send_and_record(&ingress_tx, batch, count, bytes).await {
    return Ok(());
}
// h3.rs:769 — correct pattern
if !counters.send_and_record(&ingress_tx, batch, count, bytes).await {
    return Ok(());
}
```

But `tun.rs:550` ignores it, causing the TUN RX actor to keep reading from the kernel TUN device, processing packets, and attempting sends on a dead channel indefinitely — wasting CPU and kernel I/O.

**Action**:

```rust
if !counters.send_and_record(&output_tx, batch, pkt_count, total_bytes).await {
    info!(tun = %tun_name, "TUN RX: router channel closed, shutting down");
    return Ok(());
}
```

---

### 1.4 `orch.rs:911-922` stale routing/firewall rules after peer deletion (F6)

```rust
// orch.rs:911-922
fn handle_delete_config(&mut self, peer_ids: &[String]) {
    let mut changed = false;
    for id in peer_ids {
        if self.peers.remove(id).is_some() {
            changed = true;
            info!(peer = %id, "API: peer removed");
        }
    }
    if changed {
        self.sync_peers_to_actors();
        // MISSING: self.update_accepted_sources();
        // MISSING: self.update_routing();
    }
}
```

Compare with `handle_dns_snapshot()` (lines 989-1014) which correctly calls both `update_accepted_sources()` and `update_routing()` after peer state changes. The same gap exists in `handle_post_config()`.

When a peer is deleted via API, its accepted source IPs and routing entries persist until the next DNS event or reconcile tick (which could be seconds away).

**Action**: Add `self.update_accepted_sources()` and `self.update_routing()` in both `handle_delete_config()` and `handle_post_config()` when `changed` is true. (+4 LOC)

---

### 1.5 `h3listener.rs:555` H3v2Connected event silently dropped (E1)

```rust
// h3listener.rs:555-564
let _ = engine.io.events_tx.send(Event::H3v2Connected(H3v2ConnectedEvent {
    peer_id: engine.meta.peer_id.clone(),
    remote_addr: remote,
    tx: egress_tx,
    origin: ConnOrigin::Server,
    handles: Vec::new(),
}));
```

This is the critical event that notifies the orchestrator a new connection is ready. If `events_tx` is closed (orchestrator shutdown), the event is silently lost. The engine proceeds to `run()` as an orphan — unable to receive egress traffic, with its `egress_rx` having no sender. Operators will see a "CONNECT-IP established" info log without a corresponding connected event.

**Action**:

```rust
if engine.io.events_tx.send(Event::H3v2Connected(H3v2ConnectedEvent {
    peer_id: engine.meta.peer_id.clone(),
    remote_addr: remote,
    tx: egress_tx,
    origin: ConnOrigin::Server,
    handles: Vec::new(),
})).is_err() {
    warn!(peer_id = %engine.meta.peer_id, %remote, "events channel closed; aborting connection");
    return Ok(());
}
```

---

### 1.6 `h3listener.rs:246` auth rejection logged at `debug` (E5)

```rust
// h3listener.rs:245-247
debug!(stream_id, error = %e, "rejecting unauthenticated stream");
let _ = h3.send_response(conn, stream_id,
    &[quiche::h3::Header::new(b":status", b"401")], true);
```

Failed authentication is a security-relevant event. At `debug` level (typically disabled in production), these events are invisible. Operators cannot detect brute-force token guessing, misconfigured peers, or credential rotation failures.

**Action**: Promote to `warn!` and add `%remote` context:

```rust
warn!(stream_id, %remote, error = %e, "rejecting unauthenticated stream");
```

---

### 1.7 `bare.rs` + `udp.rs` have zero tracing (E5)

These are the **only two actor modules** in the entire project without any `tracing` instrumentation:

| Module | Tracing levels used |
|--------|-------------------|
| tun.rs | `info`, `warn` |
| h3.rs | `debug`, `error`, `info`, `warn` |
| h3session.rs | `debug`, `info` |
| h3listener.rs | `debug`, `info`, `warn` |
| h3engine.rs | `debug`, `warn` |
| h3dialer.rs | `debug` |
| orch.rs | `debug`, `error`, `info`, `warn` |
| bind.rs | `warn` |
| router.rs | `warn` |
| **bare.rs** | **(none)** |
| **udp.rs** | **(none)** |

Specific events that should be traced:

- bare.rs: Actor startup/shutdown, `UpdateAcceptedSources` command received, first packet dropped from disallowed source IP (security-relevant)
- udp.rs: UDP RX/TX actor startup with local address, actor exit on channel close, fatal I/O error before returning `ActorError`
- bare.rs:223-225: TX actor exits on `udp_tx` channel close with no trace and no final metrics flush

**Action**: Add `use tracing::{debug, warn};` and ~10-15 lines of trace points per file.

---

## 2. Structural Refactoring (Category F + D4)

### 2.1 `H3v2ConnectedEvent` → `H3ConnectedEvent`, delete old `H3Connected` (C1/A1)

```rust
// events.rs — two parallel event types for the same concept
pub struct H3ConnectedEvent { ... }     // line 226 — DEPRECATED
pub struct H3v2ConnectedEvent { ... }   // line 73 — current

// Event enum carries both:
H3Connected(H3ConnectedEvent),          // line 105 — ignored by orchestrator
H3v2Connected(H3v2ConnectedEvent),      // line 107 — active
```

The "v2" suffix is an implementation-history artifact. Per CLAUDE.md ("should completely abandon forward compatibility at this stage"):

**Action**: Delete `H3ConnectedEvent`, `Event::H3Connected`, and the orch.rs warn handler. Rename `H3v2ConnectedEvent` to `H3ConnectedEvent`. ~-30 LOC, mechanical rename across ~20 call sites.

---

### 2.2 `Option<PeerBare>` + `Option<PeerH3>` → `PeerTransport` enum (H1)

```rust
// config.rs — mutual exclusion validated at runtime
pub struct Peer {
    pub h3: Option<PeerH3>,
    pub bare: Option<PeerBare>,
    // ...
}

// config.rs:679 — runtime validation
if peer.h3.is_some() == peer.bare.is_some() {
    errors.push(ValidationError::PeerTransportConflict { ... });
}

// orch.rs — triple if-else dispatch at 3 sites (119, 239, 296)
fn config_endpoint(&self) -> Option<Endpoint> {
    if let Some(bare) = &self.config.bare {
        Some(Endpoint::Udp(bare.endpoint.clone()))
    } else if let Some(h3) = &self.config.h3 {
        h3.endpoint.as_ref().map(|ep| Endpoint::H3(ep.clone()))
    } else {
        None
    }
}
```

**Action**: Replace with compile-time enforced enum:

```rust
pub enum PeerTransport {
    Bare(PeerBare),
    H3(PeerH3),
}

pub struct Peer {
    pub transport: PeerTransport,
    // ...
}
```

This collapses the 3 triple-dispatch sites into clean `match` arms and eliminates the runtime validation at config.rs:679. ~-20 LOC.

---

### 2.3 Metrics encoding extract from api.rs (D4)

`api.rs` mixes two distinct concerns:

| Concern | Lines | LOC |
|---------|-------|-----|
| Prometheus metrics encoding | 38-348 | 311 |
| HTTP API server | 350-595 | 246 |
| Tests | 597-1259 | 663 |

The metrics block (`SnapshotCollector`, `encode_metrics_snapshot`, all `encode_*_family` functions, 6 label types) is self-contained and also used from `orch.rs` tests.

**Action**: Extract to `src/metrics_encode.rs`. api.rs drops to ~948 LOC, clean single-concern HTTP module.

---

### 2.4 `alloc_packet_buf` extract from tun.rs (D4)

`alloc_packet_buf` and `alloc_uninit_packet_buf` are **not TUN-specific**. They are general-purpose headroom-aware packet buffer allocators used by 8 other modules:

```rust
// These imports in 8 modules are misleading:
use crate::tun::alloc_packet_buf;      // h3session.rs, h3.rs, h3listener.rs
use crate::tun::alloc_uninit_packet_buf; // router.rs, udp.rs, h3dialer.rs, h3engine.rs
```

**Action**: Extract `HEADROOM`, `alloc_packet_buf`, `alloc_uninit_packet_buf` into `src/buf.rs`. tun.rs drops by ~60 lines.

---

### 2.5 config.rs split into sub-modules (D4)

2561 LOC file with four distinct concerns:

| Concern | Lines | LOC |
|---------|-------|-----|
| Struct definitions | 1-300 | 300 |
| Validation logic | 370-707 | 340 |
| URI parsing + serde | 744-961 | 220 |
| Tests | 963-2561 | 1600 |

**Action**: Split into `config/{mod.rs, validate.rs, endpoint.rs}`.

---

### 2.6 `Tuning` 22-field god struct (F2)

```rust
// config.rs:161-300 — 22 fields with prefix-based naming
pub struct Tuning {
    // Data plane (5 fields)
    pub packet_queue_depth: usize,
    pub socket_buffer_size: usize,
    pub tun_tx_queue_len: u32,
    pub tun_enable_offload: bool,
    pub udp_enable_offload: bool,
    // Timing/reconnect (3 fields)
    pub reconcile_interval: Duration,
    pub reconnect_backoff_min: Duration,
    pub reconnect_backoff_max: Duration,
    // DNS (5 fields)
    pub dns_query_timeout: Duration,
    pub dns_refresh_interval: Duration,
    pub dns_snapshot_delay: Duration,
    pub dns_query_interval: Duration,
    pub dns_min_ttl: u32,
    // H3/QUIC (7 fields)
    pub h3_handshake_timeout: Duration,
    pub h3_max_idle_timeout: Duration,
    pub h3_keepalive_interval: Duration,
    pub h3_cc_algorithm: String,
    pub h3_enable_pacing: bool,
    pub h3_insecure_skip_verify: bool,
    pub h3_trusted_ca: Option<String>,
    // Metrics (2 fields)
    pub metrics_push_interval: Duration,
    pub metrics_log_interval: Duration,
}
```

The `h3_*`, `dns_*` prefix naming convention is a strong signal they belong in sub-structs. **Caveat**: `#[serde(flatten)]` + `#[serde(deny_unknown_fields)]` has a known serde incompatibility (serde-rs/serde#1547).

**Action**: Introduce nested sub-structs if `deny_unknown_fields` trade-off is resolved; otherwise, extract per-subsystem `validate()` methods.

---

### 2.7 `Orchestrator` 17 fields → extract `ActorChannels` (F2)

```rust
// orch.rs:346-387 — 17 fields
pub struct Orchestrator {
    events_rx, events_tx, join_set, tun_if, tun_mtu, tuning,
    peers, router_cmd_tx, ingress_tx, bare_rx_cmd_tx,
    h3_listener_cmd_tx, dns_cmd_tx, route_cmd_tx, input_tx,
    local, non_peer_metrics, _tun_rt, crypto_rt, udp_rt,
}
```

5 command channel fields (`router_cmd_tx`, `bare_rx_cmd_tx`, `h3_listener_cmd_tx`, `dns_cmd_tx`, `route_cmd_tx`) are always used together in `sync_peers_to_actors()`, `update_accepted_sources()`, and `update_routing()`.

**Action**: Extract `ActorChannels` sub-struct for the 5 command channels.

---

### 2.8 `try_connect` 8 params → `ConnectContext` (F2/K3)

```rust
// orch.rs:179-189
#[allow(clippy::too_many_arguments)]
fn try_connect(
    &mut self,
    events_tx: &mpsc::UnboundedSender<Event>,
    tun_if: &str,
    tun_mtu: usize,
    tuning: &Tuning,
    udp_handle: &Handle,
    crypto_handle: &Handle,
    ingress_tx: &mpsc::Sender<Vec<PooledBuf>>,
) {
```

**Action**: Bundle into `ConnectContext<'a>` struct. Both call sites (`reconcile` and `handle_dns_snapshot`) construct the same set of values.

---

### 2.9 Endpoint serde boilerplate → macro (F7)

`UdpEndpoint`, `H3Endpoint`, `ApiEndpoint` each implement identical Serialize/Deserialize boilerplate (~200 LOC total):

```rust
// Pattern repeated 3 times:
impl<'de> Deserialize<'de> for H3Endpoint {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_h3_uri(&s).map_err(de::Error::custom)
    }
}
impl Serialize for H3Endpoint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("https://{}:{}{}", self.host, self.port, self.path))
    }
}
```

**Action**: Extract macro `impl_uri_serde!($ty, $parse_fn, $format_fn)`. ~-40 LOC.

---

### 2.10 Validation trim/empty pattern extraction (E3)

```rust
// config.rs — same pattern repeated 4 times (lines 625-676)
if peer.id.trim().is_empty() {
    errors.push(ValidationError::PeerIdEmpty { ... });
} else if peer.id != peer.id.trim() {
    errors.push(ValidationError::PeerIdHasWhitespace { ... });
}
// ... same for token, sni, bindif
```

**Action**: Extract helper:

```rust
fn validate_trimmed_string(
    value: &str,
    on_empty: impl FnOnce() -> ValidationError,
    on_whitespace: impl FnOnce() -> ValidationError,
    errors: &mut Vec<ValidationError>,
) {
    if value.trim().is_empty() {
        errors.push(on_empty());
    } else if value != value.trim() {
        errors.push(on_whitespace());
    }
}
```

~-20 LOC.

---

### 2.11 `h3_cc_algorithm: String` → `CcAlgorithm` enum (B1/J1)

```rust
// config.rs:279
pub h3_cc_algorithm: String,

// config.rs:541-548 — runtime validation
const VALID_CC_ALGORITHMS: &[&str] = &["reno", "cubic", "bbr", "bbr2", "none"];
if !VALID_CC_ALGORITHMS.contains(&self.tuning.h3_cc_algorithm.as_str()) { ... }

// h3engine.rs:52 — downstream consumes as &str
config.set_cc_algorithm_name(&tuning.h3_cc_algorithm)?;

// h3.rs:61 — clone for old path
s.cc_algorithm = tuning.h3_cc_algorithm.clone();
```

**Action**:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CcAlgorithm {
    Reno, Cubic, Bbr, Bbr2, None,
}

impl CcAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reno => "reno", Self::Cubic => "cubic",
            Self::Bbr => "bbr", Self::Bbr2 => "bbr2", Self::None => "none",
        }
    }
}
```

Eliminates `InvalidCcAlgorithm` error variant, `VALID_CC_ALGORITHMS` const, validation block, and `.clone()`. ~-15 LOC.

---

### 2.12 `h3session` three scattered Options → `ConnectState` enum (B2/F1)

```rust
// h3session.rs:50-59
pub(crate) struct H3Session {
    pub(crate) connect_stream_id: Option<u64>,
    pub(crate) datagram_codec: ConnectIpDatagramCodec,  // dummy init with 0
    pub(crate) connect_accepted: bool,
    pub(crate) accepted_peer_id: Option<String>,
    // ...
}
```

Three fields (`connect_stream_id`, `connect_accepted`, `accepted_peer_id`) plus a dummy-initialized `datagram_codec` encode a single state machine: Unbound → Bound(stream_id) → Accepted(stream_id, peer_id).

**Action**:

```rust
enum ConnectState {
    Unbound,
    Bound { stream_id: u64, codec: ConnectIpDatagramCodec },
    Accepted { stream_id: u64, codec: ConnectIpDatagramCodec, peer_id: Option<String> },
}
```

Eliminates dummy codec init, 3 fields, and makes invalid states unrepresentable. ~-10 LOC.

---

### 2.13 h3listener + h3.rs duplicated header validation (C1/C4)

Two pairs of functions perform identical logic:

| h3listener.rs | h3.rs | Logic |
|---------------|-------|-------|
| `validate_server_connect_headers` (line 60) | `validate_connect_ip_headers` (line 178) | Check :method, :protocol, capsule-protocol |
| `validate_server_auth` (line 88) | `extract_and_validate_auth` (line 76) | Extract Authorization header, validate token |

Additionally, h3listener.rs:61-78 hand-rolls `.iter().find().map()` header lookup 4 times, while h3.rs:98 already has `find_header_value()` doing the same with case-insensitive matching.

**Action**: Extract shared functions to `h3session.rs` or new `h3common.rs`. ~-28 LOC.

---

### 2.14 `ConnParams` is redundant projection of `Tuning` (B1)

```rust
// h3listener.rs:354-358
pub(crate) struct ConnParams {
    pub(crate) handshake_timeout: Duration,
    pub(crate) packet_queue_depth: usize,
    pub(crate) metrics_interval: Duration,
    pub(crate) keepalive_interval: Duration,
}

// h3listener.rs:176-181 — all fields copied from Tuning
conn_params: ConnParams {
    handshake_timeout: tuning.h3_handshake_timeout,
    packet_queue_depth: tuning.packet_queue_depth,
    metrics_interval: tuning.metrics_push_interval,
    keepalive_interval: tuning.h3_keepalive_interval,
},
```

**Action**: Store `Tuning` directly (or `Arc<Tuning>`) instead of `ConnParams`. ~-12 LOC.

---

### 2.15 TunReader/TunWriter 4 duplicated fields (F2)

```rust
pub struct TunReader {
    device: Arc<AsyncDevice>, mtu: usize, name: String, offload: bool,
}
pub struct TunWriter {
    device: Arc<AsyncDevice>, mtu: usize, name: String, offload: bool,
    #[cfg(target_os = "linux")] gro_table: GROTable,
}
```

Both share 4 identical fields with duplicated `mtu()`, `name()`, `batch_size()` accessor impls.

**Action**: Extract `TunDeviceInner` shared struct. ~-20 LOC.

---

### 2.16 recv_batch/send_batch non-offload cfg duplication (C4/F5)

```rust
// tun.rs:406-409 — Linux non-offload
let _ = scratch;
let len = self.device.recv(bufs[0].as_mut()).await?;
sizes[0] = len;
Ok(1)

// tun.rs:414-417 — non-Linux (IDENTICAL)
let _ = scratch;
let len = self.device.recv(bufs[0].as_mut()).await?;
sizes[0] = len;
Ok(1)
```

Same pattern in `send_batch` (lines 462-465 vs 470-473).

**Action**: Early-return for offload case, fall through to common path:

```rust
async fn recv_batch(&mut self, scratch: &mut [u8], bufs: &mut [TunBuf], sizes: &mut [usize]) -> io::Result<usize> {
    #[cfg(target_os = "linux")]
    if self.offload {
        return self.device.recv_multiple(scratch, bufs, sizes, 0).await;
    }
    let _ = scratch;
    let len = self.device.recv(bufs[0].as_mut()).await?;
    sizes[0] = len;
    Ok(1)
}
```

~-14 LOC.

---

### 2.17 Other structural findings

| Finding | File | Pattern | LOC Impact |
|---------|------|---------|------------|
| `DedicatedRuntime` extract from actor.rs (unrelated to `ActorError`) | actor.rs | F1 | 0 (move) |
| `ActorKind` → `SupervisionPolicy` rename | actor.rs | C1 | 0 (rename) |
| Router routing table data structures extract to own module | router.rs | F1/D4 | 0 (move) |
| `RouterHandles` tuple → named struct (prevents silent sender swap) | router.rs | C1/B1 | +4 |
| `HeaderAction::Accept::stream_id` redundantly echoes caller-known value | h3session.rs | F1 | -8 |
| `accepted_peer_id` → `ConnectProgress::Ready { peer_id }` | h3session.rs | F6 | 0 |
| `qsi_bytes: Vec<u8>` (max 8 bytes) → `[u8; 8]` + len | h3session.rs | F5 | +5 (eliminates hot-path heap alloc) |
| `H3Dispatcher` and `DispatcherRuntime` share 4 identical fields → unify | h3listener.rs | B3 | -15 |
| CID table lacks rotation tracking (TODO already exists) | h3listener.rs | F6 | +40-60 |
| `api.rs:445` `base == "/"` is dead code after `trim_end_matches('/')` | api.rs | C6 | 0 |
| 3× `from_metrics` base label extraction duplicated → extract helper | api.rs | C4/F2 | -20 |
| `DnsActor` 5 loose Duration fields → `DnsTuning` sub-struct | dns.rs | F2/B1 | +3 net |
| `DnsActor::server` derivable from `socket.peer_addr()` | dns.rs | B3 | -3 |
| `ResolveInitError` single-variant enum → struct wrapping `io::Error` | dns.rs | B3 | -3 |
| bind.rs route sort uses opaque tuple → `RouteCandidate` named struct | bind.rs | C1/B1 | +12 |
| `filter_preferred_interfaces` over-general for single-element use → simplify | bind.rs | C4 | -17 |
| `h3dialer.rs` `establish` nesting reaches 7 levels → extract method | h3dialer.rs | C2 | +5 |
| `h3dialer.rs` `start_h3_session` trivial 1-line wrapper → inline | h3dialer.rs | C3 | -6 |
| `h3session.rs` `mark_connect_accepted` single-line setter → inline | h3session.rs | C3 | -4 |
| `h3session.rs` `ConnectFailure::into_actor_reason` → `impl Display` | h3session.rs | C4 | 0 |
| `orch.rs` `try_connect` bare/h3 branches ~35 lines duplicated error handling | orch.rs | C2 | -12 |
| `orch.rs:897-902` `get_mut` + `insert` → HashMap `entry` API | orch.rs | C5 | 0 |
| `dns.rs` `ipv4_from_rdata`/`ipv6_from_rdata` trivial wrappers → inline | dns.rs | C3 | -8 |
| `config.rs` `ValidationErrors::Display` manual `first` boolean → iterator | config.rs | C4 | -4 |
| Test config duplication: `H3LoopbackPair::new()` duplicates `apply_transport_config` | h3session.rs | D2 | -14 |
| `h3session.rs` wildcard catches `Data` event without draining body → potential H3 stall | h3session.rs | E2 | +4 |

---

## 3. Cross-File Deduplication (Category D)

### 3.1 Metrics tick-and-emit pattern (7 sites, ~-14 LOC)

Identical `tokio::select!` arm at 7 sites across 4 files:

```rust
// Pattern at tun.rs:558, tun.rs:621, router.rs:402, bare.rs:123, bare.rs:228, h3.rs:773, h3.rs:970
_ = ticker.tick() => {
    if events_tx.send(Event::Metrics(counters.snapshot(peer, addr))).is_err() {
        return Ok(());
    }
}
```

**Action**: Add `Counters::emit()` method:

```rust
impl Counters {
    pub(crate) fn emit(
        &self, events_tx: &mpsc::UnboundedSender<Event>,
        peer_id: Option<&str>, remote_addr: Option<SocketAddr>,
    ) -> bool {
        events_tx.send(Event::Metrics(self.snapshot(peer_id, remote_addr))).is_ok()
    }
}
```

Each call site becomes: `if !counters.emit(&events_tx, None, None) { return Ok(()); }`

---

### 3.2 `make_h3_listener` + `spawn_h3_listener` test boilerplate (11 sites, ~-55 LOC)

Every test repeats this 6-line pattern:

```rust
let listener = make_h3_listener(listen_addr, certs.cert_path(), certs.key_path(), 0)
    .expect("make_h3_listener");
let (cmd_tx, _handle, bound_addr) = spawn_h3_listener(
    listener, peer_tokens, default_mtu(), events_tx, &Tuning::default(),
);
```

**Action**: Extract `start_test_listener()` helper.

---

### 3.3 Send + recv + assert test pattern (8 sites, ~-56 LOC)

```rust
// Pattern at h3listener.rs:939, 1018, 1058, 1089, 1135; h3dialer.rs:604, 645; h3.rs:1895
let test_packet = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 1));
let pkt = alloc_packet_buf(&test_packet);
sender_tx.send(vec![pkt]).await.expect("send failed");
let batch = tokio::time::timeout(Duration::from_secs(5), receiver_rx.recv())
    .await.expect("timeout").expect("closed");
assert_eq!(batch.len(), 1);
assert_eq!(&batch[0][..], &test_packet[..]);
```

**Action**: Extract `send_and_assert_packet()` async helper.

---

### 3.4 `DialContext` test construction (6 sites, ~-30 LOC)

```rust
// Pattern at h3dialer.rs:503, 559, 788, 823; h3listener.rs:851, 988
let ctx = DialContext {
    peer_id: peer_id.to_string(),
    tun_if: String::new(),
    tun_mtu: default_mtu().into(),
    tuning,
    udp_rt: tokio::runtime::Handle::current(),
    crypto_rt: tokio::runtime::Handle::current(),
    events_tx,
};
```

**Action**: Add `DialContext::test(peer_id, tuning, events_tx)` constructor.

---

### 3.5 QUIC config constants duplicated in test code (D2, drift risk)

```rust
// h3engine.rs:41-50 — production
config.set_initial_max_data(10_000_000);
config.set_initial_max_stream_data_bidi_local(1_000_000);
// ... 7 total settings

// h3session.rs:547-553 — test (MANUALLY DUPLICATED)
client_config.set_initial_max_data(10_000_000);
client_config.set_initial_max_stream_data_bidi_local(1_000_000);
// ... same 7 settings, twice (client + server)
```

If production changes a value, tests silently diverge.

**Action**: Call `apply_transport_config(&mut config, &Tuning::default(), 1350)` from tests. ~-14 LOC.

---

### 3.6 `batch_stats` two-liner (7 sites across 4 files)

```rust
// Pattern at router.rs:422-423, 479-480, 517-518, 525-526; tun.rs:548-549; bare.rs:106-107, 220-221
let count = batch.len() as u64;
let bytes: u64 = batch.iter().map(|p| p.len() as u64).sum();
```

**Action**: Extract `fn batch_stats(batch: &[PooledBuf]) -> (u64, u64)`.

---

### 3.7 Other deduplication findings

| Pattern | Sites | LOC Saved |
|---------|-------|-----------|
| `await_*_connection` helpers → generic `await_event` | 2 | -14 |
| route.rs `sync_tun_routes` call boilerplate in tests | 22 | -44 |
| route.rs actor-test setup sequence | 5 | -15 |
| route.rs timeout-and-assert sequence | 4 | -12 |
| `tun_mtu + CONNECT_IP_OVERHEAD` computed at 3 production sites | 3 | ~0 (semantic) |
| **Cross-file D total** | | **~183** |

---

## 4. Error Handling & Observability (Category E)

### 4.1 Silent drops (E1) — all sites

| File | Line | Code | Severity |
|------|------|------|----------|
| **tun.rs** | 550 | `send_and_record` return ignored → **infinite loop** | **Critical** |
| **h3listener.rs** | 555 | `let _ = events_tx.send(H3v2Connected)` → orphaned connection | **High** |
| **dns.rs** | 151 | `let _ = events_tx.send(DnsEvent)` → snapshots lost silently | High |
| **orch.rs** | 433 | `let _ = dns_cmd_tx.send()` — inconsistent with other channels | Medium |
| **h3listener.rs** | 443 | `let _ = tx.send(batch)` → per-connection packet drop | Medium |
| **h3listener.rs** | 469 | `let _ = try_send(version_negotiation)` → RFC violation | Medium |
| **h3listener.rs** | 235,247 | `let _ = send_response(400/401)` → rejection delivery unknown | Low |
| **bare.rs** | 223-225 | TX actor exits silently, no final metrics flush | Medium |
| **bare.rs** | 124,229 | events_tx metric sends exit silently | Low |
| **udp.rs** | 140 | output.send failure exits silently | Low |
| **router.rs** | 436,494,519 | `send_and_record` return discarded (3 sites) | Medium |
| **h3engine.rs** | 312-313 | `let _ = events_tx.send(Metrics)` — shutdown only | Low |
| **h3.rs** | 775,972 | metrics channel close → silent actor exit, no log | Low |

---

### 4.2 Logging level issues (E5) — all sites

| File | Line | Current | Recommended | Reason |
|------|------|---------|-------------|--------|
| **h3listener.rs** | 246 | `debug!` | `warn!` | Auth rejection is security-relevant |
| **h3listener.rs** | 423 | `debug!` | `info!` | Token update is operational event |
| **h3listener.rs** | 457 | silent | `debug!` | Non-Initial packet silently dropped |
| **h3listener.rs** | 438 | silent | `debug!` | Header parse failure drops batch |
| **orch.rs** | 143,152,157 | `warn!` | `info!` | Prune is expected lifecycle event |
| **orch.rs** | 755 | `warn!` | `error!` + break | Signal handler failure → process un-killable |
| **orch.rs** | 967 | `warn!` | `error!` | Deprecated event shouldn't occur |
| **h3engine.rs** | 218 | `debug!` | `warn!` | dgram_send unexpected error |
| **h3engine.rs** | 114 | `debug!` | `warn!` | dgram_recv non-Done error |
| **metrics.rs** | 264-297 | `debug!` | `info!` | Periodic metrics summary invisible in production |
| **metrics.rs** | 309 | `.unwrap_or_default()` | `warn!` on error | Collection failure silently swallowed |
| **api.rs** | 424 | `debug!` | `info!` | API connection error |
| **h3dialer.rs** | 79,138,148 | silent | `warn!` | `establish()` error paths have no logging |
| **tun.rs** | 288 | unconditional `warn!` | conditional | Fires even when offload wasn't requested |

---

### 4.3 Magic numbers (E4) — all sites

| File | Line | Value | Meaning |
|------|------|-------|---------|
| **h3engine.rs** | 41-50 | `10_000_000`, `1_000_000`, `100`, `1024` | QUIC transport parameters (7 values) |
| **router.rs** | 109,118 | `20`, `40` | IPv4/IPv6 min header len (constants exist but unused here) |
| **h3listener.rs** | 398 | `Duration::from_secs(1)` | CID cleanup interval |
| **dns.rs** | 309 | `Duration::from_secs(3600)` | Disabled refresh placeholder |
| **dns.rs** | 385 | `u32::MAX` | IP literal "infinite TTL" |
| **route.rs** | 205 | `30` | Max prefix len with broadcast routes |
| **udp.rs** | 202-205 | `65535`, `20`, `8` | IP/UDP protocol constants |
| **h3.rs** | 121,911 | `error_code: 0` | QUIC NO_ERROR |
| **h3session.rs** | 234 | `/ 4` | Quarter Stream ID (RFC 9297) |
| **h3session.rs** | 24 | `86400` | Sentinel timeout (one day) |

---

## 5. Naming & Expression Clarity (Category C)

### 5.1 Highest impact

| Finding | File | Line(s) | LOC Impact |
|---------|------|---------|------------|
| 3× `from_metrics` constructors fully duplicated → `base_labels` helper | api.rs | 221-321 | -20 |
| bind.rs route sort opaque tuple `(u8, bool, Option<u32>, u32)` → `RouteCandidate` struct | bind.rs | 521-539 | +12 |
| `filter_preferred_interfaces` over-general for single-element use → simplify | bind.rs | 480-502 | -17 |
| `orch.rs` `try_connect` bare/h3 branches ~35 lines duplicated error handling | orch.rs | 219-288 | -12 |
| `dns.rs` `ipv4_from_rdata`/`ipv6_from_rdata` trivial wrappers → inline | dns.rs | 627-634 | -8 |
| `h3dialer.rs` `start_h3_session` trivial 1-line wrapper → inline | h3dialer.rs | 159-166 | -6 |
| `h3session.rs` `mark_connect_accepted` single-line setter → inline | h3session.rs | 86-88 | -4 |
| `config.rs` `ValidationErrors::Display` manual `first` boolean → iterator | config.rs | 383-395 | -4 |

### 5.2 Nesting issues (C2)

| File | Line(s) | Max Depth | Fix |
|------|---------|-----------|-----|
| h3dialer.rs `establish` | 75-152 | 7 levels | Extract `handle_startup_recv` method |
| h3listener.rs `accept` select arm | 293-314 | 5 levels | Extract `poll_accept_session` helper |
| router.rs `handle_ingress_batch` | 492-538 | 4 levels | Early `continue` for TUN-dest path |
| config.rs `validate_peers` | 641-677 | 4 levels | Extract `validate_peer_h3` function |
| h3session.rs `poll_h3_events` Accept handler | 139-149 | 5 levels | `let-else` on `HeaderAction::Accept` |

### 5.3 All other naming findings

| Finding | File | LOC |
|---------|------|-----|
| `api.rs:445` `base == "/"` is dead code after `trim_end_matches('/')` | api.rs | 0 |
| `api.rs` `response` → `text_error_response`, `store` → `snapshot`, `field` → `extractor` | api.rs | 0 |
| `orch.rs` `H3v2ConnectedEvent` → `H3ConnectedEvent` | events.rs | -30 |
| `orch.rs` `BoundState` → `ActiveConn` | orch.rs | 0 |
| `orch.rs` `peer_dns_hostname` inconsistent placement | orch.rs | 0 |
| `orch.rs` `collect_metrics_snapshot` repeated `if let Some(ref m)` → iterator chain | orch.rs | -3 |
| `orch.rs` `handle_delete_config` mutable `changed` flag → count comparison | orch.rs | -1 |
| `h3listener.rs` `maybe_pkt` misnames a batch → `maybe_batch` | h3listener.rs | 0 |
| `h3listener.rs` `hdr_ty`/`hdr_version` redundant prefix on `ServerPacketHeader` | h3listener.rs | 0 |
| `h3listener.rs` `channels` is a vague alias → destructure `DispatchIo` | h3listener.rs | -2 |
| `h3listener.rs` `rand::Rng` imported but `fill_bytes` from `RngCore` used → use `Rng::fill` | h3listener.rs | 0 |
| `h3.rs` `find_header_value` not reused for `:status` lookup | h3.rs | -4 |
| `h3.rs` duplicated error-response-and-close pattern (2 sites) | h3.rs | -8 |
| `h3.rs` three Options vs single tuple (client/server inconsistency) | h3.rs | -8 |
| `h3.rs` `matches!` guard + dead `else` branch | h3.rs | -3 to -5 |
| `h3.rs` duplicate `DialError`/`ListenerError` across modules | h3.rs | 0 to -15 |
| `tun.rs` `ok_count`/`ok_bytes` misleading on error path → `accepted_*` | tun.rs | 0 |
| `tun.rs` `offload` → `offload_enabled` | tun.rs | 0 |
| `udp.rs` `max_udp_payload` name shadowed with different meaning | udp.rs | 0 |
| `router.rs` `handle_output_batch`/`handle_ingress_batch` naming mismatch | router.rs | 0 |
| `config.rs` `s != s.trim()` repeated 4× → extract helper | config.rs | +3 |
| `config.rs` `peer.id.clone()` repeated 13× → bind once at loop top | config.rs | -10 |
| `config.rs:278,284` "client/server" → "dialer/listener" | config.rs | 0 |
| `route.rs` `make_route` → `RouteActor::new()` | route.rs | 0 |
| `route.rs` `PlatformIfIndexResolver::resolve` → inline `resolve_ifindex` | route.rs | -6 |
| `actor.rs` `ActorKind` → `SupervisionPolicy` | actor.rs | 0 |
| `events.rs` `Endpoint` → `TransportEndpoint` | events.rs | 0 |
| `auth.rs` `generate_bearer_auth` → `bearer_auth_header` | auth.rs | 0 |
| `small files` `test_packets` module misplaced in helpers.rs | helpers.rs | 0 (move) |

---

## 6. Visibility Narrowing (A4)

All items below are `pub` but only used within the crate — should be `pub(crate)`:

| File | Items |
|------|-------|
| events.rs | `Endpoint`, `DialContext`, `ConnOrigin`, `H3v2ConnectedEvent`, `ApiEvent`, `DialFailedEvent`, `BareConnectedEvent`, `H3ConnectedEvent`, `DnsEvent` (9 types) |
| config.rs | `parse_dns_server_uri`, `parse_h3_uri`, `parse_api_uri`, `parse_udp_uri` (4 functions) |
| h3.rs | All pub items — entire deprecated module (12+ items) |
| h3engine.rs | `collect_router_ingress`, `handle_router_egress` (2 functions) |
| h3listener.rs | `ServerError` (1 enum) |
| h3session.rs | `mark_connect_accepted`, `connect_ready` (2 methods), `connect_accepted` (1 field) |
| bind.rs | `make_udp_socket_raw`, `select_bind_interface`, `bind_to_device`, `interface_index`, `Domain` re-export (5 items) |
| bare.rs | `spawn_bare_tx` (1 function) |
| tun.rs | `TunReader`, `TunWriter`, `TunError` (3 types) |
| actor.rs | `ActorKind` (1 enum) |
| api.rs | `make_api`, `spawn_api` (2 functions) |

---

## 7. Type & API Refinement (Category B) — Full Coverage

### High Priority

| Finding | File(s) | Pattern | Detail |
|---------|---------|---------|--------|
| `h3_insecure_skip_verify` + `h3_trusted_ca` → `TlsVerifyMode` enum | config.rs, h3dialer.rs, h3.rs | B4 | Eliminates invalid state (`insecure=true` + `ca=Some`), removes double negation `!insecure_skip_verify` at 2 call sites |
| `ConnParams` redundant projection → store `Tuning` directly | h3listener.rs | B1 | Removes 12 lines of field shuffling |
| `RouterHandles` tuple → named struct | router.rs | B1 | Two same-typed `Sender<Vec<PooledBuf>>` — silent swap risk |
| `RouteProbe::probe_interfaces` `&str` → `IpAddr` | bind.rs | B1 | Eliminates `to_string()`/`parse()` round-trip and `InvalidTarget` error variant |
| `auth.rs` error type `&'static str` → `AuthError` enum | auth.rs | B1 | Enables programmatic error matching instead of string comparison |

### Medium Priority

| Finding | File(s) | Pattern | Detail |
|---------|---------|---------|--------|
| `DnsActor` 5 loose Duration fields → `DnsTuning` sub-struct | dns.rs | B1 | Mirrors `ConnParams` pattern, eliminates field-by-field extraction |
| `socket_buffer_size` stored in MiB → store as bytes at deserialization | config.rs, bind.rs | B1 | Removes `socket_buffer_bytes()` method and 8+ call-site conversions |
| `DialError::Socket(String)` erases `io::Error` → wrap directly | h3dialer.rs | B7 | Preserves source error chain for downstream handling |
| `H3Engine.session: Option<H3Session>` → builder/runtime split | h3engine.rs | B2 | Eliminates `.expect()` panic at runtime; clarifies API contract |
| `tun_mtu` stored as `usize` (from `u16`) → keep as `u16` | events.rs, orch.rs | B1 | Removes ~8 `as` casts across 5 files |
| `UdpTx.enable_offload` → pre-computed `max_gso_segments` | udp.rs | B4 | Eliminates boolean conditional, makes struct self-describing |
| TunReader/TunWriter `offload: bool` → pre-computed capacities | tun.rs | B4 | Reduces 3 of 5 `if self.offload` branches to field access |
| `route_match` anonymous tuple → `RouteCandidate` struct | bind.rs | B1 | Sort with `.0`, `.1`, `.2`, `.3` → named fields |
| `h3_cc_algorithm: String` → `CcAlgorithm` enum | config.rs | B1/J1 | Moves validation to deserialization, eliminates runtime error path |
| Repeated label base fields → `base_labels()` helper | api.rs | B1 | -16 LOC from 3 duplicated constructors |
| Magic numbers in `apply_transport_config` → named constants | h3engine.rs | B1 | 7 inline transport params → discoverable constants |

### Low Priority

| Finding | File(s) | Pattern |
|---------|---------|---------|
| `DnsActor::server` derivable from `socket.peer_addr()` | dns.rs | B3 |
| `ResolveInitError` single-variant enum → struct wrapping `io::Error` | dns.rs | B3 |
| `RouteSyncError::InterfaceLookup::error` always static string → remove | route.rs | B2 |
| `socket_buffer_bytes` sentinel `0` → `Option<NonZeroUsize>` | bind.rs | B1 |
| `TunError::DeviceBuild(String)` erases `tun_rs::Error` | tun.rs | B7 |
| `expand_allowed_prefixes` logs warning inside pure function | route.rs | B7 |
| `select_bind_interface` embeds 4 warnings → return richer result | bind.rs | B7 |
| `ConnectFailure::Closed`/`Poll` handled identically → merge to `Failed` | h3session.rs | B7 |
| `SendEvent::Full` ignored by 2/3 call sites | helpers.rs | B7 |
| `H3Listener.bound_addr` cached from `socket` (deprecated module) | h3.rs | B3 |
| `h3_insecure_skip_verify` double-negative → rename to `h3_verify_peer` | config.rs | B4 |
| `LoopExit::Err { reason: String }` loses structure | h3engine.rs | B7 |
| main.rs, lib.rs — no types relevant to B-category (confirmed clean) | main.rs, lib.rs | — |

---

## 8. Test Quality (Category G) — Full Coverage

### High Priority

| Finding | File | Lines | Detail |
|---------|------|-------|--------|
| OpenMetrics text validated by `contains("100")` — false positives from unrelated numbers | api.rs | 639-854 | `text.contains("100")` matches "51000", "1001", etc. Introduce `find_metric_value` structured helper |

### Medium Priority

| Finding | File | Lines | Detail |
|---------|------|-------|--------|
| `make_h3_dispatcher_rejects_missing_cert` `is_err()` without `ServerError::Config` check | h3listener.rs | 752 | 3 possible error variants |
| UDP handles silently discarded in shutdown tests (2 sites) | h3listener.rs, h3dialer.rs | 1261, 755 | `let _ = timeout(handle).await` |
| `try_recv().is_err()` doesn't distinguish `Empty` vs `Disconnected` | router.rs | 780, 848 | Use `assert_eq!(try_recv(), Err(TryRecvError::Empty))` |
| IPv6 tests pass vacuously when IPv6 unavailable (3 sites) | bind.rs | 843-953 | Zero assertions on the `Err` path |
| `spawn_route_returns_working_cmd_tx` doesn't verify processing | route.rs | 914-927 | Only checks channel send, not actor action |
| `spawn_tun_tx_returns_working_input_tx` never verifies packet reached TUN | tun.rs | 963-966 | Checks `is_ok()` but ignores `output_rx` |
| `memory_tun_rx_recv_batch_channel_closed` `is_err()` without `ErrorKind` | tun.rs | 1056 | Should assert `UnexpectedEof` |
| 3× serde rejection tests `is_err()` without checking message | api.rs | 764, 778, 801 | Could pass for wrong reason |
| `apply_transport_config_rejects_bad_cc` `is_err()` without quiche error variant | h3engine.rs | 541 | Should match specific `quiche::Error` |
| Zero-assert tests in orch.rs (2 sites) | orch.rs | 1784-1803, 2623-2631 | "Doesn't crash" only |
| `orch.rs:2078,2294` `try_recv().is_ok()` discards command variant | orch.rs | 2078, 2294 | Could receive wrong command |

### Low Priority

| Finding | File | Lines |
|---------|------|-------|
| `validate_server_connect_headers` rejection tests don't check message (2 sites) | h3listener.rs | 696, 706 |
| `validate_server_auth` rejection doesn't verify error string | h3listener.rs | 730 |
| Redundant `assert!(is_ok())` + `.unwrap()` → collapse to `.expect()` | bind.rs, h3listener.rs | various |
| `log_transport_metrics` smoke tests have zero assertions (2 sites) | metrics.rs | 409-446 |
| `poll_h3_events` result discarded in test setup with `let _ =` | h3session.rs | 868 |
| Consumed DNS snapshots not verified | dns.rs | 1259, 1265 |
| `ConnectFailure::Rejected` tested with `contains()` instead of `assert_eq!` | h3session.rs | 897-899 |
| String-based operation log could use structured `Op` enum | route.rs | various |
| Hand-rolled IPv4 checksum undocumented IHL=5 assumption | router.rs | 965-974 |
| Misleading test name (can't inspect opaque config) | h3dialer.rs | 440 |
| `default_filter_parses` in main.rs is pure "doesn't crash" test | main.rs | 124-130 |
| 10× `assert!(result.is_err())` without checking error variant across config.rs/h3.rs/orch.rs | various | various |
| `DropReason::NoPeerChannel` dead enum variant (never constructed) | metrics.rs | 59 |
| `CongestionStats::record_would_block` has no production callers | metrics.rs | 94-98 |
| h3session.rs test duplicates `apply_transport_config` (14 lines) | h3session.rs | 543-574 |
| `auth.rs:77` redundant `assert!(result.is_err())` before `assert_eq!` | auth.rs | 77 |
| events.rs, lib.rs — no test code (N/A) | events.rs, lib.rs | — |
| helpers.rs, actor.rs — test quality solid, no findings | helpers.rs, actor.rs | — |

---

## 9. Redundant Derives & Serde (A5)

| Finding | File | Line(s) |
|---------|------|---------|
| Redundant `#[serde(default)]` on `Tuning::h3_insecure_skip_verify` | config.rs | 290 |
| Redundant `#[serde(default)]` on `Tuning::h3_trusted_ca` | config.rs | 298 |
| Unused `Clone` on `DispatcherCommand` | h3listener.rs | 133 |
| Unused `Clone` on `H3ListenerCommand` | h3.rs | 1011 |
| Unused `Clone` on `BareUdpRxCommand` | bare.rs | 22 |
| Unused `PartialEq`+`Eq` on `RouteEntry` (-7 LOC impl) | router.rs | 158-164 |
| Unused `Default` impl on `RoutingTable` (-5 LOC) | router.rs | 191-195 |
| Unused `Clone` on `RoutingTable`, `RouteEntry`, `RouteMatch` | router.rs | 142, 178, 167 |
| Unused `PartialEq`+`Eq`+`Clone` on `RoutingError` | router.rs | 315 |
| Unused `Clone`+`Copy`+`Default` on `DefaultRouteProbe` | bind.rs | 324 |
| Unused `Clone`+`Copy`+`Default` on `PlatformIfIndexResolver` | route.rs | 30 |

---

## 10. Stale Documentation (A2)

| Finding | File | Line(s) |
|---------|------|---------|
| 6 orphaned "Note: test removed" changelog comments | orch.rs | 1440-1461, 1967-1969 |
| Historical "Note: InvalidServer variant removed" | dns.rs | 189 |
| Historical "Note: InvalidAddress variant removed" | tun.rs | 481 |
| `h3.rs` module doc omits deprecated status | h3.rs | 1-12 |
| `bind.rs` module doc scoped to "DNS sockets" but serves all UDP | bind.rs | 1 |
| `bare.rs` `spawn_bare_tx` rustdoc lists deleted parameters | bare.rs | 199-200 |
| `config.rs:278,284` uses "client/server" instead of "dialer/listener" | config.rs | 278, 284 |

---

## 11. Category H — Structural Collapse (Tier 3)

**Reviewed by**: 10 opus agents covering all 22 files. Total findings: ~25.

### 11.1 H1: h3.rs Is a Complete Parallel Hierarchy (-2228 LOC)

The entire `h3.rs` module is an isomorphic parallel implementation of the same HTTP/3 CONNECT-IP protocol as `h3dialer/h3listener/h3engine/h3session`. It uses tokio-quiche high-level API while the production stack uses raw quiche. `orch.rs:964-971` explicitly ignores `Event::H3Connected`. All `pub` items have zero production callers. Duplicated types include `DialError`, `ListenerError`, `H3Connection`, `H3ListenerCommand`, `validate_connect_ip_headers`, `make_quic_settings`, etc.

**Action**: Delete h3.rs, migrate interop tests to use production h3listener/h3dialer against each other. Remove `H3ConnectedEvent`, `Event::H3Connected` from events.rs/orch.rs.

### 11.2 H4/H1: Duplicate Handshake Loops `establish` vs `accept` (-50–60 LOC)

`h3dialer.rs:60-153` (`establish`) and `h3listener.rs:218-336` (`accept`) share identical `tokio::select!` scaffolding: timer arm (`conn.on_timeout()`), deadline arm (`conn.close + flush_send`), post-select tail (`flush_send + reset_timer + is_closed`). Only the header handler closure differs.

**Action**: Extract `H3Engine::run_handshake<F,E>(timeout, header_handler)` into `h3engine.rs`. Both callers become thin wrappers. Also unify `DialError`/`ServerError` into a shared `H3SetupError` and extract `make_base_quiche_config` for the common `Config::new + apply_transport_config` prefix.

### 11.3 H3: Redundant Types and Wrappers

| Finding | File(s) | LOC Impact |
|---------|---------|------------|
| `H3Endpoint` / `ApiEndpoint` structurally identical; 3 duplicate serde impls + parse functions | config.rs:762-961 | -60–80 |
| 3 newtype label wrappers (`SourceLabel`, `DirectionLabel`, `DropReasonLabel`) — orphan rule allows direct impl | api.rs:263-348 | -85 |
| 3 near-identical label set structs with duplicated `from_metrics` | api.rs:211-322 | -45 |
| `LocalBare`, `LocalApi`, `PeerTun` single-field wrappers | config.rs | -30 |
| `serde_duration_secs` / `serde_duration_millis` isomorphic modules | config.rs:339-366 | -20 |
| `LoopExit` trivial enum wrapping `Result<(), String>` | h3engine.rs:269-285 | -50 |
| `ActorKind` two-variant boolean discriminant | actor.rs:17-26 | -10 |
| `ConnectProgress` boolean enum (borderline) | h3session.rs:196-201 | -6 |
| `ResolveInitError` single-variant = `UdpError::Socket` | dns.rs:186-192 | -12 |
| `BareUdpRxCommand` single-variant enum | bare.rs:22-29 | -6 |
| `RouterCommand` / `RouteCommand` single-variant enums | router.rs:334-341, route.rs:65-76 | -15 |
| `RouterHandles` positional tuple with same-typed senders | router.rs:343-349 | 0 (safety) |
| `RouteActor` + `make_route` unnecessary two-phase struct | route.rs:79-101 | -20 |
| `ConnParams` mirrors `Tuning` fields 1:1 | h3listener.rs:353-358 | -12 |
| `DispatchIo` trivial clone-wrapper | h3listener.rs:342-350 | -8 |
| Dead `Event::H3Connected` + `H3ConnectedEvent` | events.rs, orch.rs | -30 |
| `ConnectFailure::Closed` / `::Poll` always handled identically | h3session.rs:206-222 | -4 |

### 11.4 H2: Intermediate Actors

`spawn_bare_tx` (`bare.rs:201-239`) is a pure receive-tag-forward actor: stamps a fixed `destination` address onto batches. Could be inlined by having the router send `(SocketAddr, Vec<PooledBuf>)` directly. **-40 LOC.**

### 11.5 H1 Cross-File: Metrics Ticker Duplication

The `ticker.tick() => events_tx.send(Event::Metrics(counters.snapshot(...)))` arm appears identically 4 times across `tun.rs` (×2) and `bare.rs` (×2). Extract a `emit_metrics` helper. **-16 LOC net.**

---

## 12. Category I — Simplification by Domain Insight (Tier 3)

**Reviewed by**: 10 opus agents. Most files are clean. Key findings below.

### 12.1 I1: Unnecessary Complexity

| Finding | File | LOC |
|---------|------|-----|
| `is_dgram_recv_queue_full` pre-check in `handle_udp_recv` is inaccurate (not every `recv` adds a datagram) | h3engine.rs:63-82 | -10 |
| Three separate `Option` fields for atomically-delivered `NewFlow` event | h3.rs:582-584 | -8 |
| Redundant `pending_sender` + dead `let-else` guard in server handshake | h3.rs:211-311 | -10 |
| `ServerPacketHeader` struct for single-use parse-then-destructure | h3listener.rs:191-209 | -12 |
| Version negotiation path unreachable in closed-mesh VPN | h3listener.rs:461-472 | -9 |
| `ConnectFailure::Closed`/`::Poll` never distinguished by any consumer | h3session.rs:206-222 | -4 |

### 12.2 I2/I3/I4: Already Well-Implemented

| Pattern | Status |
|---------|--------|
| **I2 (Declarative State)** | DNS uses full-snapshot `DnsEvent`, no `prev_snapshot` or `compute_diff` anywhere. orch.rs `update_routing` rebuilds table from scratch. |
| **I3 (Periodic Snapshots)** | All actors emit `Event::Metrics(counters.snapshot(...))` on timer ticks. DNS uses dirty-flag + debounce timer. No per-packet events. |
| **I4 (Built-in Identity)** | `same_channel()` for connection identity. Peer identity via config-provided `peer_id`. No custom ID counters. |
| **I4 (router.rs)** | Unused `PartialEq`/`Eq` impl on `RouteEntry` (lines 157-163) — custom identity never invoked; direct `peer_id` comparison used instead. Should remove. |

---

## 13. Category J — Type-Level Enforcement (Tier 3)

**Reviewed by**: 10 opus agents. Key findings below.

### 13.1 J1: Parse at Deserialization, Not at Runtime

| Finding | File | Severity |
|---------|------|----------|
| `h3_cc_algorithm: String` validated at runtime against hardcoded list; should be `CcAlgorithm` enum with `Deserialize` | config.rs:279 | **High** |
| `h3_insecure_skip_verify: bool` + `h3_trusted_ca: Option<String>` encode a 3-variant `TlsVerifyMode` enum; admits invalid combo | config.rs:291,299 | Medium |
| `LocalH3.cert`/`.key` are `String` paths validated only for emptiness | config.rs:57-58 | Low |
| Endpoint `host: String` parsed to `IpAddr` at runtime in multiple places | config.rs:763,792,835 | Low |

### 13.2 J2: Vec→Option When "At Most One" Is an Invariant

`H3v2ConnectedEvent.handles: Vec<JoinHandle>` (`events.rs:87`) is always either empty (server) or exactly 3 elements (client). Consumers use `.next().unwrap()` positionally. Should be `Option<(JoinHandle, JoinHandle, JoinHandle)>` or a named struct.

`ConnectIpDatagramCodec.qsi_bytes: Vec<u8>` (`h3session.rs:229`) has max length 8 (QUIC varint). Could be `[u8; 8]` + length byte.

### 13.3 J3: Make/Spawn Two-Phase Initialization

| Finding | Status |
|---------|--------|
| `accept_and_spawn` runs fallible QUIC handshake inside detached `tokio::spawn`; errors logged but not propagated to dispatcher | h3listener.rs:540-567, **Medium** |
| `H3Engine.session: Option<H3Session>` with runtime `.expect()` in `run()` — typestate split would eliminate panic path | h3engine.rs:325,377, **Medium** |
| All other actors (tun, bare, udp, dns, route, api) — correctly separated | Clean ✅ |

---

## 14. Category K — Data Layout Optimization (Tier 3)

**Reviewed by**: 10 opus agents. Key findings below.

### 14.1 K1: Hot-Path HashMap

| Finding | File | Impact |
|---------|------|--------|
| `drop_reasons: HashMap<DropReason, PktCounters>` on every packet-drop; 11-variant closed enum should be inline `[PktCounters; 11]` array | metrics.rs:133 | Eliminates hashing + heap alloc on hot path |
| `HashMap<Labels, Metrics>` duplicates `Labels` in key and value; `Metrics` already contains `labels: Labels` | api.rs:51, orch.rs:377 | Redundant alloc on every snapshot |

### 14.2 K1 Already Correct

`RouteEntry` embeds TX sender directly in the LPM trie (`router.rs:142-147`). Single trie lookup yields the sender — no secondary HashMap on the packet forwarding path. DNS `HostnameState` co-locates IPs, pending queries, and refresh scheduling per hostname.

### 14.3 K3: Bundle Common Parameters

| Finding | File | Params | Note |
|---------|------|--------|------|
| `try_connect` 8 params with `#[allow(clippy::too_many_arguments)]`; internally builds `DialContext` from 7 of them | orch.rs:179 | 8 | Should accept pre-built `DialContext` |
| `make_h3_dispatcher` 8 params with clippy suppression; no server-side context struct (asymmetric with `DialContext`) | h3listener.rs:145 | 8 | Create `ListenerContext` |
| `spawn_bare_rx` 7 params with clippy suppression; `DialContext` fields passed individually | bare.rs:52 | 7 | Reuse or extend `DialContext` |
| Socket creation functions thread `(tun_if, bind_interface, probe, socket_buffer_bytes)` through 3 layers | bind.rs | 5 | Extract `SocketContext` |
| `spawn_bare_tx` caller destructures `DialContext` to pass fields individually | bare.rs:201 | 5 | Accept `&DialContext` |

---

## 15. Areas Already Well-Implemented (No Violations)

| Category | Assessment |
|----------|-----------|
| **M (Channel & Batch Design)** | All data-plane channels use `Vec<PooledBuf>` batches. Zero per-item sends. |
| **N (Concurrency Model)** | Zero `Arc<Mutex>`. `current_thread` runtimes with `DedicatedRuntime`. Thread-per-core correctly applied. |
| **M3 (Actor Lifecycle)** | `CancellationToken` for I/O-blocked UDP RX, channel-close for all queue-draining actors. |
| **K1 (Router Co-location)** | `RouteEntry` already embeds TX channel alongside peer_id in trie. DNS `HostnameState` co-locates all per-hostname data. |
| **L1/L3 (Zero-Copy & Dual Pool)** | `TunBuf` headroom, `alloc_packet_buf`, dual-pool with threshold — all correctly implemented. |
| **B5 (deny_unknown_fields)** | All 12 config structs have `deny_unknown_fields` with tests. |
| **I2/I3 (Declarative State)** | DNS uses snapshot-based approach. Metrics use periodic timer snapshots. No diff-based processing anywhere. |
| **I4 (Identity Tracking)** | `same_channel()` for connection identity. No custom ID counters. |
| **H4/H5 (Orchestrator Loop)** | Orchestrator has single `tokio::select!` loop, no sequential phase duplication. |
| **J3 (Make/Spawn)** | All infrastructure actors (tun, bare, udp, dns, route, api) correctly separate fallible `make_*` from infallible `spawn_*`. |

---

## 16. Overall Assessment

| Dimension | Rating |
|-----------|--------|
| **Architecture** | Good: actor model, thread-per-core, batch channels correctly implemented |
| **Largest tech debt** | `h3.rs` 2228 LOC deprecated code; ~183 LOC cross-file test boilerplate |
| **Highest risk** | auth.rs timing side-channel; TUN RX infinite loop bug; stale routes after peer deletion |
| **Greatest observability gap** | bare.rs + udp.rs with zero tracing; metrics summary at debug level |
| **Tier 3 structural debt** | H4 handshake loop duplication (~50 LOC); H3 wrapper types (~400 LOC); K3 parameter bundling (4 clippy suppressions) |
| **Type-safety gaps** | J1 `h3_cc_algorithm: String`; J2 `handles: Vec` as positional tuple; J3 accept handshake error swallowing |
| **Estimated eliminable LOC** | ~2800+ (h3.rs + H3 wrappers + H4 dedup) or ~600 (without h3.rs) |

---

## 17. Coverage Matrix

All 22 source files × categories A through N. ✅ = reviewed with findings or confirmed clean.

| File (LOC) | A | B | C | D | E | F | G | H | I | J | K | L | M/N |
|------------|---|---|---|---|---|---|---|---|---|---|---|---|-----|
| orch.rs (2960) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| config.rs (2561) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| h3.rs (2228) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| h3listener.rs (1266) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| dns.rs (1277) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| api.rs (1259) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| tun.rs (1214) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | |
| bind.rs (1134) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| router.rs (1048) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| route.rs (953) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| h3session.rs (907) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| h3dialer.rs (844) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| h3engine.rs (608) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | ✅ |
| metrics.rs (508) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | ✅ |
| bare.rs (492) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | |
| udp.rs (419) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | |
| helpers.rs (371) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| actor.rs (360) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| events.rs (244) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | | |
| main.rs (131) | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| auth.rs (107) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | |
| lib.rs (36) | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | ✅* | ✅ | ✅ | ✅ | ✅ | | |

✅ = reviewed with findings or confirmed clean. ✅* = confirmed not applicable.

**Method**: A–G reviewed by 67 agents (prior session). H/I/J/K reviewed by 40 opus agents (this session). Total: 107 review agents across all categories.
