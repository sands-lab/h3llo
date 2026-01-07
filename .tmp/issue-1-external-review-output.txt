# Implementation Plan: Inline Routing in TUN TX

## Consensus Summary

Eliminate the `spawn_tun_dispatch` coroutine by inlining its routing logic directly into `spawn_tun_tx`, removing one MPSC queue hop and one task spawn. This follows the Reducer's minimalist approach while incorporating the Bold Proposer's performance rationale and the Critique's requirements for proper benchmarking and error handling documentation.

## Goal

Remove the intermediate dispatch coroutine between TUN packet reception and peer transmission by merging routing lookup directly into the TUN TX loop, reducing packet forwarding overhead.

**Success criteria:**
- All packets from TUN device are routed directly to peer TX channels without intermediate queuing
- Existing test suite passes with no regressions
- Measurable latency reduction (benchmark before/after required)

**Out of scope:**
- Module reorganization (routing.rs stays separate)
- Zero-copy optimizations or etherparse integration
- New metrics/DropReason variants (use existing debug! logging)
- Multi-module refactoring or API breaking changes

## Bug Reproduction

**Skip reason:**
- This is a performance optimization and architectural simplification, not a bug fix. No reproduction needed.

## Codebase Analysis

**Files verified (docs/code checked by agents):**
- `src/routing.rs`: Contains RoutingTable with ipnet-trie, RouteEntry, RouteMatch (239 lines) - no changes needed
- `src/tun.rs:220-260`: spawn_tun_tx implementation (40 lines) - will be extended
- `src/orch.rs:500-558`: spawn_tun_dispatch (36 lines) and extract_dst_ip (19 lines) - will be removed
- `docs/internals.md:63-95`: Outbound datapath documentation - needs update

**Files to modify:**
- `src/tun.rs` - Add routing logic to spawn_tun_tx (extend by ~55 LOC)
- `src/orch.rs` - Remove dispatch coroutine and update call sites (~10 LOC added, ~55 LOC deleted)
- `docs/internals.md` - Update architecture diagrams for inlined routing (~20 LOC)

**Files to create:**
- `tests/bench_packet_forwarding.sh` - Benchmark script for latency measurement (~40 LOC)

**Files to delete:**
- None (spawn_tun_dispatch and extract_dst_ip are deleted in-place from orch.rs)

**Current architecture notes:**
- Current flow: TUN-Rx → tun_packet_tx (MPSC) → spawn_tun_dispatch → routing.lookup() → peer_txs (MPSC) → peer TX
- spawn_tun_dispatch is a serial coroutine (awaits on packet_rx.recv()), no parallelism exploited
- Routing table is constructed from peer config in orch.rs and passed to dispatch
- extract_dst_ip uses manual byte slicing (lines 4-6 for IPv4, 24-26 for IPv6)

## Interface Design

**Modified interfaces:**

```rust
// BEFORE (src/tun.rs:220)
pub(crate) fn spawn_tun_tx<T: TunTx>(
    mut tun: T,
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()>

// AFTER (src/tun.rs:220)
pub(crate) fn spawn_tun_tx<T: TunTx>(
    mut tun: T,
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    routing: RoutingTable,
    peer_txs: HashMap<String, mpsc::Sender<Vec<u8>>>,
    events_tx: mpsc::Sender<Event>,
    interval: Duration,
) -> JoinHandle<()>
```

**Removed interfaces:**
```rust
// DELETED from src/orch.rs:500
fn spawn_tun_dispatch(
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    routing: RoutingTable,
    peer_txs: HashMap<String, mpsc::Sender<Vec<u8>>>,
    events_tx: mpsc::Sender<Event>,
) -> JoinHandle<()>

// DELETED from src/orch.rs:538
fn extract_dst_ip(packet: &[u8]) -> Option<IpAddr>
```

**Documentation changes:**
- `docs/internals.md` section "Outbound Datapath" - update to show TUN-Rx performing inline routing

## Documentation Planning

### High-level design docs (docs/)
- `docs/internals.md` — update "Outbound Datapath" section (lines ~63-95) to reflect removal of spawn_tun_dispatch coroutine and inline routing in spawn_tun_tx

### Folder READMEs
- No README changes needed (this is an internal refactoring)

### Interface docs
- No new interface documentation needed (spawn_tun_tx is internal API)

## Test Strategy

**Test modifications:**
- Existing tests in `tests/` should pass unchanged
  - `tests/test-tun.sh` - Verify TUN RX/TX still works
  - `tests/test-routing.sh` - Verify routing table logic unchanged
  - `tests/test-integration.sh` - Verify end-to-end packet forwarding

**New test files:**
- `tests/bench_packet_forwarding.sh` - Benchmark script (Estimated: 40 LOC)
  - Test case: Measure baseline latency before refactoring
  - Test case: Measure latency after refactoring
  - Test case: Calculate and report improvement percentage
  - Test case: Fail if latency increases by >5%

**Test data required:**
- Sample IP packets (IPv4 and IPv6) for benchmarking
- Mock peer configuration for routing table construction
- Expected latency threshold values

## Implementation Steps

**Step 1: Create benchmark infrastructure** (Estimated: 40 LOC)
- Create `tests/bench_packet_forwarding.sh` with baseline latency measurement
- Dependencies: None
- Correspondence:
  - Docs: Addresses Critique's requirement for performance validation
  - Tests: Establishes baseline before any code changes

**Step 2: Update documentation for new architecture** (Estimated: 20 LOC)
- Update `docs/internals.md` section "Outbound Datapath" (lines ~63-95)
  - Remove spawn_tun_dispatch coroutine from diagram
  - Show spawn_tun_tx performing inline routing lookup
  - Update text description to reflect single-hop forwarding
- Dependencies: None (documentation-first approach)
- Correspondence:
  - Docs: Defines the target architecture for implementation
  - Tests: N/A (documentation change only)

**Step 3: Inline routing logic into spawn_tun_tx** (Estimated: 55 LOC)
- File: `src/tun.rs:220-260`
- Changes:
  - Add `routing: RoutingTable` and `peer_txs: HashMap<String, mpsc::Sender<Vec<u8>>>` parameters
  - Inline extract_dst_ip helper function from orch.rs:538-558 (19 lines)
  - Replace packet write loop with routing dispatch logic:
```diff
  tokio::select! {
      maybe_packet = packet_rx.recv() => {
          let packet = match maybe_packet { Some(p) => p, None => break };
-         // Write to TUN device
-         if let Err(e) = tun.write(&packet).await {
-             debug!("Failed to write packet to TUN: {}", e);
-             counters.record_drop(DropReason::TunWriteError, packet.len());
-             continue;
-         }
-         counters.record_success(packet.len());
+         // Extract destination IP (inline from extract_dst_ip)
+         let dest = match extract_dst_ip_inline(&packet) {
+             Some(ip) => ip,
+             None => {
+                 debug!("Invalid packet: unable to extract destination IP");
+                 continue;
+             }
+         };
+         
+         // Routing lookup
+         let route = match routing.lookup(dest) {
+             Some(r) => r,
+             None => {
+                 debug!("No route found for {}", dest);
+                 continue;
+             }
+         };
+         
+         // Dispatch to peer
+         match peer_txs.get(route.peer_id) {
+             Some(tx) => {
+                 if tx.send(packet).await.is_err() {
+                     debug!("Peer channel closed for {}", route.peer_id);
+                 }
+             }
+             None => {
+                 debug!("No peer TX channel for {}", route.peer_id);
+             }
+         }
      }
      _ = ticker.tick() => { /* metrics unchanged */ }
  }
```
  - Add private helper function `extract_dst_ip_inline` inside spawn_tun_tx scope
- Dependencies: Step 2 (documentation defines this behavior)
- Correspondence:
  - Docs: Implements inline routing as described in docs/internals.md update
  - Tests: Will satisfy bench_packet_forwarding.sh latency improvement requirement

**Step 4: Remove spawn_tun_dispatch from orch.rs** (Estimated: -55 LOC deletion, +10 LOC modification)
- File: `src/orch.rs`
- Changes:
  - Delete spawn_tun_dispatch function (lines 500-536) - 36 LOC deleted
  - Delete extract_dst_ip helper (lines 538-558) - 19 LOC deleted
  - Update run_bare() to pass routing and peer_txs to spawn_tun_tx (line ~160-170):
```diff
  let tun_tx_handle = spawn_tun_tx(
      tun_tx,
      tun_packet_rx,
+     routing.clone(),
+     peer_txs.clone(),
      events_tx.clone(),
      Duration::from_secs(5),
  );
- 
- let dispatch_handle = spawn_tun_dispatch(
-     tun_packet_rx,
-     routing,
-     peer_txs,
-     events_tx.clone(),
- );
```
  - Remove dispatch_handle from JoinSet (line ~170)
- Dependencies: Step 3 (spawn_tun_tx must accept new parameters first)
- Correspondence:
  - Docs: Completes the architecture change documented in Step 2
  - Tests: Existing integration tests verify correct behavior

**Step 5: Run benchmark and validate improvement** (Estimated: 0 LOC - execution only)
- Execute `tests/bench_packet_forwarding.sh` after implementation
- Compare before/after latency measurements
- Document actual improvement percentage in commit message
- Dependencies: Steps 3, 4 (implementation must be complete)
- Correspondence:
  - Docs: Validates performance claims from docs/internals.md rationale
  - Tests: bench_packet_forwarding.sh produces measurement report

**Total estimated complexity:** ~70 LOC net change (Small-Medium feature)
- Added: ~55 LOC (routing logic in spawn_tun_tx) + ~40 LOC (benchmark) + ~20 LOC (docs)
- Deleted: ~55 LOC (spawn_tun_dispatch + extract_dst_ip)
- Net implementation: +10 LOC, Net total with docs/tests: +60 LOC

**Recommended approach:** Single session implementation
**Milestone strategy:** Not needed - small enough for single commit

## Success Criteria

- [ ] All existing tests in `tests/` pass without modification
- [ ] `tests/bench_packet_forwarding.sh` shows measurable latency reduction (target: 10-20%, acceptable: any improvement)
- [ ] No increase in packet drop rate observed in integration tests
- [ ] Documentation in `docs/internals.md` accurately reflects new architecture
- [ ] Code compiles with no warnings
- [ ] spawn_tun_dispatch and extract_dst_ip fully removed from orch.rs

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Performance improvement less than expected (Critique: 30-50% claim unverified) | Medium | Low | Benchmark before/after; document actual improvement; success = any measurable gain |
| Peer channel closure causes packet loss | Low | Medium | Use existing debug! logging for failures; document behavior: "continue processing other peers on channel close" |
| Test complexity underestimated (Critique: need routing mock) | Low | Low | Existing tests use real RoutingTable; no mocking needed for this refactor |
| Latency actually increases due to routing overhead | Low | High | Benchmark will catch this; revert if no improvement; Critique expects 10-20% gain, not 30-50% |

## Dependencies

**External crates (no changes):**
- `ipnet` and `ipnet-trie` - already used by routing.rs
- `tokio::sync::mpsc` - already used throughout
- `std::collections::HashMap` - standard library

**Internal modules:**
- `src/routing.rs` - used but not modified
- `src/events.rs` - Event type used but no new variants added
