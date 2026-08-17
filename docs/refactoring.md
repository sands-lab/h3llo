# Refactoring Pattern Library

Battle-tested refactoring strategies extracted from this codebase's commit history. Each pattern includes a recognizable signal and expected impact. Organized in three tiers by effort/risk.

## Tier 1 — Code Hygiene

Anti-patterns that should never be introduced. Flag any code change that creates these.

### A. Code Hygiene

**A1. Dead Code Accumulation**
- Unused imports, orphaned rustdoc for deleted functions, dead enum variants (`Other`/`Unknown` never matched), unused struct fields, unused builder methods, stale `#[allow(dead_code)]`.
- Signal: Items that survive refactoring but lose all callers; `Event::Other` variants that are unreachable; doc comments describing behavior that no longer exists.
- Impact: -1 to -10 LOC each, but accumulates to -50+ LOC in sweeps.

**A2. Stale Documentation**
- Rustdoc describing deleted behavior, hardcoded line number references, inaccurate adjectives (e.g., "unique" when now "random"), comments referencing old code structure.
- Signal: Doc comments that mention function names no longer present; line-specific references like "logged at line 557 of dns.rs"; documentation of fields/parameters that were renamed or removed.
- Impact: Stale docs are worse than no docs — they actively mislead.

**A3. Redundant Type Conversions**
- `.into()` where source and target types are identical; double `Url::parse()` calls; double YAML/JSON parsing when once suffices; `Duration::from_secs(config.timeout_secs)` repeated at 7+ call sites instead of storing `Duration` directly.
- Signal: Identity `.into()` calls; two parse calls for the same input in different functions; the same `T::from(config.field)` repeated across multiple call sites.
- Impact: -1 to -10 LOC per instance; see also B1 for the systematic fix.

**A4. Over-Broad Visibility**
- `pub` or `pub(crate)` on items used only within the same module. Creates implicit API surface that constrains future refactoring.
- Signal: `pub const` used only in the defining module; `pub(crate) fn` with a single caller in the same file.
- Impact: Net 0 LOC but reduces maintenance surface area.

**A5. Redundant Serde/Derive Attributes**
- Field-level `#[serde(default = "...")]` when struct-level `#[serde(default)]` already covers all fields; orphaned default functions after field removal.
- Signal: Every field in a struct has its own `#[serde(default)]` but the struct itself also has one; `fn default_*()` functions with zero callers.
- Impact: -1 to -5 LOC per struct.

## Tier 2 — Bread-and-Butter

Routine, low-risk patterns. Each typically yields -5 to -50 LOC.

### B. Type & API Refinement

**B1. Richer Types at Config Boundary**
- Config fields use primitives (`u64` for durations, `IpAddr` for networks, `Option<String>` for required fields) requiring repeated conversion at every usage site.
- Fix: Change to domain types (`Duration`, `IpNet`, `String`) with serde helpers. Delete all downstream conversion code.
- Signal: `Duration::from_secs(config.field)` at 3+ call sites; `IpNet::new(addr, 32)` at 2+ call sites; `config.field.as_ref().map(|x| !x.trim().is_empty()).unwrap_or(false)` chains.
- Impact: -50 to -135 LOC from cascading simplification. Extends J1 (parse at deserialization) to non-string types.

**B2. Eliminate Unnecessary Option Wrappers**
- `Option<T>` on fields where the value is always present at runtime. Every usage site must `.is_some()`/`.as_ref()`/`.unwrap()`.
- Fix: Remove `Option`. If the value is always constructed, make it non-optional.
- Signal: Fields that are `Option` only because initialization order was unclear during initial design; `.unwrap()` with a "we know this is Some" comment; all code paths that check `.is_some()` always take the same branch.
- Impact: -5 to -35 LOC from removing 6+ conditional check sites.

**B3. Remove Cached/Derived Struct Fields**
- Struct fields that are trivially derived from another field already in scope (e.g., `self.metrics_interval` cached from `self.tuning.metrics_interval`).
- Signal: A field whose value is always `some_fn(self.other_field)`; fields set in constructor but never independently mutated.
- Impact: -5 to -15 LOC, eliminates sync bugs between cached and source.

**B4. Boolean Feature Flag → Capability Queries**
- A boolean `supports_offload()` that callers interpret differently at each call site (different buffer sizes, batch counts, code paths).
- Fix: Replace with query methods returning actual values (`batch_size()`, `hdr_offset()`, `scratch_buf_size()`). Push platform decisions into trait impls.
- Signal: `if supports_x() { ... } else { ... }` at 3+ call sites with different logic in each branch; `#[cfg]` blocks in spawn functions.
- Impact: Eliminates all platform branching from callers, unifies dual code paths.

**B5. `deny_unknown_fields` on Config Structs**
- Config deserialization silently ignores unknown fields. Stale or misspelled fields cause silent misconfiguration.
- Fix: Add `#[serde(deny_unknown_fields)]` to all config structs.
- Signal: Test configs with fields that don't match any struct field; config fields that were renamed but old names still appear in YAML files.
- Impact: Net +1 LOC per struct, but prevents entire class of silent misconfiguration bugs.

**B6. `Option<Vec<T>>` for "Not Specified" vs "Empty"**
- A `Vec<T>` with `#[serde(default)]` where absent field and empty list have different semantics (auto-detect vs user error), but both are `vec![]`.
- Fix: Change to `Option<Vec<T>>`. `None` = not specified, `Some(vec)` = user provided. Add validation rejecting `Some(vec![])`.
- Signal: Comments like "empty means auto-detect"; `if vec.is_empty() { auto_detect() }` that could also mean "user intentionally set empty".
- Impact: Makes semantics explicit at type level, prevents user errors.

**B7. Warning Enum for Logging → Log at Origin**
- A warning enum (`RouteSyncWarning` with 5+ variants) exists solely to shuttle messages from a function to its caller for logging.
- Fix: Delete the enum. Log directly at the point of origin with `tracing::warn!`.
- Signal: `Vec<WarningEnum>` return types; callers whose only action is to iterate and log; `log_warning()` match blocks.
- Impact: -50 to -117 LOC. If the consumer only logs, the enum adds no value.

### C. Naming & Expression Clarity

**C1. Semantic Rename for Domain Accuracy**
- Names that are vague, inconsistent with siblings, or describe the wrong abstraction level.
- Fix: Rename to reflect actual behavior/role. Establish naming conventions (e.g., `handle_` for inbound, `drain_` for outbound; `h3dialer` not `h3client`; `alloc_uninit()` not `new()` for uninitialized memory).
- Signal: `h3client`/`h3server` (vague) vs `h3dialer`/`h3listener` (behavioral); `collect_quic_output` when it's actually `collect_udp_send`; metric named `_seconds` when the unit is milliseconds.
- Impact: Net 0 LOC, but dramatically improves code comprehension.

**C2. Flatten Nesting: let-else, ControlFlow, Early Return**
- Deeply nested `match`/`if let` chains, especially in event loops.
- Fix: Use `let-else` for `Option`/`Result` guards. Use `ControlFlow` for extracted loop handlers. Flatten destructuring with nested patterns.
- Signal: 3+ levels of indentation from nested `match`; `match { Some(x) => { match { Some(y) => { ... } } } }`; intermediate `let` bindings that just destructure.
- Impact: Net 0 to -5 LOC, significantly flatter control flow.

**C3. Inline Single-Use Wrappers**
- Functions at a single call site adding indirection without meaningful abstraction. Thin wrapper methods that just forward. One-line `touch()` methods whose return value is never used.
- Fix: Inline at the call site. Delete the function and its tests.
- Signal: Function called from exactly one site; function body is 1-3 lines; function exists only because of a prior refactor that has since been undone.
- Impact: -10 to -40 LOC, makes code path linear.

**C4. Leverage Library Polymorphic APIs**
- Hand-rolled V4/V6 dispatch (`match IpNet { V4(net) => {...}, V6(net) => {...} }`) where the library provides a polymorphic method; manual varint encode/decode when `octets` crate (transitive dep) does it.
- Fix: Replace with polymorphic/library API. Audit transitive dependencies before reimplementing.
- Signal: Dual-arm match for polymorphic types; hand-rolled codec for a format already handled by a dependency; `.map(|p| p.clone())` instead of `.cloned()`.
- Impact: -5 to -53 LOC per instance. Often replaces 12-line functions with 1-5 lines.

**C5. HashMap Single-Lookup Patterns**
- `contains_key()` + `get().unwrap()` double lookup; key duplicated in value; entry API when simple `get()` suffices.
- Fix: Use `get()` with `let-else` to avoid double lookups. Never store the key inside the value. Choose simplest API for access pattern.
- Signal: Sequential `if map.contains_key(&k) { map.get(&k).unwrap() }`; `HashMap<K, (K, V)>` where first tuple element always equals key.
- Impact: -2 to -5 LOC, eliminates TOCTOU risk.

**C6. Boolean/Flag Simplification**
- `retain()` with mutable `changed` boolean; verbose 4-arm matches for boolean expressions; repeated dirty-flag bookkeeping.
- Fix: `extract_if().count() > 0` replaces retain-with-flag. `|=` for boolean accumulation. `is_some() == is_some()` replaces 4-arm match. Extract `touch()` helper for dirty-flag pattern.
- Signal: `let mut changed = false; vec.retain(|x| { if condition { changed = true; false } else { true } })`.
- Impact: -3 to -10 LOC per instance, more idiomatic.

### D. Deduplication & Consolidation

**D1. Extract Repeated Multi-Step Sequences**
- A 3-10 line sequence repeated at 2+ call sites, especially multi-step topology updates or channel send-and-check patterns.
- Fix: Extract into a named helper that encodes the invariant. Often also fixes latent bugs where copies had diverged.
- Signal: Same 3-step sequence (e.g., update allowed sources → update routing → update system routes) at 2+ call sites; `collect + try_send` two-step pattern at 5+ sites.
- Impact: -6 to -73 LOC. Also prevents future divergence bugs.

**D2. Deduplicate Constants/Test Utilities via Re-export**
- Same constant or test helper defined in multiple modules.
- Fix: Define once in a canonical location, re-export elsewhere. For test utilities, use `mod test_support` with feature-gated `test-utils` for integration test access.
- Signal: Same constant name with same value in 2+ files; identical test helper functions across test modules; `FakeRouteProbe` implemented independently in 3 test modules.
- Impact: -10 to -84 LOC.

**D3. Merge Temporally Coupled Functions**
- Two functions always called together at every call site. Forgetting one is a bug.
- Fix: Merge into a single function.
- Signal: Every call to `fn_a()` is immediately followed by `fn_b()` at all 3+ call sites; no call site ever calls one without the other.
- Impact: -5 to -20 LOC, eliminates a bug class.

**D4. Module Decomposition by Responsibility**
- Single file mixing protocol session mechanics + connection management, or exceeding 500+ lines with multiple concerns.
- Fix: Split along responsibility boundaries. Each module should have a single reason to change. I/O, protocol logic, and connection management are distinct responsibilities.
- Signal: 2000+ line file with unrelated sections; `mod.rs` as a dumping ground for types from different domains; metrics types in `events.rs`.
- Impact: Net 0 LOC but dramatically improves navigability and reduces merge conflicts.

**D5. Config Construction Deduplication**
- Multiple call sites constructing the same config struct with identical field values.
- Fix: Extract `make_quic_settings(tuning, tun_mtu)` or similar factory function. Apply caller-specific overrides after shared construction.
- Signal: Duplicated 6-line QUIC config blocks in both client and server paths; identical channel capacity calculations.
- Impact: -5 to -20 LOC.

### E. Error Handling & Observability

**E1. Silent Drops → Explicit Error Responses/Logging**
- `let _ = channel.send(msg)` silently discards errors; auth failures silently drop requests; errors logged but not propagated.
- Fix: `if sender.send(msg).is_err() { warn!("...") }`. Auth failures get HTTP 400/401 responses. Channel-closed conditions return `ActorError`.
- Signal: `let _ = ...send()` pattern; missing `DropReason::ChannelClosed` metrics; functions returning `()` when they can fail.
- Impact: +2 to +5 LOC per site, but critical for production observability.

**E2. Wildcard Match → Debug Logging for External Enums**
- `_ => continue` in match arms for external `#[non_exhaustive]` enums. New library variants are silently swallowed.
- Fix: `other => { debug!("unhandled event", event = ?other); continue; }`.
- Signal: `_ => continue` or `_ => {}` matching library enum variants.
- Impact: +1 LOC per site, prevents silent behavior changes on dependency upgrades.

**E3. Validation Extraction / Table-Driven Validation**
- Inline validation chains with 4+ sequential checks scattered in caller. Or: N fields all needing the same validation (e.g., Duration > 0).
- Fix: Extract `validate_framing()` returning `Option<usize>`. For N fields with same rule, use array iteration.
- Signal: Sequential `if !check1 { return None } if !check2 { return None }` chains; 7 fields each with `if field == Duration::ZERO { return Err(...) }`.
- Impact: -5 to -30 LOC for extraction; -20+ LOC for table-driven.

**E4. Magic Numbers → Named Constants**
- Inline `Duration::from_secs(5)`, `1472`, `30` at multiple sites without domain explanation.
- Fix: Extract to named constants with comments. For derived values, express the derivation (e.g., `CONNECT_IP_OVERHEAD = 59` instead of hardcoded `MAX_SEND_UDP_PAYLOAD_SIZE = 1472`).
- Signal: Same numeric literal at 2+ sites; protocol-specific numbers without derivation; timeout values without rationale.
- Impact: Net 0 to +5 LOC, but prevents misconfiguration and documents domain knowledge.

**E5. Improve Logging Levels Systematically**
- Events at `debug` that operators need at `warn`/`info`; log messages missing key context (peer_id, direction); errors completely silenced.
- Signal: prune/dial-failed/backoff at `debug`; errors consumed with `if let Err(e) = ... { }` with empty body; log messages without structured fields.
- Impact: +1 to +3 LOC per site, essential for production debugging.

### F. Structural Cleanup

**F1. State Co-location (Move Data to Its Owner)**
- Data passed through enum variant payloads, function parameters, or local variables when it belongs as a field on a struct.
- Fix: Move to the owning struct. Simplify enum variant to unit. Use `.take()` at entry to eliminate per-iteration `.expect()`/`.clone()`.
- Signal: `EnumVariant(Option<String>)` where the string logically belongs on the parent struct; scattered `established: bool` + `pending_id: Option<String>` + `started: Instant` that should be a single `Phase` enum.
- Impact: -5 to -20 LOC, makes invalid states unrepresentable.

**F2. Field Grouping (Sub-struct Extraction)**
- Flat struct with 10+ fields where subsets are logically related or always passed together.
- Fix: Group into sub-structs. Sub-structs can enable useful trait derives (e.g., `Clone`).
- Signal: 14+ fields on a single struct; 5+ fields always cloned together for per-connection state; `clippy::too_many_arguments` on constructors.
- Impact: Reduces cognitive load, enables targeted `Clone`/`Debug` derives.

**F3. Enum Flattening**
- Wrapper enum that adds no type safety (`Event::Transport(TransportEvent::H3Connected(e))` → `Event::H3Connected(e)`). Forces double-destructuring at every match.
- Fix: Flatten the wrapper layer. Rename if the wrapper's name was the only distinction.
- Signal: Every match on the outer enum immediately destructures the inner; inner enum has only 2-3 variants; 1:1 mapping between parallel enums.
- Impact: -5 to -20 LOC from eliminated double-matching.

**F4. Control Flow Reordering for Domain Semantics**
- Branching order that doesn't match domain priority, causing bugs or unclear code.
- Fix: Reorder checks so the most restrictive/common case comes first. Sometimes moving a single line changes semantics profoundly.
- Signal: Guard that removes state before a check that could reuse it; `attempt += 1` before vs after backoff multiplier; type-first branching when interface-first is the domain priority.
- Impact: Net 0 LOC, but fixes correctness bugs and improves readability.

**F5. Ownership Refinement on Hot Paths**
- Unnecessary clones, unnecessary reference counts, hot-path `.expect()`, or direct runtime-handle access for runtime-bound initialization.
- Fix: `drop(outer_wrapper)` to release refcount after extracting inner sender. `.take()` at run entry to eliminate per-iteration unwrap. Use the runtime owner's synchronous-operation API for I/O registration instead of exposing a Tokio handle.
- Signal: `.expect("we know this is Some")` inside a tight loop; callers entering another runtime directly; `PollSender` wrapper kept alive after extracting inner `Sender`.
- Impact: -5 to -15 LOC, eliminates hot-path overhead.

**F6. Stale State Cleanup on Lifecycle Events**
- State (backoff counters, dial state, metrics) that accumulates but is never cleaned up when its associated resource goes away.
- Fix: When resources are pruned/expired/disconnected, clean up ALL associated state. Audit state fields in the prune/cleanup path.
- Signal: Backoff counters that persist after DNS re-resolution; metrics that accumulate after connection close; dial state preventing reconnection.
- Impact: Net 0 LOC, but fixes subtle reconnection/retry bugs.

**F7. Replace Struct-with-Method with Free Functions**
- A struct exists primarily to hold arguments for a single method (e.g., `BindDecision::decide()`, `DnsResolver::resolve()`).
- Fix: Replace with free functions (`make_*` for fallible construction, `spawn_*` for tasks). Functions take explicit parameters instead of `&mut self`.
- Signal: Struct with `from_config()` constructor and exactly one public method; struct used only in one function; `&mut self` causing borrow conflicts.
- Impact: -10 to -30 LOC, avoids lifetime issues, improves testability.

### G. Test Quality

**G1. Tighten Assertions**
- Tests that `assert!(result.is_err())` without checking the error variant. Pass when code fails for the wrong reason.
- Fix: `assert!(matches!(err, DialError::Handshake(_)))`. For channel errors, assert `TryRecvError::Empty` not just `is_err()`.
- Signal: `is_err()` in tests; `is_ok()` without checking the value; tests that "pass" after a refactor that broke the intended behavior.
- Impact: Net +2 LOC per assertion, but catches regressions more precisely.

**G2. Strengthen "Doesn't Crash" Tests**
- Tests that only verify "no panic" without asserting on actual state or outputs.
- Fix: Pre-populate state, exercise code, then verify both positive (expected state) and negative (no spurious side effects like unexpected commands to child actors).
- Signal: Tests with no `assert!` at all; test function named `test_foo` that only calls `foo()` without checking anything.
- Impact: +5 to +15 LOC per test, but catches real bugs.

**G3. Replace Hand-Rolled Security with Audited Libraries**
- Hand-rolled `constant_time_eq`; `&&` combining constant-time results (short-circuits, breaking timing guarantees).
- Fix: use an audited crypto primitive that compares fixed-size tags derived from the inputs, such as HMAC-SHA256 over both inputs with an ephemeral key; this removes direct length-mismatch leakage from the equality check, but callers still need explicit input bounds because MAC computation remains linear in input length. If multiple constant-time conditions must be combined, use `&` (bitwise AND) not `&&`.
- Signal: Any function named `constant_time_*` or `timing_safe_*` that isn't from a crypto crate; `&&` between results that must be constant-time.
- Impact: -10 to -37 LOC, eliminates subtle security bugs.

**G4. Replace Fragile Text Parsing with Structured APIs**
- Parsing command output with `sed | tail` or regex; parsing route info from `ip route show` output.
- Fix: `jq` for JSON, library crate for routes/system info, structured query APIs.
- Signal: `sed | tail -1` for extraction; string splitting on command output; `ip route show match` followed by field-position parsing.
- Impact: -10 to -50 LOC, more correct and cross-platform.

## Tier 3 — Architectural

High-impact, high-effort patterns. Each typically yields -100 to -300 LOC. Apply when the proposal touches the relevant subsystem and the pattern clearly fits.

### H. Structural Collapse

**H1. Unify Isomorphic Parallel Hierarchies**
- When two type hierarchies (Client/Server, Rx/Tx pairs) represent the same concept and diverged through independent development, merge into a single parameterized type.
- Signal: Two enums/structs with matching variants used in the same call chains; near-identical event loop code in separate modules.
- Impact: 100-200 LOC reduction, eliminates bug drift between copies.

**H2. Eliminate Intermediate Actors by Inlining**
- When an actor does nothing but receive-transform-forward, inline its logic into the upstream actor's loop.
- Signal: Actor whose body is `while let Some(x) = rx.recv() { tx.send(transform(x)) }` with no independent I/O or state.
- Impact: Removes one MPSC channel and one task from hot path.

**H3. Remove Wrapper Types That Add No Abstraction**
- In a single pass, identify and remove 1:1 enum mappings, trivial getter structs, and redundant handle types across the project.
- Signal: Custom enum mapping 1:1 to a library enum; handle struct with single field and forwarding methods; dead `Other`/`Unknown` variants.
- Impact: -100+ LOC, removes indirection layers.

**H4. Merge Dual Event Loops into Single State-Driven Loop**
- When init phase and runtime phase have separate event loops with duplicated shutdown/timer handling, merge into one loop with typed state.
- Signal: Separate init loop and runtime loop sharing channel receivers; duplicated `ctrl_c` handling; sequential loops that could be one.
- Impact: Eliminates duplicate handling, removes intermediate types, -100+ LOC.

**H5. Collapse Sequential Select Loops**
- When multiple sequential `tokio::select!` loops share arms with only phase-dependent differences, merge into one loop with enum guards.
- Signal: 2-3 sequential select loops with duplicated timer/recv/send arms; flush/reset calls replicated across all loops.
- Impact: Reduces duplicated select arms from N*M to M.

### I. Simplification by Domain Insight

**I1. Remove Complexity That Domain Constraints Make Unnecessary**
- When a complex mechanism (retry queue, backpressure, multi-path, recursive algorithm) exists but domain constraints make the simple alternative correct, remove it.
- Signal: Retry mechanism where the queue rarely fills due to domain constraints (e.g., `cc=none`); multi-path infrastructure with no multi-path users; recursive algorithm where only one level is ever needed.
- Impact: 100-200 LOC reduction per instance, removes entire complexity classes.

**I2. Replace Diff-Based Processing with Declarative State Check**
- When an event handler maintains a `prev_snapshot` and computes diffs, replace with "iterate current state, check each entry against desired state."
- Signal: `prev_snapshot` field; `compute_diff(old, new)` producing added/removed lists; separate `handle_added()`/`handle_removed()` methods.
- Impact: Eliminates stored state, removes TOCTOU bug class.

**I3. Replace Fine-Grained Events with Periodic State Snapshots**
- When a producer emits individual `ItemAdded`/`ItemRemoved` events and the consumer must reconstruct full state, switch to periodic snapshots with a dirty flag.
- Signal: Multiple event variants for state mutations; consumer maintaining a mirror of producer state; rapid event bursts causing redundant processing.
- Impact: Simplifies consumer logic, batches rapid changes, eliminates event variant proliferation.

**I4. Replace Custom Identity Tracking with Built-in Mechanisms**
- When monotonic ID counters exist solely for "is this the same channel/connection?", use the channel's built-in identity comparison.
- Signal: `next_id` counters on structs; ID fields compared only for equality; monotonic counters with no other purpose.
- Impact: Removes bookkeeping state, more semantically correct.

### J. Type-Level Enforcement

**J1. Parse at Deserialization, Not at Runtime**
- Move `String.parse::<T>()` from runtime into custom `Deserialize` impls so downstream code works with pre-parsed types.
- Signal: `String` config fields followed by `.parse()` in validation; error enum variants for parse failures during config load; `Option<String>` for actually-required fields.
- Impact: Eliminates entire error variant classes, makes functions infallible.

**J2. Vec→Option When "At Most One" Is an Invariant**
- When a `Vec` always has 0 or 1 elements, use `Option` to make the invariant compiler-enforced.
- Signal: `.len() <= 1` assertions; `vec[0]` accesses without bounds checking; multi-path infrastructure with single-path usage.
- Impact: Compiler-enforced invariant, eliminates bounds-check code.

**J3. Make/Spawn Two-Phase Actor Initialization**
- Separate actor creation into fallible `make_*()` (I/O, TLS) and infallible `spawn_*()` (task spawning) to prevent initialization errors from hiding inside spawned tasks.
- Signal: `tokio::spawn` blocks doing fallible I/O before entering event loop; initialization errors logged but not propagated.
- Impact: Synchronous error propagation, enables testing without spawning.

### K. Data Layout Optimization

**K1. Co-locate Lookup Data to Eliminate Hot-Path HashMap**
- Embed the second lookup's data into the first lookup's result structure when sequential lookups always succeed together.
- Signal: `let route = trie.lookup(ip); let tx = map.get(route.peer_id);` pattern; a map lookup that always succeeds after a trie lookup.
- Impact: Eliminates one HashMap lookup per packet in hot path.

**K2. Reorganize Data Model Around Primary Lookup Key**
- When data is keyed by a secondary identifier but the domain key is different, restructure around the domain key for O(1) lookup.
- Signal: O(n) scans to find entries by secondary key; multiple parallel HashMaps that must stay in sync.
- Impact: O(n) to O(1) lookup, eliminates state synchronization bugs.

**K3. Bundle Common Parameters into Context Struct**
- When multiple functions share 5+ identical parameters, bundle into a context struct and align all signatures.
- Signal: `clippy::too_many_arguments`; duplicated parameter lists across `dial_*()` functions; cloning 7 fields before each call.
- Impact: Dramatic call-site simplification, consistent API pattern.

### L. Zero-Copy and Buffer Optimization

**L1. Zero-Copy Buffer Chain with Headroom Reuse**
- Allocate buffers from pool with pre-reserved headroom, strip/prepend headers in-place using pop/push operations.
- Signal: Intermediate `Vec<u8>` allocations between stages; `[0u8; 65535]` stack buffers followed by memcpy; protocol layers that add fixed-length prefixes.
- Impact: Eliminates per-packet memcpy, removes large stack allocations.

**L2. Redesign Trait Interface to Accept Domain Buffer Type**
- When a trait uses raw `Vec<u8>` but all impls immediately wrap into domain buffer type, change the trait to accept domain type directly.
- Signal: `trait::recv(&mut Vec<u8>)` followed by `DomainBuf::from_slice(&buf[..n])` at every call site.
- Impact: Eliminates one memcpy per packet on RX hot path.

**L3. Size-Aware Dual-Pool Allocation**
- Use two pools with threshold-based selection to avoid over-allocating for the common case, with upgrade path for rare case.
- Signal: Most allocations are small but pool always allocates max-size; 97%+ allocations waste >95% capacity.
- Impact: ~97% memory reduction for typical allocations.

**L4. Move Platform Concerns Below Abstraction Boundary**
- Push platform-specific details (virtio_net_hdr, GRO/GSO) into concrete implementations behind a trait with compile-time assertions.
- Signal: Actor constructing platform-specific headers before calling trait method; conditional compilation mixing with business logic.
- Impact: Actor becomes platform-agnostic, enables zero-copy.

### M. Channel and Batch Design

**M1. Batch-Typed Channels with First-Element Routing**
- Change `Sender<Item>` to `Sender<Vec<Item>>` to make batching first-class; route/filter entire batch by first element when same-flow is guaranteed.
- Signal: Per-item sends in loop where items come from GRO/GSO; per-packet atomic wakeups dominating CPU.
- Impact: Reduces per-packet wakeups from N to 1, reduces routing lookups per batch.

**M2. Recv-Then-Drain Batch Collection**
- Replace stateful cross-iteration batch accumulation with blocking `recv()` + `try_recv()` drain loop.
- Signal: Batch state carried across loop iterations; multiple flush conditions (count, bytes, size change); adaptive flush logic.
- Impact: Eliminates cross-iteration state, removes stale-state bugs.

**M3. Principled Actor Lifecycle: Token vs. Channel-Close**
- Choose shutdown based on blocking behavior: `CancellationToken` for I/O-bound actors, channel-close for queue-draining actors.
- Signal: Actors blocking on `socket.readable()` (need explicit cancellation); actors calling `channel.recv()` (natural exit on drop); mixed mechanisms.
- Impact: Correct shutdown semantics, RAII cleanup, removes intermediate structs.

### N. Concurrency Model

**N1. Remove Arc<Mutex> by Leveraging Actor Ownership**
- Replace shared mutable state with exclusive ownership in one actor and event-driven snapshot delivery via oneshot channels.
- Signal: `Arc<Mutex<HashMap>>` shared between actors; `.lock()` on hot path; single writer with few readers.
- Impact: Eliminates Mutex, fully aligns with actor model.

**N2. Thread-Per-Core with Runtime Affinity**
- Replace the multi-threaded runtime with dedicated single-threaded runtimes per concern. Centralize task placement and runtime-bound initialization in the runtime owner.
- Signal: `multi_thread` runtime with data-plane actors; `AsyncFd` needing reactor affinity; cross-thread hops in profiling.
- Impact: Eliminates cross-thread task migration on hot paths.

**N3. Callback-Based Event Protocol for Decoupling**
- When a generic I/O primitive needs to drive different metrics/accounting strategies, use a callback parameter instead of a concrete counter type.
- Signal: I/O function coupled to specific metrics types; same send/recv logic needed with different accounting.
- Impact: Decouples I/O from metrics, enables reuse across contexts.
