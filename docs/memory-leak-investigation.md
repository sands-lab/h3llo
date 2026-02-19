# h3llo Memory Leak Investigation

## Problem

h3llo on `nl` grows from ~50MB to ~1.6GB RSS in ~23 minutes, then gets OOM killed.
dmesg: `anon-rss:1650672kB, total-vm:3635220kB`.

## Root Cause: real memory leak + musl fragmentation amplification

Two independent problems compound to cause the OOM:

1. **Real memory leak (~0.4 MiB/min)**: `huge` allocations (>64KB) accumulate and are
   never freed. Suspected source: tokio-quiche buffer pool (`buf_factory.rs`) — pools
   grow but never shrink, each buffer is 64KB.

2. **mimalloc 10x RSS amplification**: Each 1 MiB of leaked `current` causes ~10 MiB of
   RSS growth (mimalloc commits large segments for huge allocations, doesn't purge).

3. **musl fragmentation (without override)**: Without mimalloc override, BoringSSL uses
   musl malloc which fragments severely under high-churn TLS allocation patterns,
   amplifying RSS growth even further (~70 MB/min vs ~5 MB/min with mimalloc).

**Mitigation**: PR #450 enables mimalloc `override` feature — replaces system
`malloc/free/realloc` weak symbols at link time. Slows OOM from ~23 min to ~5-6 hours,
but does not fix the underlying leak.

## Evidence

### Before override (mimalloc without `override`)

- mimalloc only covers Rust allocations
- BoringSSL uses musl malloc, invisible to mimalloc stats
- mimalloc reported 9.2 MiB current but RSS was 90.8 MiB after 10 min — 80 MiB blind spot
- Production: RSS reaches 1.6 GB in ~23 min → OOM killed

### After override (PR #450)

Verified via `nm`: `malloc` and `mi_malloc` at same address `0x18bfb0` — override active.

#### 60-second test

```
heap stats:     peak       total     current
    binned:     6.0 Mi     17.5 Mi    258.3 Ki
      huge:    20.4 Mi     21.3 Mi      4.4 Mi
     total:    26.5 MiB    38.8 MiB     4.7 MiB
malloc req:                15.5 MiB
  rss: 50.8 MiB
  threads: 3/5/1  (peak/total_created/alive_at_exit)
```

#### 10-minute test

```
heap stats:     peak       total     current
    binned:     9.5 Mi     55.4 Mi    554.9 Ki
      huge:    52.0 Mi     53.6 Mi      8.4 Mi
     total:    61.6 MiB   109.1 MiB     9.0 MiB
malloc req:                48.2 MiB
  rss: 89.5 MiB
  committed: 883.5 MiB  (mimalloc pre-reserves 1GB arena for musl, normal)
  touched: 9.8 MiB current
  threads: 3/5/1
  elapsed: 572s
```

#### RSS trend (10-min test, sampled every 30s)

```
time(s)  RSS(MB)  delta
   0     51.5     baseline
  30     57.8     +6.3
  60     57.9     +0.1
  90     58.6     +0.7
 120     64.4     +5.8
 150     64.9     +0.5
 180     65.7     +0.8
 210     71.0     +5.3
 240     71.8     +0.8
 270     71.8     +0.0
 300     72.6     +0.8
 330     79.2     +6.6
 360     81.5     +2.3
 390     83.5     +2.0
 420     83.5     +0.0
 450     89.5     +6.0
```

### Analysis

1. **RSS growth ~4 MiB/min, linear** — extrapolating to 23 min gives ~143 MiB, far below
   the 1.6 GB OOM seen without override.

2. **Staircase pattern**: ~6 MiB jumps every ~2 minutes, then stable. Correlates with
   reconnect backoff cycle — each `dial_h3` creates a BoringSSL TLS context (~few MB),
   freed after QUIC draining but mimalloc doesn't immediately return RSS to OS.

3. **Thread count stable at 4** throughout — background router/IoWorker tasks properly
   terminate after connection close. No task accumulation.

4. **`current` at exit only 9.0 MiB** vs RSS 89.5 MiB — the 80 MiB gap is mimalloc's
   committed-but-not-purged pages. This is expected: mimalloc holds onto pages for reuse
   but the allocator-tracked live memory is small.

5. **`threads: 3/5/1`** — same in both 60s and 10m tests. All temporary threads cleaned up.

### Comparison: 60s vs 10m vs 30m

| Metric | 60s | 10m | 30m |
|--------|-----|-----|-----|
| current at exit | 4.7 MiB | 9.0 MiB | 17.3 MiB |
| huge current | 4.4 MiB | 8.4 MiB | 16.2 MiB |
| binned current | 258 KiB | 555 KiB | 1.1 MiB |
| peak total | 26.5 MiB | 61.6 MiB | 131.7 MiB |
| malloc req | 15.5 MiB | 48.2 MiB | 122.2 MiB |
| RSS | 50.8 MiB | 89.5 MiB | 172.5 MiB |
| threads | 3/5/1 | 3/5/1 | 3/5/1 |
| **RSS / current** | **10.8x** | **9.9x** | **10.0x** |

Key findings:
- **`current` grows linearly ~0.4 MiB/min** — this is a real leak, not mimalloc laziness
- **`huge` (>64KB) is ~95% of the leak**: 4.4 → 8.4 → 16.2 MiB
- **RSS ≈ 10 × current** — near-perfect linear relationship; RSS growth is entirely
  driven by the `current` leak, amplified ~10x by mimalloc's segment commit behavior
- **Threads stable at 3/5/1** — background tasks properly terminate

## Architecture: Connection Lifecycle

Each `dial_h3` call (h3.rs:479) creates:
1. A new UDP socket
2. A `quiche::Connection` with BoringSSL TLS context (~200KB-2MB in C memory)
3. A fire-and-forget `tokio::spawn` router task (tokio-quiche/src/quic/mod.rs:265)
4. An IoWorker task per connection

When dial fails (timeout/handshake error):
1. `close_quic_connection()` sends QUIC ConnectionClose command
2. `_quic_conn` (QuicConnection handle) is dropped — lightweight handle only
3. Background router + IoWorker continue until QUIC draining completes
4. Draining can take up to `h3_max_idle_timeout` = 60s (config default)

Backoff sequence: 3s → 6s → 12s → 24s → 48s → 60s (capped)
- Early retries (3s, 6s) create connections faster than old ones drain
- At steady state (60s backoff), roughly 1-2 concurrent draining connections per peer

### Listener side

`spawn_h3_listener` (h3.rs:1182-1184):
```rust
let quic_conn = initial_conn.start(driver);  // spawns IoWorker
drop(quic_conn);  // handle dropped, IoWorker still running
tokio::spawn(handle_h3_connection(...));
```

Each inbound connection also spawns an IoWorker that lives until QUIC draining.

## Confirmed Leak Source: tokio-quiche Buffer Pool

Static buffer pools in `tokio-quiche/src/buf_factory.rs`:
- `BUF_POOL` (generic_pool): 16,384 capacity × 64KB max = ~1GB theoretical max
- `DATAGRAM_POOL`: 65,536 capacity × ~1.5KB

### 10-minute `/metrics` monitoring (with override)

| time | RSS(MB) | gp_active | gp_idle | gp_total | consume_buf(MB) |
|------|---------|-----------|---------|----------|-----------------|
| 0m   | 41.3    | 41        | 13      | 54       | 3.4             |
| 1m   | 52.9    | 57        | 12      | 69       | 4.3             |
| 2m   | 53.1    | 49        | 28      | 77       | 4.8             |
| 3m   | 58.8    | 69        | 17      | 86       | 5.4             |
| 4m   | 65.3    | 80        | 18      | 98       | 6.1             |
| 5m   | 73.0    | 91        | 11      | 102      | 6.4             |
| 6m   | 75.2    | 81        | 25      | 106      | 6.6             |
| 7m   | 79.9    | 100       | 12      | 112      | 7.0             |
| 8m   | 83.4    | 93        | 24      | 117      | 7.3             |
| 9m   | 91.9    | 114       | 9       | 123      | 7.7             |
| 10m  | 91.9    | 104       | 26      | 130      | 8.1             |

### Analysis

- **gp_total grows linearly**: 54 → 130 = +76 buffers / 10 min ≈ 7.6/min
- **consume_buf grows ~0.47 MB/min** — matches mimalloc `huge` current growth (0.4 MiB/min)
- **gp_idle fluctuates (9-28)** but does not accumulate — buffers checked out are mostly
  NOT returned to idle pool
- **gp_active grows**: 41 → 104 — something is holding buffers after connections close
- **datagram_pool stable** (idle 3→7) — not a problem
- **130 buffers × 64KB = 8.3 MB ≈ consume_buf 8.1 MB** — consistent

### Conclusion

Buffers are checked out by QUIC connection IoWorker/router tasks. When connections fail
and close, the buffers are not properly returned to the pool. The pool only grows,
never shrinks, and the "active" count keeps rising even though threads are stable at 4.

This means buffers are being leaked — held by something that outlives the connection
but doesn't drop them back to the pool.

## Other Investigated Sources (ruled out or bounded)

1. **foundations metrics registry**: `invalid_cid_packet_count(reason: String)` could
   have unbounded cardinality, but default CID generator always returns Ok.

2. **TransportStats.drop_reasons HashMap**: Fixed enum (9 variants) — bounded.

3. **Unbounded event channel** (orch.rs:518): Could accumulate if orchestrator falls
   behind, but unlikely to reach GB scale.

4. **peer_tokens.clone()** per inbound connection: Clones entire HashMap per connection,
   but freed when connection handler exits.

## OOM Timeline Estimates

| Scenario | RSS growth | Time to 1.6GB OOM |
|----------|-----------|-------------------|
| No override (musl) | ~70 MB/min | ~23 min |
| With override (mimalloc) | ~5 MB/min | ~5-6 hours |
| After fixing leak (goal) | 0 | never |

## Root Cause Found: tokio-quiche Router leak on client handshake timeout

### Problem

When `connect_with_config` (tokio-quiche/src/quic/mod.rs:264) spawns a Router task
fire-and-forget, and the QUIC handshake **fails** (e.g., peer unreachable → timeout), the
Router task is **never cleaned up**. Each failed `dial_h3` permanently leaks:
- 1 Router tokio task (stuck in `Poll::Pending`)
- 1 UDP socket (FD)
- 1 `PooledBuf` (64KB from generic_pool)
- The `Arc<UdpSocket>` and all associated state

### Mechanism

The Router exits via a two-step shutdown (router/mod.rs:754-762):

```
1. accept_sink.is_closed() → drop own shutdown_tx
2. shutdown_rx.poll_recv(cx).is_ready() → exit
```

For **successful** connections, an IoWorker is spawned holding a `shutdown_tx` clone.
When the IoWorker exits, the clone is dropped, waking `shutdown_rx` → Router exits. ✓

For **failed** handshakes, **no IoWorker is ever created** (the handshake is driven by
`ClientConnector` inside the Router's poll loop). The timeline:

1. Router poll → ClientConnector timeout → error sent to caller via `accept_sink`
2. Router polls socket → `Poll::Pending` (no packets from dead peer)
3. Router checks `accept_sink.is_closed()` → **false** (caller still awaiting `recv()`)
4. Router returns `Poll::Pending`, registering wakers for: socket recv + shutdown_rx
5. Caller receives error → drops `quic_connection_stream` → `accept_sink.is_closed()` = true
6. **Nobody wakes the Router** — socket has no data, shutdown_rx has no event
7. Router stuck in `Poll::Pending` **forever**

### Evidence

Tested on `nl` with `RUST_LOG=warn,h3llo=info,tokio_quiche=debug`:

| Metric | Value |
|--------|-------|
| "incoming packet router finished" in logs | **0** for failed handshakes |
| "incoming packet router finished" for closed successful connections | **1** (jp) |
| UDP sockets after 2 min | 49 (14 connections) |
| UDP sockets after 4 min | 60 (14 connections) |
| Growth rate | ~5.5 sockets/min |
| Per-peer socket count (20 min run) | 13-27 per unreachable peer |

Socket-to-node mapping (after 20 min, previous test run):
```
 27  hk4    (unreachable)
 15  hk3, jp2, kr, us2, hk, sg3, au, hk5, cn, nl2  (unreachable)
  6  ru     (unreachable, higher backoff?)
  1  jp, sg, sg2, sg4, tw2  (active connections — 1 socket each)
```

### Fix

The fix belongs in **tokio-quiche**. Options (in order of preference):

1. **Abort Router on connect failure** — `connect_with_config` keeps the `JoinHandle`
   and calls `handle.abort()` when the handshake fails. Simplest, no API change.

2. **Poll `accept_sink.closed()`** — add the closed-detection future to the Router's
   poll loop so it gets woken when the receiver is dropped. Fixes both handshake-failure
   and post-connection-close cases.

3. **Periodic self-wake** — Router sets a timer (e.g., 5s) to periodically re-check
   shutdown conditions. Least surgical but simple.

## Status

- [x] Identified blind spot: BoringSSL allocations invisible to mimalloc
- [x] PR #450: enable mimalloc `override` feature (mitigation, not fix)
- [x] Verified override active via `nm` symbol check
- [x] 60s test: RSS 50.8 MiB, current 4.7 MiB
- [x] 10m test: RSS 89.5 MiB, current 9.0 MiB, threads stable
- [x] 30m test: RSS 172.5 MiB, current 17.3 MiB — confirmed real leak ~0.4 MiB/min
- [x] Identified RSS ≈ 10× current relationship
- [x] Narrowed leak to `huge` (>64KB) allocations — suspected buffer pool
- [x] Confirmed via `/metrics`: gp_total +7.6/min, consume_buf +0.47 MB/min = mimalloc huge leak
- [x] **Root cause found**: tokio-quiche Router task leak on client handshake failure
- [x] Verified with debug logging: 0 Router exits for failed handshakes, 1 for closed success
- [x] Confirmed linear UDP socket growth correlating with handshake failures
- [ ] Fix in tokio-quiche (abort Router on connect failure)

## Profiling Commands

```bash
# Extract binary from Docker image
CID=$(docker create nekonuts/h3llo:latest)
docker cp $CID:/usr/local/bin/h3llo /tmp/h3llo-from-image
docker rm $CID

# Run with mimalloc stats (stats printed on SIGINT exit)
MIMALLOC_SHOW_STATS=1 RUST_LOG=h3llo=info /tmp/h3llo-from-image -c /root/v5/h3llo.yaml

# Verify override is active
nm /tmp/h3llo-from-image | grep -w "T malloc"    # should show same addr as mi_malloc
nm /tmp/h3llo-from-image | grep "mi_malloc$"

# Monitor RSS and thread count
while [ -d /proc/$PID ]; do
  RSS=$(awk '/VmRSS/{print $2}' /proc/$PID/status)
  THR=$(ls /proc/$PID/task | wc -l)
  echo "$(date +%s) RSS=${RSS}kB threads=$THR"
  sleep 10
done

# Check smaps for top memory regions
awk '/^[0-9a-f]/{r=$0;s=0} /^Rss:/{s=$2} /^VmFlags:/{if(s>500) print s"kB",r}' \
  /proc/$PID/smaps | sort -rn | head -20
```
