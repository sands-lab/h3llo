# tokio-quiche: Router Task Leak on Client Handshake Failure

## Summary

When `connect_with_config` fails due to handshake timeout (peer unreachable),
the spawned Router task is never cleaned up. Each failed attempt permanently
leaks:

- 1 tokio task (stuck in `Poll::Pending` forever)
- 1 UDP socket (file descriptor)
- 1 `PooledBuf` (64 KB from `BUF_POOL`)

In h3llo, this causes OOM within hours: unreachable peers are retried with
exponential backoff (3s → 60s), each attempt leaking ~64 KB of buffer +
socket. With mimalloc's 10x RSS amplification, RSS grows ~5 MB/min.

## Affected Code

Upstream `cloudflare/quiche` master (as of 2026-02) has the same code — **not
fixed**.

Relevant files in `tokio-quiche/src/`:

| File | Role |
|------|------|
| `quic/mod.rs:191-279` | `connect_with_config` — spawns Router fire-and-forget |
| `quic/router/mod.rs:675-773` | Router poll loop — shutdown detection logic |
| `quic/router/connector.rs` | `ClientConnector` — drives handshake inside Router |
| `quic/io/worker.rs` | `IoWorker` — only created after successful handshake |

## Root Cause

### Normal shutdown path (handshake succeeds)

```
connect_with_config
  ├─ spawn Router (fire-and-forget)
  └─ await quic_connection_stream.recv()
       └─ Router handshake succeeds
            └─ spawn_new_connection() creates IoWorker
                 └─ IoWorker gets shutdown_tx.clone()

[later, connection closes]
  IoWorker exits → drops shutdown_tx clone
    → shutdown_rx wakes → Router exits ✓
```

### Broken path (handshake fails)

```
connect_with_config
  ├─ spawn Router (fire-and-forget, JoinHandle dropped)
  └─ await quic_connection_stream.recv()
       └─ Router: ClientConnector timeout → error sent via accept_sink
            → caller receives Err, drops quic_connection_stream

Router poll loop:
  1. Polls socket → Poll::Pending (no packets from dead peer)
  2. Checks accept_sink.is_closed() → WAS false during poll
  3. Returns Poll::Pending, registers wakers: [socket_recv, shutdown_rx]
  4. Caller drops quic_connection_stream → accept_sink.is_closed() = true
  5. Nobody wakes Router — socket has no data, shutdown_rx has no event
  6. Router stuck in Poll::Pending FOREVER ✗
```

The core issue: Router only re-checks `accept_sink.is_closed()` when it is
**woken**, but after a failed handshake there are no events to wake it. No
IoWorker was ever created, so no `shutdown_tx` clone exists to signal via
`shutdown_rx`.

### Why H3Driver::drop cannot fix this

`H3Driver` (or any `ApplicationOverQuic`) is passed to `connect_with_config`
but only consumed by `.start(app)` **after** handshake success:

```rust
// quic/mod.rs:274-278
Ok(quic_connection_stream
    .recv().await
    .ok_or("unable to establish connection")??
    .start(app))  // ← never reached on failure
```

On failure, `app` is dropped normally on the caller's stack. It was never moved
into the Router or IoWorker. Any changes to `H3Driver::drop` are irrelevant to
this bug.

## Evidence

### Reproduction (`examples/router_leak.rs`)

10 concurrent `connect_with_config` calls to `192.0.2.1:443` (RFC 5737
TEST-NET, guaranteed unreachable) with 500ms handshake timeout:

```
Baseline: 10 FDs, 15 UDP sockets

[ 1/10] error: connection ... timed out | FDs: +10 | UDP: +10
[ 2/10] error: connection ... timed out | FDs: +10 | UDP: +10
...
[10/10] error: connection ... timed out | FDs: +10 | UDP: +10

Waiting 3s for async cleanup...

Final: 20 FDs (+10), 25 UDP sockets (+10)
BUG CONFIRMED: 10 FDs leaked after 10 failed handshakes.
```

### Production observation (h3llo on `nl`)

Debug logging (`RUST_LOG=warn,h3llo=info,tokio_quiche=debug`):

| Metric | Value |
|--------|-------|
| "incoming packet router finished" for failed handshakes | **0** |
| "incoming packet router finished" for closed successful connections | **1** |
| UDP socket growth rate | ~5.5 sockets/min |
| Per unreachable peer (20 min run) | 13–27 leaked sockets |

Buffer pool metrics confirm: `gp_total` grows +7.6 buffers/min, `gp_active`
rises while `gp_idle` stays bounded — buffers are checked out and never
returned.

## Proposed Fixes

### Option A: Abort Router on connect failure (simplest)

Keep the `JoinHandle` from `tokio::spawn` and abort the Router when the
handshake fails. Only touches `connect_with_config`.

```diff
--- a/tokio-quiche/src/quic/mod.rs
+++ b/tokio-quiche/src/quic/mod.rs
@@ -264,15 +264,20 @@
     // drive the packet router:
-    tokio::spawn(async move {
+    let router_handle = tokio::spawn(async move {
         match router.await {
             Ok(()) => log::debug!("incoming packet router finished"),
             Err(error) => {
                 log::error!("incoming packet router failed"; "error"=>error)
             },
         }
     });

-    Ok(quic_connection_stream
-        .recv()
-        .await
-        .ok_or("unable to establish connection")??
-        .start(app))
+    match quic_connection_stream.recv().await {
+        Some(Ok(initial_conn)) => Ok(initial_conn.start(app)),
+        Some(Err(e)) => {
+            router_handle.abort();
+            Err(e.into())
+        },
+        None => {
+            router_handle.abort();
+            Err("unable to establish connection".into())
+        },
+    }
 }
```

**Pros:** Minimal change, no Router internals modified, immediate cleanup.
**Cons:** `abort()` is forceful — any in-flight QUIC close frames won't be
sent. Acceptable for failed handshakes since there's nothing to close cleanly.

### Option B: Poll `accept_sink.closed()` in Router (most correct)

Add the `accept_sink.closed()` future to the Router's poll set so it gets woken
when the receiver is dropped. This ensures Router exits promptly whenever the
accept stream is gone — regardless of whether handshake succeeded or not.

```diff
--- a/tokio-quiche/src/quic/router/mod.rs
+++ b/tokio-quiche/src/quic/router/mod.rs
@@ -50,6 +50,7 @@
 use std::default::Default;
 use std::future::Future;
 use std::io;
+use std::mem::MaybeUninit;
 use std::net::SocketAddr;
 use std::pin::Pin;
 use std::sync::Arc;
@@ -139,6 +140,7 @@
 pub struct InboundPacketRouter<Tx, Rx, M, I>
 where
     Tx: DatagramSocketSend + Send + 'static,
     M: Metrics,
 {
     socket_tx: Arc<Tx>,
     socket_rx: Rx,
@@ -150,6 +152,8 @@
     conn_map_cmd_tx: mpsc::UnboundedSender<ConnectionMapCommand>,
     conn_map_cmd_rx: mpsc::UnboundedReceiver<ConnectionMapCommand>,
     accept_sink: mpsc::Sender<io::Result<InitialQuicConnection<Tx, M>>>,
+    /// Wakes this task when the accept stream receiver is dropped.
+    accept_closed: Pin<Box<dyn Future<Output = ()> + Send>>,
     metrics: M,
     #[cfg(target_os = "linux")]
     udp_drop_count: u32,
```

In `InboundPacketRouter::new`, initialize the future:

```diff
@@ -178,6 +182,7 @@
     pub(crate) fn new(...) -> ... {
         let (accept_sink, accept_stream) = mpsc::channel(config.listen_backlog);
+        let accept_closed = Box::pin(accept_sink.closed());
         // ... existing code ...
         (
             Self {
                 // ... existing fields ...
                 accept_sink,
+                accept_closed,
                 // ...
             },
             accept_stream,
         )
     }
```

In the poll loop, register the waker:

```diff
@@ -754,6 +759,12 @@
                 Poll::Pending => {
+                    // Register waker for accept stream closure. When the
+                    // receiver is dropped, this future completes and wakes
+                    // the Router so it can detect is_closed() and shut down.
+                    let _ = self.accept_closed.as_mut().poll(cx);
+
                     // Check whether any connections are still active
                     if self.shutdown_tx.is_some() && self.accept_sink.is_closed()
                     {
                         self.shutdown_tx = None;
                     }
```

**Pros:** Fixes both handshake-failure and post-connection-close cases. Router
exits promptly whenever no one is listening. No forceful abort.
**Cons:** Requires adding a field to Router struct. Slightly more invasive.

### Option C: Periodic self-wake (least surgical)

Router sets a timer to periodically re-poll shutdown conditions.

```diff
--- a/tokio-quiche/src/quic/router/mod.rs
+++ b/tokio-quiche/src/quic/router/mod.rs
@@ -59,6 +59,7 @@
 use std::time::Instant;
 use std::time::SystemTime;
 use task_killswitch::spawn_with_killswitch;
 use tokio::sync::mpsc;
+use tokio::time::{self, Interval};

@@ -139,6 +140,7 @@
 pub struct InboundPacketRouter<Tx, Rx, M, I>
 {
     // ... existing fields ...
     accept_sink: mpsc::Sender<io::Result<InitialQuicConnection<Tx, M>>>,
+    cleanup_interval: Interval,
     metrics: M,
```

In `InboundPacketRouter::new`:

```diff
@@ -178,6 +182,7 @@
         (
             Self {
                 // ... existing fields ...
                 accept_sink,
+                cleanup_interval: time::interval(Duration::from_secs(5)),
                 // ...
             },
             accept_stream,
         )
```

In the poll loop:

```diff
@@ -754,6 +759,10 @@
                 Poll::Pending => {
+                    // Periodically re-check shutdown conditions in case no
+                    // other event wakes this task (e.g. failed handshake).
+                    let _ = self.cleanup_interval.poll_tick(cx);
+
                     // Check whether any connections are still active
                     if self.shutdown_tx.is_some() && self.accept_sink.is_closed()
                     {
```

**Pros:** Simple, same pattern as Options A/B fields.
**Cons:** Delayed cleanup (up to 5s). Adds unnecessary periodic wake-ups to
every Router, not just failed ones.

## Recommendation

**Option A** for an immediate fix — it's a ~10-line change in one function with
no risk to existing connection lifecycle. Can be combined with **Option B** as a
longer-term improvement to make Router shutdown more robust in general.
