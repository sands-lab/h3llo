//! Helpers for retrying transient I/O errors, channel backpressure, and
//! headroom-aware packet buffer allocation.

use std::time::{Duration, Instant};
use tokio_quiche::buf_factory::{BufFactory, PooledBuf};

/// Reserved headroom bytes at the start of every packet buffer.
///
/// 9 bytes tokio-quiche DGRAM_PREFIX (flow ID + flow context encoding) +
/// 1 byte CONNECT-IP Context ID (0x00). If tokio-quiche `DGRAM_PREFIX`
/// changes, this value must be updated accordingly.
///
/// All packet-producing paths (TUN RX, BareUDP RX) reserve this headroom
/// so downstream consumers (H3 TX, TUN TX) can prepend headers in-place.
pub(crate) const HEADROOM: usize = 10;

/// Allocates an uninitialized pooled buffer with [`HEADROOM`] bytes reserved,
/// selecting the smallest pool that fits `length + HEADROOM`.
///
/// Uses the datagram pool (≤ [`BufFactory::MAX_DGRAM_SIZE`] bytes) for typical
/// packets and falls back to the generic pool for oversized payloads.
///
/// The returned buffer's visible length is `pool_capacity - HEADROOM`, which
/// may exceed `length`. Callers must [`truncate`](PooledBuf::truncate) to the
/// actual payload size.
///
/// # Arguments
///
/// * `length` - Expected payload size (excluding headroom).
pub(crate) fn alloc_uninit_packet_buf(length: usize) -> PooledBuf {
    if length + HEADROOM <= BufFactory::MAX_DGRAM_SIZE {
        let mut buf = BufFactory::get_max_datagram();
        // get_max_datagram() reserves an internal prefix (DGRAM_PREFIX) that
        // may differ from our HEADROOM.  Compute and consume the difference.
        let dgram_headroom = BufFactory::MAX_DGRAM_SIZE - buf.len();
        if dgram_headroom < HEADROOM {
            buf.pop_front(HEADROOM - dgram_headroom);
        }
        buf
    } else {
        let mut buf = BufFactory::get_max_buf();
        buf.pop_front(HEADROOM);
        buf
    }
}

/// Allocates a pooled buffer with headroom for in-place header prepending.
///
/// Data starts at offset `HEADROOM`, leaving room for downstream consumers
/// to prepend headers via `add_prefix` without reallocation.
pub(crate) fn alloc_packet_buf(data: &[u8]) -> PooledBuf {
    let mut buf = alloc_uninit_packet_buf(data.len());
    buf.truncate(data.len());
    buf[..data.len()].copy_from_slice(data);
    buf
}

/// Returns `(packet_count, total_bytes)` for a batch of pooled buffers.
pub(crate) fn batch_stats(batch: &[PooledBuf]) -> (u64, u64) {
    (
        batch.len() as u64,
        batch.iter().map(|p| p.len() as u64).sum(),
    )
}

/// Retries an async I/O expression on transient errors (`Interrupted`, `WouldBlock`).
///
/// `Interrupted` errors retry immediately (no yield). `WouldBlock` errors
/// call `tokio::task::yield_now().await` before retrying.
///
/// The second argument is a closure invoked when a WouldBlock sequence
/// completes (on both `Ok` and non-transient `Err`), receiving the total
/// `Duration` spent waiting. Pass `|_| {}` when no tracking is needed.
macro_rules! retry_on_transient {
    ($expr:expr, $on_would_block:expr) => {{
        let mut __wb_start: Option<std::time::Instant> = None;
        let mut __on_wb = $on_would_block;
        loop {
            match $expr {
                Ok(val) => {
                    if let Some(start) = __wb_start {
                        __on_wb(start.elapsed());
                    }
                    break Ok(val);
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if __wb_start.is_none() {
                        __wb_start = Some(std::time::Instant::now());
                    }
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(err) => {
                    if let Some(start) = __wb_start {
                        __on_wb(start.elapsed());
                    }
                    break Err(err);
                }
            }
        }
    }};
}

pub(crate) use retry_on_transient;

// ---------------------------------------------------------------------------
// Channel backpressure helper
// ---------------------------------------------------------------------------

/// Event emitted by [`send_with_backpressure`] to report channel state.
pub(crate) enum SendEvent {
    /// `try_send` succeeded on the fast path (no contention).
    Fast,
    /// `try_send` returned `Full`; an awaited send will follow.
    Full,
    /// Awaited send completed after a wait of the given duration.
    Waited(Duration),
}

/// Sends a value through a bounded channel and exposes backpressure events.
///
/// Event order:
/// - Fast path: `Fast`
/// - Full then success: `Full` → `Waited(duration)`
pub(crate) async fn send_with_backpressure<T, F>(
    tx: &tokio::sync::mpsc::Sender<T>,
    value: T,
    mut on_event: F,
) -> Result<(), tokio::sync::mpsc::error::SendError<T>>
where
    F: FnMut(SendEvent),
{
    match tx.try_send(value) {
        Ok(()) => {
            on_event(SendEvent::Fast);
            Ok(())
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(val)) => {
            on_event(SendEvent::Full);
            let start = Instant::now();
            match tx.send(val).await {
                Ok(()) => {
                    on_event(SendEvent::Waited(start.elapsed()));
                    Ok(())
                }
                Err(tokio::sync::mpsc::error::SendError(val)) => {
                    Err(tokio::sync::mpsc::error::SendError(val))
                }
            }
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(val)) => {
            Err(tokio::sync::mpsc::error::SendError(val))
        }
    }
}

/// Test utilities for constructing IP packets.
#[cfg(test)]
pub(crate) mod test_packets {
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Creates a minimal IPv4 packet with the given destination address.
    ///
    /// The packet has version 4, IHL 5 (20 bytes), and the destination IP set.
    /// All other fields are zeroed.
    pub fn make_ipv4_packet(dst: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        let octets = dst.octets();
        packet[16..20].copy_from_slice(&octets);
        packet
    }

    /// Creates a minimal IPv6 packet with the given destination address.
    ///
    /// The packet has version 6 and the destination IP set.
    /// All other fields are zeroed.
    pub fn make_ipv6_packet(dst: Ipv6Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60; // Version 6
        let octets = dst.octets();
        packet[24..40].copy_from_slice(&octets);
        packet
    }

    /// Creates a minimal IPv4 packet with the given destination and TTL.
    pub fn make_ipv4_with_ttl(dst: Ipv4Addr, ttl: u8) -> Vec<u8> {
        let mut pkt = make_ipv4_packet(dst);
        pkt[8] = ttl;
        pkt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn retries_on_interrupted_errors() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();

        let result = retry_on_transient!(
            {
                let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "injected interruption",
                    ))
                } else {
                    Ok(5)
                }
            },
            |_| {}
        )
        .expect("retry should eventually succeed");

        assert_eq!(result, 5);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn retries_on_would_block_errors() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();

        let result = retry_on_transient!(
            {
                let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "injected would-block",
                    ))
                } else {
                    Ok(42)
                }
            },
            |_| {}
        )
        .expect("retry should eventually succeed");

        assert_eq!(result, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn make_ipv4_packet_has_correct_structure() {
        let dst = Ipv4Addr::new(192, 0, 2, 1);
        let packet = test_packets::make_ipv4_packet(dst);
        assert_eq!(packet.len(), 20);
        assert_eq!(packet[0], 0x45);
        assert_eq!(&packet[16..20], &[192, 0, 2, 1]);
    }

    #[test]
    fn make_ipv6_packet_has_correct_structure() {
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let packet = test_packets::make_ipv6_packet(dst);
        assert_eq!(packet.len(), 40);
        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(&packet[24..40], &dst.octets());
    }

    #[tokio::test]
    async fn would_block_callback_invoked_with_duration() {
        use std::sync::Mutex;
        use std::time::Duration;

        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();
        let recorded_dur = Arc::new(Mutex::new(None::<Duration>));
        let recorded_dur_clone = recorded_dur.clone();

        let result = retry_on_transient!(
            {
                let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    Err(io::Error::new(io::ErrorKind::WouldBlock, "injected"))
                } else {
                    Ok(42)
                }
            },
            |dur: Duration| {
                *recorded_dur_clone.lock().unwrap() = Some(dur);
            }
        )
        .expect("retry should succeed");

        assert_eq!(result, 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        let dur = recorded_dur.lock().unwrap().expect("callback should fire");
        assert!(dur.as_nanos() > 0, "duration should be nonzero");
    }

    #[tokio::test]
    async fn would_block_callback_not_invoked_on_success() {
        use std::time::Duration;
        let invoked = Arc::new(AtomicUsize::new(0));
        let invoked_clone = invoked.clone();

        let result: Result<i32, io::Error> =
            retry_on_transient!(Ok::<i32, io::Error>(99), |_dur: Duration| {
                invoked_clone.fetch_add(1, Ordering::SeqCst);
            });

        assert_eq!(result.unwrap(), 99);
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn interrupted_does_not_yield() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();
        let interloper_ran = Arc::new(AtomicUsize::new(0));
        let interloper_ran_clone = interloper_ran.clone();

        let interloper = tokio::spawn(async move {
            loop {
                interloper_ran_clone.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
            }
        });

        tokio::task::yield_now().await;
        let before = interloper_ran.load(Ordering::SeqCst);

        retry_on_transient!(
            {
                let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
                if count < 3 {
                    Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"))
                } else {
                    Ok(())
                }
            },
            |_| {}
        )
        .unwrap();

        let after = interloper_ran.load(Ordering::SeqCst);
        interloper.abort();
        assert_eq!(before, after, "Interrupted should not yield to other tasks");
    }

    // -- send_with_backpressure tests --

    #[tokio::test]
    async fn send_with_backpressure_fast_path() {
        let (tx, mut rx) = mpsc::channel::<u32>(4);
        let mut saw_fast = false;
        let mut saw_full = false;
        let mut waited = Duration::ZERO;

        send_with_backpressure(&tx, 7, |event| match event {
            SendEvent::Fast => saw_fast = true,
            SendEvent::Full => saw_full = true,
            SendEvent::Waited(d) => waited = d,
        })
        .await
        .unwrap();

        assert_eq!(rx.recv().await, Some(7));
        assert!(saw_fast);
        assert!(!saw_full);
        assert_eq!(waited, Duration::ZERO);
    }

    #[tokio::test]
    async fn send_with_backpressure_waited_path() {
        let (tx, mut rx) = mpsc::channel::<u32>(1);
        tx.send(1).await.unwrap();

        let drain = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            rx.recv().await;
            rx
        });

        let mut saw_fast = false;
        let mut saw_full = false;
        let mut waited = Duration::ZERO;

        send_with_backpressure(&tx, 2, |event| match event {
            SendEvent::Fast => saw_fast = true,
            SendEvent::Full => saw_full = true,
            SendEvent::Waited(d) => waited = d,
        })
        .await
        .unwrap();

        assert!(!saw_fast);
        assert!(saw_full);
        assert!(waited > Duration::ZERO);
        let _rx = drain.await.unwrap();
    }

    #[tokio::test]
    async fn send_with_backpressure_closed_path() {
        let (tx, rx) = mpsc::channel::<u32>(1);
        drop(rx);

        let mut saw_fast = false;
        let mut saw_full = false;
        let mut waited = Duration::ZERO;

        let err = send_with_backpressure(&tx, 9, |event| match event {
            SendEvent::Fast => saw_fast = true,
            SendEvent::Full => saw_full = true,
            SendEvent::Waited(d) => waited = d,
        })
        .await
        .unwrap_err();

        assert_eq!(err.0, 9);
        assert!(!saw_fast);
        assert!(!saw_full);
        assert_eq!(waited, Duration::ZERO);
    }
}
