//! Helpers for retrying transient I/O errors.

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
    use super::test_packets;
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

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

        let _result = retry_on_transient!(
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
}
