//! Helpers for retrying I/O operations and IP packet utilities.

use std::net::IpAddr;

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

/// Extracts the destination IP address from an IP packet.
///
/// Returns `None` if the packet is too short or has an unrecognized IP version.
pub(crate) fn extract_dst_ip(packet: &[u8]) -> Option<IpAddr> {
    let first = *packet.first()?;
    match first >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let dst = [packet[16], packet[17], packet[18], packet[19]];
            Some(IpAddr::from(dst))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut dst = [0u8; 16];
            dst.copy_from_slice(&packet[24..40]);
            Some(IpAddr::from(dst))
        }
        _ => None,
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
}

#[cfg(test)]
mod tests {
    use super::{extract_dst_ip, test_packets};
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
        assert_eq!(packet[0], 0x45); // Version 4, IHL 5
        assert_eq!(&packet[16..20], &[192, 0, 2, 1]);
    }

    #[test]
    fn make_ipv6_packet_has_correct_structure() {
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let packet = test_packets::make_ipv6_packet(dst);
        assert_eq!(packet.len(), 40);
        assert_eq!(packet[0] >> 4, 6); // Version 6
        assert_eq!(&packet[24..40], &dst.octets());
    }

    #[test]
    fn extract_dst_ip_parses_ipv4() {
        let dst = Ipv4Addr::new(10, 20, 30, 40);
        let packet = test_packets::make_ipv4_packet(dst);
        assert_eq!(extract_dst_ip(&packet), Some(IpAddr::V4(dst)));
    }

    #[test]
    fn extract_dst_ip_parses_ipv6() {
        let dst: Ipv6Addr = "fe80::1".parse().unwrap();
        let packet = test_packets::make_ipv6_packet(dst);
        assert_eq!(extract_dst_ip(&packet), Some(IpAddr::V6(dst)));
    }

    #[test]
    fn extract_dst_ip_returns_none_for_invalid_packets() {
        // Empty packet
        assert_eq!(extract_dst_ip(&[]), None);
        // Truncated IPv4 (less than 20 bytes)
        assert_eq!(extract_dst_ip(&[0x45; 10]), None);
        // Truncated IPv6 (less than 40 bytes)
        assert_eq!(extract_dst_ip(&[0x60; 30]), None);
        // Unknown version
        assert_eq!(extract_dst_ip(&[0x30; 20]), None);
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
