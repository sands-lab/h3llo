//! Helpers for retrying I/O operations and IP packet utilities.

use std::net::IpAddr;

/// IPv4 header field offsets.
const IPV4_TTL_OFFSET: usize = 8;
const IPV4_CHECKSUM_OFFSET: usize = 10;
/// IPv6 hop limit offset.
const IPV6_HOP_LIMIT_OFFSET: usize = 7;
/// Minimum IPv4 header length.
const IPV4_MIN_LEN: usize = 20;
/// Minimum IPv6 header length.
const IPV6_MIN_LEN: usize = 40;

/// Decrements the TTL (IPv4) or hop limit (IPv6) by 1 in-place.
///
/// For IPv4, also performs an RFC 1624 incremental checksum update.
/// Returns the **original** TTL/hop-limit value before decrement, or `None`
/// if the packet is malformed (too short, unrecognized version, or TTL already 0).
///
/// # IPv4 incremental checksum ([RFC 1624])
///
/// TTL occupies byte 8, the high byte of the 16-bit word `[TTL, Protocol]`.
/// Decrementing TTL by 1 subtracts `0x0100` from that word. The one's-complement
/// checksum update adds `0x0100` with carry folding.
///
/// # IPv6
///
/// IPv6 has no header checksum. Only the hop limit (byte 7) is decremented.
///
/// [RFC 1624]: https://www.rfc-editor.org/rfc/rfc1624
pub(crate) fn decrement_ttl(packet: &mut [u8]) -> Option<u8> {
    let version = packet.first().map(|b| b >> 4)?;
    match version {
        4 => {
            if packet.len() < IPV4_MIN_LEN {
                return None;
            }
            let old_ttl = packet[IPV4_TTL_OFFSET];
            if old_ttl == 0 {
                return None;
            }
            packet[IPV4_TTL_OFFSET] = old_ttl - 1;

            // RFC 1624 incremental checksum update.
            let old_check = u16::from_be_bytes([
                packet[IPV4_CHECKSUM_OFFSET],
                packet[IPV4_CHECKSUM_OFFSET + 1],
            ]);
            let mut sum = old_check as u32 + 0x0100;
            sum = (sum & 0xFFFF) + (sum >> 16);
            sum = (sum & 0xFFFF) + (sum >> 16);
            // Handle -0 edge case (RFC 1624 Section 4).
            let new_check = if sum as u16 == 0xFFFF {
                0u16
            } else {
                sum as u16
            };
            packet[IPV4_CHECKSUM_OFFSET..IPV4_CHECKSUM_OFFSET + 2]
                .copy_from_slice(&new_check.to_be_bytes());

            Some(old_ttl)
        }
        6 => {
            if packet.len() < IPV6_MIN_LEN {
                return None;
            }
            let old_hl = packet[IPV6_HOP_LIMIT_OFFSET];
            if old_hl == 0 {
                return None;
            }
            packet[IPV6_HOP_LIMIT_OFFSET] = old_hl - 1;
            Some(old_hl)
        }
        _ => None,
    }
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

    // ========== decrement_ttl tests ==========

    /// Compute IPv4 header checksum from scratch for test verification.
    fn compute_ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn decrement_ttl_ipv4_updates_checksum() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[8] = 64;
        // Compute initial checksum from scratch.
        pkt[10] = 0;
        pkt[11] = 0;
        let initial = compute_ipv4_checksum(&pkt);
        pkt[10..12].copy_from_slice(&initial.to_be_bytes());

        let old_ttl = decrement_ttl(&mut pkt);
        assert_eq!(old_ttl, Some(64));
        assert_eq!(pkt[8], 63);

        // Verify incremental matches from-scratch.
        let stored = u16::from_be_bytes([pkt[10], pkt[11]]);
        pkt[10] = 0;
        pkt[11] = 0;
        let recomputed = compute_ipv4_checksum(&pkt);
        assert_eq!(stored, recomputed);
    }

    #[test]
    fn decrement_ttl_ipv4_ttl_one_becomes_zero() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[8] = 1;
        assert_eq!(decrement_ttl(&mut pkt), Some(1));
        assert_eq!(pkt[8], 0);
    }

    #[test]
    fn decrement_ttl_ipv4_checksum_carry_folds() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[8] = 10;
        pkt[10] = 0xFF;
        pkt[11] = 0x00;
        let old = decrement_ttl(&mut pkt).unwrap();
        assert_eq!(old, 10);
        assert_eq!(u16::from_be_bytes([pkt[10], pkt[11]]), 0x0001);
    }

    #[test]
    fn decrement_ttl_ipv6_decrements_hop_limit() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[7] = 128;
        assert_eq!(decrement_ttl(&mut pkt), Some(128));
        assert_eq!(pkt[7], 127);
    }

    #[test]
    fn decrement_ttl_returns_none_for_malformed() {
        assert!(decrement_ttl(&mut [0x45; 10]).is_none()); // IPv4 too short
        assert!(decrement_ttl(&mut [0x60; 20]).is_none()); // IPv6 too short
        assert!(decrement_ttl(&mut [0x30; 20]).is_none()); // Unknown version
    }

    #[test]
    fn decrement_ttl_zero_ttl_returns_none() {
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[8] = 0;
        assert_eq!(decrement_ttl(&mut pkt), None);
    }
}
