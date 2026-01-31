//! Helpers for retrying I/O operations and IP packet utilities.

use std::net::IpAddr;

/// Retries an async I/O expression, looping on `io::ErrorKind::Interrupted`.
///
/// The expression should evaluate to `io::Result<usize>` and already include `.await`
/// for async operations.
macro_rules! retry_on_interrupted {
    ($expr:expr) => {{
        loop {
            match $expr {
                Ok(written) => break Ok(written),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
                    // Yield to avoid spinning when syscalls are repeatedly interrupted.
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(err) => break Err(err),
            }
        }
    }};
}

pub(crate) use retry_on_interrupted;

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

        let result = retry_on_interrupted!({
            let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected interruption",
                ))
            } else {
                Ok(5)
            }
        })
        .expect("retry should eventually succeed");

        assert_eq!(result, 5);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
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
}
