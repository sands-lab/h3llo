//! BareUDP transport: socket setup, source-IP filtering, and send/receive loops.

use crate::bind::{bind_udp_socket, select_bind_interface, BindWarning, RouteProbe};
use log::warn;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Collects resolved peer addresses, preserving the first entry as outbound destination and all IPs for source filtering.
#[derive(Debug, Clone)]
pub struct PeerEndpoints {
    destination: SocketAddr,
    allowed_sources: HashSet<IpAddr>,
    multiple_answers: bool,
}

impl PeerEndpoints {
    /// Builds endpoint selection from resolved addresses, warning when multiple unique IPs exist.
    ///
    /// # Errors
    ///
    /// Returns `BareError::NoResolvedAddresses` when `endpoints` is empty.
    pub fn new(endpoints: Vec<SocketAddr>) -> Result<Self, BareError> {
        if endpoints.is_empty() {
            return Err(BareError::NoResolvedAddresses);
        }

        let destination = endpoints[0];
        let mut allowed_sources = HashSet::new();
        for addr in endpoints {
            allowed_sources.insert(addr.ip());
        }
        let multiple_answers = allowed_sources.len() > 1;
        if multiple_answers {
            warn!(
                "bareudp resolved multiple addresses; using {} for outbound and filtering on {:?}",
                destination, allowed_sources
            );
        }

        Ok(Self {
            destination,
            allowed_sources,
            multiple_answers,
        })
    }

    /// Returns the outbound destination socket address (first resolved entry).
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Returns the set of source IPs allowed for inbound packets.
    pub fn allowed_sources(&self) -> &HashSet<IpAddr> {
        &self.allowed_sources
    }

    /// Indicates whether multiple unique IPs were provided.
    pub fn had_multiple_answers(&self) -> bool {
        self.multiple_answers
    }
}

/// Represents BareUDP socket binding and loop construction errors.
#[derive(Debug, Error)]
pub enum BareError {
    /// No resolved addresses were provided for the peer.
    #[error("bareudp requires at least one resolved address")]
    NoResolvedAddresses,
    /// Socket creation, binding, or conversion failed.
    #[error("bareudp socket setup failed: {0}")]
    Socket(String),
}

/// Binds a UDP socket to `listen` and optionally to `bind_interface`, returning the socket and any binding warnings.
///
/// Binding to an interface is best-effort: missing or ambiguous probe results emit warnings and the socket continues unbound.
///
/// # Arguments
/// - `listen`: Local socket address to bind.
/// - `bind_interface`: Optional preferred interface; treated as a filter during probing.
/// - `target`: Remote server IP used for route probing.
/// - `tun_if`: Optional TUN interface name to exclude from probing.
/// - `probe`: Route probe implementation.
pub async fn bind_socket<P: RouteProbe>(
    listen: SocketAddr,
    bind_interface: Option<&str>,
    target: IpAddr,
    tun_if: Option<&str>,
    probe: &P,
) -> Result<(UdpSocket, Vec<BindWarning>), BareError> {
    // Probe using the remote server IP to avoid recursive routing; pick the first match and warn on ambiguity.
    let (selected_interface, mut warnings) =
        select_bind_interface(target, tun_if, bind_interface, probe).await;

    let (socket, mut bind_warnings) = bind_udp_socket(listen, selected_interface.as_deref())
        .map_err(|e| BareError::Socket(e.to_string()))?;
    warnings.append(&mut bind_warnings);

    Ok((socket, warnings))
}

/// Spawns the BareUDP receive loop, dropping packets whose source IP is not in `allowed_sources`.
pub fn spawn_receiver(
    socket: UdpSocket,
    allowed_sources: HashSet<IpAddr>,
    outbound: mpsc::Sender<Vec<u8>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; u16::MAX as usize];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, remote)) => {
                    if len == 0 || !allowed_sources.contains(&remote.ip()) {
                        continue;
                    }
                    let packet = buf[..len].to_vec();
                    if outbound.send(packet).await.is_err() {
                        break;
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    })
}

/// Spawns the BareUDP send loop, forwarding packets from `inbound` to `destination`.
pub fn spawn_sender(
    socket: UdpSocket,
    destination: SocketAddr,
    mut inbound: mpsc::Receiver<Vec<u8>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(packet) = inbound.recv().await {
            match socket.send_to(&packet, destination).await {
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    #[test]
    fn selects_destination_and_flags_multiple_answers() {
        let endpoints = vec![
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 6635)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 6635)),
        ];
        let set = PeerEndpoints::new(endpoints).expect("peer endpoints should build");
        assert_eq!(
            set.destination(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 6635))
        );
        assert!(set
            .allowed_sources()
            .contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(set
            .allowed_sources()
            .contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        assert!(set.had_multiple_answers());
    }

    #[tokio::test]
    async fn receiver_filters_disallowed_sources() {
        let (socket, addr) = {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            (sock, addr)
        };

        let (tx, mut rx) = mpsc::channel(4);
        let allowed = HashSet::from([IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]);
        let handle = spawn_receiver(socket, allowed, tx);

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(&[1, 2, 3], addr)
            .await
            .expect("send should succeed");

        // Packet should be dropped because source IP is not allowed.
        let result = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(result.is_err(), "no packet should be delivered");

        handle.abort();
    }

    #[tokio::test]
    async fn sender_forwards_packets_to_destination() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let sender_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (tx, rx) = mpsc::channel(4);
        let handle = spawn_sender(sender_socket, dest, rx);

        tx.send(vec![9, 8, 7]).await.unwrap();

        let mut buf = vec![0u8; 64];
        let (len, _) = receiver
            .recv_from(&mut buf)
            .await
            .expect("receiver should get packet");
        assert_eq!(&buf[..len], &[9, 8, 7]);

        handle.abort();
    }
}
