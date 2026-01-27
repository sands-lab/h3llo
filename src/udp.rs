//! UDP helpers shared by BareUDP and DNS flows.

use crate::bind::{bind_udp_socket, select_bind_interface, BindWarning, RouteProbe};
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;
use tokio::net::UdpSocket;

/// Represents UDP socket binding and loop construction errors.
#[derive(Debug, Error)]
pub enum UdpError {
    /// No resolved addresses were provided for the peer.
    #[error("udp requires at least one resolved address")]
    NoResolvedAddresses,
    /// Socket creation, binding, or conversion failed.
    #[error("udp socket setup failed: {0}")]
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
) -> Result<(UdpSocket, Vec<BindWarning>), UdpError> {
    // Skip interface binding for localhost addresses (127.x.x.x, ::1).
    // Docker DNS (127.0.0.11) and other localhost services may not work
    // correctly when the socket is bound to a specific interface like 'lo'.
    let is_localhost = match target {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };

    let (selected_interface, mut warnings) = if is_localhost {
        (None, Vec::new())
    } else {
        // Probe using the remote server IP to avoid recursive routing; pick the first match and warn on ambiguity.
        select_bind_interface(target, tun_if, bind_interface, probe).await
    };

    let (socket, mut bind_warnings) = bind_udp_socket(listen, selected_interface.as_deref())
        .map_err(|e| UdpError::Socket(e.to_string()))?;
    warnings.append(&mut bind_warnings);

    Ok((socket, warnings))
}
