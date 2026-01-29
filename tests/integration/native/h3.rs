//! Integration tests for HTTP/3 module.

use h3llo::auth::{generate_basic_auth, validate_basic_auth, validate_connect_auth};
use h3llo::h3::{
    accept_connect_ip, connect_ip_client, create_client_endpoint, create_server_endpoint,
    load_certs, load_key, unwrap_datagram, wrap_datagram, ConnectIpError, CONTEXT_ID_ZERO,
};
use std::net::{Ipv4Addr, SocketAddr};

// ========== Auth Tests ==========

#[test]
fn auth_roundtrip_validates_correctly() {
    let header = generate_basic_auth("test-user", "test-pass");
    assert!(header.starts_with("Basic "));
    assert!(validate_basic_auth(&header, "test-user", "test-pass"));
}

#[test]
fn auth_rejects_mismatched_username() {
    let header = generate_basic_auth("user1", "password");
    assert!(!validate_basic_auth(&header, "user2", "password"));
}

#[test]
fn auth_rejects_mismatched_password() {
    let header = generate_basic_auth("user", "correct");
    assert!(!validate_basic_auth(&header, "user", "wrong"));
}

#[test]
fn auth_rejects_bearer_scheme() {
    assert!(!validate_basic_auth("Bearer xyz", "user", "pass"));
}

#[test]
fn auth_handles_colon_in_password() {
    let header = generate_basic_auth("user", "pass:with:colons");
    assert!(validate_basic_auth(&header, "user", "pass:with:colons"));
}

#[test]
fn connect_auth_accepts_valid_peer() {
    let header = generate_basic_auth("peer-a", "secret-a");
    let peers = [("peer-a", "secret-a"), ("peer-b", "secret-b")];
    let result = validate_connect_auth(Some(&header), peers);
    assert_eq!(result, Ok("peer-a".to_string()));
}

#[test]
fn connect_auth_accepts_second_peer() {
    let header = generate_basic_auth("peer-b", "secret-b");
    let peers = [("peer-a", "secret-a"), ("peer-b", "secret-b")];
    let result = validate_connect_auth(Some(&header), peers);
    assert_eq!(result, Ok("peer-b".to_string()));
}

#[test]
fn connect_auth_rejects_unknown_peer() {
    let header = generate_basic_auth("unknown", "secret");
    let peers = [("peer-a", "secret-a")];
    let result = validate_connect_auth(Some(&header), peers);
    assert_eq!(result, Err("unknown peer or invalid secret"));
}

#[test]
fn connect_auth_rejects_wrong_secret() {
    let header = generate_basic_auth("peer-a", "wrong-secret");
    let peers = [("peer-a", "secret-a")];
    let result = validate_connect_auth(Some(&header), peers);
    assert_eq!(result, Err("unknown peer or invalid secret"));
}

#[test]
fn connect_auth_rejects_missing_header() {
    let peers = [("peer-a", "secret-a")];
    let result = validate_connect_auth(None, peers);
    assert_eq!(result, Err("missing Authorization header"));
}

// ========== Datagram Framing Tests ==========

#[test]
fn datagram_wrap_prepends_context_id() {
    let payload = vec![0x45, 0x00, 0x00, 0x14]; // IPv4 header fragment
    let wrapped = wrap_datagram(&payload);
    assert_eq!(wrapped.len(), 5);
    assert_eq!(wrapped[0], CONTEXT_ID_ZERO);
    assert_eq!(&wrapped[1..], &payload[..]);
}

#[test]
fn datagram_unwrap_strips_context_id() {
    let framed = vec![0x00, 0x45, 0x00, 0x00, 0x14];
    let unwrapped = unwrap_datagram(&framed);
    assert_eq!(unwrapped, Some(&[0x45, 0x00, 0x00, 0x14][..]));
}

#[test]
fn datagram_unwrap_rejects_wrong_context_id() {
    let framed = vec![0x01, 0x45, 0x00];
    assert!(unwrap_datagram(&framed).is_none());
}

#[test]
fn datagram_unwrap_rejects_empty_input() {
    assert!(unwrap_datagram(&[]).is_none());
}

#[test]
fn datagram_roundtrip() {
    let original = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x08]; // IPv6 header fragment
    let wrapped = wrap_datagram(&original);
    let unwrapped = unwrap_datagram(&wrapped).unwrap();
    assert_eq!(unwrapped, &original[..]);
}

// ========== TLS Configuration Tests ==========

/// Generates a self-signed certificate and key for testing.
fn generate_test_cert() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::io::Write;

    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();

    let mut cert_file = tempfile::NamedTempFile::new().unwrap();
    cert_file.write_all(cert.pem().as_bytes()).unwrap();
    cert_file.flush().unwrap();

    let mut key_file = tempfile::NamedTempFile::new().unwrap();
    key_file
        .write_all(key_pair.serialize_pem().as_bytes())
        .unwrap();
    key_file.flush().unwrap();

    (cert_file, key_file)
}

#[test]
fn load_certs_from_pem_file() {
    let (cert_file, _key_file) = generate_test_cert();
    let certs = load_certs(cert_file.path()).expect("should load certificate");
    assert_eq!(certs.len(), 1, "should have exactly one certificate");
}

#[test]
fn load_key_from_pem_file() {
    let (_cert_file, key_file) = generate_test_cert();
    let key = load_key(key_file.path()).expect("should load private key");
    // Just verify we got a key (can't easily inspect the contents)
    assert!(std::mem::size_of_val(&key) > 0);
}

#[test]
fn load_certs_returns_error_for_nonexistent_file() {
    let result = load_certs(std::path::Path::new("/nonexistent/path/cert.pem"));
    assert!(result.is_err());
}

#[test]
fn load_key_returns_error_for_nonexistent_file() {
    let result = load_key(std::path::Path::new("/nonexistent/path/key.pem"));
    assert!(result.is_err());
}

#[tokio::test]
async fn create_server_endpoint_with_test_certs() {
    let (cert_file, key_file) = generate_test_cert();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

    let endpoint = create_server_endpoint(addr, cert_file.path(), key_file.path())
        .expect("should create server endpoint");

    // Verify the endpoint is bound
    let local_addr = endpoint.local_addr().expect("should have local address");
    assert!(local_addr.port() > 0, "should be bound to a port");

    // Clean up
    endpoint.close(0u32.into(), b"test done");
}

#[tokio::test]
async fn create_client_endpoint_insecure_mode() {
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    let endpoint = create_client_endpoint(addr, None, true)
        .expect("should create client endpoint in insecure mode");

    // Verify the endpoint is bound
    let local_addr = endpoint.local_addr().expect("should have local address");
    assert!(local_addr.port() > 0, "should be bound to a port");

    // Clean up
    endpoint.close(0u32.into(), b"test done");
}

#[tokio::test]
async fn create_client_endpoint_with_custom_ca() {
    let (cert_file, _key_file) = generate_test_cert();
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    let endpoint = create_client_endpoint(addr, Some(cert_file.path()), false)
        .expect("should create client endpoint with custom CA");

    // Verify the endpoint is bound
    let local_addr = endpoint.local_addr().expect("should have local address");
    assert!(local_addr.port() > 0, "should be bound to a port");

    // Clean up
    endpoint.close(0u32.into(), b"test done");
}

// ========== CONNECT-IP Handshake Tests ==========

#[tokio::test]
async fn connect_ip_handshake_success() {
    let (cert_file, key_file) = generate_test_cert();
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

    // Create server endpoint
    let server_endpoint = create_server_endpoint(server_addr, cert_file.path(), key_file.path())
        .expect("server endpoint");
    let actual_addr = server_endpoint.local_addr().unwrap();

    // Create client endpoint with the test cert as CA
    let client_endpoint = create_client_endpoint(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        Some(cert_file.path()),
        false,
    )
    .expect("client endpoint");

    let peer_secrets = [("test-peer", "test-secret-12345")];

    // Spawn server accept task
    let server_handle = tokio::spawn({
        let endpoint = server_endpoint.clone();
        async move {
            let incoming = endpoint.accept().await.expect("accept incoming");
            let quic_conn = incoming.await.expect("quic connection");
            accept_connect_ip(quic_conn, "/tunnel", peer_secrets).await
        }
    });

    // Client connects
    let quic_conn = client_endpoint
        .connect(actual_addr, "localhost")
        .expect("connect")
        .await
        .expect("quic connection");

    let client_result = connect_ip_client(
        quic_conn,
        &format!("localhost:{}", actual_addr.port()),
        "/tunnel",
        "test-peer",
        "test-secret-12345",
    )
    .await;

    assert!(
        client_result.is_ok(),
        "client handshake should succeed: {:?}",
        client_result.err()
    );

    let server_result = server_handle.await.unwrap();
    assert!(
        server_result.is_ok(),
        "server handshake should succeed: {:?}",
        server_result.err()
    );

    let (peer_id, _, _) = server_result.unwrap();
    assert_eq!(peer_id, "test-peer");

    // Cleanup
    server_endpoint.close(0u32.into(), b"done");
    client_endpoint.close(0u32.into(), b"done");
}

#[tokio::test]
async fn connect_ip_rejects_invalid_credentials() {
    let (cert_file, key_file) = generate_test_cert();
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

    let server_endpoint = create_server_endpoint(server_addr, cert_file.path(), key_file.path())
        .expect("server endpoint");
    let actual_addr = server_endpoint.local_addr().unwrap();

    let client_endpoint = create_client_endpoint(
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        Some(cert_file.path()),
        false,
    )
    .expect("client endpoint");

    // Server expects different credentials
    let peer_secrets = [("test-peer", "correct-secret")];

    let server_handle = tokio::spawn({
        let endpoint = server_endpoint.clone();
        async move {
            let incoming = endpoint.accept().await.expect("accept incoming");
            let quic_conn = incoming.await.expect("quic connection");
            accept_connect_ip(quic_conn, "/tunnel", peer_secrets).await
        }
    });

    let quic_conn = client_endpoint
        .connect(actual_addr, "localhost")
        .expect("connect")
        .await
        .expect("quic connection");

    // Client sends wrong secret
    let client_result = connect_ip_client(
        quic_conn,
        &format!("localhost:{}", actual_addr.port()),
        "/tunnel",
        "test-peer",
        "wrong-secret",
    )
    .await;

    // Client should receive error - either AuthFailed (401) or connection closed
    // The race between server sending 401 and closing connection can cause either
    assert!(
        client_result.is_err(),
        "client should fail with invalid credentials"
    );

    let server_result = server_handle.await.unwrap();
    assert!(matches!(server_result, Err(ConnectIpError::AuthFailed)));

    server_endpoint.close(0u32.into(), b"done");
    client_endpoint.close(0u32.into(), b"done");
}

// ========== Actor Lifecycle Tests ==========
//
// Note: Full H3 actor lifecycle tests require establishing a real QUIC connection
// between a server and client, which involves:
// 1. Starting a server endpoint and accepting connections
// 2. Connecting a client to the server
// 3. Spawning actors on the established connection
// 4. Testing shutdown behavior
//
// These tests are more suitable for e2e tests with container support.
// The unit tests in src/h3.rs cover the core actor logic.
// See tests/e2e/ for full tunnel tests when available.
