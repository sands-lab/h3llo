//! Integration tests for HTTP/3 module.

use h3llo::auth::{generate_basic_auth, validate_basic_auth, validate_connect_auth};
use h3llo::h3::{unwrap_datagram, wrap_datagram, CONTEXT_ID_ZERO};

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
