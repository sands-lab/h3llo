//! Basic Auth helpers for HTTP/3 CONNECT-IP and control plane.
//!
//! Provides generation and validation functions reusable across
//! CONNECT-IP authentication (Step 9) and control plane (Step 10).
//!
//! # Security
//!
//! All password comparisons use constant-time operations to prevent timing attacks.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

/// Generates HTTP Basic Auth header value.
///
/// # Arguments
/// - `username`: The username (e.g., `local.id` for CONNECT)
/// - `password`: The password (e.g., `peers[target].h3.secret`)
///
/// # Returns
/// Header value: `Basic base64(username:password)`
pub fn generate_basic_auth(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    format!("Basic {}", BASE64.encode(credentials))
}

/// Constant-time byte slice comparison to prevent timing attacks.
///
/// Returns `true` if both slices are equal, `false` otherwise.
/// The comparison always examines all bytes regardless of where differences occur.
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // XOR all bytes and accumulate; result is 0 only if all bytes match
    let diff = a
        .iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    diff == 0
}

/// Parses and validates HTTP Basic Auth credentials.
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Arguments
/// - `header_value`: The Authorization header value
/// - `expected_username`: Expected username
/// - `expected_password`: Expected password
///
/// # Returns
/// `true` if credentials match, `false` otherwise.
pub fn validate_basic_auth(
    header_value: &str,
    expected_username: &str,
    expected_password: &str,
) -> bool {
    let Some(encoded) = header_value.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = BASE64.decode(encoded.as_bytes()) else {
        return false;
    };
    let Ok(credentials) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((user, pass)) = credentials.split_once(':') else {
        return false;
    };
    // Use constant-time comparison for both username and password
    constant_time_eq(user.as_bytes(), expected_username.as_bytes())
        && constant_time_eq(pass.as_bytes(), expected_password.as_bytes())
}

/// Validates CONNECT-IP authentication against peer secrets.
///
/// Per `docs/protocol.md`: client sends `username = local.id`,
/// `password = peers[target].h3.secret`.
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Returns
/// The peer ID if authentication succeeds, or an error description.
pub fn validate_connect_auth<'a>(
    header_value: Option<&str>,
    peer_secrets: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<String, &'static str> {
    let header = header_value.ok_or("missing Authorization header")?;
    let encoded = header.strip_prefix("Basic ").ok_or("not Basic auth")?;
    let decoded = BASE64
        .decode(encoded.as_bytes())
        .map_err(|_| "invalid base64")?;
    let credentials = String::from_utf8(decoded).map_err(|_| "invalid UTF-8")?;
    let (username, password) = credentials.split_once(':').ok_or("missing colon")?;

    for (peer_id, secret) in peer_secrets {
        // Use constant-time comparison to prevent timing attacks
        let user_match = constant_time_eq(peer_id.as_bytes(), username.as_bytes());
        let pass_match = constant_time_eq(secret.as_bytes(), password.as_bytes());
        if user_match && pass_match {
            return Ok(peer_id.to_string());
        }
    }
    Err("unknown peer or invalid secret")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_validate_roundtrip() {
        let header = generate_basic_auth("node1", "secret123");
        assert!(validate_basic_auth(&header, "node1", "secret123"));
    }

    #[test]
    fn rejects_wrong_password() {
        let header = generate_basic_auth("node1", "correct");
        assert!(!validate_basic_auth(&header, "node1", "wrong"));
    }

    #[test]
    fn rejects_wrong_username() {
        let header = generate_basic_auth("node1", "pass");
        assert!(!validate_basic_auth(&header, "node2", "pass"));
    }

    #[test]
    fn rejects_non_basic_prefix() {
        assert!(!validate_basic_auth("Bearer token", "user", "pass"));
    }

    #[test]
    fn validate_connect_auth_success() {
        let header = generate_basic_auth("peer1", "secret1");
        let secrets = [("peer1", "secret1"), ("peer2", "secret2")];
        let result = validate_connect_auth(Some(&header), secrets);
        assert_eq!(result, Ok("peer1".to_string()));
    }

    #[test]
    fn validate_connect_auth_unknown_peer() {
        let header = generate_basic_auth("unknown", "secret");
        let secrets = [("peer1", "secret1")];
        let result = validate_connect_auth(Some(&header), secrets);
        assert!(result.is_err());
    }

    #[test]
    fn validate_connect_auth_missing_header() {
        let secrets = [("peer1", "secret1")];
        let result = validate_connect_auth(None, secrets);
        assert_eq!(result, Err("missing Authorization header"));
    }

    #[test]
    fn validate_connect_auth_invalid_base64() {
        let result = validate_connect_auth(Some("Basic !!!invalid!!!"), [("p", "s")]);
        assert_eq!(result, Err("invalid base64"));
    }

    // ========== Constant-time comparison tests ==========

    #[test]
    fn constant_time_eq_same_values() {
        assert!(constant_time_eq(b"password", b"password"));
    }

    #[test]
    fn constant_time_eq_different_values() {
        assert!(!constant_time_eq(b"password", b"passwort"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }
}
