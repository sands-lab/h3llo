//! Bearer Token authentication helpers for HTTP/3 CONNECT-IP.
//!
//! Provides Bearer Token generation and validation for CONNECT-IP
//! authentication per RFC 6750.
//!
//! # Security
//!
//! Token comparisons use HMAC-SHA256 with a per-call random key to normalize
//! variable-length tokens to fixed 32-byte digests before verification.
//! This removes direct length-mismatch leakage from the equality check, though
//! total processing cost still scales with token length, so inputs are bounded.

use std::fmt;

use hmac_sha256::HMAC;

/// Authentication failure reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No `Authorization` header was present.
    MissingHeader,
    /// Header did not use `Bearer` scheme.
    NotBearer,
    /// Bearer token was empty.
    EmptyToken,
    /// Token did not match any configured peer.
    InvalidToken,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHeader => f.write_str("missing Authorization header"),
            Self::NotBearer => f.write_str("not Bearer auth"),
            Self::EmptyToken => f.write_str("empty token"),
            Self::InvalidToken => f.write_str("unknown peer or invalid token"),
        }
    }
}

/// Generates HTTP Bearer Token Authorization header value.
///
/// # Arguments
/// - `token`: The bearer token (e.g., `peers[target].h3.token`)
///
/// # Returns
/// Header value: `Bearer <token>`
#[must_use]
pub fn bearer_auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

/// Validates CONNECT-IP authentication against peer tokens using Bearer scheme.
///
/// Per `docs/protocol.md`: client sends `Authorization: Bearer <peers[target].h3.token>`.
/// Server matches token against its `peers[].h3.token` collection.
///
/// Uses HMAC-SHA256 with a per-call random key to compare fixed-size MACs
/// instead of the original variable-length token bytes.
///
/// # Errors
///
/// Returns [`AuthError`] if the header is missing, not Bearer-prefixed, empty,
/// or no token matches any configured peer.
pub fn validate_connect_auth<'a>(
    header_value: Option<&str>,
    peer_tokens: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<String, AuthError> {
    let header = header_value.ok_or(AuthError::MissingHeader)?;
    let token = header.strip_prefix("Bearer ").ok_or(AuthError::NotBearer)?;

    if token.is_empty() {
        return Err(AuthError::EmptyToken);
    }

    // Compare fixed-size MACs so the equality check does not expose whether
    // the original token lengths differ.
    let key: [u8; 32] = rand::random();
    let presented_mac = HMAC::mac(token.as_bytes(), key);

    for (peer_id, peer_token) in peer_tokens {
        if HMAC::verify(peer_token.as_bytes(), key, &presented_mac) {
            return Ok(peer_id.to_string());
        }
    }
    Err(AuthError::InvalidToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_auth_header_format() {
        let header = bearer_auth_header("my-secret-token");
        assert_eq!(header, "Bearer my-secret-token");
    }

    #[test]
    fn validate_connect_auth_success() {
        let header = bearer_auth_header("token-for-peer1");
        let tokens = [("peer1", "token-for-peer1"), ("peer2", "token-for-peer2")];
        let result = validate_connect_auth(Some(&header), tokens);
        assert_eq!(result, Ok("peer1".to_string()));
    }

    #[test]
    fn validate_connect_auth_wrong_token() {
        let header = bearer_auth_header("wrong-token");
        let tokens = [("peer1", "correct-token")];
        let result = validate_connect_auth(Some(&header), tokens);
        assert_eq!(result, Err(AuthError::InvalidToken));
    }

    #[test]
    fn validate_connect_auth_missing_header() {
        let tokens = [("peer1", "token1")];
        let result = validate_connect_auth(None, tokens);
        assert_eq!(result, Err(AuthError::MissingHeader));
    }

    #[test]
    fn validate_connect_auth_rejects_basic_auth() {
        let result = validate_connect_auth(Some("Basic dXNlcjpwYXNz"), [("p", "s")]);
        assert_eq!(result, Err(AuthError::NotBearer));
    }

    #[test]
    fn validate_connect_auth_accepts_second_peer() {
        let header = bearer_auth_header("token-b");
        let tokens = [("peer-a", "token-a"), ("peer-b", "token-b")];
        let result = validate_connect_auth(Some(&header), tokens);
        assert_eq!(result, Ok("peer-b".to_string()));
    }

    #[test]
    fn validate_connect_auth_empty_token() {
        let result = validate_connect_auth(Some("Bearer "), [("peer", "token")]);
        assert_eq!(result, Err(AuthError::EmptyToken));
    }

    #[test]
    fn validate_connect_auth_different_length_tokens() {
        let header = bearer_auth_header("short");
        let tokens = [("peer1", "a-much-longer-token-here")];
        let result = validate_connect_auth(Some(&header), tokens);
        assert_eq!(result, Err(AuthError::InvalidToken));
    }

    #[test]
    fn validate_connect_auth_same_length_wrong_token() {
        let header = bearer_auth_header("aaaa-bbbb-cccc");
        let tokens = [("peer1", "xxxx-yyyy-zzzz")];
        let result = validate_connect_auth(Some(&header), tokens);
        assert_eq!(result, Err(AuthError::InvalidToken));
    }

    #[test]
    fn validate_connect_auth_rejects_prefix_of_valid_token() {
        let header = bearer_auth_header("token-for");
        let tokens = [("peer1", "token-for-peer1")];
        let result = validate_connect_auth(Some(&header), tokens);
        assert_eq!(result, Err(AuthError::InvalidToken));
    }
}
