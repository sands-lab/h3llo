//! Bearer Token authentication helpers for HTTP/3 CONNECT-IP.
//!
//! Provides Bearer Token generation and validation for CONNECT-IP
//! authentication per RFC 6750.
//!
//! # Security
//!
//! All token comparisons use constant-time operations via the `subtle` crate
//! to prevent timing attacks.

use std::fmt;
use subtle::ConstantTimeEq;

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
pub fn generate_bearer_auth(token: &str) -> String {
    format!("Bearer {token}")
}

/// Validates CONNECT-IP authentication against peer tokens using Bearer scheme.
///
/// Per `docs/protocol.md`: client sends `Authorization: Bearer <peers[target].h3.token>`.
/// Server matches token against its `peers[].h3.token` collection.
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// # Errors
///
/// Returns [`AuthError`] if the header is missing, not Bearer-prefixed,
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

    for (peer_id, peer_token) in peer_tokens {
        // Use constant-time comparison to prevent timing attacks
        let token_match: bool = peer_token.as_bytes().ct_eq(token.as_bytes()).into();
        if token_match {
            return Ok(peer_id.to_string());
        }
    }
    Err(AuthError::InvalidToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_bearer_auth_format() {
        let header = generate_bearer_auth("my-secret-token");
        assert_eq!(header, "Bearer my-secret-token");
    }

    #[test]
    fn validate_connect_auth_success() {
        let header = generate_bearer_auth("token-for-peer1");
        let tokens = [("peer1", "token-for-peer1"), ("peer2", "token-for-peer2")];
        let result = validate_connect_auth(Some(&header), tokens);
        assert_eq!(result, Ok("peer1".to_string()));
    }

    #[test]
    fn validate_connect_auth_wrong_token() {
        let header = generate_bearer_auth("wrong-token");
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
        let header = generate_bearer_auth("token-b");
        let tokens = [("peer-a", "token-a"), ("peer-b", "token-b")];
        let result = validate_connect_auth(Some(&header), tokens);
        assert_eq!(result, Ok("peer-b".to_string()));
    }

    #[test]
    fn validate_connect_auth_empty_token() {
        let result = validate_connect_auth(Some("Bearer "), [("peer", "token")]);
        assert_eq!(result, Err(AuthError::EmptyToken));
    }
}
