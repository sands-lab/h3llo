//! Internal routing table using ipnet-trie for longest-prefix matches.

use crate::config::Peer;
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use log::warn;
use std::fmt;
use std::net::IpAddr;
use thiserror::Error;

fn log_duplicate_allowed(peer_id: &str, cidr: &str) {
    warn!(
        "duplicate allowedIPs '{}' for peer '{}'; keeping the first entry",
        cidr, peer_id
    );
}

/// Stores routing metadata for a prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// Identifier of the peer owning the prefix.
    pub peer_id: String,
}

/// Represents the result of a longest-prefix lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteMatch<'a> {
    /// Matched prefix.
    pub prefix: IpNet,
    /// Identifier of the peer selected by the lookup.
    pub peer_id: &'a str,
}

/// In-memory routing table supporting IPv4 and IPv6 longest-prefix matches.
#[derive(Clone)]
pub struct RoutingTable {
    trie: IpnetTrie<RouteEntry>,
}

impl fmt::Debug for RoutingTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutingTable")
            .field("len", &self.trie.len())
            .finish()
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingTable {
    /// Creates an empty routing table.
    pub fn new() -> Self {
        Self {
            trie: IpnetTrie::new(),
        }
    }

    /// Builds a routing table from enabled peers, validating prefixes and skipping duplicates within a peer.
    ///
    /// # Errors
    ///
    /// Returns `RoutingError` when a prefix is invalid or conflicts with an existing peer.
    pub fn from_peers(peers: &[Peer]) -> Result<Self, RoutingError> {
        let mut table = RoutingTable::new();

        for peer in peers.iter().filter(|peer| peer.enabled) {
            for cidr in &peer.tun.allowed_ips {
                let net: IpNet =
                    cidr.parse::<IpNet>()
                        .map_err(|err| RoutingError::InvalidAllowedIp {
                            peer_id: peer.id.clone(),
                            cidr: cidr.clone(),
                            error: err.to_string(),
                        })?;

                table.insert(
                    net,
                    RouteEntry {
                        peer_id: peer.id.clone(),
                    },
                )?;
            }
        }

        Ok(table)
    }

    /// Inserts a prefix and associated peer into the table, rejecting conflicting owners.
    ///
    /// # Errors
    ///
    /// Returns `RoutingError::ConflictingPrefix` when the prefix already belongs to another peer.
    pub fn insert(&mut self, prefix: IpNet, entry: RouteEntry) -> Result<(), RoutingError> {
        if let Some(existing) = self.trie.exact_match(prefix.clone()) {
            if existing.peer_id == entry.peer_id {
                log_duplicate_allowed(&entry.peer_id, &prefix.to_string());
                return Ok(());
            }

            return Err(RoutingError::ConflictingPrefix {
                prefix,
                existing_peer_id: existing.peer_id.clone(),
                new_peer_id: entry.peer_id,
            });
        }

        self.trie.insert(prefix, entry);
        Ok(())
    }

    /// Performs a longest-prefix match for the provided address.
    pub fn lookup(&self, addr: IpAddr) -> Option<RouteMatch<'_>> {
        let net = IpNet::from(addr);
        self.trie
            .longest_match(&net)
            .map(|(prefix, entry)| RouteMatch {
                prefix,
                peer_id: entry.peer_id.as_str(),
            })
    }

    /// Returns the number of IPv4 and IPv6 prefixes stored.
    pub fn len(&self) -> (usize, usize) {
        self.trie.len()
    }

    /// Returns true when no prefixes are present.
    pub fn is_empty(&self) -> bool {
        self.trie.is_empty()
    }
}

/// Routing table construction or lookup error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoutingError {
    /// Allowed IP entry cannot be parsed.
    #[error("peer '{peer_id}' has invalid allowedIPs entry '{cidr}': {error}")]
    InvalidAllowedIp {
        /// Identifier of the owning peer.
        peer_id: String,
        /// Raw CIDR string that failed to parse.
        cidr: String,
        /// Parsing failure detail.
        error: String,
    },
    /// Two peers claim the same prefix.
    #[error("prefix {prefix} already assigned to peer '{existing_peer_id}', cannot assign to '{new_peer_id}'")]
    ConflictingPrefix {
        /// Prefix that was duplicated.
        prefix: IpNet,
        /// Existing owner of the prefix.
        existing_peer_id: String,
        /// New peer that attempted to claim the prefix.
        new_peer_id: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Peer, PeerBare, PeerTun};
    use std::net::{IpAddr, Ipv4Addr};

    fn bare_peer(id: &str, enabled: bool, allowed: &[&str]) -> Peer {
        Peer {
            id: id.to_string(),
            enabled,
            h3: None,
            bare: Some(PeerBare {
                endpoint: Some("udp://127.0.0.1:5353".to_string()),
                bindif: None,
            }),
            tun: PeerTun {
                allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            },
        }
    }

    #[test]
    fn chooses_longest_prefix() {
        let peers = vec![
            bare_peer("peer-a", true, &["10.0.0.0/16"]),
            bare_peer("peer-b", true, &["10.0.0.0/24"]),
        ];
        let table = RoutingTable::from_peers(&peers).expect("table should build");
        let result = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)))
            .expect("lookup should succeed");
        assert_eq!(result.peer_id, "peer-b");
        assert_eq!(result.prefix, "10.0.0.0/24".parse::<IpNet>().unwrap());
    }

    #[test]
    fn ignores_disabled_peers() {
        let peers = vec![
            bare_peer("peer-disabled", false, &["10.1.0.0/16"]),
            bare_peer("peer-active", true, &["10.0.0.0/8"]),
        ];
        let table = RoutingTable::from_peers(&peers).expect("table should build");
        assert_eq!(table.len(), (1, 0));
        let result = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 2, 3, 4)))
            .expect("lookup should succeed");
        assert_eq!(result.peer_id, "peer-active");
    }

    #[test]
    fn errors_on_conflicting_prefix_ownership() {
        let peers = vec![
            bare_peer("peer-a", true, &["10.0.0.0/24"]),
            bare_peer("peer-b", true, &["10.0.0.0/24"]),
        ];
        let err = RoutingTable::from_peers(&peers).unwrap_err();
        assert!(matches!(
            err,
            RoutingError::ConflictingPrefix {
                existing_peer_id,
                new_peer_id,
                ..
            } if existing_peer_id == "peer-a" && new_peer_id == "peer-b"
        ));
    }

    #[test]
    fn skips_duplicate_prefixes_within_peer() {
        let peers = vec![bare_peer("peer-a", true, &["10.0.0.0/24", "10.0.0.0/24"])];
        let table = RoutingTable::from_peers(&peers).expect("table should build");
        assert_eq!(table.len(), (1, 0));
        let result = table
            .lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .expect("lookup should succeed");
        assert_eq!(result.peer_id, "peer-a");
    }
}
