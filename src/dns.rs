use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::bind::{bind_to_device, BindDecision, BindWarning, RouteProbe};
use crate::config::{parse_dns_server_uri, LocalDns};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time;

/// Performs DNS resolution over UDP sockets bound to the chosen interface.
#[derive(Debug, Clone)]
pub struct DnsResolver {
    server: SocketAddr,
    timeout: Duration,
}

impl DnsResolver {
    /// Creates a resolver targeting `server` with the provided timeout.
    pub fn new(server: SocketAddr, timeout: Duration) -> Self {
        Self { server, timeout }
    }

    /// Builds a resolver from `local_dns` configuration, parsing the UDP URI.
    pub fn from_config(local_dns: &LocalDns, timeout: Duration) -> Result<Self, ResolveInitError> {
        let server =
            parse_dns_server_uri(&local_dns.server).map_err(ResolveInitError::InvalidServer)?;
        Ok(Self::new(server, timeout))
    }

    /// Resolves `hosts` sequentially using a socket bound according to `bind`, skipping the TUN when possible.
    pub async fn resolve_hosts(&self, hosts: &[String], bind: &BindDecision) -> ResolveOutcome {
        let mut warnings = Vec::new();
        if let Some(warning) = bind.warning.clone() {
            warnings.push(DnsWarning::Bind(warning));
        }

        let (socket, mut bind_warnings) = match self.prepare_socket(bind) {
            Ok(pair) => pair,
            Err(err) => {
                return ResolveOutcome {
                    records: HashMap::new(),
                    errors: vec![err],
                    warnings,
                };
            }
        };
        warnings.append(&mut bind_warnings);

        let mut records = HashMap::new();
        let mut errors = Vec::new();

        for host in hosts {
            match self.resolve_single(&socket, host).await {
                Ok(ips) => {
                    if !ips.is_empty() {
                        records.insert(host.clone(), ips);
                    }
                }
                Err(err) => errors.push(err),
            }
        }

        ResolveOutcome {
            records,
            errors,
            warnings,
        }
    }

    fn prepare_socket(
        &self,
        bind: &BindDecision,
    ) -> Result<(UdpSocket, Vec<DnsWarning>), ResolveError> {
        let mut warnings = Vec::new();

        let domain = match self.server {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let bind_addr: SocketAddr = match self.server {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| {
            ResolveError::Resolver {
                error: e.to_string(),
            }
        })?;
        socket
            .set_nonblocking(true)
            .map_err(|e| ResolveError::Resolver {
                error: e.to_string(),
            })?;
        socket
            .bind(&bind_addr.into())
            .map_err(|e| ResolveError::Resolver {
                error: e.to_string(),
            })?;

        if let Some(interface) = bind.interface.as_ref() {
            let domain = match self.server {
                SocketAddr::V4(_) => Domain::IPV4,
                SocketAddr::V6(_) => Domain::IPV6,
            };
            if let Err(warning) = bind_to_device(&socket, domain, interface) {
                warnings.push(DnsWarning::Bind(warning));
            }
        }

        socket
            .connect(&self.server.into())
            .map_err(|e| ResolveError::Resolver {
                error: e.to_string(),
            })?;

        let udp = UdpSocket::from_std(socket.into()).map_err(|e| ResolveError::Resolver {
            error: e.to_string(),
        })?;

        Ok((udp, warnings))
    }

    async fn resolve_single(
        &self,
        socket: &UdpSocket,
        host: &str,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        let name = Name::from_ascii(host).map_err(|e| ResolveError::InvalidHost {
            host: host.to_string(),
            error: e.to_string(),
        })?;

        let mut ips = Vec::new();

        for record_type in [RecordType::A, RecordType::AAAA] {
            let mut result = self.query(socket, host, &name, record_type).await?;
            ips.append(&mut result);
        }

        Ok(dedup_ips(ips))
    }

    async fn query(
        &self,
        socket: &UdpSocket,
        host: &str,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        let mut message = Message::new();
        let id = rand::rng().random::<u16>();
        message.set_id(id);
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);
        message.add_query(record_type_query(name.clone(), record_type));

        let outbound = message.to_vec().map_err(|e| ResolveError::QueryFailed {
            host: host.to_string(),
            error: e.to_string(),
        })?;

        let mut inbound = vec![0u8; 1500];
        let send_recv = async {
            socket
                .send(&outbound)
                .await
                .map_err(|e| ResolveError::QueryFailed {
                    host: host.to_string(),
                    error: e.to_string(),
                })?;
            let len = socket
                .recv(&mut inbound)
                .await
                .map_err(|e| ResolveError::QueryFailed {
                    host: host.to_string(),
                    error: e.to_string(),
                })?;
            Ok(len)
        };

        let len = match time::timeout(self.timeout, send_recv).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(ResolveError::Timeout {
                    host: host.to_string(),
                })
            }
        };

        let response =
            Message::from_vec(&inbound[..len]).map_err(|e| ResolveError::QueryFailed {
                host: host.to_string(),
                error: e.to_string(),
            })?;

        if response.id() != id {
            return Err(ResolveError::QueryFailed {
                host: host.to_string(),
                error: "response id mismatch".to_string(),
            });
        }

        if response.response_code() != ResponseCode::NoError {
            return Err(ResolveError::QueryFailed {
                host: host.to_string(),
                error: format!("dns error: {:?}", response.response_code()),
            });
        }

        let mut ips = Vec::new();
        for answer in response.answers() {
            match answer.data() {
                RData::A(addr) if record_type == RecordType::A => {
                    ips.push(IpAddr::V4(ipv4_from_rdata(addr)));
                }
                RData::AAAA(addr) if record_type == RecordType::AAAA => {
                    ips.push(IpAddr::V6(ipv6_from_rdata(addr)));
                }
                _ => {}
            }
        }

        Ok(ips)
    }
}

fn record_type_query(name: Name, record_type: RecordType) -> Query {
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(record_type);
    query
}

fn dedup_ips(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for ip in ips {
        if seen.insert(ip) {
            out.push(ip);
        }
    }
    out
}

fn ipv4_from_rdata(data: &hickory_proto::rr::rdata::A) -> Ipv4Addr {
    data.0
}

fn ipv6_from_rdata(data: &hickory_proto::rr::rdata::AAAA) -> Ipv6Addr {
    data.0
}

/// Returns a DNS bind decision preferring the configured interface when present and skipping the TUN.
pub fn decide_dns_binding<P: RouteProbe>(
    local_dns: &LocalDns,
    tun_if: &str,
    probe: &P,
) -> BindDecision {
    let target = match parse_dns_server_uri(&local_dns.server) {
        Ok(addr) => addr.ip().to_string(),
        Err(reason) => {
            return BindDecision {
                interface: None,
                warning: Some(BindWarning::ProbeFailed(format!(
                    "invalid dns server: {}",
                    reason
                ))),
            };
        }
    };
    BindDecision::choose(local_dns.bindif.as_deref(), &target, tun_if, probe)
}

/// Tracks the result of DNS resolution attempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveOutcome {
    /// Latest answers per host (empty when a host failed).
    pub records: HashMap<String, Vec<IpAddr>>,
    /// Errors encountered during resolution.
    pub errors: Vec<ResolveError>,
    /// Warnings about binding or platform limitations.
    pub warnings: Vec<DnsWarning>,
}

/// Describes DNS resolution errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// DNS resolver socket could not be prepared.
    #[error("dns resolver failed to initialize: {error}")]
    Resolver { error: String },
    /// Hostname was not valid.
    #[error("invalid host {host}: {error}")]
    InvalidHost { host: String, error: String },
    /// DNS exchange failed.
    #[error("failed to resolve {host}: {error}")]
    QueryFailed { host: String, error: String },
    /// DNS response timed out.
    #[error("dns query for {host} timed out")]
    Timeout { host: String },
}

/// Captures warnings raised during DNS resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsWarning {
    /// Binding decision emitted a warning.
    Bind(BindWarning),
}

/// Describes resolver construction errors.
#[derive(Debug, Error)]
pub enum ResolveInitError {
    /// DNS server URI could not be parsed.
    #[error("invalid dns server: {0}")]
    InvalidServer(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::Record;
    use tokio::net::UdpSocket;

    fn make_decision() -> BindDecision {
        BindDecision {
            interface: None,
            warning: None,
        }
    }

    #[tokio::test]
    async fn resolves_a_and_aaaa_records() {
        let (server, handle) = start_dns_stub(
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            2,
        )
        .await;

        let resolver = DnsResolver::new(server, Duration::from_secs(1));
        let outcome = resolver
            .resolve_hosts(&vec!["example.com".to_string()], &make_decision())
            .await;

        assert!(outcome.errors.is_empty());
        let ips = outcome
            .records
            .get("example.com")
            .cloned()
            .unwrap_or_default();
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));

        handle.abort();
    }

    #[tokio::test]
    async fn times_out_on_silent_server() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        // Drop the socket to leave an unresponsive endpoint.
        drop(socket);

        let resolver = DnsResolver::new(addr, Duration::from_millis(50));
        let outcome = resolver
            .resolve_hosts(&vec!["example.com".to_string()], &make_decision())
            .await;
        assert_eq!(outcome.records.len(), 0);
        assert!(!outcome.errors.is_empty());
    }

    async fn start_dns_stub(
        ipv4: Option<IpAddr>,
        ipv6: Option<IpAddr>,
        expected_queries: usize,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            for _ in 0..expected_queries {
                if let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                    let request = Message::from_vec(&buf[..len]).unwrap();
                    let mut response = Message::new();
                    response.set_id(request.id());
                    response.set_message_type(MessageType::Response);
                    response.set_op_code(OpCode::Query);
                    response.set_response_code(ResponseCode::NoError);

                    for query in request.queries() {
                        response.add_query(query.clone());
                        match query.query_type() {
                            RecordType::A => {
                                if let Some(IpAddr::V4(ip)) = ipv4 {
                                    response.add_answer(Record::from_rdata(
                                        query.name().clone().into(),
                                        60,
                                        RData::A(A(ip)),
                                    ));
                                }
                            }
                            RecordType::AAAA => {
                                if let Some(IpAddr::V6(ip)) = ipv6 {
                                    response.add_answer(Record::from_rdata(
                                        query.name().clone().into(),
                                        60,
                                        RData::AAAA(AAAA(ip)),
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }

                    if let Ok(out) = response.to_vec() {
                        let _ = socket.send_to(&out, peer).await;
                    }
                }
            }
        });

        (addr, handle)
    }
}
