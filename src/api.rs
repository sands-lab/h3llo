//! Management API actor for runtime peer configuration.
//!
//! Provides an HTTP/1.1 server bound to a configured localhost address,
//! serving GET/POST/DELETE /config endpoints for peer management and
//! GET /metrics for Prometheus-compatible metrics exposition.
//! Communicates with the orchestrator through `ActorBus` events.

use crate::actor::{ActorContext, ActorRef, ActorRuntime, SupervisionPolicy};
use crate::config::{Config, Peer};
use crate::events::Event;
use crate::metrics::encode_metrics_snapshot;
use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::info;

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

/// Maximum request body size (1 MiB).
const MAX_BODY_SIZE: usize = 1024 * 1024;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PostPayload {
    #[serde(default)]
    peers: Vec<Peer>,
}

/// DELETE payload entry: only peer ID is required.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletePeerRef {
    id: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeletePayload {
    #[serde(default)]
    peers: Vec<DeletePeerRef>,
}

/// Binds a `TcpListener` for the management API.
///
/// # Arguments
///
/// * `addr` - Socket address to bind.
///
/// # Errors
///
/// Returns an I/O error if binding fails.
pub(crate) async fn make_api(addr: SocketAddr) -> Result<TcpListener, std::io::Error> {
    TcpListener::bind(addr).await
}

/// Spawns the management API actor.
///
/// Registers the accept loop with `ActorBus`.
///
/// # Arguments
///
/// * `listener` - Bound TCP listener from `make_api`.
/// * `api_path` - Configured base path for prefix-strip routing.
pub(crate) fn spawn_api(listener: TcpListener, api_path: String, ctx: &ActorContext) -> ActorRef {
    let addr = listener.local_addr().unwrap_or_else(|_| {
        "0.0.0.0:0"
            .parse()
            .expect("infallible: constant literal parse")
    });
    info!(%addr, "API listener started");
    ctx.spawn(
        format!("api[{addr}]"),
        ActorRuntime::Main,
        SupervisionPolicy::Critical,
        |mut ctx| async move {
            loop {
                let Some(accepted) = ctx.run_until_stopped(listener.accept()).await else {
                    return Ok(());
                };
                let (stream, remote) = accepted.context("accept management API connection")?;
                let io = TokioIo::new(stream);
                let api_path = api_path.clone();
                let _connection_ref = ctx.spawn(
                    format!("api-connection[{remote}]"),
                    ActorRuntime::Main,
                    SupervisionPolicy::Detached,
                    |ctx| async move {
                        let svc = service_fn(|req| handle_request(req, &ctx, api_path.clone()));
                        if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                            info!(remote = %remote, error = %e, "API connection error");
                        }
                        Ok(())
                    },
                );
            }
        },
    )
}

fn response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("infallible: response builder with valid constants")
}

async fn handle_request(
    req: Request<Incoming>,
    ctx: &ActorContext,
    api_path: String,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path();
    let base = api_path.trim_end_matches('/');
    let relative = if base.is_empty() {
        path.to_string()
    } else {
        match path.strip_prefix(base) {
            Some(rest) if rest.is_empty() || rest.starts_with('/') => {
                if rest.is_empty() {
                    "/".to_string()
                } else {
                    rest.to_string()
                }
            }
            _ => return Ok(response(StatusCode::NOT_FOUND, "not found")),
        }
    };

    let resp = match (req.method(), relative.as_str()) {
        (&Method::GET, "/config" | "/config/") => handle_get_config(ctx).await,
        (&Method::POST, "/config" | "/config/") => handle_post_config(req, ctx).await,
        (&Method::DELETE, "/config" | "/config/") => handle_delete_config(req, ctx).await,
        (&Method::GET, "/metrics" | "/metrics/") => handle_get_metrics(ctx).await,
        _ => response(StatusCode::NOT_FOUND, "not found"),
    };
    Ok(resp)
}

/// Serializes a `Config` to a YAML HTTP response.
///
/// Shared by GET/POST/DELETE success paths to ensure consistent response format.
fn yaml_config_response(config: &Config) -> Response<Full<Bytes>> {
    match serde_yaml::to_string(config) {
        Ok(yaml) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/yaml")
            .body(Full::new(Bytes::from(yaml)))
            .expect("infallible: response builder with valid constants"),
        Err(e) => response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("serialization error: {e}"),
        ),
    }
}

/// Sends an event carrying a oneshot reply channel and awaits the response.
///
/// Returns the orchestrator's reply or an HTTP 500 error response.
async fn send_and_await<T>(
    ctx: &ActorContext,
    make_event: impl FnOnce(oneshot::Sender<T>) -> Event,
) -> Result<T, Response<Full<Bytes>>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    ctx.notify_owner(make_event(reply_tx)).map_err(|_| {
        response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "orchestrator unavailable",
        )
    })?;
    reply_rx.await.map_err(|_| {
        response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "orchestrator dropped reply",
        )
    })
}

async fn handle_get_config(ctx: &ActorContext) -> Response<Full<Bytes>> {
    match send_and_await(ctx, |reply_tx| Event::GetConfig { reply_tx }).await {
        Ok(config) => yaml_config_response(&config),
        Err(err_resp) => err_resp,
    }
}

async fn handle_post_config(req: Request<Incoming>, ctx: &ActorContext) -> Response<Full<Bytes>> {
    let body = match Limited::new(req.into_body(), MAX_BODY_SIZE).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => return response(StatusCode::BAD_REQUEST, &format!("body read error: {e}")),
    };

    let payload: PostPayload = match serde_yaml::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return response(StatusCode::BAD_REQUEST, &format!("invalid YAML: {e}")),
    };

    let peers = payload.peers;
    match send_and_await(ctx, |reply_tx| Event::PostConfig { peers, reply_tx }).await {
        Ok(Ok(config)) => yaml_config_response(&config),
        Ok(Err(e)) => response(StatusCode::BAD_REQUEST, &e),
        Err(err_resp) => err_resp,
    }
}

async fn handle_delete_config(req: Request<Incoming>, ctx: &ActorContext) -> Response<Full<Bytes>> {
    let body = match Limited::new(req.into_body(), MAX_BODY_SIZE).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => return response(StatusCode::BAD_REQUEST, &format!("body read error: {e}")),
    };

    let payload: DeletePayload = match serde_yaml::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return response(StatusCode::BAD_REQUEST, &format!("invalid YAML: {e}")),
    };
    let peer_ids: Vec<String> = payload.peers.into_iter().map(|p| p.id).collect();

    match send_and_await(ctx, |reply_tx| Event::DeleteConfig { peer_ids, reply_tx }).await {
        Ok(Ok(config)) => yaml_config_response(&config),
        Ok(Err(e)) => response(StatusCode::BAD_REQUEST, &e),
        Err(err_resp) => err_resp,
    }
}

/// Handles `GET /metrics` — returns `OpenMetrics` text format.
///
/// Requests a raw metrics snapshot from the orchestrator through `ActorBus`,
/// then renders `OpenMetrics` text locally using `prometheus-client`.
async fn handle_get_metrics(ctx: &ActorContext) -> Response<Full<Bytes>> {
    match send_and_await(ctx, |reply_tx| Event::GetMetricsSnapshot { reply_tx }).await {
        Ok(snapshot) => {
            let text = encode_metrics_snapshot(snapshot);
            Response::builder()
                .status(StatusCode::OK)
                .header(
                    "content-type",
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                )
                .body(Full::new(Bytes::from(text)))
                .expect("infallible: response builder with valid constants")
        }
        Err(err_resp) => err_resp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Local, LocalDns, LocalTun, Tuning};
    use crate::events::Event;
    use crate::metrics::{Direction, Labels, Metrics, PktCounters, Source, Stats};
    use hyper::client::conn::http1;
    use std::collections::HashMap;
    use tokio::net::TcpStream;

    #[test]
    fn post_payload_rejects_unknown_key() {
        let body = "local:\n  table: false\n";
        let result: Result<super::PostPayload, _> = serde_yaml::from_str(body);
        assert!(result.is_err());
    }

    #[test]
    fn post_payload_accepts_peers_only() {
        let body = "peers: []\n";
        let payload: super::PostPayload = serde_yaml::from_str(body).unwrap();
        assert!(payload.peers.is_empty());
    }

    #[test]
    fn delete_payload_rejects_old_peer_ids_key() {
        let body = "peer_ids:\n  - test\n";
        let result: Result<super::DeletePayload, _> = serde_yaml::from_str(body);
        assert!(result.is_err());
    }

    #[test]
    fn delete_payload_accepts_peers_with_id() {
        let body = "peers:\n- id: test\n";
        let payload: super::DeletePayload = serde_yaml::from_str(body).unwrap();
        assert_eq!(payload.peers.len(), 1);
        assert_eq!(payload.peers[0].id, "test");
    }

    #[test]
    fn delete_payload_extracts_multiple_ids() {
        let body = "peers:\n- id: a\n- id: b\n";
        let payload: super::DeletePayload = serde_yaml::from_str(body).unwrap();
        let ids: Vec<String> = payload.peers.into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn delete_payload_rejects_string_list() {
        let body = "peers:\n- peer-1\n- peer-2\n";
        let result: Result<super::DeletePayload, _> = serde_yaml::from_str(body);
        assert!(result.is_err());
    }

    // ========== Real-Network Test Helpers ==========

    /// Spawns the API actor on an ephemeral port and returns the bound address,
    /// the orchestrator mailbox (to mock replies), and its actor bus.
    fn start_api(api_path: &str) -> (SocketAddr, ActorContext, crate::actor::ActorBus) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = TcpListener::from_std(listener).unwrap();
        let actor_bus = crate::actor::ActorBus::on_current_runtime();
        let orchestrator = actor_bus.mailbox("test-orchestrator");
        spawn_api(listener, api_path.to_string(), &orchestrator);
        (addr, orchestrator, actor_bus)
    }

    /// Constructs a minimal `Config` for orchestrator mock replies.
    fn test_config() -> Config {
        Config {
            local: Local {
                table: false,
                dns: LocalDns {
                    server: "127.0.0.1:53".parse().unwrap(),
                    bindif: None,
                },
                h3: None,
                bare: None,
                api: None,
                tun: LocalTun {
                    ifname: "test0".to_string(),
                    addrs: vec!["10.0.0.1/24".parse().unwrap()],
                    mtu: 1400,
                },
            },
            tuning: Tuning::default(),
            peers: vec![],
        }
    }

    /// Creates a hyper HTTP/1.1 client connected to the given address.
    async fn http_client(addr: SocketAddr) -> http1::SendRequest<Full<Bytes>> {
        let stream = TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (sender, conn) = http1::handshake(io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        sender
    }

    /// Reads the full response body as a string.
    async fn body_string(resp: Response<hyper::body::Incoming>) -> String {
        let collected = resp.collect().await.unwrap();
        String::from_utf8(collected.to_bytes().to_vec()).unwrap()
    }

    /// Receives the next message with a 2-second timeout.
    async fn recv_event(ctx: &mut ActorContext) -> Event {
        tokio::time::timeout(std::time::Duration::from_secs(2), ctx.recv())
            .await
            .expect("timeout waiting for API event")
            .expect("orchestrator inbox closed unexpectedly")
    }

    // ========== Real-Network HTTP Tests ==========

    #[tokio::test]
    async fn get_config_returns_yaml() {
        let (addr, mut events_rx, _actor_bus) = start_api("");
        let mut sender = http_client(addr).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/config")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let fut = sender.send_request(req);

        let config = test_config();
        let reply_config = config.clone();
        let mock = tokio::spawn(async move {
            let event = recv_event(&mut events_rx).await;
            if let Event::GetConfig { reply_tx } = event {
                reply_tx.send(reply_config).ok();
            } else {
                panic!("expected GetConfig, got {event:?}");
            }
        });

        let resp = fut.await.unwrap();
        mock.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/yaml"
        );
        let body = body_string(resp).await;
        let parsed: Config = serde_yaml::from_str(&body).unwrap();
        assert_eq!(parsed, config);
    }

    #[tokio::test]
    async fn post_config_upserts_peers() {
        let (addr, mut events_rx, _actor_bus) = start_api("");
        let mut sender = http_client(addr).await;

        let yaml_body = "peers:\n- id: peer-1\n  bare:\n    endpoint: udp://1.2.3.4:6635\n  tun:\n    allowed_ips:\n    - 10.0.1.0/24\n";
        let req = Request::builder()
            .method(Method::POST)
            .uri("/config")
            .body(Full::new(Bytes::from(yaml_body)))
            .unwrap();
        let fut = sender.send_request(req);

        let mock = tokio::spawn(async move {
            let event = recv_event(&mut events_rx).await;
            if let Event::PostConfig { peers, reply_tx } = event {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].id, "peer-1");
                let mut config = test_config();
                config.peers = peers;
                reply_tx.send(Ok(config)).ok();
            } else {
                panic!("expected PostConfig, got {event:?}");
            }
        });

        let resp = fut.await.unwrap();
        mock.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let parsed: Config = serde_yaml::from_str(&body).unwrap();
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].id, "peer-1");
    }

    #[tokio::test]
    async fn post_config_invalid_yaml_returns_400() {
        let (addr, _events_rx, _actor_bus) = start_api("");
        let mut sender = http_client(addr).await;

        let req = Request::builder()
            .method(Method::POST)
            .uri("/config")
            .body(Full::new(Bytes::from("{{invalid yaml")))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp).await;
        assert!(body.contains("invalid YAML"), "body: {body}");
    }

    #[tokio::test]
    async fn post_config_orchestrator_rejects_returns_400() {
        let (addr, mut events_rx, _actor_bus) = start_api("");
        let mut sender = http_client(addr).await;

        let yaml_body = "peers: []\n";
        let req = Request::builder()
            .method(Method::POST)
            .uri("/config")
            .body(Full::new(Bytes::from(yaml_body)))
            .unwrap();
        let fut = sender.send_request(req);

        let mock = tokio::spawn(async move {
            let event = recv_event(&mut events_rx).await;
            if let Event::PostConfig { reply_tx, .. } = event {
                reply_tx.send(Err("validation failed".to_string())).ok();
            } else {
                panic!("expected PostConfig, got {event:?}");
            }
        });

        let resp = fut.await.unwrap();
        mock.await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_string(resp).await;
        assert!(body.contains("validation failed"), "body: {body}");
    }

    #[tokio::test]
    async fn delete_config_removes_peers() {
        let (addr, mut events_rx, _actor_bus) = start_api("");
        let mut sender = http_client(addr).await;

        let yaml_body = "peers:\n- id: peer-1\n";
        let req = Request::builder()
            .method(Method::DELETE)
            .uri("/config")
            .body(Full::new(Bytes::from(yaml_body)))
            .unwrap();
        let fut = sender.send_request(req);

        let mock = tokio::spawn(async move {
            let event = recv_event(&mut events_rx).await;
            if let Event::DeleteConfig { peer_ids, reply_tx } = event {
                assert_eq!(peer_ids, vec!["peer-1"]);
                reply_tx.send(Ok(test_config())).ok();
            } else {
                panic!("expected DeleteConfig, got {event:?}");
            }
        });

        let resp = fut.await.unwrap();
        mock.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/yaml"
        );
    }

    #[tokio::test]
    async fn get_metrics_returns_openmetrics() {
        let (addr, mut events_rx, _actor_bus) = start_api("");
        let mut sender = http_client(addr).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let fut = sender.send_request(req);

        let mock = tokio::spawn(async move {
            let event = recv_event(&mut events_rx).await;
            if let Event::GetMetricsSnapshot { reply_tx } = event {
                let mut snapshot = HashMap::new();
                let metrics = Metrics {
                    labels: Labels {
                        source: Source::BareUdp,
                        direction: Direction::Rx,
                        peer_id: Some("test-peer".to_string()),
                        remote_addr: None,
                    },
                    stats: Stats {
                        succeeded: PktCounters {
                            packets: 42,
                            bytes: 12345,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                };
                snapshot.insert(metrics.labels.clone(), metrics);
                reply_tx.send(snapshot).ok();
            } else {
                panic!("expected GetMetricsSnapshot, got {event:?}");
            }
        });

        let resp = fut.await.unwrap();
        mock.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("openmetrics-text"),
            "content-type should be OpenMetrics: {ct}"
        );
        let body = body_string(resp).await;
        assert!(body.contains("# EOF"), "must contain EOF: {body}");
        assert!(
            body.contains("h3llo_transport_packets_total"),
            "must contain packet metrics: {body}"
        );
        assert!(body.contains("42"), "must contain packet count: {body}");
    }

    // ========== Path Routing Tests ==========

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let (addr, _events_rx, _actor_bus) = start_api("");
        let mut sender = http_client(addr).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/nonexistent")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unsupported_method_returns_404() {
        let (addr, _events_rx, _actor_bus) = start_api("");
        let mut sender = http_client(addr).await;

        let req = Request::builder()
            .method(Method::PUT)
            .uri("/config")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_path_prefix_strips_correctly() {
        let (addr, mut events_rx, _actor_bus) = start_api("/api/v1");
        let mut sender = http_client(addr).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/config")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let fut = sender.send_request(req);

        let mock = tokio::spawn(async move {
            let event = recv_event(&mut events_rx).await;
            if let Event::GetConfig { reply_tx } = event {
                reply_tx.send(test_config()).ok();
            } else {
                panic!("expected GetConfig, got {event:?}");
            }
        });

        let resp = fut.await.unwrap();
        mock.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ========== Error Path Tests ==========

    #[tokio::test]
    async fn get_config_orchestrator_unavailable_returns_500() {
        let (addr, events_rx, _actor_bus) = start_api("");
        drop(events_rx);

        let mut sender = http_client(addr).await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("/config")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_string(resp).await;
        assert!(body.contains("orchestrator unavailable"), "body: {body}");
    }

    #[tokio::test]
    async fn get_config_orchestrator_drops_reply_returns_500() {
        let (addr, mut events_rx, _actor_bus) = start_api("");
        let mut sender = http_client(addr).await;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/config")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let fut = sender.send_request(req);

        let mock = tokio::spawn(async move {
            let event = recv_event(&mut events_rx).await;
            if let Event::GetConfig { reply_tx } = event {
                drop(reply_tx);
            } else {
                panic!("expected GetConfig, got {event:?}");
            }
        });

        let resp = fut.await.unwrap();
        mock.await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_string(resp).await;
        assert!(body.contains("orchestrator dropped reply"), "body: {body}");
    }
}
