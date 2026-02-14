//! Management API actor for runtime peer configuration.
//!
//! Provides an HTTP/1.1 server bound to a configured localhost address,
//! serving GET/POST/DELETE /config endpoints for peer management.
//! Communicates with the orchestrator via the `Event` channel pattern.

use crate::actor::{ActorError, ActorExitResult};
use crate::config::{Config, Peer};
use crate::events::{ApiEvent, Event};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::debug;

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
pub async fn make_api(addr: SocketAddr) -> Result<TcpListener, std::io::Error> {
    TcpListener::bind(addr).await
}

/// Spawns the management API actor.
///
/// Returns a `JoinHandle` for the accept loop. Shutdown via `JoinSet` abort-on-drop.
///
/// # Arguments
///
/// * `listener` - Bound TCP listener from `make_api`.
/// * `api_path` - Configured base path for prefix-strip routing.
/// * `events_tx` - Channel to send API events to the orchestrator.
pub fn spawn_api(
    listener: TcpListener,
    api_path: String,
    events_tx: mpsc::UnboundedSender<Event>,
) -> JoinHandle<ActorExitResult> {
    let addr = listener.local_addr().unwrap_or_else(|_| {
        "0.0.0.0:0"
            .parse()
            .expect("infallible: constant literal parse")
    });
    tokio::spawn(async move {
        loop {
            let (stream, remote) = listener.accept().await.map_err(|e| ActorError::ApiServer {
                addr: addr.to_string(),
                reason: format!("accept failed: {e}"),
            })?;
            let io = TokioIo::new(stream);
            let events_tx = events_tx.clone();
            let api_path = api_path.clone();
            tokio::spawn(async move {
                let svc =
                    service_fn(|req| handle_request(req, events_tx.clone(), api_path.clone()));
                if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                    debug!(remote = %remote, error = %e, "API connection error");
                }
            });
        }
    })
}

fn response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("infallible: response builder with valid constants")
}

async fn handle_request(
    req: Request<Incoming>,
    events_tx: mpsc::UnboundedSender<Event>,
    api_path: String,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path();
    let base = api_path.trim_end_matches('/');
    let relative = if base.is_empty() || base == "/" {
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
        (&Method::GET, "/config") | (&Method::GET, "/config/") => {
            handle_get_config(&events_tx).await
        }
        (&Method::POST, "/config") | (&Method::POST, "/config/") => {
            handle_post_config(req, &events_tx).await
        }
        (&Method::DELETE, "/config") | (&Method::DELETE, "/config/") => {
            handle_delete_config(req, &events_tx).await
        }
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

async fn handle_get_config(events_tx: &mpsc::UnboundedSender<Event>) -> Response<Full<Bytes>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    if events_tx
        .send(Event::Api(ApiEvent::GetConfig { reply_tx }))
        .is_err()
    {
        return response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "orchestrator unavailable",
        );
    }
    match reply_rx.await {
        Ok(config) => yaml_config_response(&config),
        Err(_) => response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "orchestrator dropped reply",
        ),
    }
}

async fn handle_post_config(
    req: Request<Incoming>,
    events_tx: &mpsc::UnboundedSender<Event>,
) -> Response<Full<Bytes>> {
    let body = match Limited::new(req.into_body(), MAX_BODY_SIZE).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => return response(StatusCode::BAD_REQUEST, &format!("body read error: {e}")),
    };

    let payload: PostPayload = match serde_yaml::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return response(StatusCode::BAD_REQUEST, &format!("invalid YAML: {e}")),
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    if events_tx
        .send(Event::Api(ApiEvent::PostConfig {
            peers: payload.peers,
            reply_tx,
        }))
        .is_err()
    {
        return response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "orchestrator unavailable",
        );
    }
    match reply_rx.await {
        Ok(Ok(config)) => yaml_config_response(&config),
        Ok(Err(e)) => response(StatusCode::BAD_REQUEST, &e),
        Err(_) => response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "orchestrator dropped reply",
        ),
    }
}

async fn handle_delete_config(
    req: Request<Incoming>,
    events_tx: &mpsc::UnboundedSender<Event>,
) -> Response<Full<Bytes>> {
    let body = match Limited::new(req.into_body(), MAX_BODY_SIZE).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => return response(StatusCode::BAD_REQUEST, &format!("body read error: {e}")),
    };

    let payload: DeletePayload = match serde_yaml::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return response(StatusCode::BAD_REQUEST, &format!("invalid YAML: {e}")),
    };
    let peer_ids: Vec<String> = payload.peers.into_iter().map(|p| p.id).collect();

    let (reply_tx, reply_rx) = oneshot::channel();
    if events_tx
        .send(Event::Api(ApiEvent::DeleteConfig { peer_ids, reply_tx }))
        .is_err()
    {
        return response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "orchestrator unavailable",
        );
    }
    match reply_rx.await {
        Ok(Ok(config)) => yaml_config_response(&config),
        Ok(Err(e)) => response(StatusCode::BAD_REQUEST, &e),
        Err(_) => response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "orchestrator dropped reply",
        ),
    }
}

#[cfg(test)]
mod tests {
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
}
