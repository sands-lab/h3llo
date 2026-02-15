//! Management API actor for runtime peer configuration.
//!
//! Provides an HTTP/1.1 server bound to a configured localhost address,
//! serving GET/POST/DELETE /config endpoints for peer management and
//! GET /metrics for Prometheus-compatible metrics exposition.
//! Communicates with the orchestrator via the `Event` channel pattern.
//!
//! Also houses the `SnapshotCollector` and `encode_metrics_snapshot` for
//! rendering transport metrics on `GET /metrics` from owned snapshot data.

use crate::actor::{ActorError, ActorExitResult};
use crate::config::{Config, Peer};
use crate::events::{
    ApiEvent, CongestionStats, Direction, DropReason, Event, PktCounters, TransportKind,
    TransportLabels, TransportMetrics,
};
use crate::metrics::collect_quic_metrics;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{
    DescriptorEncoder, EncodeCounterValue, EncodeLabelSet, EncodeLabelValue, EncodeMetric,
};
use prometheus_client::metrics::counter::ConstCounter;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::debug;

/// OpenMetrics text format EOF marker.
const OPENMETRICS_EOF: &str = "# EOF\n";

// ---------------------------------------------------------------------------
// Snapshot-based Collector (lock-free, owned data)
// ---------------------------------------------------------------------------

/// Collector that owns a snapshot of metrics data for one-shot encoding.
///
/// Created per scrape from the snapshot received via `ApiEvent::GetMetricsSnapshot`.
/// No `Arc`, no `Mutex` — the collector owns the `HashMap` directly.
#[derive(Debug)]
struct SnapshotCollector(HashMap<TransportLabels, TransportMetrics>);

/// Encodes a metrics snapshot into OpenMetrics text format.
///
/// Combines application-level transport metrics (via `prometheus-client`) with
/// QUIC-level metrics (via `foundations::telemetry::metrics`) into a single
/// Prometheus-compatible text response.
pub(crate) fn encode_metrics_snapshot(
    snapshot: HashMap<TransportLabels, TransportMetrics>,
) -> String {
    let mut registry = Registry::default();
    registry.register_collector(Box::new(SnapshotCollector(snapshot)));
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry)
        .expect("infallible: encoding to String cannot fail");

    // Append QUIC-level metrics from foundations global registry.
    let quic_text = collect_quic_metrics();
    if !quic_text.is_empty() {
        // Strip EOF from both sources and re-add a single EOF at the end.
        if text.ends_with(OPENMETRICS_EOF) {
            text.truncate(text.len() - OPENMETRICS_EOF.len());
        }
        let quic_text = quic_text
            .strip_suffix(OPENMETRICS_EOF)
            .unwrap_or(&quic_text);
        text.push_str(quic_text);
        text.push_str(OPENMETRICS_EOF);
    }

    text
}

impl Collector for SnapshotCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), fmt::Error> {
        encode_counter_family(
            &mut encoder,
            "h3llo_transport_packets",
            "Cumulative packet count.",
            &self.0,
            |m| (m.stats.succeeded.packets, m.stats.dropped.packets),
        )?;
        encode_counter_family(
            &mut encoder,
            "h3llo_transport_bytes",
            "Cumulative byte count.",
            &self.0,
            |m| (m.stats.succeeded.bytes, m.stats.dropped.bytes),
        )?;
        encode_counter_family(
            &mut encoder,
            "h3llo_transport_batches",
            "Cumulative batch count (record() invocations for GSO/GRO tracking).",
            &self.0,
            |m| (m.stats.succeeded.batches, m.stats.dropped.batches),
        )?;

        encode_drop_counter_family(
            &mut encoder,
            "h3llo_transport_drops",
            "Cumulative drop count by reason.",
            &self.0,
            |c| c.packets,
        )?;
        encode_drop_counter_family(
            &mut encoder,
            "h3llo_transport_drop_bytes",
            "Cumulative drop bytes by reason.",
            &self.0,
            |c| c.bytes,
        )?;

        encode_congestion_family(
            &mut encoder,
            "h3llo_transport_congestion",
            "Cumulative congestion event count.",
            &self.0,
            |cg| (cg.queue_full_count, cg.would_block_count),
        )?;
        encode_congestion_family(
            &mut encoder,
            "h3llo_transport_congestion_wait_seconds",
            "Cumulative congestion wait time in seconds.",
            &self.0,
            |cg| {
                (
                    cg.queue_full_duration.as_secs_f64(),
                    cg.would_block_duration.as_secs_f64(),
                )
            },
        )?;

        Ok(())
    }
}

/// Encodes a per-reason drop counter family, reducing duplication between drops and drop_bytes.
fn encode_drop_counter_family(
    encoder: &mut DescriptorEncoder,
    name: &str,
    help: &str,
    store: &HashMap<TransportLabels, TransportMetrics>,
    field: fn(&PktCounters) -> u64,
) -> Result<(), fmt::Error> {
    let counter = ConstCounter::new(0u64);
    let mut metric_enc = encoder.encode_descriptor(name, help, None, counter.metric_type())?;
    for m in store.values() {
        for (reason, counters) in &m.stats.drop_reasons {
            let labels = DropLabelSet::from_metrics(m, *reason);
            ConstCounter::new(field(counters)).encode(metric_enc.encode_family(&labels)?)?;
        }
    }
    Ok(())
}

/// Encodes a congestion counter family with `event` label (queue_full / would_block).
///
/// Generic over the counter value type (`u64` for counts, `f64` for durations).
fn encode_congestion_family<N, F>(
    encoder: &mut DescriptorEncoder,
    name: &str,
    help: &str,
    store: &HashMap<TransportLabels, TransportMetrics>,
    extractor: F,
) -> Result<(), fmt::Error>
where
    N: EncodeCounterValue + Default,
    F: Fn(&CongestionStats) -> (N, N),
{
    let counter = ConstCounter::new(N::default());
    let mut metric_enc = encoder.encode_descriptor(name, help, None, counter.metric_type())?;
    for m in store.values() {
        let (queue_full, would_block) = extractor(&m.stats.congestion);
        for (event, value) in [("queue_full", queue_full), ("would_block", would_block)] {
            let labels = CongestionLabelSet::from_metrics(m, event);
            ConstCounter::new(value).encode(metric_enc.encode_family(&labels)?)?;
        }
    }
    Ok(())
}

/// Encodes a succeeded/dropped counter family, reducing duplication.
fn encode_counter_family(
    encoder: &mut DescriptorEncoder,
    name: &str,
    help: &str,
    store: &HashMap<TransportLabels, TransportMetrics>,
    extractor: fn(&TransportMetrics) -> (u64, u64),
) -> Result<(), fmt::Error> {
    let counter = ConstCounter::new(0u64);
    let mut metric_enc = encoder.encode_descriptor(name, help, None, counter.metric_type())?;
    for m in store.values() {
        let (succeeded, dropped) = extractor(m);
        let labels = PacketLabelSet::from_metrics(m, "succeeded");
        ConstCounter::new(succeeded).encode(metric_enc.encode_family(&labels)?)?;
        let labels = PacketLabelSet::from_metrics(m, "dropped");
        ConstCounter::new(dropped).encode(metric_enc.encode_family(&labels)?)?;
    }
    Ok(())
}

/// Label set for packet/byte counter families.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PacketLabelSet {
    kind: TransportKindLabel,
    direction: DirectionLabel,
    peer_id: String,
    remote_addr: String,
    outcome: String,
}

impl PacketLabelSet {
    fn from_metrics(m: &TransportMetrics, outcome: &str) -> Self {
        Self {
            kind: TransportKindLabel(m.labels.kind),
            direction: DirectionLabel(m.labels.direction),
            peer_id: m.labels.peer_id.clone().unwrap_or_default(),
            remote_addr: m
                .labels
                .remote_addr
                .map(|a| a.to_string())
                .unwrap_or_default(),
            outcome: outcome.to_string(),
        }
    }
}

/// Label set for drop-reason counter families.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DropLabelSet {
    kind: TransportKindLabel,
    direction: DirectionLabel,
    peer_id: String,
    remote_addr: String,
    reason: DropReasonLabel,
}

impl DropLabelSet {
    fn from_metrics(m: &TransportMetrics, reason: DropReason) -> Self {
        Self {
            kind: TransportKindLabel(m.labels.kind),
            direction: DirectionLabel(m.labels.direction),
            peer_id: m.labels.peer_id.clone().unwrap_or_default(),
            remote_addr: m
                .labels
                .remote_addr
                .map(|a| a.to_string())
                .unwrap_or_default(),
            reason: DropReasonLabel(reason),
        }
    }
}

/// Prometheus label value for transport kind.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct TransportKindLabel(TransportKind);

impl EncodeLabelValue for TransportKindLabel {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        let s = match self.0 {
            TransportKind::Tun => "tun",
            TransportKind::BareUdp => "bare_udp",
            TransportKind::Http3 => "http3",
        };
        EncodeLabelValue::encode(&s, encoder)
    }
}

/// Prometheus label value for direction.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct DirectionLabel(Direction);

impl EncodeLabelValue for DirectionLabel {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        let s = match self.0 {
            Direction::Rx => "rx",
            Direction::Tx => "tx",
        };
        EncodeLabelValue::encode(&s, encoder)
    }
}

/// Label set for congestion counter families with `event` dimension.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct CongestionLabelSet {
    kind: TransportKindLabel,
    direction: DirectionLabel,
    peer_id: String,
    remote_addr: String,
    event: String,
}

impl CongestionLabelSet {
    fn from_metrics(m: &TransportMetrics, event: &str) -> Self {
        Self {
            kind: TransportKindLabel(m.labels.kind),
            direction: DirectionLabel(m.labels.direction),
            peer_id: m.labels.peer_id.clone().unwrap_or_default(),
            remote_addr: m
                .labels
                .remote_addr
                .map(|a| a.to_string())
                .unwrap_or_default(),
            event: event.to_string(),
        }
    }
}

/// Prometheus label value for drop reason.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct DropReasonLabel(DropReason);

impl EncodeLabelValue for DropReasonLabel {
    fn encode(
        &self,
        encoder: &mut prometheus_client::encoding::LabelValueEncoder,
    ) -> Result<(), fmt::Error> {
        let s = match self.0 {
            DropReason::Oversize => "oversize",
            DropReason::DisallowedSource => "disallowed_source",
            DropReason::SendError => "send_error",
            DropReason::ChannelClosed => "channel_closed",
            DropReason::InvalidIpVersion => "invalid_ip_version",
            DropReason::InvalidFraming => "invalid_framing",
            DropReason::NoRoute => "no_route",
            DropReason::NoPeerChannel => "no_peer_channel",
            DropReason::NoHeadroom => "no_headroom",
        };
        EncodeLabelValue::encode(&s, encoder)
    }
}

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
        (&Method::GET, "/config" | "/config/") => handle_get_config(&events_tx).await,
        (&Method::POST, "/config" | "/config/") => handle_post_config(req, &events_tx).await,
        (&Method::DELETE, "/config" | "/config/") => handle_delete_config(req, &events_tx).await,
        (&Method::GET, "/metrics" | "/metrics/") => handle_get_metrics(&events_tx).await,
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
    events_tx: &mpsc::UnboundedSender<Event>,
    make_event: impl FnOnce(oneshot::Sender<T>) -> Event,
) -> Result<T, Response<Full<Bytes>>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    events_tx.send(make_event(reply_tx)).map_err(|_| {
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

async fn handle_get_config(events_tx: &mpsc::UnboundedSender<Event>) -> Response<Full<Bytes>> {
    match send_and_await(events_tx, |reply_tx| {
        Event::Api(ApiEvent::GetConfig { reply_tx })
    })
    .await
    {
        Ok(config) => yaml_config_response(&config),
        Err(err_resp) => err_resp,
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

    let peers = payload.peers;
    match send_and_await(events_tx, |reply_tx| {
        Event::Api(ApiEvent::PostConfig { peers, reply_tx })
    })
    .await
    {
        Ok(Ok(config)) => yaml_config_response(&config),
        Ok(Err(e)) => response(StatusCode::BAD_REQUEST, &e),
        Err(err_resp) => err_resp,
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

    match send_and_await(events_tx, |reply_tx| {
        Event::Api(ApiEvent::DeleteConfig { peer_ids, reply_tx })
    })
    .await
    {
        Ok(Ok(config)) => yaml_config_response(&config),
        Ok(Err(e)) => response(StatusCode::BAD_REQUEST, &e),
        Err(err_resp) => err_resp,
    }
}

/// Handles `GET /metrics` — returns OpenMetrics text format.
///
/// Requests a raw metrics snapshot from the orchestrator via event channel,
/// then renders OpenMetrics text locally using `prometheus-client`.
async fn handle_get_metrics(events_tx: &mpsc::UnboundedSender<Event>) -> Response<Full<Bytes>> {
    match send_and_await(events_tx, |reply_tx| {
        Event::Api(ApiEvent::GetMetricsSnapshot { reply_tx })
    })
    .await
    {
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
    use crate::events::{PktCounters, TransportStats};

    #[test]
    fn encode_empty_snapshot() {
        let text = encode_metrics_snapshot(HashMap::new());
        assert!(text.contains("# EOF"), "should contain EOF: {text}");
    }

    #[test]
    fn encode_snapshot_includes_succeeded_and_dropped() {
        let mut snapshot = HashMap::new();
        let metrics = TransportMetrics {
            labels: TransportLabels {
                kind: TransportKind::Tun,
                direction: Direction::Rx,
                peer_id: None,
                remote_addr: None,
            },
            stats: TransportStats {
                succeeded: PktCounters {
                    packets: 100,
                    bytes: 50000,
                    ..Default::default()
                },
                dropped: PktCounters {
                    packets: 2,
                    bytes: 128,
                    ..Default::default()
                },
                drop_reasons: HashMap::new(),
                ..Default::default()
            },
        };
        snapshot.insert(metrics.labels.clone(), metrics);
        let text = encode_metrics_snapshot(snapshot);
        assert!(
            text.contains("h3llo_transport_packets_total"),
            "missing packets: {text}"
        );
        assert!(text.contains("100"), "missing succeeded count: {text}");
        assert!(
            text.contains("h3llo_transport_bytes_total"),
            "missing bytes: {text}"
        );
        assert!(text.contains("50000"), "missing succeeded bytes: {text}");
        assert!(
            text.contains("h3llo_transport_batches_total"),
            "missing batches: {text}"
        );
    }

    #[test]
    fn encode_snapshot_includes_drop_reasons() {
        let mut drop_reasons = HashMap::new();
        drop_reasons.insert(
            DropReason::Oversize,
            PktCounters {
                packets: 3,
                bytes: 4500,
                ..Default::default()
            },
        );
        let mut snapshot = HashMap::new();
        let metrics = TransportMetrics {
            labels: TransportLabels {
                kind: TransportKind::BareUdp,
                direction: Direction::Tx,
                peer_id: Some("peer-1".to_string()),
                remote_addr: None,
            },
            stats: TransportStats {
                succeeded: PktCounters {
                    packets: 50,
                    bytes: 25000,
                    ..Default::default()
                },
                dropped: PktCounters {
                    packets: 3,
                    bytes: 4500,
                    ..Default::default()
                },
                drop_reasons,
                ..Default::default()
            },
        };
        snapshot.insert(metrics.labels.clone(), metrics);
        let text = encode_metrics_snapshot(snapshot);
        assert!(
            text.contains("h3llo_transport_drops_total"),
            "missing drops: {text}"
        );
        assert!(
            text.contains("reason=\"oversize\""),
            "missing oversize: {text}"
        );
        assert!(
            text.contains("h3llo_transport_drop_bytes_total"),
            "missing drop bytes: {text}"
        );
    }

    #[test]
    fn encode_snapshot_is_openmetrics_format() {
        let mut snapshot = HashMap::new();
        let metrics = TransportMetrics {
            labels: TransportLabels {
                kind: TransportKind::Tun,
                direction: Direction::Rx,
                peer_id: None,
                remote_addr: None,
            },
            stats: TransportStats::default(),
        };
        snapshot.insert(metrics.labels.clone(), metrics);
        let text = encode_metrics_snapshot(snapshot);
        assert!(text.ends_with("# EOF\n"), "must end with # EOF: {text}");
        assert!(
            text.contains("_total{"),
            "counters must have _total suffix: {text}"
        );
    }

    #[test]
    fn encode_snapshot_includes_remote_addr_label() {
        let mut snapshot = HashMap::new();
        let addr: std::net::SocketAddr = "1.2.3.4:5353".parse().unwrap();
        let metrics = TransportMetrics {
            labels: TransportLabels {
                kind: TransportKind::BareUdp,
                direction: Direction::Tx,
                peer_id: Some("peer-x".to_string()),
                remote_addr: Some(addr),
            },
            stats: TransportStats {
                succeeded: PktCounters {
                    packets: 10,
                    bytes: 1000,
                    ..Default::default()
                },
                dropped: PktCounters::default(),
                drop_reasons: HashMap::new(),
                ..Default::default()
            },
        };
        snapshot.insert(metrics.labels.clone(), metrics);
        let text = encode_metrics_snapshot(snapshot);
        assert!(
            text.contains("remote_addr=\"1.2.3.4:5353\""),
            "missing remote_addr label: {text}"
        );
        assert!(
            text.contains("peer_id=\"peer-x\""),
            "missing peer_id label: {text}"
        );
    }

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

    #[test]
    fn encode_snapshot_ends_with_eof() {
        let text = encode_metrics_snapshot(HashMap::new());
        assert!(text.ends_with("# EOF\n"), "must end with # EOF: {text}");
    }

    #[test]
    fn encode_snapshot_has_single_eof() {
        let text = encode_metrics_snapshot(HashMap::new());
        let eof_count = text.matches("# EOF").count();
        assert_eq!(eof_count, 1, "should have exactly one EOF marker: {text}");
    }

    #[test]
    fn encode_snapshot_with_congestion_metrics() {
        use std::time::Duration;

        let mut snapshot = HashMap::new();
        let mut stats = TransportStats::default();
        stats.congestion.record_queue_full(Duration::from_millis(5));
        stats
            .congestion
            .record_would_block(Duration::from_micros(200));
        let labels = TransportLabels {
            kind: TransportKind::Tun,
            direction: Direction::Rx,
            peer_id: None,
            remote_addr: None,
        };
        let metrics = TransportMetrics {
            labels: labels.clone(),
            stats,
        };
        snapshot.insert(labels, metrics);
        let text = encode_metrics_snapshot(snapshot);
        assert!(
            text.contains("h3llo_transport_congestion_total"),
            "missing congestion: {text}"
        );
        assert!(
            text.contains("event=\"queue_full\""),
            "missing queue_full label: {text}"
        );
        assert!(
            text.contains("event=\"would_block\""),
            "missing would_block label: {text}"
        );
        assert!(
            text.contains("h3llo_transport_congestion_wait_seconds_total"),
            "missing wait: {text}"
        );
    }
}
