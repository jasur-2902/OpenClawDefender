//! HTTP/SSE-based MCP proxy.
//!
//! Implements a reverse proxy for MCP servers that use HTTP+SSE transport.
//! Intercepts JSON-RPC messages in HTTP request bodies, applies the same
//! classification and policy evaluation as the stdio proxy.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use chrono::Utc;
use reqwest::Client;
use serde_json::json;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use clawdefender_core::audit::AuditRecord;
use clawdefender_core::event::mcp::{
    McpEvent, McpEventKind, ResourceRead, SamplingRequest, ToolCall,
};
use clawdefender_core::ipc::protocol::UiRequest;
use clawdefender_core::policy::engine::DefaultPolicyEngine;
use clawdefender_core::policy::{PolicyAction, PolicyEngine};

use crate::classifier::rules::{classify, extract_resource_uri, extract_tool_call, Classification};
use crate::jsonrpc::parser::parse_message;
use crate::jsonrpc::types::{
    JsonRpcError, JsonRpcId, JsonRpcMessage, JsonRpcResponse, POLICY_BLOCK_ERROR_CODE,
};

use super::{ProxyConfig, ProxyMetrics, UiBridge};

/// Shared state for axum handlers.
#[derive(Clone)]
struct AppState {
    target_url: String,
    http_client: Client,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
    audit_tx: mpsc::Sender<AuditRecord>,
    ui_bridge: Option<Arc<UiBridge>>,
    metrics: Arc<ProxyMetrics>,
    prompt_timeout: Duration,
}

/// HTTP reverse proxy for MCP servers that use HTTP+SSE transport.
pub struct HttpProxy {
    target_url: String,
    policy_engine: Arc<RwLock<DefaultPolicyEngine>>,
    audit_tx: mpsc::Sender<AuditRecord>,
    ui_bridge: Option<Arc<UiBridge>>,
    metrics: Arc<ProxyMetrics>,
    config: ProxyConfig,
    insecure: bool,
}

impl HttpProxy {
    /// Create a new HTTP proxy targeting the given URL.
    pub fn new(target_url: String, policy_path: &Path) -> Result<Self> {
        let policy_engine = if policy_path.exists() {
            DefaultPolicyEngine::load(policy_path)?
        } else {
            DefaultPolicyEngine::empty()
        };

        let (audit_tx, _audit_rx) = mpsc::channel(1024);

        Ok(Self {
            target_url,
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            audit_tx,
            ui_bridge: None,
            metrics: Arc::new(ProxyMetrics::new()),
            config: ProxyConfig::default(),
            insecure: false,
        })
    }

    /// Create with full configuration.
    pub fn with_full_config(
        target_url: String,
        policy_engine: DefaultPolicyEngine,
        audit_tx: mpsc::Sender<AuditRecord>,
        ui_bridge: Option<Arc<UiBridge>>,
        config: ProxyConfig,
        insecure: bool,
    ) -> Self {
        Self {
            target_url,
            policy_engine: Arc::new(RwLock::new(policy_engine)),
            audit_tx,
            ui_bridge,
            metrics: Arc::new(ProxyMetrics::new()),
            config,
            insecure,
        }
    }

    /// Get a reference to the proxy metrics.
    pub fn metrics(&self) -> &Arc<ProxyMetrics> {
        &self.metrics
    }

    /// Start the HTTP proxy server.
    pub async fn start(&self, addr: SocketAddr) -> Result<()> {
        let http_client = Client::builder()
            .danger_accept_invalid_certs(self.insecure)
            .timeout(Duration::from_secs(300))
            .build()
            .context("failed to build HTTP client")?;

        let state = AppState {
            target_url: self.target_url.clone(),
            http_client,
            policy_engine: Arc::clone(&self.policy_engine),
            audit_tx: self.audit_tx.clone(),
            ui_bridge: self.ui_bridge.clone(),
            metrics: Arc::clone(&self.metrics),
            prompt_timeout: self.config.prompt_timeout,
        };

        let app = Router::new()
            .route("/sse", get(handle_sse))
            .route("/", any(handle_jsonrpc))
            .route("/{*path}", any(handle_jsonrpc))
            .with_state(state);

        info!(%addr, target = %self.target_url, "starting HTTP proxy");

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind to {addr}"))?;

        axum::serve(listener, app)
            .await
            .context("HTTP proxy server error")?;

        Ok(())
    }
}

/// Handle SSE streaming -- relay without blocking.
async fn handle_sse(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let url = format!("{}/sse", state.target_url.trim_end_matches('/'));

    let mut req_builder = state.http_client.get(&url);

    // Forward relevant headers
    for (name, value) in &headers {
        if !is_hop_by_hop(name.as_str()) {
            req_builder = req_builder.header(name.clone(), value.clone());
        }
    }

    match req_builder.send().await {
        Ok(upstream_resp) => {
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let mut resp_headers = HeaderMap::new();
            for (name, value) in upstream_resp.headers() {
                if !is_hop_by_hop(name.as_str()) {
                    resp_headers.insert(name.clone(), value.clone());
                }
            }

            let body = Body::from_stream(upstream_resp.bytes_stream());
            let mut response = Response::new(body);
            *response.status_mut() = status;
            *response.headers_mut() = resp_headers;
            response
        }
        Err(e) => {
            error!("SSE upstream error: {e}");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Handle JSON-RPC requests: parse, classify, evaluate policy, forward or block.
async fn handle_jsonrpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    state.metrics.inc_total();

    // Try to parse as JSON-RPC
    let msg = match parse_message(&body) {
        Ok(msg) => msg,
        Err(_) => {
            // Not valid JSON-RPC -- forward as-is (could be non-JSON-RPC endpoint)
            return forward_raw(&state, &headers, &body).await;
        }
    };

    let classification = classify(&msg);

    match classification {
        Classification::Pass | Classification::Log => {
            if matches!(classification, Classification::Log) {
                state.metrics.inc_logged();
                let event = build_mcp_event(&msg);
                let record = build_audit_record(&event, "log", None);
                let _ = state.audit_tx.try_send(record);
            } else {
                state.metrics.inc_allowed();
            }
            forward_raw(&state, &headers, &body).await
        }
        Classification::Review => {
            let event = build_mcp_event(&msg);
            let action = {
                let engine = state.policy_engine.read().await;
                engine.evaluate(&event)
            };

            match action {
                PolicyAction::Allow | PolicyAction::Log => {
                    if matches!(action, PolicyAction::Log) {
                        state.metrics.inc_logged();
                    } else {
                        state.metrics.inc_allowed();
                    }
                    let record = build_audit_record(
                        &event,
                        if matches!(action, PolicyAction::Log) {
                            "log"
                        } else {
                            "allow"
                        },
                        None,
                    );
                    let _ = state.audit_tx.try_send(record);
                    forward_raw(&state, &headers, &body).await
                }
                PolicyAction::Block => {
                    state.metrics.inc_blocked();
                    let record = build_audit_record(&event, "block", None);
                    let _ = state.audit_tx.try_send(record);

                    if let Some(id) = request_id(&msg) {
                        make_http_block_response(&id, "Blocked by ClawDefender policy")
                    } else {
                        StatusCode::FORBIDDEN.into_response()
                    }
                }
                PolicyAction::Prompt(prompt_msg) => {
                    state.metrics.inc_prompted();

                    if let Some(ref bridge) = state.ui_bridge {
                        let ui_req = UiRequest::PromptUser {
                            event_summary: event_summary(&event),
                            rule_name: "policy".to_string(),
                            options: vec![
                                "Allow once".into(),
                                "Deny".into(),
                                "Allow for session".into(),
                            ],
                        };

                        match bridge.send_prompt(ui_req).await {
                            Ok(resp_rx) => {
                                match tokio::time::timeout(state.prompt_timeout, resp_rx).await {
                                    Ok(Ok(clawdefender_core::ipc::protocol::UiResponse::Decision {
                                        action: clawdefender_core::ipc::protocol::UserDecision::AllowOnce
                                        | clawdefender_core::ipc::protocol::UserDecision::AllowSession,
                                        ..
                                    })) => {
                                        state.metrics.inc_allowed();
                                        forward_raw(&state, &headers, &body).await
                                    }
                                    _ => {
                                        state.metrics.inc_blocked();
                                        if let Some(id) = request_id(&msg) {
                                            make_http_block_response(
                                                &id,
                                                &format!("ClawDefender: {prompt_msg}"),
                                            )
                                        } else {
                                            StatusCode::FORBIDDEN.into_response()
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                // Bridge unavailable, allow (backwards compat)
                                warn!("UI bridge unavailable, allowing");
                                state.metrics.inc_allowed();
                                forward_raw(&state, &headers, &body).await
                            }
                        }
                    } else {
                        // No bridge, allow
                        warn!("prompt action without UI bridge, allowing");
                        state.metrics.inc_allowed();
                        forward_raw(&state, &headers, &body).await
                    }
                }
            }
        }
        Classification::Block => {
            state.metrics.inc_blocked();
            if let Some(id) = request_id(&msg) {
                make_http_block_response(&id, "Blocked by classifier")
            } else {
                StatusCode::FORBIDDEN.into_response()
            }
        }
    }
}

/// Forward the raw request body to the upstream server.
async fn forward_raw(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Response {
    let url = state.target_url.clone();
    let mut req_builder = state.http_client.post(&url).body(body.to_vec());

    for (name, value) in headers {
        if !is_hop_by_hop(name.as_str()) && name.as_str() != "host" {
            req_builder = req_builder.header(name.clone(), value.clone());
        }
    }

    match req_builder.send().await {
        Ok(upstream_resp) => {
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let mut resp_headers = HeaderMap::new();
            for (name, value) in upstream_resp.headers() {
                if !is_hop_by_hop(name.as_str()) {
                    resp_headers.insert(name.clone(), value.clone());
                }
            }

            let resp_body = match upstream_resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    error!("error reading upstream response: {e}");
                    return StatusCode::BAD_GATEWAY.into_response();
                }
            };

            let mut response = Response::new(Body::from(resp_body));
            *response.status_mut() = status;
            *response.headers_mut() = resp_headers;
            response
        }
        Err(e) => {
            error!("upstream request error: {e}");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Build an HTTP 200 response with a JSON-RPC error body (not HTTP 403).
fn make_http_block_response(request_id: &JsonRpcId, message: &str) -> Response {
    let error_resp = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: request_id.clone(),
        result: None,
        error: Some(JsonRpcError {
            code: POLICY_BLOCK_ERROR_CODE,
            message: message.to_string(),
            data: None,
        }),
    };

    let body = serde_json::to_vec(&error_resp).unwrap_or_default();

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    response
}

/// Check if a header is a hop-by-hop header that should not be forwarded.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn request_id(msg: &JsonRpcMessage) -> Option<JsonRpcId> {
    match msg {
        JsonRpcMessage::Request(r) => Some(r.id.clone()),
        JsonRpcMessage::Response(r) => Some(r.id.clone()),
        JsonRpcMessage::Notification(_) => None,
    }
}

fn build_mcp_event(msg: &JsonRpcMessage) -> McpEvent {
    let raw = serde_json::to_value(msg).unwrap_or(json!({}));
    let kind = match msg {
        JsonRpcMessage::Request(r) => match r.method.as_str() {
            "tools/call" => {
                if let Some((name, args)) = extract_tool_call(msg) {
                    McpEventKind::ToolCall(ToolCall {
                        tool_name: name,
                        arguments: args,
                        request_id: serde_json::to_value(&r.id).unwrap_or_default(),
                    })
                } else {
                    McpEventKind::Other(r.method.clone())
                }
            }
            "resources/read" => {
                if let Some(uri) = extract_resource_uri(msg) {
                    McpEventKind::ResourceRead(ResourceRead {
                        uri,
                        request_id: serde_json::to_value(&r.id).unwrap_or_default(),
                    })
                } else {
                    McpEventKind::Other(r.method.clone())
                }
            }
            "sampling/createMessage" => {
                let params = r.params.clone().unwrap_or(json!({}));
                let messages = params
                    .get("messages")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let model_preferences = params.get("modelPreferences").cloned();
                McpEventKind::SamplingRequest(SamplingRequest {
                    messages,
                    model_preferences,
                    request_id: serde_json::to_value(&r.id).unwrap_or_default(),
                })
            }
            "tools/list" | "resources/list" | "prompts/list" => McpEventKind::ListRequest,
            other => McpEventKind::Other(other.to_string()),
        },
        JsonRpcMessage::Notification(n) => McpEventKind::Notification(n.method.clone()),
        JsonRpcMessage::Response(_) => McpEventKind::Other("response".to_string()),
    };

    McpEvent {
        timestamp: Utc::now(),
        source: "mcp-proxy-http".to_string(),
        kind,
        raw_message: raw,
    }
}

fn event_summary(event: &McpEvent) -> String {
    match &event.kind {
        McpEventKind::ToolCall(tc) => format!("tool_call: {}", tc.tool_name),
        McpEventKind::ResourceRead(rr) => format!("resource_read: {}", rr.uri),
        McpEventKind::SamplingRequest(_) => "sampling_request".to_string(),
        McpEventKind::ListRequest => "list_request".to_string(),
        McpEventKind::Notification(n) => format!("notification: {n}"),
        McpEventKind::Other(m) => format!("other: {m}"),
    }
}

fn build_audit_record(event: &McpEvent, action: &str, rule_name: Option<&str>) -> AuditRecord {
    AuditRecord {
        timestamp: event.timestamp,
        source: event.source.clone(),
        event_summary: event_summary(event),
        event_details: serde_json::to_value(event).unwrap_or_default(),
        rule_matched: rule_name.map(|s| s.to_string()),
        action_taken: action.to_string(),
        response_time_ms: None,
        session_id: None,
        direction: None,
        server_name: None,
        client_name: None,
        jsonrpc_method: None,
        tool_name: None,
        arguments: None,
        classification: None,
        policy_rule: None,
        policy_action: None,
        user_decision: None,
        proxy_latency_us: None,
        slm_analysis: None,
        swarm_analysis: None,
        behavioral: None,
        injection_scan: None,
        threat_intel: None,
        network_connection: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_hop_by_hop() {
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("authorization"));
    }

    #[test]
    fn test_make_http_block_response() {
        let resp = make_http_block_response(&JsonRpcId::Number(1), "blocked");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_request_id_extraction() {
        use crate::jsonrpc::types::JsonRpcRequest;
        let msg = JsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: JsonRpcId::Number(42),
            method: "tools/call".into(),
            params: None,
        });
        assert_eq!(request_id(&msg), Some(JsonRpcId::Number(42)));
    }
}
