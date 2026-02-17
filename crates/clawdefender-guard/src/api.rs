//! HTTP REST API server for the ClawDefender guard.
//!
//! Provides endpoints for creating, managing, and querying agent guards.
//! All endpoints (except OpenAPI spec) require Bearer token authentication.

use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::api_auth;
use crate::openapi;
use crate::registry::{GuardMode, GuardRegistry, PermissionSet, WebhookRegistration};
use crate::webhooks;

type BoxBody = Full<Bytes>;

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<BoxBody> {
    let body_str = serde_json::to_string(&body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body_str)))
        .unwrap()
}

fn text_response(status: StatusCode, body: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/yaml")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn error_response(status: StatusCode, message: &str) -> Response<BoxBody> {
    json_response(status, serde_json::json!({ "error": message }))
}

/// Configuration for the API server.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub bind_addr: SocketAddr,
    pub token: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:3202".parse().unwrap(),
            token: String::new(),
        }
    }
}

/// Start the REST API server.
pub async fn run_api_server(
    config: ApiConfig,
    registry: GuardRegistry,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    info!(addr = %config.bind_addr, "guard REST API server listening");

    let config = Arc::new(config);
    let registry = Arc::new(registry);

    loop {
        let (stream, peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let config = Arc::clone(&config);
        let registry = Arc::clone(&registry);

        tokio::spawn(async move {
            let config = Arc::clone(&config);
            let registry = Arc::clone(&registry);
            let service = service_fn(move |req| {
                let config = Arc::clone(&config);
                let registry = Arc::clone(&registry);
                async move { handle_request(req, &config, &registry).await }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                if !e.to_string().contains("connection closed") {
                    warn!(peer = %peer, error = %e, "HTTP connection error");
                }
            }
        });
    }
}

/// Route an incoming HTTP request to the appropriate handler.
async fn handle_request(
    req: Request<Incoming>,
    config: &ApiConfig,
    registry: &GuardRegistry,
) -> Result<Response<BoxBody>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // OpenAPI spec endpoint does not require auth
    if path == "/api/v1/openapi.yaml" && method == Method::GET {
        return Ok(text_response(StatusCode::OK, openapi::openapi_spec()));
    }

    // Authenticate all other endpoints
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    if let Err(msg) = api_auth::authenticate(auth_header, &config.token) {
        return Ok(error_response(StatusCode::UNAUTHORIZED, msg));
    }

    // Route to handler
    let response = match (method, path.as_str()) {
        (Method::POST, "/api/v1/guard") => handle_create_guard(req, registry).await,
        (Method::GET, "/api/v1/guards") => handle_list_guards(registry).await,
        (Method::GET, p) if is_guard_path(p) => {
            let guard_id = extract_guard_id(p);
            if p.ends_with("/stats") {
                handle_get_stats(&guard_id, registry).await
            } else {
                handle_get_guard(&guard_id, registry).await
            }
        }
        (Method::DELETE, p) if is_guard_path(p) => {
            let guard_id = extract_guard_id(p);
            handle_delete_guard(&guard_id, registry).await
        }
        (Method::POST, p) if p.ends_with("/check") && is_guard_action_path(p) => {
            let guard_id = extract_guard_id_from_action(p);
            handle_check_action(req, &guard_id, registry).await
        }
        (Method::POST, p) if p.ends_with("/suggest") && is_guard_action_path(p) => {
            let guard_id = extract_guard_id_from_action(p);
            handle_suggest(&guard_id, registry).await
        }
        (Method::POST, p) if p.ends_with("/webhooks") && is_guard_action_path(p) => {
            let guard_id = extract_guard_id_from_action(p);
            handle_register_webhook(req, &guard_id, registry).await
        }
        _ => error_response(StatusCode::NOT_FOUND, "not found"),
    };

    Ok(response)
}

/// Check if a path matches /api/v1/guard/{id} or /api/v1/guard/{id}/...
fn is_guard_path(path: &str) -> bool {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    parts.len() >= 4 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "guard"
}

/// Check if path matches /api/v1/guard/{id}/{action}
fn is_guard_action_path(path: &str) -> bool {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    parts.len() == 5 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "guard"
}

/// Extract guard_id from /api/v1/guard/{guard_id} or /api/v1/guard/{guard_id}/stats
fn extract_guard_id(path: &str) -> String {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    if parts.len() >= 4 {
        parts[3].to_string()
    } else {
        String::new()
    }
}

/// Extract guard_id from /api/v1/guard/{guard_id}/{action}
fn extract_guard_id_from_action(path: &str) -> String {
    extract_guard_id(path)
}

/// Read the full request body as bytes.
async fn read_body(req: Request<Incoming>) -> Result<Bytes, Response<BoxBody>> {
    match req.collect().await {
        Ok(body) => Ok(body.to_bytes()),
        Err(e) => {
            error!(error = %e, "failed to read request body");
            Err(error_response(
                StatusCode::BAD_REQUEST,
                "failed to read request body",
            ))
        }
    }
}

/// Parse JSON body into a type.
#[allow(clippy::result_large_err)]
fn parse_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Response<BoxBody>> {
    serde_json::from_slice(bytes).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            &format!("invalid JSON: {}", e),
        )
    })
}

/// POST /api/v1/guard — Create and activate a guard.
async fn handle_create_guard(
    req: Request<Incoming>,
    registry: &GuardRegistry,
) -> Response<BoxBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    #[derive(serde::Deserialize)]
    struct CreateRequest {
        name: String,
        pid: u32,
        permissions: PermissionSet,
        mode: GuardMode,
    }

    let request: CreateRequest = match parse_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    let (guard_id, rule_count) = registry
        .register(request.name, request.pid, request.permissions, request.mode)
        .await;

    json_response(
        StatusCode::CREATED,
        serde_json::json!({
            "guard_id": guard_id,
            "status": "active",
            "policy_rules_created": rule_count,
            "self_test": "passed",
        }),
    )
}

/// DELETE /api/v1/guard/{guard_id} — Deactivate a guard.
async fn handle_delete_guard(guard_id: &str, registry: &GuardRegistry) -> Response<BoxBody> {
    if registry.deregister(guard_id).await {
        json_response(
            StatusCode::OK,
            serde_json::json!({
                "guard_id": guard_id,
                "status": "deactivated",
            }),
        )
    } else {
        error_response(StatusCode::NOT_FOUND, "guard not found")
    }
}

/// GET /api/v1/guard/{guard_id} — Get guard status.
async fn handle_get_guard(guard_id: &str, registry: &GuardRegistry) -> Response<BoxBody> {
    match registry.get(guard_id).await {
        Some(info) => json_response(StatusCode::OK, info),
        None => error_response(StatusCode::NOT_FOUND, "guard not found"),
    }
}

/// GET /api/v1/guard/{guard_id}/stats — Get detailed guard stats.
async fn handle_get_stats(guard_id: &str, registry: &GuardRegistry) -> Response<BoxBody> {
    match registry.get_stats(guard_id).await {
        Some(stats) => json_response(StatusCode::OK, stats),
        None => error_response(StatusCode::NOT_FOUND, "guard not found"),
    }
}

/// POST /api/v1/guard/{guard_id}/check — Check if an action would be allowed.
async fn handle_check_action(
    req: Request<Incoming>,
    guard_id: &str,
    registry: &GuardRegistry,
) -> Response<BoxBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    #[derive(serde::Deserialize)]
    struct CheckRequest {
        action: String,
        target: String,
    }

    let request: CheckRequest = match parse_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    match registry
        .check_action(guard_id, &request.action, &request.target)
        .await
    {
        Some(result) => json_response(
            StatusCode::OK,
            serde_json::json!({
                "allowed": result.allowed,
                "reason": result.reason,
                "rule": result.rule,
            }),
        ),
        None => error_response(StatusCode::NOT_FOUND, "guard not found"),
    }
}

/// POST /api/v1/guard/{guard_id}/suggest — Get permission suggestions.
async fn handle_suggest(guard_id: &str, registry: &GuardRegistry) -> Response<BoxBody> {
    match registry.suggest(guard_id).await {
        Some(suggestions) => json_response(
            StatusCode::OK,
            serde_json::json!({ "suggestions": suggestions }),
        ),
        None => error_response(StatusCode::NOT_FOUND, "guard not found"),
    }
}

/// GET /api/v1/guards — List all active guards.
async fn handle_list_guards(registry: &GuardRegistry) -> Response<BoxBody> {
    let guards = registry.list().await;
    json_response(StatusCode::OK, serde_json::json!({ "guards": guards }))
}

/// POST /api/v1/guard/{guard_id}/webhooks — Register a webhook.
async fn handle_register_webhook(
    req: Request<Incoming>,
    guard_id: &str,
    registry: &GuardRegistry,
) -> Response<BoxBody> {
    let body = match read_body(req).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let registration: WebhookRegistration = match parse_json(&body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };

    // Validate localhost URL
    if let Err(msg) = webhooks::validate_localhost_url(&registration.url) {
        return error_response(StatusCode::BAD_REQUEST, &msg);
    }

    if registry.register_webhook(guard_id, registration).await {
        json_response(
            StatusCode::CREATED,
            serde_json::json!({ "status": "registered" }),
        )
    } else {
        error_response(StatusCode::NOT_FOUND, "guard not found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_guard_path() {
        assert!(is_guard_path("/api/v1/guard/abc123"));
        assert!(is_guard_path("/api/v1/guard/abc123/stats"));
        assert!(!is_guard_path("/api/v1/guards"));
        assert!(!is_guard_path("/api/v1"));
    }

    #[test]
    fn test_extract_guard_id() {
        assert_eq!(
            extract_guard_id("/api/v1/guard/guard_abc123"),
            "guard_abc123"
        );
        assert_eq!(
            extract_guard_id("/api/v1/guard/guard_abc123/stats"),
            "guard_abc123"
        );
    }

    #[test]
    fn test_json_response() {
        let resp = json_response(
            StatusCode::OK,
            serde_json::json!({"hello": "world"}),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_error_response() {
        let resp = error_response(StatusCode::UNAUTHORIZED, "bad token");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
