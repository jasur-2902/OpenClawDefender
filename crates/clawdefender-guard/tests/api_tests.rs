//! Integration tests for the ClawDefender Guard REST API.

use std::net::SocketAddr;

use clawdefender_guard::api::{ApiConfig, run_api_server};
use clawdefender_guard::registry::{GuardMode, GuardRegistry, PermissionSet};
use clawdefender_guard::webhooks;

const TEST_TOKEN: &str = "test-token-abc123";

/// Helper: create a test registry and API config on a random port.
async fn setup() -> (GuardRegistry, SocketAddr) {
    let registry = GuardRegistry::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    (registry, addr)
}

/// Helper: start the API server in the background and return the base URL.
async fn start_server() -> (String, GuardRegistry) {
    let (registry, addr) = setup().await;
    let config = ApiConfig {
        bind_addr: addr,
        token: TEST_TOKEN.to_string(),
    };
    let reg_clone = registry.clone();
    tokio::spawn(async move {
        run_api_server(config, reg_clone).await.unwrap();
    });
    // Give server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (format!("http://{}", addr), registry)
}

/// Helper: make a raw HTTP request using a TCP stream.
async fn http_request(
    method: &str,
    url: &str,
    body: Option<&str>,
    auth: Option<&str>,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let parsed = url.strip_prefix("http://").unwrap();
    let (host_port, path) = match parsed.find('/') {
        Some(idx) => (&parsed[..idx], &parsed[idx..]),
        None => (parsed, "/"),
    };

    let mut stream = tokio::net::TcpStream::connect(host_port).await.unwrap();

    let body_str = body.unwrap_or("");
    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        method, path, host_port, body_str.len()
    );
    if let Some(token) = auth {
        request.push_str(&format!("Authorization: Bearer {}\r\n", token));
    }
    request.push_str("\r\n");
    request.push_str(body_str);

    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    // Read response with a timeout
    let mut response = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut response),
    )
    .await;

    let response_str = String::from_utf8_lossy(&response).to_string();

    // Parse status code
    let status_line = response_str.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Extract body (after empty line)
    let resp_body = response_str
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .to_string();

    (status, resp_body)
}

fn test_permissions_json() -> String {
    serde_json::json!({
        "name": "test-agent",
        "pid": 12345,
        "permissions": {
            "file_read": ["~/Projects/workspace/**"],
            "file_write": ["~/Projects/workspace/**"],
            "file_delete": [],
            "shell_policy": "deny",
            "network_allowlist": ["api.anthropic.com"],
            "tools": ["read_file", "write_file", "list_directory"],
            "max_file_size": null,
            "max_files_per_minute": null,
            "max_network_requests_per_minute": null
        },
        "mode": "enforce"
    })
    .to_string()
}

// ---- Authentication tests ----

#[tokio::test]
async fn test_auth_missing_token_returns_401() {
    let (base_url, _registry) = start_server().await;
    let (status, body) = http_request("GET", &format!("{}/api/v1/guards", base_url), None, None).await;
    assert_eq!(status, 401);
    assert!(body.contains("error"));
}

#[tokio::test]
async fn test_auth_wrong_token_returns_401() {
    let (base_url, _registry) = start_server().await;
    let (status, _body) =
        http_request("GET", &format!("{}/api/v1/guards", base_url), None, Some("wrong-token")).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn test_auth_valid_token() {
    let (base_url, _registry) = start_server().await;
    let (status, _body) =
        http_request("GET", &format!("{}/api/v1/guards", base_url), None, Some(TEST_TOKEN)).await;
    assert_eq!(status, 200);
}

// ---- Guard lifecycle tests ----

#[tokio::test]
async fn test_create_guard() {
    let (base_url, _registry) = start_server().await;
    let body = test_permissions_json();
    let (status, resp) =
        http_request("POST", &format!("{}/api/v1/guard", base_url), Some(&body), Some(TEST_TOKEN)).await;
    assert_eq!(status, 201);
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["status"], "active");
    assert!(json["guard_id"].as_str().unwrap().starts_with("guard_"));
    assert!(json["policy_rules_created"].as_u64().unwrap() > 0);
    assert_eq!(json["self_test"], "passed");
}

#[tokio::test]
async fn test_get_guard() {
    let (base_url, registry) = start_server().await;
    let perms = PermissionSet {
        file_read: vec!["~/test/**".to_string()],
        file_write: vec![],
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec![],
        tools: vec![],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };
    let (guard_id, _) = registry
        .register("test".into(), 1234, perms, GuardMode::Enforce)
        .await;

    let (status, resp) = http_request(
        "GET",
        &format!("{}/api/v1/guard/{}", base_url, guard_id),
        None,
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["guard_id"], guard_id);
    assert_eq!(json["status"], "active");
}

#[tokio::test]
async fn test_get_nonexistent_guard_returns_404() {
    let (base_url, _registry) = start_server().await;
    let (status, _) = http_request(
        "GET",
        &format!("{}/api/v1/guard/nonexistent", base_url),
        None,
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_delete_guard() {
    let (base_url, registry) = start_server().await;
    let perms = PermissionSet {
        file_read: vec![],
        file_write: vec![],
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec![],
        tools: vec![],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };
    let (guard_id, _) = registry
        .register("del-test".into(), 999, perms, GuardMode::Enforce)
        .await;

    let (status, resp) = http_request(
        "DELETE",
        &format!("{}/api/v1/guard/{}", base_url, guard_id),
        None,
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["status"], "deactivated");

    // Verify it's gone
    let (status, _) = http_request(
        "GET",
        &format!("{}/api/v1/guard/{}", base_url, guard_id),
        None,
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn test_guard_lifecycle_create_check_stats_delete() {
    let (base_url, _registry) = start_server().await;

    // Create
    let body = test_permissions_json();
    let (status, resp) =
        http_request("POST", &format!("{}/api/v1/guard", base_url), Some(&body), Some(TEST_TOKEN)).await;
    assert_eq!(status, 201);
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    let guard_id = json["guard_id"].as_str().unwrap().to_string();

    // Check action (should be blocked - sensitive path)
    let check_body = serde_json::json!({
        "action": "file_read",
        "target": "~/.ssh/id_rsa"
    })
    .to_string();
    let (status, resp) = http_request(
        "POST",
        &format!("{}/api/v1/guard/{}/check", base_url, guard_id),
        Some(&check_body),
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["allowed"], false);

    // Stats
    let (status, resp) = http_request(
        "GET",
        &format!("{}/api/v1/guard/{}/stats", base_url, guard_id),
        None,
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["checks_total"], 1);
    assert_eq!(json["checks_blocked"], 1);

    // Delete
    let (status, _) = http_request(
        "DELETE",
        &format!("{}/api/v1/guard/{}", base_url, guard_id),
        None,
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 200);
}

// ---- Check endpoint tests ----

#[tokio::test]
async fn test_check_action_blocked() {
    let (base_url, registry) = start_server().await;
    let perms = PermissionSet {
        file_read: vec!["~/safe/**".to_string()],
        file_write: vec![],
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec![],
        tools: vec![],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };
    let (guard_id, _) = registry
        .register("check-test".into(), 1, perms, GuardMode::Enforce)
        .await;

    let body = serde_json::json!({
        "action": "file_read",
        "target": "~/.ssh/id_rsa"
    })
    .to_string();
    let (status, resp) = http_request(
        "POST",
        &format!("{}/api/v1/guard/{}/check", base_url, guard_id),
        Some(&body),
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(json["allowed"], false);
    assert_eq!(json["rule"], "guard_block_sensitive_paths");
}

// ---- Suggest endpoint tests ----

#[tokio::test]
async fn test_suggest_permissions() {
    let (base_url, registry) = start_server().await;
    let perms = PermissionSet {
        file_read: vec![],
        file_write: vec![],
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec![],
        tools: vec![],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };
    let (guard_id, _) = registry
        .register("suggest-test".into(), 1, perms, GuardMode::Monitor)
        .await;

    // First do a check to generate a blocked operation
    let body = serde_json::json!({
        "action": "file_read",
        "target": "~/.ssh/id_rsa"
    })
    .to_string();
    http_request(
        "POST",
        &format!("{}/api/v1/guard/{}/check", base_url, guard_id),
        Some(&body),
        Some(TEST_TOKEN),
    )
    .await;

    // Now get suggestions
    let (status, resp) = http_request(
        "POST",
        &format!("{}/api/v1/guard/{}/suggest", base_url, guard_id),
        None,
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    let suggestions = json["suggestions"].as_array().unwrap();
    assert!(!suggestions.is_empty());
}

// ---- List guards ----

#[tokio::test]
async fn test_list_guards() {
    let (base_url, registry) = start_server().await;
    let perms = PermissionSet {
        file_read: vec![],
        file_write: vec![],
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec![],
        tools: vec![],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };
    registry
        .register("agent-1".into(), 1, perms.clone(), GuardMode::Enforce)
        .await;
    registry
        .register("agent-2".into(), 2, perms, GuardMode::Monitor)
        .await;

    let (status, resp) =
        http_request("GET", &format!("{}/api/v1/guards", base_url), None, Some(TEST_TOKEN)).await;
    assert_eq!(status, 200);
    let json: serde_json::Value = serde_json::from_str(&resp).unwrap();
    let guards = json["guards"].as_array().unwrap();
    assert_eq!(guards.len(), 2);
}

// ---- Webhook tests ----

#[tokio::test]
async fn test_webhook_registration_localhost() {
    let (base_url, registry) = start_server().await;
    let perms = PermissionSet {
        file_read: vec![],
        file_write: vec![],
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec![],
        tools: vec![],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };
    let (guard_id, _) = registry
        .register("webhook-test".into(), 1, perms, GuardMode::Enforce)
        .await;

    let body = serde_json::json!({
        "url": "http://127.0.0.1:8080/callback",
        "events": ["blocked", "anomaly"]
    })
    .to_string();
    let (status, _) = http_request(
        "POST",
        &format!("{}/api/v1/guard/{}/webhooks", base_url, guard_id),
        Some(&body),
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 201);
}

#[tokio::test]
async fn test_webhook_rejects_remote_url() {
    let (base_url, registry) = start_server().await;
    let perms = PermissionSet {
        file_read: vec![],
        file_write: vec![],
        file_delete: vec![],
        shell_policy: "deny".to_string(),
        network_allowlist: vec![],
        tools: vec![],
        max_file_size: None,
        max_files_per_minute: None,
        max_network_requests_per_minute: None,
    };
    let (guard_id, _) = registry
        .register("webhook-reject-test".into(), 1, perms, GuardMode::Enforce)
        .await;

    let body = serde_json::json!({
        "url": "http://evil.example.com/steal",
        "events": ["blocked"]
    })
    .to_string();
    let (status, _) = http_request(
        "POST",
        &format!("{}/api/v1/guard/{}/webhooks", base_url, guard_id),
        Some(&body),
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 400);
}

// ---- OpenAPI spec test ----

#[tokio::test]
async fn test_openapi_spec_endpoint_no_auth_required() {
    let (base_url, _registry) = start_server().await;
    let (status, body) = http_request(
        "GET",
        &format!("{}/api/v1/openapi.yaml", base_url),
        None,
        None, // No auth!
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("openapi:"));
    assert!(body.contains("/api/v1/guard:"));
}

// ---- Not found test ----

#[tokio::test]
async fn test_unknown_endpoint_returns_404() {
    let (base_url, _registry) = start_server().await;
    let (status, _) = http_request(
        "GET",
        &format!("{}/api/v1/nonexistent", base_url),
        None,
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 404);
}

// ---- Invalid JSON test ----

#[tokio::test]
async fn test_create_guard_invalid_json() {
    let (base_url, _registry) = start_server().await;
    let (status, resp) = http_request(
        "POST",
        &format!("{}/api/v1/guard", base_url),
        Some("not json"),
        Some(TEST_TOKEN),
    )
    .await;
    assert_eq!(status, 400);
    assert!(resp.contains("invalid JSON"));
}

// ---- Registry unit tests ----

#[tokio::test]
async fn test_registry_check_action_nonexistent() {
    let registry = GuardRegistry::new();
    let result = registry.check_action("nonexistent", "file_read", "/tmp/test").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_registry_suggest_nonexistent() {
    let registry = GuardRegistry::new();
    let result = registry.suggest("nonexistent").await;
    assert!(result.is_none());
}

// ---- Webhook validation unit tests ----

#[test]
fn test_webhook_validate_localhost_variants() {
    assert!(webhooks::validate_localhost_url("http://127.0.0.1:8080/cb").is_ok());
    assert!(webhooks::validate_localhost_url("http://localhost:3000/hook").is_ok());
    assert!(webhooks::validate_localhost_url("http://[::1]:9090/events").is_ok());
    assert!(webhooks::validate_localhost_url("http://evil.com/steal").is_err());
    assert!(webhooks::validate_localhost_url("no-scheme").is_err());
}

// ---- OpenAPI spec unit tests ----

#[test]
fn test_openapi_spec_contains_all_endpoints() {
    let spec = clawdefender_guard::openapi::openapi_spec();
    assert!(spec.contains("/api/v1/guard:"));
    assert!(spec.contains("/api/v1/guard/{guard_id}:"));
    assert!(spec.contains("/api/v1/guard/{guard_id}/stats:"));
    assert!(spec.contains("/api/v1/guard/{guard_id}/check:"));
    assert!(spec.contains("/api/v1/guard/{guard_id}/suggest:"));
    assert!(spec.contains("/api/v1/guard/{guard_id}/webhooks:"));
    assert!(spec.contains("/api/v1/guards:"));
    assert!(spec.contains("/api/v1/openapi.yaml:"));
    assert!(spec.contains("bearerAuth"));
}
