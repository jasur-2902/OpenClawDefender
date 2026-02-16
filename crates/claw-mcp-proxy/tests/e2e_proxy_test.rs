//! End-to-end integration tests for the MCP proxy.
//!
//! These tests spawn the actual `claw-mcp-proxy` binary wrapping the
//! `mock-mcp-server` binary and verify the full pipeline: JSON-RPC parsing,
//! classification, policy evaluation, forwarding, and blocking.
//!
//! Prerequisites: `cargo build --workspace` must be run first.
//! All tests are marked `#[ignore]` because they require both binaries to be
//! built and the full proxy pipeline to be operational.

mod helpers;

use serde_json::json;

/// Policy that blocks access to ~/.ssh/* paths via resource_path matching.
const BLOCK_SSH_POLICY: &str = r#"
[rules.block_ssh]
description = "Block SSH key access"
action = "block"
message = "SSH key access is not allowed"
priority = 0

[rules.block_ssh.match]
resource_path = ["*/.ssh/*"]

[rules.allow_all]
description = "Allow everything else"
action = "allow"
message = "Allowed"
priority = 100

[rules.allow_all.match]
any = true
"#;

/// Policy that allows project paths.
const ALLOW_PROJECT_POLICY: &str = r#"
[rules.allow_project]
description = "Allow project file reads"
action = "allow"
message = "Project file access allowed"
priority = 0

[rules.allow_project.match]
resource_path = ["*/Projects/**"]

[rules.allow_all]
description = "Allow everything else"
action = "allow"
message = "Allowed"
priority = 100

[rules.allow_all.match]
any = true
"#;

/// Minimal permissive policy.
const ALLOW_ALL_POLICY: &str = r#"
[rules.allow_all]
description = "Allow everything"
action = "allow"
message = "Allowed"
priority = 100

[rules.allow_all.match]
any = true
"#;

/// Policy that blocks several dangerous paths.
const BLOCK_DANGEROUS_PATHS_POLICY: &str = r#"
[rules.block_ssh]
description = "Block SSH keys"
action = "block"
message = "SSH key access blocked"
priority = 0

[rules.block_ssh.match]
resource_path = ["*/.ssh/*"]

[rules.block_aws]
description = "Block AWS credentials"
action = "block"
message = "AWS credential access blocked"
priority = 0

[rules.block_aws.match]
resource_path = ["*/.aws/credentials"]

[rules.block_gnupg]
description = "Block GnuPG keyring"
action = "block"
message = "GnuPG access blocked"
priority = 0

[rules.block_gnupg.match]
resource_path = ["*/.gnupg/*"]

[rules.block_bash_history]
description = "Block bash history"
action = "block"
message = "Bash history access blocked"
priority = 0

[rules.block_bash_history.match]
resource_path = ["*/.bash_history"]

[rules.allow_all]
description = "Allow everything else"
action = "allow"
message = "Allowed"
priority = 100

[rules.allow_all.match]
any = true
"#;

fn make_initialize_request(id: i64) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "0.1.0" }
        }
    })
}

fn make_tools_list_request(id: i64) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/list"
    })
}

fn make_tool_call_request(
    id: i64,
    tool_name: &str,
    arguments: serde_json::Value,
) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    })
}

fn make_resource_read_request(id: i64, uri: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "resources/read",
        "params": {
            "uri": uri
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that the proxy forwards the initialize handshake and returns the
/// mock server's capabilities.
#[tokio::test]
#[ignore = "requires built binaries: cargo build --workspace"]
async fn test_initialize_handshake() {
    let mut h = helpers::TestHarness::new(ALLOW_ALL_POLICY).await;

    let resp = h.send(&make_initialize_request(1)).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert!(resp["result"].is_object(), "expected result object");
    assert!(
        resp["result"]["serverInfo"]["name"].as_str().is_some(),
        "expected serverInfo.name in response"
    );

    h.shutdown().await;
}

/// Verify that a resources/read targeting ~/.ssh/id_rsa is blocked by policy.
///
/// Note: policy resource_path matching works on `resources/read` URIs, not on
/// tools/call arguments. This is by design -- tools/call blocks are done via
/// tool_name patterns.
#[tokio::test]
#[ignore = "requires built binaries: cargo build --workspace"]
async fn test_block_ssh_key_access() {
    let mut h = helpers::TestHarness::new(BLOCK_SSH_POLICY).await;

    let _ = h.send(&make_initialize_request(1)).await;

    // resources/read targeting an SSH key
    let resp = h
        .send(&make_resource_read_request(2, "~/.ssh/id_rsa"))
        .await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 2);
    assert!(
        resp["error"].is_object(),
        "expected error response for blocked SSH access, got: {resp}"
    );
    assert_eq!(
        resp["error"]["code"], -32001,
        "expected policy block error code -32001"
    );

    h.shutdown().await;
}

/// Verify that a benign file read is allowed and forwarded to the mock server.
#[tokio::test]
#[ignore = "requires built binaries: cargo build --workspace"]
async fn test_allow_benign_file_read() {
    let mut h = helpers::TestHarness::new(ALLOW_PROJECT_POLICY).await;

    let _ = h.send(&make_initialize_request(1)).await;

    let resp = h
        .send(&make_tool_call_request(
            2,
            "read_file",
            json!({ "path": "~/Projects/myapp/src/main.rs" }),
        ))
        .await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 2);
    assert!(
        resp["result"].is_object(),
        "expected result for allowed file read, got: {:?}",
        resp["error"]
    );
    assert!(
        resp["result"]["content"].is_array(),
        "expected content array in result"
    );

    h.shutdown().await;
}

/// Verify that tools/list passes through and returns the mock server's tool list.
#[tokio::test]
#[ignore = "requires built binaries: cargo build --workspace"]
async fn test_log_listing_operations() {
    let mut h = helpers::TestHarness::new(ALLOW_ALL_POLICY).await;

    let _ = h.send(&make_initialize_request(1)).await;

    let resp = h.send(&make_tools_list_request(2)).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 2);
    assert!(resp["result"].is_object(), "expected result object");
    let tools = &resp["result"]["tools"];
    assert!(tools.is_array(), "expected tools array");
    let tools_arr = tools.as_array().unwrap();
    assert!(
        tools_arr.len() >= 3,
        "expected at least 3 mock tools, got {}",
        tools_arr.len()
    );

    let names: Vec<&str> = tools_arr
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"read_file"));
    assert!(names.contains(&"write_file"));
    assert!(names.contains(&"run_command"));

    h.shutdown().await;
}

/// Verify that notifications are forwarded to the mock server without breaking
/// subsequent request/response pairs.
#[tokio::test]
#[ignore = "requires built binaries: cargo build --workspace"]
async fn test_server_notifications_forwarded() {
    let mut h = helpers::TestHarness::new(ALLOW_ALL_POLICY).await;

    let _ = h.send(&make_initialize_request(1)).await;

    // Send a notification (no id) - proxy should forward it, no response expected
    let notification = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    h.send_no_response(&notification).await;

    // Verify proxy still works by sending a request
    let resp = h.send(&make_tools_list_request(2)).await;
    assert_eq!(resp["id"], 2);
    assert!(resp["result"].is_object());

    h.shutdown().await;
}

/// Verify that several known dangerous paths are all blocked.
#[tokio::test]
#[ignore = "requires built binaries: cargo build --workspace"]
async fn test_default_policy_blocks_dangerous_paths() {
    let mut h = helpers::TestHarness::new(BLOCK_DANGEROUS_PATHS_POLICY).await;

    let _ = h.send(&make_initialize_request(1)).await;

    let dangerous_paths = [
        ("~/.ssh/id_rsa", 10),
        ("~/.aws/credentials", 11),
        ("~/.gnupg/secring.gpg", 12),
        ("~/.bash_history", 13),
    ];

    for (path, id) in &dangerous_paths {
        let resp = h.send(&make_resource_read_request(*id, path)).await;

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], *id);
        assert!(
            resp["error"].is_object(),
            "expected error for blocked path {path}, got: {resp}"
        );
        assert_eq!(
            resp["error"]["code"], -32001,
            "expected policy block error code for path {path}"
        );
    }

    h.shutdown().await;
}

/// Verify that 50 rapid messages all receive correctly-ordered responses.
#[tokio::test]
#[ignore = "requires built binaries: cargo build --workspace"]
async fn test_message_ordering() {
    let mut h = helpers::TestHarness::new(ALLOW_ALL_POLICY).await;

    let _ = h.send(&make_initialize_request(0)).await;

    for i in 1..=50i64 {
        let resp = h.send(&make_tools_list_request(i)).await;
        assert_eq!(
            resp["id"], i,
            "response id mismatch: expected {i}, got {}",
            resp["id"]
        );
        assert!(resp["result"].is_object(), "expected result for request {i}");
    }

    h.shutdown().await;
}

/// Verify that the proxy exits cleanly when the client disconnects (stdin EOF).
#[tokio::test]
#[ignore = "requires built binaries: cargo build --workspace"]
async fn test_graceful_shutdown() {
    let h = helpers::TestHarness::new(ALLOW_ALL_POLICY).await;

    let status = h.shutdown().await;
    assert!(status.success(), "proxy should exit cleanly, got: {status}");
}

/// Verify that resources/read works when policy allows.
#[tokio::test]
#[ignore = "requires built binaries: cargo build --workspace"]
async fn test_resource_read_allowed() {
    let mut h = helpers::TestHarness::new(ALLOW_ALL_POLICY).await;

    let _ = h.send(&make_initialize_request(1)).await;

    let resp = h
        .send(&make_resource_read_request(2, "file:///tmp/test.txt"))
        .await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 2);
    assert!(
        resp["result"].is_object(),
        "expected result for allowed resource read"
    );
    assert!(resp["result"]["contents"].is_array());

    h.shutdown().await;
}

/// Verify that sampling/createMessage works through the proxy.
#[tokio::test]
#[ignore = "requires built binaries: cargo build --workspace"]
async fn test_sampling_request() {
    let mut h = helpers::TestHarness::new(ALLOW_ALL_POLICY).await;

    let _ = h.send(&make_initialize_request(1)).await;

    let req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "sampling/createMessage",
        "params": {
            "messages": [
                {
                    "role": "user",
                    "content": { "type": "text", "text": "Hello" }
                }
            ],
            "maxTokens": 100
        }
    });
    let resp = h.send(&req).await;

    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 2);
    assert!(
        resp["result"].is_object(),
        "expected result for sampling request"
    );

    h.shutdown().await;
}
