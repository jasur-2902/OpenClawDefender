//! Classification rules for MCP tool calls.

use crate::jsonrpc::types::JsonRpcMessage;

/// How the proxy should handle a particular message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// Allow the message through without logging.
    Pass,
    /// Allow the message but record it in the audit log.
    Log,
    /// Hold the message for human / policy-engine review before forwarding.
    Review,
    /// Block the message outright.
    Block,
}

/// Classify an intercepted JSON-RPC message.
pub fn classify(msg: &JsonRpcMessage) -> Classification {
    let method = match msg {
        JsonRpcMessage::Request(r) => r.method.as_str(),
        JsonRpcMessage::Notification(n) => n.method.as_str(),
        JsonRpcMessage::Response(_) => return Classification::Pass,
    };

    match method {
        // Handshake / keepalive — always pass.
        "initialize" | "initialized" | "ping" => Classification::Pass,

        // Notifications — pass.
        m if m.starts_with("notifications/") => Classification::Pass,

        // Discovery — log only.
        "tools/list" | "resources/list" | "prompts/list" => Classification::Log,

        // Sensitive operations — require review.
        "tools/call" => Classification::Review,
        "resources/read" => Classification::Review,
        "sampling/createMessage" => Classification::Review,

        // Anything else — log for visibility.
        _ => Classification::Log,
    }
}

/// Extract (tool_name, arguments) from a `tools/call` request.
pub fn extract_tool_call(msg: &JsonRpcMessage) -> Option<(String, serde_json::Value)> {
    if let JsonRpcMessage::Request(r) = msg {
        if r.method != "tools/call" {
            return None;
        }
        let params = r.params.as_ref()?;
        let name = params.get("name")?.as_str()?.to_owned();
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        Some((name, arguments))
    } else {
        None
    }
}

/// Extract the resource URI from a `resources/read` request.
pub fn extract_resource_uri(msg: &JsonRpcMessage) -> Option<String> {
    if let JsonRpcMessage::Request(r) = msg {
        if r.method != "resources/read" {
            return None;
        }
        let params = r.params.as_ref()?;
        let uri = params.get("uri")?.as_str()?.to_owned();
        Some(uri)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonrpc::types::*;

    fn make_request(method: &str, params: Option<serde_json::Value>) -> JsonRpcMessage {
        JsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: JsonRpcId::Number(1),
            method: method.into(),
            params,
        })
    }

    fn make_notification(method: &str) -> JsonRpcMessage {
        JsonRpcMessage::Notification(JsonRpcNotification {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params: None,
        })
    }

    fn make_response() -> JsonRpcMessage {
        JsonRpcMessage::Response(JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: JsonRpcId::Number(1),
            result: Some(serde_json::json!({})),
            error: None,
        })
    }

    // -----------------------------------------------------------------------
    // classify
    // -----------------------------------------------------------------------

    #[test]
    fn classify_initialize() {
        assert_eq!(
            classify(&make_request("initialize", None)),
            Classification::Pass
        );
    }

    #[test]
    fn classify_initialized() {
        assert_eq!(
            classify(&make_notification("initialized")),
            Classification::Pass
        );
    }

    #[test]
    fn classify_ping() {
        assert_eq!(classify(&make_request("ping", None)), Classification::Pass);
    }

    #[test]
    fn classify_notification() {
        assert_eq!(
            classify(&make_notification("notifications/tools/list_changed")),
            Classification::Pass
        );
    }

    #[test]
    fn classify_tools_list() {
        assert_eq!(
            classify(&make_request("tools/list", None)),
            Classification::Log
        );
    }

    #[test]
    fn classify_resources_list() {
        assert_eq!(
            classify(&make_request("resources/list", None)),
            Classification::Log
        );
    }

    #[test]
    fn classify_prompts_list() {
        assert_eq!(
            classify(&make_request("prompts/list", None)),
            Classification::Log
        );
    }

    #[test]
    fn classify_tools_call() {
        assert_eq!(
            classify(&make_request("tools/call", None)),
            Classification::Review
        );
    }

    #[test]
    fn classify_resources_read() {
        assert_eq!(
            classify(&make_request("resources/read", None)),
            Classification::Review
        );
    }

    #[test]
    fn classify_sampling() {
        assert_eq!(
            classify(&make_request("sampling/createMessage", None)),
            Classification::Review
        );
    }

    #[test]
    fn classify_unknown_method() {
        assert_eq!(
            classify(&make_request("some/unknown", None)),
            Classification::Log
        );
    }

    #[test]
    fn classify_response_passes() {
        assert_eq!(classify(&make_response()), Classification::Pass);
    }

    // -----------------------------------------------------------------------
    // extract_tool_call
    // -----------------------------------------------------------------------

    #[test]
    fn extract_tool_call_valid() {
        let msg = make_request(
            "tools/call",
            Some(serde_json::json!({"name": "read_file", "arguments": {"path": "/etc/passwd"}})),
        );
        let (name, args) = extract_tool_call(&msg).unwrap();
        assert_eq!(name, "read_file");
        assert_eq!(args["path"], "/etc/passwd");
    }

    #[test]
    fn extract_tool_call_no_arguments() {
        let msg = make_request(
            "tools/call",
            Some(serde_json::json!({"name": "list_tools"})),
        );
        let (name, args) = extract_tool_call(&msg).unwrap();
        assert_eq!(name, "list_tools");
        assert!(args.is_object());
    }

    #[test]
    fn extract_tool_call_wrong_method() {
        let msg = make_request("tools/list", None);
        assert!(extract_tool_call(&msg).is_none());
    }

    #[test]
    fn extract_tool_call_no_params() {
        let msg = make_request("tools/call", None);
        assert!(extract_tool_call(&msg).is_none());
    }

    #[test]
    fn extract_tool_call_from_notification() {
        let msg = make_notification("tools/call");
        assert!(extract_tool_call(&msg).is_none());
    }

    // -----------------------------------------------------------------------
    // extract_resource_uri
    // -----------------------------------------------------------------------

    #[test]
    fn extract_resource_uri_valid() {
        let msg = make_request(
            "resources/read",
            Some(serde_json::json!({"uri": "file:///tmp/secret.txt"})),
        );
        assert_eq!(
            extract_resource_uri(&msg).unwrap(),
            "file:///tmp/secret.txt"
        );
    }

    #[test]
    fn extract_resource_uri_wrong_method() {
        let msg = make_request(
            "resources/list",
            Some(serde_json::json!({"uri": "file:///x"})),
        );
        assert!(extract_resource_uri(&msg).is_none());
    }

    #[test]
    fn extract_resource_uri_no_params() {
        let msg = make_request("resources/read", None);
        assert!(extract_resource_uri(&msg).is_none());
    }

    // -----------------------------------------------------------------------
    // Regression: vendor/custom methods pass through as Log
    // -----------------------------------------------------------------------

    #[test]
    fn classify_vendor_method_logs() {
        assert_eq!(
            classify(&make_request("vendor.acme/custom_action", None)),
            Classification::Log,
            "unknown vendor methods should be logged, not blocked"
        );
    }

    #[test]
    fn classify_unicode_method_logs() {
        assert_eq!(
            classify(&make_request("日本語/メソッド", None)),
            Classification::Log,
            "Unicode method names should be logged"
        );
    }

    #[test]
    fn classify_method_with_dots_and_slashes() {
        assert_eq!(
            classify(&make_request("x.y.z/a.b.c", None)),
            Classification::Log,
            "methods with dots and slashes should be logged"
        );
    }

    #[test]
    fn classify_empty_method_logs() {
        assert_eq!(
            classify(&make_request("", None)),
            Classification::Log,
            "empty method string should be logged"
        );
    }
}
