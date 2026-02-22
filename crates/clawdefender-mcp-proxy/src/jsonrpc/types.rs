//! JSON-RPC 2.0 type definitions.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Error code returned when a policy blocks a request.
pub const POLICY_BLOCK_ERROR_CODE: i32 = -32001;

/// A JSON-RPC 2.0 request/response/notification identifier.
///
/// Per the JSON-RPC 2.0 spec, the `id` field can be a string, a number,
/// or `null`. Null IDs are used in error responses when the request ID
/// could not be determined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    Number(i64),
    String(String),
    Null,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 notification (no `id` field).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A parsed JSON-RPC 2.0 message: request, response, or notification.
#[derive(Debug, Clone)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Response(JsonRpcResponse),
    Notification(JsonRpcNotification),
}

// ---------------------------------------------------------------------------
// Custom Serialize / Deserialize for JsonRpcMessage
//
// Discrimination logic:
//   - has "id" + "method" → Request
//   - has "id" without "method" → Response
//   - has "method" without "id" → Notification
// ---------------------------------------------------------------------------

impl Serialize for JsonRpcMessage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            JsonRpcMessage::Request(r) => r.serialize(serializer),
            JsonRpcMessage::Response(r) => r.serialize(serializer),
            JsonRpcMessage::Notification(n) => n.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for JsonRpcMessage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(deserializer)?;
        let obj = v
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("JSON-RPC message must be an object"))?;

        let has_id = obj.contains_key("id");
        let has_method = obj.contains_key("method");

        if has_id && has_method {
            let req: JsonRpcRequest =
                serde_json::from_value(v).map_err(serde::de::Error::custom)?;
            Ok(JsonRpcMessage::Request(req))
        } else if has_id {
            let resp: JsonRpcResponse =
                serde_json::from_value(v).map_err(serde::de::Error::custom)?;
            Ok(JsonRpcMessage::Response(resp))
        } else if has_method {
            let notif: JsonRpcNotification =
                serde_json::from_value(v).map_err(serde::de::Error::custom)?;
            Ok(JsonRpcMessage::Notification(notif))
        } else {
            Err(serde::de::Error::custom(
                "JSON-RPC message must have 'id' and/or 'method'",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_request_numeric_id() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match msg {
            JsonRpcMessage::Request(r) => {
                assert_eq!(r.id, JsonRpcId::Number(1));
                assert_eq!(r.method, "tools/call");
                assert!(r.params.is_some());
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn deserialize_request_string_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc","method":"initialize"}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match msg {
            JsonRpcMessage::Request(r) => {
                assert_eq!(r.id, JsonRpcId::String("abc".into()));
                assert_eq!(r.method, "initialize");
                assert!(r.params.is_none());
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn deserialize_response_with_result() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match msg {
            JsonRpcMessage::Response(r) => {
                assert_eq!(r.id, JsonRpcId::Number(1));
                assert!(r.result.is_some());
                assert!(r.error.is_none());
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn deserialize_response_with_error() {
        let json = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"blocked"}}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match msg {
            JsonRpcMessage::Response(r) => {
                assert!(r.error.is_some());
                let e = r.error.unwrap();
                assert_eq!(e.code, POLICY_BLOCK_ERROR_CODE);
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn deserialize_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match msg {
            JsonRpcMessage::Notification(n) => {
                assert_eq!(n.method, "notifications/tools/list_changed");
            }
            _ => panic!("expected Notification"),
        }
    }

    #[test]
    fn roundtrip_request() {
        let original = JsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: JsonRpcId::Number(42),
            method: "tools/call".into(),
            params: Some(serde_json::json!({"name": "exec", "arguments": {"cmd": "ls"}})),
        });
        let bytes = serde_json::to_vec(&original).unwrap();
        let parsed: JsonRpcMessage = serde_json::from_slice(&bytes).unwrap();
        match parsed {
            JsonRpcMessage::Request(r) => {
                assert_eq!(r.id, JsonRpcId::Number(42));
                assert_eq!(r.method, "tools/call");
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn reject_non_object() {
        let result: Result<JsonRpcMessage, _> = serde_json::from_str("42");
        assert!(result.is_err());
    }

    #[test]
    fn reject_missing_id_and_method() {
        let result: Result<JsonRpcMessage, _> = serde_json::from_str(r#"{"jsonrpc":"2.0"}"#);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Regression: null ID support (JSON-RPC 2.0 spec)
    // -----------------------------------------------------------------------

    #[test]
    fn deserialize_response_with_null_id() {
        let json = r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match msg {
            JsonRpcMessage::Response(r) => {
                assert_eq!(r.id, JsonRpcId::Null);
                assert!(r.error.is_some());
            }
            _ => panic!("expected Response with null id"),
        }
    }

    #[test]
    fn serialize_null_id_roundtrip() {
        let original = JsonRpcMessage::Response(JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: JsonRpcId::Null,
            result: None,
            error: Some(JsonRpcError {
                code: -32700,
                message: "Parse error".into(),
                data: None,
            }),
        });
        let json = serde_json::to_string(&original).unwrap();
        assert!(
            json.contains("\"id\":null"),
            "null id should serialize as null"
        );
        let parsed: JsonRpcMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            JsonRpcMessage::Response(r) => {
                assert_eq!(r.id, JsonRpcId::Null);
            }
            _ => panic!("expected Response"),
        }
    }

    // -----------------------------------------------------------------------
    // Regression: Unicode in method names
    // -----------------------------------------------------------------------

    #[test]
    fn classify_unicode_method_name() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"日本語/ツール","params":{}}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match msg {
            JsonRpcMessage::Request(r) => {
                assert_eq!(r.method, "日本語/ツール");
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn classify_dotted_method_name() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"vendor.custom/method.v2"}"#;
        let msg: JsonRpcMessage = serde_json::from_str(json).unwrap();
        match msg {
            JsonRpcMessage::Request(r) => {
                assert_eq!(r.method, "vendor.custom/method.v2");
            }
            _ => panic!("expected Request"),
        }
    }
}
