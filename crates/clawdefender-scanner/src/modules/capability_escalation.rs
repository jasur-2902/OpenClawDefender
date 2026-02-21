use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::client::ToolInfo;
use crate::finding::{Evidence, Finding, ModuleCategory, Reproduction, Severity};
use crate::modules::{ScanContext, ScanModule};

/// Payloads for shell injection testing.
struct ShellPayload {
    label: &'static str,
    template: &'static str,
}

#[derive(Default)]
pub struct CapabilityEscalationModule;

impl CapabilityEscalationModule {
    pub fn new() -> Self {
        Self
    }
}

fn shell_injection_payloads() -> Vec<ShellPayload> {
    vec![
        ShellPayload {
            label: "semicolon",
            template: "; cat /etc/passwd",
        },
        ShellPayload {
            label: "dollar-paren",
            template: "$(cat /etc/passwd)",
        },
        ShellPayload {
            label: "backtick",
            template: "`cat /etc/passwd`",
        },
        ShellPayload {
            label: "pipe",
            template: "| cat /etc/passwd",
        },
        ShellPayload {
            label: "and-chain",
            template: "&& cat /etc/passwd",
        },
        ShellPayload {
            label: "or-chain",
            template: "|| cat /etc/passwd",
        },
        ShellPayload {
            label: "newline",
            template: "\n cat /etc/passwd",
        },
        ShellPayload {
            label: "marker-subshell",
            template: "$(echo SHELL_INJECTION_MARKER)",
        },
    ]
}

fn generate_large_string(size: usize) -> String {
    "A".repeat(size)
}

fn generate_nested_json(depth: usize) -> Value {
    let mut val = json!("leaf");
    for _ in 0..depth {
        val = json!({ "a": val });
    }
    val
}

fn is_error_response(response: &Value) -> bool {
    if response.get("error").is_some() {
        return true;
    }
    if let Some(result) = response.get("result") {
        if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
            for item in content {
                if item.get("isError").and_then(|v| v.as_bool()) == Some(true) {
                    return true;
                }
            }
        }
        if result.get("isError").and_then(|v| v.as_bool()) == Some(true) {
            return true;
        }
    }
    false
}

fn contains_shell_output(response: &Value) -> bool {
    let text = response.to_string();
    let indicators = [
        "root:",
        "/bin/bash",
        "/bin/sh",
        "SHELL_INJECTION_MARKER",
        "nobody:",
        "daemon:",
        "/etc/passwd",
        "/usr/sbin/nologin",
    ];
    indicators.iter().any(|indicator| text.contains(indicator))
}

fn undeclared_tool_names() -> Vec<&'static str> {
    vec![
        "run_command",
        "execute",
        "shell",
        "eval",
        "system",
        "subprocess",
        "exec",
        "admin",
        "debug",
        "internal",
        "_hidden",
        "__private",
    ]
}

/// Extract string parameter names from a tool's input schema.
fn extract_string_params(tool: &ToolInfo) -> Vec<String> {
    let mut params = Vec::new();
    if let Some(properties) = tool
        .input_schema
        .get("properties")
        .and_then(|p| p.as_object())
    {
        for (name, schema) in properties {
            let type_val = schema.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if type_val == "string" {
                params.push(name.clone());
            }
        }
    }
    params
}

/// Extract all parameter names and their types from a tool's input schema.
fn extract_all_params(tool: &ToolInfo) -> Vec<(String, String)> {
    let mut params = Vec::new();
    if let Some(properties) = tool
        .input_schema
        .get("properties")
        .and_then(|p| p.as_object())
    {
        for (name, schema) in properties {
            let type_val = schema
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("string")
                .to_string();
            params.push((name.clone(), type_val));
        }
    }
    params
}

fn is_file_related_tool(tool: &ToolInfo) -> bool {
    let name_lower = tool.name.to_lowercase();
    let desc_lower = tool.description.to_lowercase();
    let keywords = [
        "file", "read", "write", "path", "directory", "dir", "folder", "fs", "open", "save",
        "list",
    ];
    keywords
        .iter()
        .any(|k| name_lower.contains(k) || desc_lower.contains(k))
}

fn is_read_tool(tool: &ToolInfo) -> bool {
    let name_lower = tool.name.to_lowercase();
    let desc_lower = tool.description.to_lowercase();
    (name_lower.contains("read") || name_lower.contains("get") || name_lower.contains("list"))
        && !name_lower.contains("write")
        && !desc_lower.contains("write")
}

#[async_trait]
impl ScanModule for CapabilityEscalationModule {
    fn name(&self) -> &str {
        "capability-escalation"
    }

    fn description(&self) -> &str {
        "Tests for capability escalation through MCP protocol abuse"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::CapabilityEscalation
    }

    async fn run(&self, ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        let mut findings: Vec<Finding> = Vec::new();
        let mut finding_counter: u32 = 0;

        let tools = ctx.tool_list.clone();
        let resources = ctx.resource_list.clone();

        // 1. Shell injection testing
        let payloads = shell_injection_payloads();
        for tool in &tools {
            let string_params = extract_string_params(tool);
            if string_params.is_empty() {
                continue;
            }

            for param in &string_params {
                for payload in &payloads {
                    let args = json!({ param: format!("test{}", payload.template) });
                    debug!(
                        tool = tool.name,
                        param = param,
                        payload = payload.label,
                        "Testing shell injection"
                    );

                    let result = ctx.client.call_tool_raw(&tool.name, args.clone()).await;

                    if !ctx.client.is_running() {
                        finding_counter += 1;
                        findings.push(Finding {
                            id: format!("CRIT-CAPESC-{finding_counter:03}"),
                            title: format!(
                                "Server crashed during shell injection test on tool '{}'",
                                tool.name
                            ),
                            severity: Severity::Critical,
                            cvss: 9.8,
                            category: ModuleCategory::CapabilityEscalation,
                            description: format!(
                                "The server process terminated when tool '{}' parameter '{}' \
                                 received shell injection payload '{}'. This indicates the \
                                 payload may have reached an underlying shell.",
                                tool.name, param, payload.label
                            ),
                            reproduction: Some(Reproduction {
                                method: "tools/call".to_string(),
                                tool: Some(tool.name.clone()),
                                arguments: Some(args),
                            }),
                            evidence: Evidence::empty(),
                            remediation: "Sanitize all tool inputs before passing to shell. \
                                          Use parameterized commands instead of string \
                                          concatenation."
                                .to_string(),
                        });
                        // Server is dead, stop testing this tool
                        break;
                    }

                    if let Ok(ref resp) = result {
                        if contains_shell_output(resp) {
                            finding_counter += 1;
                            warn!(
                                tool = tool.name,
                                param = param,
                                payload = payload.label,
                                "Shell injection detected!"
                            );
                            findings.push(Finding {
                                id: format!("CRIT-CAPESC-{finding_counter:03}"),
                                title: format!(
                                    "Shell command injection via tool '{}' parameter '{}'",
                                    tool.name, param
                                ),
                                severity: Severity::Critical,
                                cvss: 9.8,
                                category: ModuleCategory::CapabilityEscalation,
                                description: format!(
                                    "Shell injection payload '{}' in parameter '{}' of tool \
                                     '{}' produced shell output in the response. An attacker \
                                     could execute arbitrary commands on the server.",
                                    payload.label, param, tool.name
                                ),
                                reproduction: Some(Reproduction {
                                    method: "tools/call".to_string(),
                                    tool: Some(tool.name.clone()),
                                    arguments: Some(args),
                                }),
                                evidence: Evidence {
                                    messages: vec![ctx.client.history().len().saturating_sub(1)],
                                    stderr_output: None,
                                    ..Evidence::empty()
                                },
                                remediation: "Never pass user-controlled input directly to \
                                              shell commands. Use parameterized execution or \
                                              allowlists."
                                    .to_string(),
                            });
                        }
                    }
                }

                if !ctx.client.is_running() {
                    break;
                }
            }

            if !ctx.client.is_running() {
                break;
            }
        }

        // 2. Argument type abuse testing
        if ctx.client.is_running() {
            for tool in &tools {
                let all_params = extract_all_params(tool);
                if all_params.is_empty() {
                    continue;
                }

                // Large string test
                if let Some((param_name, _)) =
                    all_params.iter().find(|(_, t)| t == "string")
                {
                    let large = generate_large_string(100_000);
                    let args = json!({ param_name: large });
                    debug!(tool = tool.name, "Testing large string input");

                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        ctx.client.call_tool_raw(&tool.name, args.clone()),
                    )
                    .await;

                    if !ctx.client.is_running() {
                        finding_counter += 1;
                        findings.push(Finding {
                            id: format!("HIGH-CAPESC-{finding_counter:03}"),
                            title: format!(
                                "Server crashed on large string input to tool '{}'",
                                tool.name
                            ),
                            severity: Severity::High,
                            cvss: 7.5,
                            category: ModuleCategory::CapabilityEscalation,
                            description: format!(
                                "Sending a 100KB string to parameter '{}' of tool '{}' \
                                 caused the server to crash.",
                                param_name, tool.name
                            ),
                            reproduction: Some(Reproduction {
                                method: "tools/call".to_string(),
                                tool: Some(tool.name.clone()),
                                arguments: Some(json!({ param_name: "<100KB of 'A'>" })),
                            }),
                            evidence: Evidence::empty(),
                            remediation: "Implement input length validation on all tool \
                                          parameters."
                                .to_string(),
                        });
                        break;
                    } else if result.is_err() {
                        finding_counter += 1;
                        findings.push(Finding {
                            id: format!("MED-CAPESC-{finding_counter:03}"),
                            title: format!(
                                "Server hangs on large string input to tool '{}'",
                                tool.name
                            ),
                            severity: Severity::Medium,
                            cvss: 5.3,
                            category: ModuleCategory::CapabilityEscalation,
                            description: format!(
                                "Sending a 100KB string to parameter '{}' of tool '{}' \
                                 caused the server to hang (no response within 30s).",
                                param_name, tool.name
                            ),
                            reproduction: Some(Reproduction {
                                method: "tools/call".to_string(),
                                tool: Some(tool.name.clone()),
                                arguments: Some(json!({ param_name: "<100KB of 'A'>" })),
                            }),
                            evidence: Evidence::empty(),
                            remediation: "Implement input length validation and timeouts on \
                                          all tool parameters."
                                .to_string(),
                        });
                    }
                }

                if !ctx.client.is_running() {
                    break;
                }

                // Deeply nested JSON test
                {
                    let nested = generate_nested_json(100);
                    let first_param = &all_params[0].0;
                    let args = json!({ first_param: nested });
                    debug!(tool = tool.name, "Testing deeply nested JSON input");

                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        ctx.client.call_tool_raw(&tool.name, args.clone()),
                    )
                    .await;

                    if !ctx.client.is_running() {
                        finding_counter += 1;
                        findings.push(Finding {
                            id: format!("HIGH-CAPESC-{finding_counter:03}"),
                            title: format!(
                                "Server crashed on deeply nested JSON in tool '{}'",
                                tool.name
                            ),
                            severity: Severity::High,
                            cvss: 7.5,
                            category: ModuleCategory::CapabilityEscalation,
                            description: format!(
                                "Sending a 100-level nested JSON object to parameter '{}' \
                                 of tool '{}' caused the server to crash.",
                                first_param, tool.name
                            ),
                            reproduction: Some(Reproduction {
                                method: "tools/call".to_string(),
                                tool: Some(tool.name.clone()),
                                arguments: Some(
                                    json!({ first_param: "<100-level nested JSON>" }),
                                ),
                            }),
                            evidence: Evidence::empty(),
                            remediation: "Implement JSON depth limits when parsing tool \
                                          arguments."
                                .to_string(),
                        });
                        break;
                    } else if result.is_err() {
                        finding_counter += 1;
                        findings.push(Finding {
                            id: format!("MED-CAPESC-{finding_counter:03}"),
                            title: format!(
                                "Server hangs on deeply nested JSON in tool '{}'",
                                tool.name
                            ),
                            severity: Severity::Medium,
                            cvss: 5.3,
                            category: ModuleCategory::CapabilityEscalation,
                            description: format!(
                                "Sending a 100-level nested JSON to parameter '{}' of tool \
                                 '{}' caused a timeout.",
                                first_param, tool.name
                            ),
                            reproduction: Some(Reproduction {
                                method: "tools/call".to_string(),
                                tool: Some(tool.name.clone()),
                                arguments: Some(
                                    json!({ first_param: "<100-level nested JSON>" }),
                                ),
                            }),
                            evidence: Evidence::empty(),
                            remediation: "Implement JSON depth limits and request timeouts."
                                .to_string(),
                        });
                    }
                }

                if !ctx.client.is_running() {
                    break;
                }

                // Null / empty / special value tests for each parameter
                let abuse_values: Vec<(&str, Value)> = vec![
                    ("null", Value::Null),
                    ("empty-string", json!("")),
                    ("empty-array", json!([])),
                    ("empty-object", json!({})),
                    ("negative-number", json!(-1)),
                    ("nan-string", json!("NaN")),
                    ("infinity-string", json!("Infinity")),
                    ("neg-infinity-string", json!("-Infinity")),
                    ("null-byte", json!("test\x00value")),
                    ("control-chars", json!("test\x01\x02\x03\x1b[31mred\x1b[0m")),
                    ("path-glob", json!("*?{}[]")),
                ];

                for (param_name, _param_type) in &all_params {
                    for (abuse_label, abuse_val) in &abuse_values {
                        let args = json!({ param_name: abuse_val });

                        let result = tokio::time::timeout(
                            std::time::Duration::from_secs(15),
                            ctx.client.call_tool_raw(&tool.name, args.clone()),
                        )
                        .await;

                        if !ctx.client.is_running() {
                            finding_counter += 1;
                            findings.push(Finding {
                                id: format!("HIGH-CAPESC-{finding_counter:03}"),
                                title: format!(
                                    "Server crashed on {} input to tool '{}' param '{}'",
                                    abuse_label, tool.name, param_name
                                ),
                                severity: Severity::High,
                                cvss: 7.5,
                                category: ModuleCategory::CapabilityEscalation,
                                description: format!(
                                    "Sending {} value to parameter '{}' of tool '{}' \
                                     caused the server to crash.",
                                    abuse_label, param_name, tool.name
                                ),
                                reproduction: Some(Reproduction {
                                    method: "tools/call".to_string(),
                                    tool: Some(tool.name.clone()),
                                    arguments: Some(args),
                                }),
                                evidence: Evidence::empty(),
                                remediation: "Validate and sanitize all input types. Handle \
                                              unexpected types gracefully."
                                    .to_string(),
                            });
                            break;
                        } else if result.is_err() {
                            finding_counter += 1;
                            findings.push(Finding {
                                id: format!("MED-CAPESC-{finding_counter:03}"),
                                title: format!(
                                    "Server hangs on {} input to tool '{}' param '{}'",
                                    abuse_label, tool.name, param_name
                                ),
                                severity: Severity::Medium,
                                cvss: 5.3,
                                category: ModuleCategory::CapabilityEscalation,
                                description: format!(
                                    "Sending {} value to parameter '{}' of tool '{}' \
                                     caused a timeout.",
                                    abuse_label, param_name, tool.name
                                ),
                                reproduction: Some(Reproduction {
                                    method: "tools/call".to_string(),
                                    tool: Some(tool.name.clone()),
                                    arguments: Some(args),
                                }),
                                evidence: Evidence::empty(),
                                remediation: "Implement request timeouts and input validation."
                                    .to_string(),
                            });
                        }

                        if !ctx.client.is_running() {
                            break;
                        }
                    }

                    if !ctx.client.is_running() {
                        break;
                    }
                }

                if !ctx.client.is_running() {
                    break;
                }
            }
        }

        // 3. Capability boundary testing
        if ctx.client.is_running() {
            for tool in &tools {
                if is_file_related_tool(tool) && is_read_tool(tool) {
                    // Try write operations on a read-only tool
                    let write_attempts = vec![
                        json!({"path": "/tmp/clawdefender_boundary_test.txt", "content": "test"}),
                        json!({"file": "/tmp/clawdefender_boundary_test.txt", "data": "test"}),
                        json!({"filename": "/tmp/clawdefender_boundary_test.txt", "text": "test"}),
                    ];

                    for write_args in &write_attempts {
                        let result = ctx
                            .client
                            .call_tool_raw(&tool.name, write_args.clone())
                            .await;

                        if let Ok(ref resp) = result {
                            if !is_error_response(resp) {
                                finding_counter += 1;
                                findings.push(Finding {
                                    id: format!("HIGH-CAPESC-{finding_counter:03}"),
                                    title: format!(
                                        "Read-only tool '{}' accepted write operation",
                                        tool.name
                                    ),
                                    severity: Severity::High,
                                    cvss: 7.0,
                                    category: ModuleCategory::CapabilityEscalation,
                                    description: format!(
                                        "Tool '{}' appears to be read-only but accepted \
                                         a write operation with arguments: {}",
                                        tool.name, write_args
                                    ),
                                    reproduction: Some(Reproduction {
                                        method: "tools/call".to_string(),
                                        tool: Some(tool.name.clone()),
                                        arguments: Some(write_args.clone()),
                                    }),
                                    evidence: Evidence {
                                        messages: vec![
                                            ctx.client.history().len().saturating_sub(1),
                                        ],
                                        ..Evidence::empty()
                                    },
                                    remediation: "Enforce capability boundaries. Read-only \
                                                  tools should reject write operations."
                                        .to_string(),
                                });
                            }
                        }

                        if !ctx.client.is_running() {
                            break;
                        }
                    }

                    // Try accessing parent directories
                    let parent_paths = vec![
                        json!({"path": "../../../etc/passwd"}),
                        json!({"directory": ".."}),
                        json!({"path": "/"}),
                    ];

                    for parent_args in &parent_paths {
                        let result = ctx
                            .client
                            .call_tool_raw(&tool.name, parent_args.clone())
                            .await;

                        if let Ok(ref resp) = result {
                            if !is_error_response(resp) && contains_shell_output(resp) {
                                finding_counter += 1;
                                findings.push(Finding {
                                    id: format!("HIGH-CAPESC-{finding_counter:03}"),
                                    title: format!(
                                        "Tool '{}' allows directory traversal outside \
                                         boundaries",
                                        tool.name
                                    ),
                                    severity: Severity::High,
                                    cvss: 7.0,
                                    category: ModuleCategory::CapabilityEscalation,
                                    description: format!(
                                        "Tool '{}' returned data from outside its expected \
                                         directory boundary.",
                                        tool.name
                                    ),
                                    reproduction: Some(Reproduction {
                                        method: "tools/call".to_string(),
                                        tool: Some(tool.name.clone()),
                                        arguments: Some(parent_args.clone()),
                                    }),
                                    evidence: Evidence {
                                        messages: vec![
                                            ctx.client.history().len().saturating_sub(1),
                                        ],
                                        ..Evidence::empty()
                                    },
                                    remediation: "Implement path canonicalization and enforce \
                                                  directory boundaries."
                                        .to_string(),
                                });
                            }
                        }

                        if !ctx.client.is_running() {
                            break;
                        }
                    }
                }

                if !ctx.client.is_running() {
                    break;
                }
            }
        }

        // 4. Undeclared tool detection
        if ctx.client.is_running() {
            let declared_names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();

            for hidden_name in undeclared_tool_names() {
                if declared_names.contains(&hidden_name) {
                    continue;
                }

                debug!(tool = hidden_name, "Testing for undeclared tool");

                let result = ctx
                    .client
                    .call_tool_raw(hidden_name, json!({}))
                    .await;

                if let Ok(ref resp) = result {
                    if !is_error_response(resp) {
                        finding_counter += 1;
                        warn!(tool = hidden_name, "Undeclared tool is accessible!");
                        findings.push(Finding {
                            id: format!("HIGH-CAPESC-{finding_counter:03}"),
                            title: format!(
                                "Undeclared tool '{}' is accessible",
                                hidden_name
                            ),
                            severity: Severity::High,
                            cvss: 7.5,
                            category: ModuleCategory::CapabilityEscalation,
                            description: format!(
                                "Tool '{}' is not listed in tools/list but returned a \
                                 non-error response when called. Hidden tools may provide \
                                 elevated capabilities.",
                                hidden_name
                            ),
                            reproduction: Some(Reproduction {
                                method: "tools/call".to_string(),
                                tool: Some(hidden_name.to_string()),
                                arguments: Some(json!({})),
                            }),
                            evidence: Evidence {
                                messages: vec![
                                    ctx.client.history().len().saturating_sub(1),
                                ],
                                ..Evidence::empty()
                            },
                            remediation: "Remove or properly declare all accessible tools. \
                                          Undeclared tools should return method-not-found \
                                          errors."
                                .to_string(),
                        });
                    }
                }

                if !ctx.client.is_running() {
                    break;
                }
            }
        }

        // Test undeclared resource URIs
        if ctx.client.is_running() {
            let declared_uris: Vec<&str> = resources.iter().map(|r| r.uri.as_str()).collect();
            let hidden_uris = [
                "file:///etc/passwd",
                "file:///etc/shadow",
                "internal://config",
                "admin://settings",
                "debug://state",
            ];

            for uri in &hidden_uris {
                if declared_uris.contains(uri) {
                    continue;
                }

                let result = ctx
                    .client
                    .call_method("resources/read", json!({ "uri": uri }))
                    .await;

                if let Ok(ref resp) = result {
                    if !is_error_response(resp) {
                        finding_counter += 1;
                        findings.push(Finding {
                            id: format!("HIGH-CAPESC-{finding_counter:03}"),
                            title: format!(
                                "Undeclared resource URI '{}' is accessible",
                                uri
                            ),
                            severity: Severity::High,
                            cvss: 7.5,
                            category: ModuleCategory::CapabilityEscalation,
                            description: format!(
                                "Resource URI '{}' is not in resources/list but returned a \
                                 non-error response. Hidden resources may expose sensitive data.",
                                uri
                            ),
                            reproduction: Some(Reproduction {
                                method: "resources/read".to_string(),
                                tool: None,
                                arguments: Some(json!({ "uri": uri })),
                            }),
                            evidence: Evidence {
                                messages: vec![
                                    ctx.client.history().len().saturating_sub(1),
                                ],
                                ..Evidence::empty()
                            },
                            remediation: "Restrict resource access to declared URIs only."
                                .to_string(),
                        });
                    }
                }

                if !ctx.client.is_running() {
                    break;
                }
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_injection_payloads_comprehensive() {
        let payloads = shell_injection_payloads();
        assert!(payloads.len() >= 8, "Should have at least 8 injection payloads");

        let labels: Vec<&str> = payloads.iter().map(|p| p.label).collect();
        assert!(labels.contains(&"semicolon"));
        assert!(labels.contains(&"dollar-paren"));
        assert!(labels.contains(&"backtick"));
        assert!(labels.contains(&"pipe"));
        assert!(labels.contains(&"and-chain"));
        assert!(labels.contains(&"or-chain"));
        assert!(labels.contains(&"newline"));
        assert!(labels.contains(&"marker-subshell"));

        // Verify all payloads contain something dangerous
        for payload in &payloads {
            let t = payload.template;
            assert!(
                t.contains("cat") || t.contains("echo"),
                "Payload '{}' should contain a command",
                payload.label
            );
        }
    }

    #[test]
    fn test_generate_large_string_correct_size() {
        assert_eq!(generate_large_string(0).len(), 0);
        assert_eq!(generate_large_string(1).len(), 1);
        assert_eq!(generate_large_string(100_000).len(), 100_000);
        assert!(generate_large_string(50).chars().all(|c| c == 'A'));
    }

    #[test]
    fn test_generate_nested_json_correct_depth() {
        let val = generate_nested_json(0);
        assert_eq!(val, json!("leaf"));

        let val = generate_nested_json(1);
        assert_eq!(val, json!({"a": "leaf"}));

        let val = generate_nested_json(3);
        assert_eq!(val, json!({"a": {"a": {"a": "leaf"}}}));

        // Verify deep nesting doesn't panic
        let deep = generate_nested_json(100);
        let mut current = &deep;
        for _ in 0..100 {
            current = current.get("a").expect("Should have key 'a' at each level");
        }
        assert_eq!(current, &json!("leaf"));
    }

    #[test]
    fn test_is_error_response_identifies_errors() {
        // JSON-RPC error
        assert!(is_error_response(&json!({
            "error": { "code": -32601, "message": "Method not found" }
        })));

        // Content-level error
        assert!(is_error_response(&json!({
            "result": {
                "content": [{ "type": "text", "text": "Error", "isError": true }]
            }
        })));

        // Result-level isError
        assert!(is_error_response(&json!({
            "result": { "isError": true, "content": [] }
        })));

        // Not an error
        assert!(!is_error_response(&json!({
            "result": {
                "content": [{ "type": "text", "text": "Hello" }]
            }
        })));

        assert!(!is_error_response(&json!({
            "result": { "data": "ok" }
        })));
    }

    #[test]
    fn test_contains_shell_output_detects_injected_output() {
        // Contains /etc/passwd content
        assert!(contains_shell_output(&json!({
            "result": { "content": [{ "text": "root:x:0:0:root:/root:/bin/bash" }] }
        })));

        // Contains our marker
        assert!(contains_shell_output(&json!({
            "result": { "content": [{ "text": "SHELL_INJECTION_MARKER" }] }
        })));

        // Contains nologin indicator
        assert!(contains_shell_output(&json!({
            "result": { "content": [{ "text": "daemon:x:1:1::/usr/sbin/nologin" }] }
        })));

        // Clean response
        assert!(!contains_shell_output(&json!({
            "result": { "content": [{ "text": "File successfully read" }] }
        })));

        // Empty response
        assert!(!contains_shell_output(&json!({
            "result": {}
        })));
    }

    #[test]
    fn test_undeclared_tool_names_list() {
        let names = undeclared_tool_names();
        assert!(names.len() >= 12, "Should have at least 12 hidden tool names");
        assert!(names.contains(&"run_command"));
        assert!(names.contains(&"execute"));
        assert!(names.contains(&"shell"));
        assert!(names.contains(&"eval"));
        assert!(names.contains(&"system"));
        assert!(names.contains(&"exec"));
        assert!(names.contains(&"admin"));
        assert!(names.contains(&"debug"));
        assert!(names.contains(&"__private"));
    }

    #[test]
    fn test_severity_scoring_shell_injection() {
        // Shell injection should be Critical with CVSS 9.8
        let finding = Finding {
            id: "CRIT-CAPESC-001".to_string(),
            title: "Shell command injection".to_string(),
            severity: Severity::Critical,
            cvss: 9.8,
            category: ModuleCategory::CapabilityEscalation,
            description: "test".to_string(),
            reproduction: None,
            evidence: Evidence::empty(),
            remediation: "test".to_string(),
        };
        assert_eq!(finding.severity, Severity::Critical);
        assert!((finding.cvss - 9.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_severity_scoring_crash() {
        let finding = Finding {
            id: "HIGH-CAPESC-001".to_string(),
            title: "Server crash".to_string(),
            severity: Severity::High,
            cvss: 7.5,
            category: ModuleCategory::CapabilityEscalation,
            description: "test".to_string(),
            reproduction: None,
            evidence: Evidence::empty(),
            remediation: "test".to_string(),
        };
        assert_eq!(finding.severity, Severity::High);
        assert!((finding.cvss - 7.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_severity_scoring_hang() {
        let finding = Finding {
            id: "MED-CAPESC-001".to_string(),
            title: "Server hang".to_string(),
            severity: Severity::Medium,
            cvss: 5.3,
            category: ModuleCategory::CapabilityEscalation,
            description: "test".to_string(),
            reproduction: None,
            evidence: Evidence::empty(),
            remediation: "test".to_string(),
        };
        assert_eq!(finding.severity, Severity::Medium);
        assert!((finding.cvss - 5.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_argument_abuse_payloads() {
        let large = generate_large_string(100_000);
        assert_eq!(large.len(), 100_000);

        let nested = generate_nested_json(100);
        assert!(nested.is_object());

        // Verify null bytes in string
        let null_byte_str = "test\x00value";
        assert!(null_byte_str.contains('\x00'));
    }

    #[test]
    fn test_module_metadata() {
        let module = CapabilityEscalationModule::new();
        assert_eq!(module.name(), "capability-escalation");
        assert_eq!(
            module.description(),
            "Tests for capability escalation through MCP protocol abuse"
        );
        assert_eq!(module.category(), ModuleCategory::CapabilityEscalation);
    }

    #[test]
    fn test_finding_creation_with_evidence() {
        let finding = Finding {
            id: "CRIT-CAPESC-001".to_string(),
            title: "Shell injection in tool 'exec'".to_string(),
            severity: Severity::Critical,
            cvss: 9.8,
            category: ModuleCategory::CapabilityEscalation,
            description: "Shell injection found".to_string(),
            reproduction: Some(Reproduction {
                method: "tools/call".to_string(),
                tool: Some("exec".to_string()),
                arguments: Some(json!({"cmd": "; cat /etc/passwd"})),
            }),
            evidence: Evidence {
                messages: vec![0, 1],
                audit_record: Some("audit-123".to_string()),
                canary_detected: false,
                os_events: vec!["process_exec: cat".to_string()],
                files_modified: vec![],
                network_connections: vec![],
                stderr_output: Some("error output".to_string()),
            },
            remediation: "Sanitize inputs".to_string(),
        };

        assert_eq!(finding.id, "CRIT-CAPESC-001");
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.reproduction.is_some());
        let repro = finding.reproduction.unwrap();
        assert_eq!(repro.tool, Some("exec".to_string()));
        assert_eq!(finding.evidence.messages.len(), 2);
        assert_eq!(finding.evidence.os_events.len(), 1);
        assert!(finding.evidence.stderr_output.is_some());
    }

    #[test]
    fn test_extract_string_params() {
        let tool = ToolInfo {
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "count": { "type": "number" },
                    "name": { "type": "string" }
                }
            }),
        };
        let params = extract_string_params(&tool);
        assert_eq!(params.len(), 2);
        assert!(params.contains(&"path".to_string()));
        assert!(params.contains(&"name".to_string()));
    }

    #[test]
    fn test_is_file_related_tool() {
        let file_tool = ToolInfo {
            name: "read_file".to_string(),
            description: "Reads a file".to_string(),
            input_schema: json!({}),
        };
        assert!(is_file_related_tool(&file_tool));

        let non_file_tool = ToolInfo {
            name: "calculate".to_string(),
            description: "Performs math".to_string(),
            input_schema: json!({}),
        };
        assert!(!is_file_related_tool(&non_file_tool));
    }

    #[test]
    fn test_is_read_tool() {
        let read_tool = ToolInfo {
            name: "read_file".to_string(),
            description: "Reads contents".to_string(),
            input_schema: json!({}),
        };
        assert!(is_read_tool(&read_tool));

        let write_tool = ToolInfo {
            name: "write_file".to_string(),
            description: "Writes data".to_string(),
            input_schema: json!({}),
        };
        assert!(!is_read_tool(&write_tool));
    }
}
