use std::collections::HashMap;
use std::os::unix::fs as unix_fs;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::client::ToolInfo;
use crate::finding::{Evidence, Finding, ModuleCategory, Reproduction, Severity};
use crate::modules::{ScanContext, ScanModule};

/// Sensitive target files used in traversal attempts.
const SENSITIVE_TARGETS: &[(&str, Severity, f64)] = &[
    (".ssh/id_rsa", Severity::Critical, 9.1),
    (".aws/credentials", Severity::Critical, 9.1),
    (".gnupg/secring.gpg", Severity::Critical, 9.1),
    (".env", Severity::Critical, 9.1),
    (".bash_history", Severity::High, 7.0),
];

/// Keywords that indicate a tool handles files.
const FILE_TOOL_KEYWORDS: &[&str] = &[
    "file", "read", "write", "edit", "search", "list",
];

/// Parameter names that indicate a path-like argument.
const PATH_PARAM_NAMES: &[&str] = &[
    "path", "file", "directory", "filename", "filepath", "dir",
];

pub struct PathTraversalModule;

impl PathTraversalModule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ScanModule for PathTraversalModule {
    fn name(&self) -> &str {
        "path-traversal"
    }

    fn description(&self) -> &str {
        "Tests for path traversal vulnerabilities in file-related tools"
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::PathTraversal
    }

    async fn run(&self, ctx: &mut ScanContext) -> Result<Vec<Finding>> {
        let mut findings: Vec<Finding> = Vec::new();
        let mut id_counters: HashMap<String, u32> = HashMap::new();

        let canaries = ctx.sandbox.canary_strings();
        let home_dir = ctx.sandbox.home();
        let project_dir = home_dir.join("Projects").join("test-project");

        // Identify file-related tools
        let file_tool_names: Vec<(String, Option<String>)> = {
            let tools = &ctx.tool_list;
            let file_tools = detect_file_tools(tools);
            file_tools
                .into_iter()
                .map(|t| (t.name.clone(), find_path_param(&t.input_schema)))
                .collect()
        };

        if file_tool_names.is_empty() {
            debug!("No file-related tools found; skipping path traversal tests");
            return Ok(findings);
        }

        for (tool_name, path_param) in &file_tool_names {
            let param_name = match path_param {
                Some(p) => p.clone(),
                None => "path".to_string(),
            };

            // (a) Basic traversal: ../ sequences depth 1-10
            for (target, severity, cvss) in SENSITIVE_TARGETS {
                let paths = build_traversal_paths(10, target);
                for tpath in &paths {
                    let args = json!({ &param_name: tpath });
                    let history_idx = ctx.client.history().len();

                    match ctx.client.call_tool_raw(tool_name, args.clone()).await {
                        Ok(response) => {
                            let resp_str = serde_json::to_string(&response).unwrap_or_default();
                            let detected = check_response_for_data(&response, &canaries);
                            if !detected.is_empty() {
                                let fid = next_finding_id(&mut id_counters, severity);
                                warn!("Path traversal success: {} via {}", tpath, tool_name);
                                findings.push(Finding {
                                    id: fid,
                                    title: format!(
                                        "Path traversal allows reading {} via {}",
                                        target, tool_name
                                    ),
                                    severity: *severity,
                                    cvss: *cvss,
                                    category: ModuleCategory::PathTraversal,
                                    description: format!(
                                        "The tool '{}' allowed reading sensitive file '{}' \
                                         using traversal path '{}'. Canary strings detected: {:?}",
                                        tool_name, target, tpath, detected
                                    ),
                                    reproduction: Some(Reproduction {
                                        method: format!("tools/call {}", tool_name),
                                        tool: Some(tool_name.clone()),
                                        arguments: Some(args),
                                    }),
                                    evidence: Evidence {
                                        messages: vec![history_idx],
                                        audit_record: None,
                                        canary_detected: true,
                                        os_events: Vec::new(),
                                        files_modified: Vec::new(),
                                        network_connections: Vec::new(),
                                        stderr_output: None,
                                    },
                                    remediation: format!(
                                        "Sanitize path inputs in '{}'. Reject paths containing \
                                         '..' sequences. Use path canonicalization and verify \
                                         the resolved path stays within the allowed directory.",
                                        tool_name
                                    ),
                                });
                                // One finding per target per tool is enough for basic traversal
                                break;
                            }
                            let _ = resp_str;
                        }
                        Err(e) => {
                            debug!("Tool call error for {} with {}: {}", tool_name, tpath, e);
                        }
                    }
                }
            }

            // (b) Encoded traversal
            let encoded_variants = build_encoded_paths();
            for (target, severity, cvss) in SENSITIVE_TARGETS {
                for prefix in &encoded_variants {
                    let tpath = format!("{}{}", prefix, target);
                    let args = json!({ &param_name: &tpath });
                    let history_idx = ctx.client.history().len();

                    match ctx.client.call_tool_raw(tool_name, args.clone()).await {
                        Ok(response) => {
                            let detected = check_response_for_data(&response, &canaries);
                            if !detected.is_empty() {
                                let fid = next_finding_id(&mut id_counters, severity);
                                findings.push(Finding {
                                    id: fid,
                                    title: format!(
                                        "Encoded path traversal bypasses filter via {}",
                                        tool_name
                                    ),
                                    severity: *severity,
                                    cvss: *cvss,
                                    category: ModuleCategory::PathTraversal,
                                    description: format!(
                                        "The tool '{}' allowed reading '{}' using encoded \
                                         traversal '{}'. Canary strings: {:?}",
                                        tool_name, target, tpath, detected
                                    ),
                                    reproduction: Some(Reproduction {
                                        method: format!("tools/call {}", tool_name),
                                        tool: Some(tool_name.clone()),
                                        arguments: Some(args),
                                    }),
                                    evidence: Evidence {
                                        messages: vec![history_idx],
                                        audit_record: None,
                                        canary_detected: true,
                                        os_events: Vec::new(),
                                        files_modified: Vec::new(),
                                        network_connections: Vec::new(),
                                        stderr_output: None,
                                    },
                                    remediation: format!(
                                        "Decode all URL-encoded sequences before path validation \
                                         in '{}'. Apply canonicalization after decoding.",
                                        tool_name
                                    ),
                                });
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("Encoded traversal error: {}", e);
                        }
                    }
                }
            }

            // (c) Null byte injection
            let null_paths = vec![
                format!("readme.txt\x00.png"),
                format!("readme.txt%00.png"),
                format!("../.ssh/id_rsa\x00.txt"),
                format!("../.ssh/id_rsa%00.txt"),
            ];
            for tpath in &null_paths {
                let args = json!({ &param_name: tpath });
                let history_idx = ctx.client.history().len();

                match ctx.client.call_tool_raw(tool_name, args.clone()).await {
                    Ok(response) => {
                        let detected = check_response_for_data(&response, &canaries);
                        if !detected.is_empty() {
                            let fid = next_finding_id(&mut id_counters, &Severity::Medium);
                            findings.push(Finding {
                                id: fid,
                                title: format!(
                                    "Null byte injection bypasses extension check via {}",
                                    tool_name
                                ),
                                severity: Severity::Medium,
                                cvss: 6.0,
                                category: ModuleCategory::PathTraversal,
                                description: format!(
                                    "The tool '{}' is vulnerable to null byte injection. \
                                     Path '{}' returned sensitive data. Canaries: {:?}",
                                    tool_name, tpath, detected
                                ),
                                reproduction: Some(Reproduction {
                                    method: format!("tools/call {}", tool_name),
                                    tool: Some(tool_name.clone()),
                                    arguments: Some(args),
                                }),
                                evidence: Evidence {
                                    messages: vec![history_idx],
                                    audit_record: None,
                                    canary_detected: true,
                                    os_events: Vec::new(),
                                    files_modified: Vec::new(),
                                    network_connections: Vec::new(),
                                    stderr_output: None,
                                },
                                remediation: format!(
                                    "Reject paths containing null bytes in '{}'. \
                                     Validate the full path string before any file operation.",
                                    tool_name
                                ),
                            });
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Null byte injection error: {}", e);
                    }
                }
            }

            // (d) Absolute path escape
            let ssh_key_abs = home_dir.join(".ssh").join("id_rsa");
            let absolute_paths: Vec<(String, Severity, f64)> = vec![
                ("/etc/passwd".to_string(), Severity::High, 7.0),
                ("/etc/hosts".to_string(), Severity::High, 7.0),
                (
                    ssh_key_abs.display().to_string(),
                    Severity::Critical,
                    9.1,
                ),
            ];
            for (tpath, severity, cvss) in &absolute_paths {
                let args = json!({ &param_name: tpath });
                let history_idx = ctx.client.history().len();

                match ctx.client.call_tool_raw(tool_name, args.clone()).await {
                    Ok(response) => {
                        let detected = check_response_for_data(&response, &canaries);
                        // For /etc/passwd and /etc/hosts, check for actual content patterns
                        let resp_str = serde_json::to_string(&response).unwrap_or_default();
                        let has_system_content = resp_str.contains("root:")
                            || resp_str.contains("localhost")
                            || !detected.is_empty();

                        if has_system_content {
                            let fid = next_finding_id(&mut id_counters, severity);
                            findings.push(Finding {
                                id: fid,
                                title: format!(
                                    "Absolute path access to {} via {}",
                                    tpath, tool_name
                                ),
                                severity: *severity,
                                cvss: *cvss,
                                category: ModuleCategory::PathTraversal,
                                description: format!(
                                    "The tool '{}' allowed reading '{}' using an absolute path. \
                                     No directory restriction is enforced.",
                                    tool_name, tpath
                                ),
                                reproduction: Some(Reproduction {
                                    method: format!("tools/call {}", tool_name),
                                    tool: Some(tool_name.clone()),
                                    arguments: Some(args),
                                }),
                                evidence: Evidence {
                                    messages: vec![history_idx],
                                    audit_record: None,
                                    canary_detected: !detected.is_empty(),
                                    os_events: Vec::new(),
                                    files_modified: Vec::new(),
                                    network_connections: Vec::new(),
                                    stderr_output: None,
                                },
                                remediation: format!(
                                    "Reject absolute paths in '{}'. All file operations should be \
                                     relative to the project root. Validate that resolved paths \
                                     begin with the allowed base directory.",
                                    tool_name
                                ),
                            });
                        }
                    }
                    Err(e) => {
                        debug!("Absolute path error: {}", e);
                    }
                }
            }

            // (e) Symlink following
            let symlink_name = "test_symlink_probe";
            let symlink_path = project_dir.join(symlink_name);
            let target_path = home_dir.join(".ssh").join("id_rsa");
            if let Err(e) = unix_fs::symlink(&target_path, &symlink_path) {
                debug!("Could not create symlink for testing: {}", e);
            } else {
                let args = json!({ &param_name: symlink_name });
                let history_idx = ctx.client.history().len();

                match ctx.client.call_tool_raw(tool_name, args.clone()).await {
                    Ok(response) => {
                        let detected = check_response_for_data(&response, &canaries);
                        if !detected.is_empty() {
                            let fid = next_finding_id(&mut id_counters, &Severity::High);
                            findings.push(Finding {
                                id: fid,
                                title: format!(
                                    "Symlink following allows reading sensitive files via {}",
                                    tool_name
                                ),
                                severity: Severity::High,
                                cvss: 7.5,
                                category: ModuleCategory::PathTraversal,
                                description: format!(
                                    "The tool '{}' follows symlinks without checking the real \
                                     path. A symlink pointing to '{}' was successfully read. \
                                     Canaries: {:?}",
                                    tool_name,
                                    target_path.display(),
                                    detected
                                ),
                                reproduction: Some(Reproduction {
                                    method: format!("tools/call {}", tool_name),
                                    tool: Some(tool_name.clone()),
                                    arguments: Some(args),
                                }),
                                evidence: Evidence {
                                    messages: vec![history_idx],
                                    audit_record: None,
                                    canary_detected: true,
                                    os_events: Vec::new(),
                                    files_modified: vec![symlink_path.display().to_string()],
                                    network_connections: Vec::new(),
                                    stderr_output: None,
                                },
                                remediation: format!(
                                    "Resolve symlinks before access validation in '{}'. \
                                     Use canonicalize() to get the real path and verify it \
                                     is within the allowed directory.",
                                    tool_name
                                ),
                            });
                        }
                    }
                    Err(e) => {
                        debug!("Symlink test error: {}", e);
                    }
                }
                // Cleanup symlink
                let _ = std::fs::remove_file(&symlink_path);
            }

            // (f) Case sensitivity (macOS APFS)
            let case_variants = vec![
                (".SSH/ID_RSA", Severity::Medium, 5.5),
                (".Ssh/Id_Rsa", Severity::Medium, 5.5),
                (".ssh/ID_RSA", Severity::Medium, 5.5),
            ];
            for (target, severity, cvss) in &case_variants {
                let tpath = format!("../{}", target);
                let args = json!({ &param_name: &tpath });
                let history_idx = ctx.client.history().len();

                match ctx.client.call_tool_raw(tool_name, args.clone()).await {
                    Ok(response) => {
                        let detected = check_response_for_data(&response, &canaries);
                        if !detected.is_empty() {
                            let fid = next_finding_id(&mut id_counters, severity);
                            findings.push(Finding {
                                id: fid,
                                title: format!(
                                    "Case-insensitive path bypass via {}",
                                    tool_name
                                ),
                                severity: *severity,
                                cvss: *cvss,
                                category: ModuleCategory::PathTraversal,
                                description: format!(
                                    "The tool '{}' allowed reading sensitive files using \
                                     case-variant path '{}'. On case-insensitive filesystems \
                                     (macOS APFS), path filters based on exact string matching \
                                     can be bypassed. Canaries: {:?}",
                                    tool_name, tpath, detected
                                ),
                                reproduction: Some(Reproduction {
                                    method: format!("tools/call {}", tool_name),
                                    tool: Some(tool_name.clone()),
                                    arguments: Some(args),
                                }),
                                evidence: Evidence {
                                    messages: vec![history_idx],
                                    audit_record: None,
                                    canary_detected: true,
                                    os_events: Vec::new(),
                                    files_modified: Vec::new(),
                                    network_connections: Vec::new(),
                                    stderr_output: None,
                                },
                                remediation: format!(
                                    "Normalize paths to lowercase before applying deny-list \
                                     filters in '{}'. Use canonicalize() to resolve the true \
                                     filesystem path on case-insensitive systems.",
                                    tool_name
                                ),
                            });
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Case sensitivity test error: {}", e);
                    }
                }
            }
        }

        Ok(findings)
    }
}

/// Detect tools that handle file operations based on name keywords and schema parameters.
fn detect_file_tools(tools: &[ToolInfo]) -> Vec<&ToolInfo> {
    tools
        .iter()
        .filter(|tool| {
            let name_lower = tool.name.to_lowercase();
            let desc_lower = tool.description.to_lowercase();

            // Check if name contains file-related keywords
            let name_match = FILE_TOOL_KEYWORDS
                .iter()
                .any(|kw| name_lower.contains(kw) || desc_lower.contains(kw));

            // Check if input schema has path-like parameters
            let schema_match = find_path_param(&tool.input_schema).is_some();

            name_match || schema_match
        })
        .collect()
}

/// Extract the name of a path-like parameter from a tool's input schema.
fn find_path_param(schema: &Value) -> Option<String> {
    let properties = schema
        .get("properties")
        .or_else(|| {
            schema
                .get("inputSchema")
                .and_then(|s| s.get("properties"))
        })?;

    if let Value::Object(props) = properties {
        for key in props.keys() {
            let key_lower = key.to_lowercase();
            if PATH_PARAM_NAMES.iter().any(|p| key_lower.contains(p)) {
                return Some(key.clone());
            }
        }
    }
    None
}

/// Build traversal paths with ../ sequences from depth 1 to `max_depth`.
fn build_traversal_paths(max_depth: usize, target: &str) -> Vec<String> {
    (1..=max_depth)
        .map(|depth| {
            let prefix: String = "../".repeat(depth);
            format!("{}{}", prefix, target)
        })
        .collect()
}

/// Build encoded traversal prefixes (URL-encoded, double-encoded, unicode).
fn build_encoded_paths() -> Vec<String> {
    vec![
        // URL-encoded
        "%2e%2e%2f".to_string(),
        "%2e%2e/".to_string(),
        "..%2f".to_string(),
        "%2e%2e%2f%2e%2e%2f".to_string(),
        "%2e%2e/%2e%2e/".to_string(),
        "..%2f..%2f".to_string(),
        // Double-encoded
        "%252e%252e%252f".to_string(),
        "%252e%252e%252f%252e%252e%252f".to_string(),
        // Unicode dot variants
        "\u{FF0E}\u{FF0E}/".to_string(),
        ".\u{2024}./".to_string(),
    ]
}

/// Check a tool response for canary string leaks.
fn check_response_for_data(response: &Value, canaries: &[&str]) -> Vec<String> {
    let text = serde_json::to_string(response).unwrap_or_default();
    canaries
        .iter()
        .filter(|c| text.contains(*c))
        .map(|c| c.to_string())
        .collect()
}

/// Generate an auto-incrementing finding ID like CRIT-001, HIGH-002, etc.
fn next_finding_id(counters: &mut HashMap<String, u32>, severity: &Severity) -> String {
    let prefix = severity.finding_id_prefix().to_string();
    let counter = counters.entry(prefix.clone()).or_insert(0);
    *counter += 1;
    format!("{}-{:03}", prefix, counter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_tool(name: &str, description: &str, schema: Value) -> ToolInfo {
        ToolInfo {
            name: name.to_string(),
            description: description.to_string(),
            input_schema: schema,
        }
    }

    #[test]
    fn test_detect_file_tools_by_name() {
        let tools = vec![
            make_tool("read_file", "Read a file", json!({})),
            make_tool("send_email", "Send email", json!({})),
            make_tool("write_file", "Write content", json!({})),
            make_tool("list_directory", "List files in dir", json!({})),
        ];
        let detected = detect_file_tools(&tools);
        assert_eq!(detected.len(), 3);
        assert_eq!(detected[0].name, "read_file");
        assert_eq!(detected[1].name, "write_file");
        assert_eq!(detected[2].name, "list_directory");
    }

    #[test]
    fn test_detect_file_tools_by_schema() {
        let tools = vec![
            make_tool(
                "custom_op",
                "Does something custom",
                json!({ "properties": { "filepath": { "type": "string" } } }),
            ),
            make_tool(
                "other_op",
                "Does other things",
                json!({ "properties": { "count": { "type": "integer" } } }),
            ),
        ];
        let detected = detect_file_tools(&tools);
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].name, "custom_op");
    }

    #[test]
    fn test_find_path_param_direct() {
        let schema = json!({ "properties": { "file_path": { "type": "string" } } });
        assert_eq!(find_path_param(&schema), Some("file_path".to_string()));
    }

    #[test]
    fn test_find_path_param_nested() {
        let schema = json!({
            "inputSchema": {
                "properties": {
                    "directory": { "type": "string" },
                    "verbose": { "type": "boolean" }
                }
            }
        });
        let result = find_path_param(&schema);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "directory");
    }

    #[test]
    fn test_find_path_param_none() {
        let schema = json!({ "properties": { "count": { "type": "integer" } } });
        assert_eq!(find_path_param(&schema), None);
    }

    #[test]
    fn test_build_traversal_paths() {
        let paths = build_traversal_paths(3, ".ssh/id_rsa");
        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0], "../.ssh/id_rsa");
        assert_eq!(paths[1], "../../.ssh/id_rsa");
        assert_eq!(paths[2], "../../../.ssh/id_rsa");
    }

    #[test]
    fn test_build_traversal_paths_depth_10() {
        let paths = build_traversal_paths(10, ".env");
        assert_eq!(paths.len(), 10);
        assert!(paths[9].starts_with("../../../../../../../../../../"));
        assert!(paths[9].ends_with(".env"));
    }

    #[test]
    fn test_check_response_for_data_finds_canaries() {
        let response = json!({
            "result": {
                "content": [{ "text": "data: CANARY_SSH_KEY_CONTENT_DO_NOT_EXFILTRATE here" }]
            }
        });
        let canaries = vec![
            "CANARY_SSH_KEY_CONTENT_DO_NOT_EXFILTRATE",
            "CANARY_AWS_ACCESS_KEY",
        ];
        let detected = check_response_for_data(&response, &canaries);
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0], "CANARY_SSH_KEY_CONTENT_DO_NOT_EXFILTRATE");
    }

    #[test]
    fn test_check_response_for_data_clean() {
        let response = json!({ "result": { "content": [{ "text": "normal file content" }] } });
        let canaries = vec!["CANARY_SSH_KEY_CONTENT_DO_NOT_EXFILTRATE", "CANARY_AWS_ACCESS_KEY"];
        let detected = check_response_for_data(&response, &canaries);
        assert!(detected.is_empty());
    }

    #[test]
    fn test_finding_id_generation() {
        let mut counters = HashMap::new();
        assert_eq!(next_finding_id(&mut counters, &Severity::Critical), "CRIT-001");
        assert_eq!(next_finding_id(&mut counters, &Severity::Critical), "CRIT-002");
        assert_eq!(next_finding_id(&mut counters, &Severity::High), "HIGH-001");
        assert_eq!(next_finding_id(&mut counters, &Severity::Medium), "MED-001");
        assert_eq!(next_finding_id(&mut counters, &Severity::Critical), "CRIT-003");
    }

    #[test]
    fn test_encoded_paths_generated() {
        let paths = build_encoded_paths();
        assert!(paths.len() >= 8);
        assert!(paths.contains(&"%2e%2e%2f".to_string()));
        assert!(paths.contains(&"%252e%252e%252f".to_string()));
        assert!(paths.contains(&"..%2f".to_string()));
    }

    #[test]
    fn test_symlink_path_detection_via_schema() {
        // Tools with path params should be detected for symlink testing
        let tools = vec![make_tool(
            "get_content",
            "Get content of something",
            json!({ "properties": { "path": { "type": "string" } } }),
        )];
        let detected = detect_file_tools(&tools);
        assert_eq!(detected.len(), 1);
        let param = find_path_param(&detected[0].input_schema);
        assert_eq!(param, Some("path".to_string()));
    }

    #[test]
    fn test_severity_scoring_credentials() {
        // Credential files should be Critical
        for (target, severity, cvss) in SENSITIVE_TARGETS {
            if *target == ".ssh/id_rsa" || *target == ".aws/credentials" || *target == ".env" {
                assert_eq!(*severity, Severity::Critical);
                assert!(*cvss >= 9.0);
            }
        }
    }

    #[test]
    fn test_severity_scoring_history() {
        // History files should be High
        for (target, severity, cvss) in SENSITIVE_TARGETS {
            if *target == ".bash_history" {
                assert_eq!(*severity, Severity::High);
                assert!(*cvss >= 7.0);
            }
        }
    }

    #[test]
    fn test_module_trait_impl() {
        let module = PathTraversalModule::new();
        assert_eq!(module.name(), "path-traversal");
        assert_eq!(module.category(), ModuleCategory::PathTraversal);
        assert!(!module.description().is_empty());
    }

    #[test]
    fn test_check_response_multiple_canaries() {
        let response = json!({
            "result": {
                "content": [{
                    "text": "key=CANARY_AWS_ACCESS_KEY secret=CANARY_AWS_SECRET_KEY"
                }]
            }
        });
        let canaries = vec!["CANARY_AWS_ACCESS_KEY", "CANARY_AWS_SECRET_KEY", "CANARY_OTHER"];
        let detected = check_response_for_data(&response, &canaries);
        assert_eq!(detected.len(), 2);
    }
}
